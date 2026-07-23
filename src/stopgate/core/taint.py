r"""THE MOAT — provenance, taint propagation, and egress matching.

This is the part of Stopgate that a lexical guardrail cannot copy. It does not
read words. It tracks *where bytes came from* and *where they are going*:

  * **Provenance** — every tool RESULT is tagged trusted (the operator/host) or
    untrusted (web / email / file / MCP). Reading untrusted content taints the
    session.
  * **Temporal-proximity heuristic** (formerly "escalation") — a high-risk action
    within ``window`` steps of untrusted content has its severity raised, because
    "the agent read a webpage and then tried to POST somewhere" is the actual shape
    of a prompt-injection exploit. Be honest about what this is: a proximity
    HEURISTIC, not true taint — we cannot see which datum actually influenced the
    model at the tool boundary. Confidence DECAYS with distance (nearest step ~1.0,
    edge of the window ~1/window) and it is trivially EVADABLE by spacing the action
    more than ``window`` steps after the untrusted read.
  * **Egress matching** — when a secret or file is read, its bytes are
    fingerprinted with a rolling hash over overlapping shingles. When a later
    action's outbound payload contains those same bytes (even if the surrounding
    command is worded to look innocent, even base64-wrapped), the overlap is
    detected. You cannot reword your way past a hash comparison.
  * **Taint graph** — every escalation / hit records an edge from the untrusted
    source (or secret read) it is downstream of, emitted into the audit log.

Pure, standard-library only, no I/O. The rolling hash is a plain polynomial
(Rabin-Karp) hash so behaviour does not depend on ``PYTHONHASHSEED``.
"""

from __future__ import annotations

import hashlib

import base64
import math
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from . import detectors
from .action import Action, Severity

# --------------------------------------------------------------------------- #
# Rolling-hash shingling (Rabin-Karp)
# --------------------------------------------------------------------------- #
_SHINGLE_K = 12          # window size in bytes; long enough to be distinctive
_BASE = 257
_MOD = (1 << 61) - 1
_MAX_FINGERPRINT_BYTES = 200_000   # cap work per read so `report` stays fast
_MIN_SECRET_LEN = 8                # ignore trivially short "secrets"
_MATCH_RATIO = 0.6                 # fraction of a secret's shingles that must
#                                    appear in an outbound payload to flag it
_MAX_SECRETS_PER_READ = 512        # cap distinct secrets captured from one read


def rolling_shingles(data: str, k: int = _SHINGLE_K) -> Set[int]:
    """Return the set of rolling-hash fingerprints of every k-byte window.

    A short input (``len < k``) is hashed whole so tiny secrets still fingerprint.
    Byte-oriented (UTF-8) so it is agnostic to text vs binary payloads.
    """
    if not data:
        return set()
    b = data.encode("utf-8", "surrogatepass")[:_MAX_FINGERPRINT_BYTES]
    n = len(b)
    if n == 0:
        return set()
    if n <= k:
        h = 0
        for c in b:
            h = (h * _BASE + c) % _MOD
        return {h}

    out: Set[int] = set()
    high = pow(_BASE, k - 1, _MOD)
    h = 0
    for i in range(k):
        h = (h * _BASE + b[i]) % _MOD
    out.add(h)
    for i in range(k, n):
        h = (h - b[i - k] * high) % _MOD
        h = (h * _BASE + b[i]) % _MOD
        out.add(h)
    return out


def _shannon_entropy(s: str) -> float:
    """Shannon entropy (bits/char) — a cheap high-randomness proxy."""
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _looks_secretish(val: str) -> bool:
    """Whether a bare ``KEY=VALUE`` value is distinctive enough to be a secret.

    Pattern-matched tokens (AKIA…, ghp_…, JWTs) are captured elsewhere and are
    always secret. This gate is for the ``.env`` fallback, where treating every
    short/low-entropy value (``DEBUG=true``, ``ENV=production``) as a secret
    would cause false-positive egress hits. We require real length AND either a
    known secret shape or genuine randomness.
    """
    if len(val) < _MIN_SECRET_LEN:
        return False
    from . import patterns as P

    if P.matches_any(val, P.SECRET_VALUE_PATTERNS):
        return True
    if len(val) >= 16 and len(set(val)) >= 8:
        return True
    if len(val) >= 12 and _shannon_entropy(val) >= 3.0:
        return True
    return False


def _encoded_variants(val: str) -> List[str]:
    """Common encodings an exfil attempt wraps a secret in.

    Fingerprinting these too is what makes egress matching survive base64/hex
    wrapping — you cannot reword your way past a hash comparison, and now you
    cannot base64 your way past it either.
    """
    try:
        b = val.encode("utf-8", "surrogatepass")
    except Exception:
        return []
    variants: List[str] = []
    try:
        std = base64.b64encode(b).decode("ascii")
        variants.append(std)
        variants.append(std.rstrip("="))  # unpadded base64
    except Exception:
        pass
    try:
        variants.append(base64.urlsafe_b64encode(b).decode("ascii"))
    except Exception:
        pass
    try:
        variants.append(b.hex())
    except Exception:
        pass
    out: List[str] = []
    seen: Set[str] = set()
    for v in variants:
        if v and v != val and v not in seen:
            seen.add(v)
            out.append(v)
    return out


def _fingerprint_value(val: str, k: int) -> Tuple[List[str], List[Set[int]]]:
    """Return (literals, per-literal shingle sets) for a secret and its encodings.

    ``literals`` drive an exact-substring fast path (catches short secrets and
    verbatim encoded copies that are too short to shingle); the shingle sets
    drive fuzzy overlap matching for reworded / partial payloads.
    """
    literals = [val]
    literals.extend(_encoded_variants(val))
    kept: List[str] = []
    fingerprints: List[Set[int]] = []
    for lit in literals:
        sh = rolling_shingles(lit, k)
        if sh:
            kept.append(lit)
            fingerprints.append(sh)
    return kept, fingerprints


def _extract_secret_values(content: str) -> List[str]:
    """Pull the distinctive secret *values* out of a read result.

    We fingerprint the values, not the whole file, so that later egress is
    flagged by the secret itself leaving — not by an unrelated line of the file
    happening to reappear. Falls back to the whole content when no discrete
    value is recognised (e.g. an opaque private-key blob read in full).
    """
    from . import patterns as P

    values: List[str] = []
    seen: Set[str] = set()

    def _add(v: str) -> None:
        if v and v not in seen:
            seen.add(v)
            values.append(v)

    for pat in P.SECRET_VALUE_PATTERNS:
        for m in pat.finditer(content):
            _add(m.group(0))
    # `.env`-style KEY=VALUE lines: the value side is the secret — but only if it
    # actually looks like one, so low-entropy config values don't taint egress.
    for line in content.splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            val = line.split("=", 1)[1].strip().strip("'\"")
            if _looks_secretish(val):
                _add(val)
    return values


_MAX_HASH_SCAN = 65_536            # cap the sliding-window scan; a huge write
                                   # must never stall the gate


def _short_hash_hits(payload: str, refs: List["SecretRef"], salt: str,
                     shingle_k: int) -> Set[str]:
    """Match secrets we know only by salted hash (state restored from disk).

    Only *sub-shingle-length* secrets need this: anything at least ``shingle_k``
    long is already covered by its rolling-hash fingerprints, which survive
    persistence. Short ones cannot be shingled and their plaintext was never
    written to disk (by design), so we slide a window of each known length over
    the payload and compare salted hashes. One bounded scan per action.
    """
    wanted: dict = {}
    for ref in refs:
        for h, n in (getattr(ref, "literal_hashes", None) or ()):
            n = int(n)
            if 0 < n < shingle_k:
                wanted.setdefault(n, set()).add(h)
    if not wanted or not payload:
        return set()
    data = payload[:_MAX_HASH_SCAN]
    hits: Set[str] = set()
    for length, hashes in wanted.items():
        if length > len(data):
            continue
        for i in range(len(data) - length + 1):
            h = hashlib.sha256(
                (salt + data[i:i + length]).encode("utf-8", "replace")).hexdigest()
            if h in hashes:
                hits.add(h)
    return hits


@dataclass
class SecretRef:
    """A fingerprinted secret captured from a read, for egress matching.

    ``literals`` are the secret plus its common encodings (base64/hex) for an
    exact-substring fast path; ``fingerprints`` holds one rolling-hash shingle
    set per literal for fuzzy / partial matching.
    """

    step: int
    source: str
    label: str
    literals: List[str] = field(default_factory=list)
    fingerprints: List[Set[int]] = field(default_factory=list)
    # Salted (hash, length) pairs. Populated ONLY when this ref was restored from
    # a persisted session, where the secret bytes are deliberately never written
    # to disk. Lets a sub-shingle-length secret still be matched on egress
    # without Stopgate ever storing the secret itself. See stopgate.session.
    literal_hashes: List[Tuple[str, int]] = field(default_factory=list)

    @property
    def shingle_count(self) -> int:
        return sum(len(f) for f in self.fingerprints)


@dataclass
class TaintEvent:
    """A node in the taint graph: an untrusted read that can taint later work."""

    step: int
    source: str
    tool: str
    summary: str


@dataclass
class TaintEdge:
    """A downstream link: action at ``step`` is downstream of ``origin_step``."""

    origin_step: int
    action_step: int
    kind: str          # "escalation" | "egress"
    detail: str


@dataclass
class Observation:
    """What the taint layer concluded about one action, for the engine."""

    step: int
    tainted_session: bool = False
    escalated: bool = False
    proximity: float = 0.0                   # decaying temporal-proximity weight (heuristic)
    taint_hit: bool = False                  # egress match found
    added_severity: Severity = Severity.NONE
    downstream_of: List[TaintEvent] = field(default_factory=list)
    matched_secrets: List[SecretRef] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)


class TaintTracker:
    """Stateful, ordered taint state for one agent session.

    Feed it actions in execution order via :meth:`observe`. It is the only
    stateful object in ``core``; the policy engine wraps it. No I/O.
    """

    def __init__(self, window: int = 6, shingle_k: int = _SHINGLE_K) -> None:
        self.window = int(window)
        self.shingle_k = int(shingle_k)
        self.step = 0
        self.tainted = False
        self.events: List[TaintEvent] = []
        self.secrets: List[SecretRef] = []
        self.edges: List[TaintEdge] = []
        self._last_untrusted_step: Optional[int] = None

    # -- fingerprint capture ------------------------------------------------ #
    def _capture_secrets(self, action: Action) -> None:
        """If this read exposed secret material, fingerprint it for egress."""
        result = action.result
        content = result.content if result else ""
        # A read is "secret-touching" if its path/args OR its content look secret.
        touches_secret = detectors.is_secret_material(action.text) or (
            bool(content) and detectors.is_secret_material(content)
        )
        if not touches_secret:
            return
        values = _extract_secret_values(content) if content else []
        if not values and content:
            values = [content]                      # opaque blob: fingerprint whole
        if not values and not content:
            # We know a secret PATH was touched but have no bytes (e.g. a
            # pre-tool hook with no result yet). Nothing to fingerprint.
            return
        label = _first_secret_label(action) or "secret"
        for val in values[:_MAX_SECRETS_PER_READ]:
            if len(val) < _MIN_SECRET_LEN:
                continue
            literals, fingerprints = _fingerprint_value(val, self.shingle_k)
            if fingerprints:
                self.secrets.append(
                    SecretRef(
                        step=self.step,
                        source=action.source,
                        label=label,
                        literals=literals,
                        fingerprints=fingerprints,
                    )
                )

    # -- egress matching ---------------------------------------------------- #
    def _match_egress(self, action: Action) -> List[SecretRef]:
        """Return secrets whose bytes appear in this action's outbound payload."""
        if not self.secrets:
            return []
        payload = action.outbound_bytes
        if not payload:
            return []
        out_shingles = rolling_shingles(payload, self.shingle_k)
        short_hits = _short_hash_hits(payload, self.secrets,
                                      getattr(self, "salt", "") or "", self.shingle_k)
        hits: List[SecretRef] = []
        for ref in self.secrets:
            if ref.step == self.step:
                continue  # a read cannot exfiltrate itself
            # Exact-substring fast path: catches short secrets (too small to
            # shingle inside a longer payload) and verbatim base64/hex copies.
            if any(lit and lit in payload for lit in ref.literals):
                hits.append(ref)
                continue
            # Same guarantee for a session restored from disk, where the secret
            # bytes were never persisted — only their salted hashes.
            if short_hits and any(
                h in short_hits for h, _n in (ref.literal_hashes or ())
            ):
                hits.append(ref)
                continue
            # Fuzzy path: enough of the secret's (or an encoding's) shingles
            # reappear in the outbound payload.
            if out_shingles and any(
                fp and len(fp & out_shingles) / len(fp) >= _MATCH_RATIO
                for fp in ref.fingerprints
            ):
                hits.append(ref)
        return hits

    # -- main entry point --------------------------------------------------- #
    def observe(self, action: Action) -> Observation:
        self.step += 1
        obs = Observation(step=self.step)

        result = action.result
        # 1) Provenance: an untrusted result with real content taints the session.
        if result is not None and not result.trusted and result.content.strip():
            self.tainted = True
            self._last_untrusted_step = self.step
            ev = TaintEvent(
                step=self.step,
                source=result.source,
                tool=action.tool,
                summary=_snippet(result.content),
            )
            self.events.append(ev)
            obs.reasons.append(
                "untrusted content read from {!r}".format(result.source)
            )

        # 2) Capture secret fingerprints from this read (post-taint so a secret
        #    read from an untrusted place still registers as a source).
        self._capture_secrets(action)

        obs.tainted_session = self.tainted

        # 3) Egress matching — the thing keyword gates cannot do.
        hits = self._match_egress(action)
        if hits:
            obs.taint_hit = True
            obs.matched_secrets = hits
            obs.added_severity = Severity.CRITICAL
            for ref in hits:
                self.edges.append(
                    TaintEdge(
                        origin_step=ref.step,
                        action_step=self.step,
                        kind="egress",
                        detail="secret {!r} (read at step {}) present in outbound payload".format(
                            ref.label, ref.step
                        ),
                    )
                )
                obs.reasons.append(
                    "EGRESS: bytes of secret {!r} from step {} are leaving in this payload".format(
                        ref.label, ref.step
                    )
                )

        # 4) Escalation — high-risk action close behind untrusted content.
        cls = detectors.classify(action)
        is_high_risk = bool(set(cls.kinds) & detectors.HIGH_RISK_KINDS)
        if (
            is_high_risk
            and self._last_untrusted_step is not None
            and self.step != self._last_untrusted_step
            and (self.step - self._last_untrusted_step) <= self.window
        ):
            obs.escalated = True
            distance = self.step - self._last_untrusted_step
            # Decaying confidence: nearest step ~1.0, edge of window ~1/window.
            obs.proximity = round((self.window - distance + 1) / self.window, 2)
            obs.reasons.append(
                "temporal-proximity heuristic: high-risk action {} step(s) after untrusted "
                "content (confidence {}, decays with distance; evadable by spacing > {} steps)"
                .format(distance, obs.proximity, self.window))
            recent = [e for e in self.events if 0 < self.step - e.step <= self.window]
            obs.downstream_of = recent
            obs.added_severity = max(obs.added_severity, Severity.HIGH)
            for e in recent:
                self.edges.append(
                    TaintEdge(
                        origin_step=e.step,
                        action_step=self.step,
                        kind="escalation",
                        detail="{} action {} step(s) after untrusted read from {!r}".format(
                            cls.primary, distance, e.source
                        ),
                    )
                )
            obs.reasons.append(
                "{} action {} step(s) after reading untrusted content".format(
                    cls.primary, distance
                )
            )

        return obs

    # -- audit -------------------------------------------------------------- #
    def graph(self) -> Dict[str, object]:
        """Emit the taint graph for the audit log (JSON-serializable)."""
        return {
            "tainted": self.tainted,
            "nodes": [
                {"step": e.step, "source": e.source, "tool": e.tool, "summary": e.summary}
                for e in self.events
            ],
            "secrets": [
                {"step": s.step, "source": s.source, "label": s.label,
                 "shingles": s.shingle_count}
                for s in self.secrets
            ],
            "edges": [
                {
                    "origin_step": e.origin_step,
                    "action_step": e.action_step,
                    "kind": e.kind,
                    "detail": e.detail,
                }
                for e in self.edges
            ],
        }


def _snippet(text: str, n: int = 80) -> str:
    t = " ".join(str(text).split())
    return t if len(t) <= n else t[: n - 1] + "…"


def _first_secret_label(action: Action) -> Optional[str]:
    """A human label for a captured secret: the path/arg that looked secret."""
    from . import patterns as P

    for chunk in action.text.split("\n"):
        if P.matches_any(chunk, P.CREDENTIAL_PATH_PATTERNS) or P.matches_any(
            chunk, P.SECRET_VALUE_PATTERNS
        ):
            return _snippet(chunk, 60)
    return None
