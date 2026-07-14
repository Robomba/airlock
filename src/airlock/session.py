r"""Cross-call session state — Airlock's dataflow moat, live.

A PreToolUse hook is a FRESH PROCESS on every single tool call. A TaintTracker
built inside it starts empty and dies a millisecond later. Without this module
the live gate can therefore only ever judge ONE action in isolation — which
quietly demotes Airlock to the keyword-style matcher it exists to beat: "read
the .env at step 3, POST it to an unknown host at step 19" would sail straight
through, because step 19 looks innocent on its own.

So the tracker is persisted between calls, keyed by the agent's session id.

Two seams, and you need BOTH:

  * ``PostToolUse`` -> ``airlock watch`` — the only place tool RESULTS exist, and
    therefore the only place a secret can actually be captured. Advances state.
  * ``PreToolUse``  -> ``airlock hook``  — judges the PENDING action against the
    state captured so far. Evaluates on a COPY, so a ruling never rewrites history.

**The secret bytes are never written to disk.** State holds only rolling-hash
shingle fingerprints plus salted hashes of the secret material — enough to
recognise those bytes trying to leave, not enough to reconstruct them. A stolen
state file yields nothing.

Best-effort by design: unreadable, corrupt, or oversized state degrades to a
FRESH tracker rather than bricking the agent. Airlock is a safety net, not a
guarantee.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import secrets as _secrets
import tempfile
import time
from typing import Any, Dict, List, Optional

from .core.taint import SecretRef, TaintEdge, TaintEvent, TaintTracker

STATE_VERSION = 2
MAX_STATE_BYTES = 8_000_000        # a runaway session must not fill the disk
STATE_TTL_SECONDS = 7 * 24 * 3600  # forget sessions after a week
_SAFE_ID = re.compile(r"[^A-Za-z0-9_.-]")


def state_dir() -> str:
    d = os.environ.get("AIRLOCK_STATE_DIR")
    if not d:
        d = os.path.join(os.path.expanduser("~"), ".cache", "airlock", "sessions")
    return d


def _safe_id(session_id: Optional[str]) -> str:
    sid = _SAFE_ID.sub("_", str(session_id or "default"))[:64]
    return sid or "default"


def path_for(session_id: Optional[str]) -> str:
    return os.path.join(state_dir(), _safe_id(session_id) + ".json")



# --- redaction --------------------------------------------------------------- #
# A TaintEvent's summary is a snippet of what was READ. If the agent read a
# credentials file, that snippet IS the credential — persisting it verbatim would
# mean Airlock, a security tool, quietly writing your secrets to disk. So every
# summary is scrubbed on the way out: the secret VALUES are masked, while
# non-secret untrusted text (e.g. an injected instruction in a README) is kept
# visible, because seeing that is the whole point of the taint graph.

_MAX_SUMMARY = 200


def _scrub(text: str) -> str:
    if not text:
        return text
    from .core import detectors
    from .core.taint import _extract_secret_values
    out = text[:_MAX_SUMMARY]
    try:
        for val in _extract_secret_values(text):
            if len(val) >= 6:
                out = out.replace(val, "<redacted:{}>".format(len(val)))
    except Exception:
        return "<redacted: {} chars>".format(len(text))
    try:
        # Belt and braces: if it still smells like credential material at all
        # (e.g. the KEY NAME survived), drop the whole thing.
        if detectors.is_secret_material(out):
            return "<redacted secret material: {} chars>".format(len(text))
    except Exception:
        return "<redacted: {} chars>".format(len(text))
    return out


# --- serialisation (fingerprints only; never the secret itself) ------------- #

def _hash_literal(lit: str, salt: str) -> List[Any]:
    h = hashlib.sha256((salt + lit).encode("utf-8", "replace")).hexdigest()
    return [h, len(lit)]


def to_dict(t: TaintTracker, salt: str) -> Dict[str, Any]:
    return {
        "v": STATE_VERSION,
        "salt": salt,
        "ts": int(time.time()),
        "window": t.window,
        "shingle_k": t.shingle_k,
        "step": t.step,
        "tainted": bool(t.tainted),
        "last_untrusted_step": getattr(t, "_last_untrusted_step", None),
        "events": [
            {"step": e.step, "source": e.source, "tool": e.tool,
             "summary": _scrub(e.summary)}
            for e in t.events
        ],
        "secrets": [
            {
                "step": s.step,
                "source": s.source,
                "label": s.label,
                # literals are DELIBERATELY not persisted.
                "literal_hashes": [_hash_literal(lit, salt)
                                   for lit in s.literals if lit],
                "fingerprints": [sorted(fp) for fp in s.fingerprints],
            }
            for s in t.secrets
        ],
        "edges": [
            {"origin_step": x.origin_step, "action_step": x.action_step,
             "kind": x.kind, "detail": x.detail}
            for x in t.edges
        ],
    }


def from_dict(d: Dict[str, Any]) -> TaintTracker:
    t = TaintTracker(window=int(d.get("window", 6)),
                     shingle_k=int(d.get("shingle_k", 12)))
    t.step = int(d.get("step", 0))
    t.tainted = bool(d.get("tainted", False))
    t._last_untrusted_step = d.get("last_untrusted_step")
    t.events = [
        TaintEvent(step=int(e["step"]), source=e.get("source", ""),
                   tool=e.get("tool", ""), summary=e.get("summary", ""))
        for e in d.get("events", []) if isinstance(e, dict) and "step" in e
    ]
    t.edges = [
        TaintEdge(origin_step=int(x["origin_step"]), action_step=int(x["action_step"]),
                  kind=x.get("kind", ""), detail=x.get("detail", ""))
        for x in d.get("edges", []) if isinstance(x, dict) and "origin_step" in x
    ]
    secs: List[SecretRef] = []
    for s in d.get("secrets", []):
        if not isinstance(s, dict):
            continue
        ref = SecretRef(
            step=int(s.get("step", 0)),
            source=s.get("source", ""),
            label=s.get("label", "secret"),
            literals=[],                                  # never restored: never stored
            fingerprints=[set(fp) for fp in s.get("fingerprints", []) if fp],
        )
        ref.literal_hashes = [(h, int(n)) for h, n in s.get("literal_hashes", [])]
        secs.append(ref)
    t.secrets = secs
    return t


# --- load / save ------------------------------------------------------------ #

def load(session_id: Optional[str]) -> TaintTracker:
    """Restore the session's tracker. Any problem at all -> a fresh one."""
    p = path_for(session_id)
    try:
        if not os.path.exists(p) or os.path.getsize(p) > MAX_STATE_BYTES:
            return _fresh()
        if time.time() - os.path.getmtime(p) > STATE_TTL_SECONDS:
            return _fresh()
        with open(p, "r", encoding="utf-8") as fh:
            d = json.load(fh)
        if not isinstance(d, dict) or int(d.get("v", 0)) != STATE_VERSION:
            return _fresh()
        t = from_dict(d)
        t.salt = d.get("salt") or _new_salt()
        return t
    except Exception:
        return _fresh()          # corrupt state must never brick the agent


def _fresh() -> TaintTracker:
    t = TaintTracker()
    t.salt = _new_salt()
    return t


def _new_salt() -> str:
    return _secrets.token_hex(16)


def save(session_id: Optional[str], t: TaintTracker) -> bool:
    """Atomically persist. Returns False on any failure (never raises)."""
    try:
        salt = getattr(t, "salt", None) or _new_salt()
        d = to_dict(t, salt)
        blob = json.dumps(d, separators=(",", ":"))
        if len(blob) > MAX_STATE_BYTES:
            return False
        p = path_for(session_id)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(p), suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(blob)
            os.replace(tmp, p)
            try:
                os.chmod(p, 0o600)   # fingerprints only, but still: user-only
            except OSError:
                pass
        finally:
            if os.path.exists(tmp):
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
        return True
    except Exception:
        return False


def snapshot(t: TaintTracker) -> TaintTracker:
    """A deep copy, so evaluating a PENDING action never mutates real history."""
    c = copy.deepcopy(t)
    c.salt = getattr(t, "salt", None)
    return c


def prune(max_age: int = STATE_TTL_SECONDS) -> int:
    """Delete stale session files. Returns how many were removed."""
    n = 0
    try:
        d = state_dir()
        now = time.time()
        for name in os.listdir(d):
            if not name.endswith(".json"):
                continue
            p = os.path.join(d, name)
            try:
                if now - os.path.getmtime(p) > max_age:
                    os.unlink(p)
                    n += 1
            except OSError:
                pass
    except OSError:
        pass
    return n
