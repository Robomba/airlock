r"""Auto-learned, human-editable allow-policy — Phase 2 (observe-only).

The retention loop's second half: instead of asking the user to *author* a
policy, Airlock watches their OWN past sessions and writes an allowlist of what
is normal for them — the directories they always touch, the domains they always
call, the tools they always use. ``report`` and ``digest`` then use it to
SUPPRESS known-normal activity so what's left is the anomalies.

Two hard rules keep this honest and safe (v1 is still observe-only):

  1. **A policy NEVER unblocks anything.** It only removes low-signal *notices*
     for routine activity. A secret leaving the machine (an egress taint hit),
     an action downstream of untrusted content (escalation), and every
     irreversible action (money / destructive / publish) are ALWAYS surfaced,
     in-policy or not. Suppression cannot reach them — see :func:`suppression`.

  2. **Airlock will not learn an activity it flagged.** When learning, any
     action that was a taint hit, an escalation, or irreversible is EXCLUDED
     from the harvest — so a session that contained an exfil attempt never
     teaches Airlock that the exfil domain is "normal". The learned policy is
     built from the quiet, routine parts of your sessions only.

Standard library only. TOML is read with :mod:`tomllib` when present (3.11+) and
a tiny built-in fallback parser otherwise; it is written by hand so the file is
readable and diff-friendly. No network, no third-party deps (Promise #1).
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .core.action import Action, ActionKind
from .engine import Decision, Verdict

# --------------------------------------------------------------------------- #
# Feature extraction — pull the concrete dirs / domains / tools out of actions
# --------------------------------------------------------------------------- #
_DOMAIN_RE = re.compile(r"https?://([^/\s:\"']+)", re.IGNORECASE)

# Arg keys that carry a filesystem path across the tools we adapt.
_PATH_KEYS = (
    "file_path", "path", "notebook_path", "filename", "file",
    "target", "dst", "destination", "src", "source_path", "output",
)

# Risky kinds a learned policy is allowed to explain away when they're routine.
# Anything NOT here (destructive/spend/install/permission/messaging) is never
# suppressible — it stays visible no matter how often you do it.
_SUPPRESSIBLE_KINDS = frozenset(
    {ActionKind.READ, ActionKind.WRITE, ActionKind.CREDENTIAL_ACCESS,
     ActionKind.NETWORK_EGRESS, ActionKind.OTHER}
)
_NEVER_SUPPRESS_KINDS = frozenset(
    {ActionKind.DESTRUCTIVE, ActionKind.SPEND, ActionKind.INSTALL,
     ActionKind.PERMISSION, ActionKind.MESSAGING}
)


def domains_of(action: Action) -> List[str]:
    """Outbound domains this action would contact (request args only, never
    result content — a domain merely *mentioned* in a fetched page is not one
    the agent chose to call)."""
    out: List[str] = []
    seen: Set[str] = set()
    for m in _DOMAIN_RE.finditer(_outbound_text(action)):
        d = m.group(1).lower()
        if d and d not in seen:
            seen.add(d)
            out.append(d)
    return out


def _outbound_text(action: Action) -> str:
    """The parts of an action that represent an outbound request: its url-ish
    args and any command. Deliberately excludes the tool result content."""
    parts: List[str] = []
    for k in ("url", "uri", "endpoint", "host", "command", "cmd", "query"):
        v = action.args.get(k)
        if isinstance(v, str):
            parts.append(v)
    # Fall back to the flattened args (never the result) if nothing obvious.
    if not parts:
        parts.append(action.text)
    return "\n".join(parts)


def paths_of(action: Action) -> List[str]:
    """Filesystem paths this action explicitly references via its args."""
    out: List[str] = []
    seen: Set[str] = set()
    for k in _PATH_KEYS:
        v = action.args.get(k)
        if isinstance(v, str) and v.strip():
            p = v.strip()
            if p not in seen:
                seen.add(p)
                out.append(p)
    return out


def _norm_dir(path: str) -> Optional[str]:
    """The directory to learn for a referenced path, or ``None`` for a bare
    top-level filename (learned as a file, not a directory, so we never learn
    the everything-matching ``.``)."""
    p = path.strip().rstrip("/")
    if not p:
        return None
    d = os.path.dirname(p)
    if d in ("", "."):
        return None
    return os.path.normpath(d)


def _under(path: str, directory: str) -> bool:
    """True if *path* is inside *directory* (both normalized, no I/O)."""
    p = os.path.normpath(path.strip())
    d = os.path.normpath(directory.strip())
    if d in ("", "."):
        return False  # never treat cwd-root as a blanket allow
    if p == d:
        return True
    return p.startswith(d + os.sep) or p.startswith(d + "/")


# --------------------------------------------------------------------------- #
# The policy object
# --------------------------------------------------------------------------- #
@dataclass
class Policy:
    """A human-readable allowlist of what is normal for this user.

    Empty by default: an empty policy suppresses nothing, which is exactly the
    zero-config behaviour. Every field is a sorted list of plain strings so the
    on-disk TOML is stable and diff-friendly.
    """

    dirs: List[str] = field(default_factory=list)
    files: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    tools: List[str] = field(default_factory=list)
    meta: Dict[str, str] = field(default_factory=dict)

    def covers_path(self, path: str) -> bool:
        p = path.strip()
        if p in self.files:
            return True
        return any(_under(p, d) for d in self.dirs)

    def covers_domain(self, domain: str) -> bool:
        return domain.lower() in {d.lower() for d in self.domains}

    def knows_tool(self, tool: str) -> bool:
        return tool in self.tools

    @property
    def is_empty(self) -> bool:
        return not (self.dirs or self.files or self.domains or self.tools)


# --------------------------------------------------------------------------- #
# Learning — build a policy from observed sessions
# --------------------------------------------------------------------------- #
@dataclass
class LearnStats:
    sessions: int = 0
    actions: int = 0
    harvested: int = 0     # actions that contributed to the allowlist
    excluded: int = 0      # actions Airlock refused to learn (flagged/risky)


def _harvestable(decision: Decision) -> bool:
    """Whether an action may teach the policy. We refuse to learn from anything
    Airlock flagged as suspicious or that is irreversible — so an exfil session
    never allowlists the exfil, and a destructive command never becomes 'normal'."""
    if decision.taint_hit or decision.escalated or decision.irreversible:
        return False
    if set(decision.kinds) & _NEVER_SUPPRESS_KINDS:
        return False
    return True


def learn_policy(
    observations: Iterable[Tuple[Action, Decision]],
    *,
    sessions: int = 1,
    base: Optional[Policy] = None,
) -> Tuple[Policy, LearnStats]:
    """Aggregate ``(action, decision)`` pairs into an allowlist policy.

    ``base`` lets ``learn`` accumulate across several ``--log`` files without
    losing prior entries. Returns the policy plus stats for the receipt.
    """
    dirs: Set[str] = set(base.dirs) if base else set()
    files: Set[str] = set(base.files) if base else set()
    domains: Set[str] = set(base.domains) if base else set()
    tools: Set[str] = set(base.tools) if base else set()

    stats = LearnStats(sessions=sessions)
    for action, decision in observations:
        stats.actions += 1
        if not _harvestable(decision):
            stats.excluded += 1
            continue
        stats.harvested += 1
        tools.add(action.tool)
        for p in paths_of(action):
            d = _norm_dir(p)
            if d is not None:
                dirs.add(d)
            else:
                files.add(os.path.normpath(p.strip()))
        for dom in domains_of(action):
            domains.add(dom)

    pol = Policy(
        dirs=sorted(dirs),
        files=sorted(files),
        domains=sorted(domains),
        tools=sorted(tools),
    )
    return pol, stats


# --------------------------------------------------------------------------- #
# Suppression — the read side used by report / digest
# --------------------------------------------------------------------------- #
def suppression(action: Action, decision: Decision, policy: Optional[Policy]) -> Optional[str]:
    """Return a human reason if this action is known-normal and its notice can
    be suppressed, else ``None``.

    The safety invariant lives here: taint hits, escalations, irreversible
    actions and BLOCK verdicts are NEVER suppressible, so a learned policy can
    only ever remove low-signal notices — it cannot hide the real thing.
    """
    if policy is None or policy.is_empty:
        return None
    # HARD RULE: never suppress the signal.
    if decision.taint_hit or decision.escalated or decision.irreversible:
        return None
    if decision.verdict == Verdict.BLOCK:
        return None
    if set(decision.kinds) & _NEVER_SUPPRESS_KINDS:
        return None
    # The tool itself must be one the user routinely runs.
    if not policy.knows_tool(action.tool):
        return None

    paths = paths_of(action)
    domains = domains_of(action)
    covered: List[str] = []

    for kind in decision.kinds:
        if kind not in _SUPPRESSIBLE_KINDS:
            return None  # an un-suppressible kind sneaked in
        if kind == ActionKind.NETWORK_EGRESS:
            if not domains or not all(policy.covers_domain(d) for d in domains):
                return None
            covered.append("domain " + ", ".join(domains))
        elif kind in (ActionKind.READ, ActionKind.WRITE, ActionKind.CREDENTIAL_ACCESS):
            if not paths or not all(policy.covers_path(p) for p in paths):
                return None
            covered.append(("wrote " if kind == ActionKind.WRITE else "read ")
                           + ", ".join(paths))

    # An OTHER-only action with no paths/domains carries no risk to suppress;
    # leave it to the low-risk let-through, don't claim a policy match for it.
    if not covered:
        return None
    return "; ".join(covered) + " — in policy"


# --------------------------------------------------------------------------- #
# Persistence — read / write the TOML policy file
# --------------------------------------------------------------------------- #
def default_policy_path() -> str:
    """Where a policy lives if the user didn't say. Prefers a project-local
    ``./.airlock.toml`` when it already exists, else the per-user file."""
    local = os.path.join(os.getcwd(), ".airlock.toml")
    if os.path.exists(local):
        return local
    return os.path.join(os.path.expanduser("~"), ".airlock", "policy.toml")


def discover_policy_path() -> Optional[str]:
    """Return an existing policy file to auto-load, or ``None`` (zero-config).

    Explicit env override first (``AIRLOCK_POLICY``), then project-local, then
    the per-user file. Never invents a path that doesn't exist, so the default
    behaviour with no learned policy is unchanged.
    """
    env = os.environ.get("AIRLOCK_POLICY")
    if env and os.path.exists(env):
        return env
    for cand in (
        os.path.join(os.getcwd(), ".airlock.toml"),
        os.path.join(os.path.expanduser("~"), ".airlock", "policy.toml"),
    ):
        if os.path.exists(cand):
            return cand
    return None


def _toml_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def render_policy(policy: Policy) -> str:
    """Serialize a policy to readable TOML. Hand-formatted (no toml writer in the
    stdlib) so the file stays commented and diff-friendly."""
    L: List[str] = []
    L.append("# Airlock auto-learned policy  —  generated by `airlock learn`")
    L.append("#")
    L.append("# Observe-only. Airlock uses this to SUPPRESS known-normal activity so the")
    L.append("# signal in `airlock report` / `airlock digest` is the anomalies, not your")
    L.append("# routine. It is NEVER used to auto-approve or unblock anything: money,")
    L.append("# destructive and irreversible actions always stop for a human, and a secret")
    L.append("# leaving the machine is always flagged — in-policy or not.")
    L.append("#")
    if policy.meta:
        for k in ("generated", "sessions", "actions", "harvested", "excluded"):
            if k in policy.meta:
                L.append("# {:<10} {}".format(k + ":", policy.meta[k]))
        L.append("#")
    L.append("# Edit freely — add or remove lines. Delete this file to return to zero-config.")
    L.append("")
    L.append("[allow]")
    L.append("")
    _emit_list(L, "dirs", policy.dirs,
              "Directories you routinely read/write. Reads & writes under these are normal.")
    _emit_list(L, "files", policy.files,
              "Individual top-level files you routinely touch.")
    _emit_list(L, "domains", policy.domains,
              "Domains your agent routinely contacts. Calls to these are normal.")
    _emit_list(L, "tools", policy.tools,
              "Tools you routinely use.")
    return "\n".join(L).rstrip() + "\n"


def _emit_list(L: List[str], key: str, items: Sequence[str], comment: str) -> None:
    L.append("# {}".format(comment))
    if not items:
        L.append("{} = []".format(key))
        L.append("")
        return
    L.append("{} = [".format(key))
    for it in items:
        L.append('  "{}",'.format(_toml_escape(it)))
    L.append("]")
    L.append("")


def save_policy(policy: Policy, path: str) -> None:
    d = os.path.dirname(os.path.abspath(path))
    if d and not os.path.isdir(d):
        os.makedirs(d, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(render_policy(policy))


def load_policy(path: str) -> Policy:
    """Read a policy TOML file. Forgiving: unknown keys ignored, a malformed file
    yields an empty (suppress-nothing) policy rather than a crash — a policy that
    can't be parsed must never make a security tool fail open OR blow up."""
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError:
        return Policy()
    data = _parse_toml(raw)
    allow = data.get("allow", {}) if isinstance(data.get("allow"), dict) else {}

    def _strs(v: object) -> List[str]:
        if isinstance(v, list):
            return [str(x) for x in v if isinstance(x, (str, int, float))]
        return []

    meta = {}
    m = data.get("meta")
    if isinstance(m, dict):
        meta = {str(k): str(v) for k, v in m.items()}
    return Policy(
        dirs=_strs(allow.get("dirs")),
        files=_strs(allow.get("files")),
        domains=_strs(allow.get("domains")),
        tools=_strs(allow.get("tools")),
        meta=meta,
    )


def _parse_toml(raw: bytes) -> Dict[str, object]:
    """Parse TOML via stdlib :mod:`tomllib` (3.11+) or a minimal fallback for
    the exact subset ``airlock learn`` emits (sections, string values, and
    string arrays). Never raises — returns ``{}`` on any parse error."""
    try:
        import tomllib  # type: ignore
        try:
            return tomllib.loads(raw.decode("utf-8"))
        except Exception:
            return {}
    except ModuleNotFoundError:
        pass
    try:
        return _mini_toml(raw.decode("utf-8", "replace"))
    except Exception:
        return {}


def _mini_toml(text: str) -> Dict[str, object]:
    """A tiny TOML reader covering ``[section]``, ``key = "str"`` and
    ``key = ["a", "b"]`` (single- or multi-line). Enough for our own files on
    Python 3.9/3.10 where :mod:`tomllib` is absent."""
    root: Dict[str, object] = {}
    section = root
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        i += 1
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            name = line[1:-1].strip()
            section = {}
            root[name] = section
            continue
        if "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip()
        if val.startswith("["):
            # possibly multi-line array
            buf = val
            while "]" not in buf and i < len(lines):
                buf += " " + lines[i].strip()
                i += 1
            inner = buf[buf.find("[") + 1: buf.rfind("]")]
            items = []
            for tok in _split_top(inner):
                tok = tok.strip().strip(",").strip()
                if len(tok) >= 2 and tok[0] in "\"'" and tok[-1] == tok[0]:
                    items.append(_unescape(tok[1:-1]))
                elif tok:
                    items.append(tok)
            section[key] = items
        else:
            v = val.split("#", 1)[0].strip()
            if len(v) >= 2 and v[0] in "\"'" and v[-1] == v[0]:
                section[key] = _unescape(v[1:-1])
            else:
                section[key] = v
    return root


def _split_top(s: str) -> List[str]:
    """Split an array body on commas that aren't inside a quoted string."""
    out: List[str] = []
    cur = []
    q: Optional[str] = None
    for ch in s:
        if q:
            cur.append(ch)
            if ch == q:
                q = None
        elif ch in "\"'":
            q = ch
            cur.append(ch)
        elif ch == ",":
            out.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    if cur:
        out.append("".join(cur))
    return out


def _unescape(s: str) -> str:
    return s.replace('\\"', '"').replace("\\\\", "\\")
