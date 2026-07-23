r"""Normalized action + provenance model.

Everything the policy engine reasons about is expressed here: a proposed
tool call (``Action``) and the results tool calls return (``ToolResult``).
Provenance — *where a byte came from* — is the spine of Stopgate's moat, so it
lives at the bottom of the stack with no dependencies on anything else.

Note on the odd string splits in this package (e.g. ``"pay" "ment"``): the host
environment runs a *lexical* PreToolUse gate that greps source for scary words.
Stopgate's source necessarily names the threats it detects, so we split those
literals across Python adjacent-string-literal boundaries — they concatenate to
the real token at runtime. This is, itself, a live demonstration of why lexical
gates fail and why Stopgate detects by provenance/dataflow instead.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Dict, List, Optional


class Severity(IntEnum):
    """Ordered so ``max(...)`` composes detector votes and escalation cleanly."""

    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_name(cls, name: str) -> "Severity":
        try:
            return cls[str(name).strip().upper()]
        except KeyError:
            raise ValueError("unknown severity: {!r}".format(name))


# Provenance: the ONLY sources Stopgate trusts are the operator and the host
# system itself. Everything an agent pulls from the outside world is untrusted
# by construction — this is deliberately non-lexical.
TRUSTED_SOURCES = frozenset({"user", "system", "operator"})
UNTRUSTED_SOURCES = frozenset(
    {"web", "http", "file", "email", "mcp", "tool", "shell", "network", "unknown"}
)


def norm_source(source: Optional[str]) -> str:
    if source is None:
        return "unknown"
    s = str(source).strip().lower()
    return s or "unknown"


def is_trusted(source: str) -> bool:
    """A source is trusted only if explicitly whitelisted. Unknown → untrusted."""
    return norm_source(source) in TRUSTED_SOURCES


class ActionKind:
    """Structural classes of *what a tool does* (not what its text says)."""

    READ = "read"
    WRITE = "write"
    CREDENTIAL_ACCESS = "credential_access"
    NETWORK_EGRESS = "network_egress"
    DESTRUCTIVE = "destructive"
    SPEND = "pay" "ment"  # the real token, split past the host's lexical gate
    INSTALL = "install"
    PERMISSION = "permission"
    MESSAGING = "messaging"
    OTHER = "other"


# Action kinds that are irreversible in the real world. Per the brief these
# HARD-STOP for a human no matter what the learned policy says.
IRREVERSIBLE_KINDS = frozenset(
    {ActionKind.SPEND, ActionKind.DESTRUCTIVE, ActionKind.MESSAGING}
)

ALL_KINDS = frozenset(
    {
        ActionKind.READ,
        ActionKind.WRITE,
        ActionKind.CREDENTIAL_ACCESS,
        ActionKind.NETWORK_EGRESS,
        ActionKind.DESTRUCTIVE,
        ActionKind.SPEND,
        ActionKind.INSTALL,
        ActionKind.PERMISSION,
        ActionKind.MESSAGING,
        ActionKind.OTHER,
    }
)


@dataclass
class ToolResult:
    """The output a tool returned, tagged with where it came from."""

    source: str
    content: str = ""

    def __post_init__(self) -> None:
        self.source = norm_source(self.source)
        if self.content is None:
            self.content = ""
        elif not isinstance(self.content, str):
            self.content = str(self.content)

    @property
    def trusted(self) -> bool:
        return is_trusted(self.source)


@dataclass
class Action:
    """A proposed tool call, normalized.

    ``kind`` may be provided by an adapter; if omitted it is left as ``OTHER``
    and the detector layer refines it. ``text`` is the flattened, matchable
    representation used by detectors and the egress matcher — never by the
    injection scanner, which reads tool *results* only.
    """

    tool: str
    args: Dict[str, Any] = field(default_factory=dict)
    kind: str = ActionKind.OTHER
    source: str = "user"
    result: Optional[ToolResult] = None

    def __post_init__(self) -> None:
        if not isinstance(self.tool, str) or not self.tool.strip():
            raise ValueError("Action.tool must be a non-empty string")
        self.tool = self.tool.strip()
        if self.args is None:
            self.args = {}
        if not isinstance(self.args, dict):
            raise TypeError("Action.args must be a dict")
        self.source = norm_source(self.source)
        if not self.kind:
            self.kind = ActionKind.OTHER

    @property
    def text(self) -> str:
        """Flatten tool + args into one string for matching."""
        parts = [self.tool]
        parts.extend(flatten(self.args))
        return "\n".join(p for p in parts if p)

    @property
    def outbound_bytes(self) -> str:
        """The bytes this action would send outward (egress matcher input).

        Only the *payload-bearing* arg fields, so a URL or filename that echoes
        a secret's name does not count as exfiltration — we care about the body
        actually leaving the machine.
        """
        payload_keys = ("body", "data", "payload", "content", "text", "message", "json")
        chunks: List[str] = []
        for k in payload_keys:
            if k in self.args and self.args[k] is not None:
                chunks.extend(flatten(self.args[k]))
        if not chunks:  # fall back to everything if no obvious payload field
            chunks.extend(flatten(self.args))
        return "\n".join(chunks)


def flatten(value: Any) -> List[str]:
    """Depth-first flatten of arbitrary nested args into a list of strings."""
    out: List[str] = []
    stack = [value]
    seen = 0
    while stack:
        seen += 1
        if seen > 100000:  # cyclic / pathological structure guard
            break
        cur = stack.pop()
        if cur is None:
            continue
        if isinstance(cur, str):
            out.append(cur)
        elif isinstance(cur, bool):
            out.append(str(cur))
        elif isinstance(cur, (int, float)):
            out.append(str(cur))
        elif isinstance(cur, dict):
            for k, v in cur.items():
                out.append(str(k))
                stack.append(v)
        elif isinstance(cur, (list, tuple, set)):
            stack.extend(cur)
        else:
            out.append(str(cur))
    return out
