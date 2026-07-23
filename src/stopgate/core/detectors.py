r"""Action-class detectors — classify *what kind of operation* a call is.

This layer is legitimately lexical: it reads :attr:`Action.text` and matches the
compiled tables in :mod:`stopgate.core.patterns` to decide whether a call is a
credential read, a network egress, a destructive command, and so on. It is the
``(a) action-class`` box in the architecture diagram — the *floor* of severity.

It is emphatically NOT the moat. Vocabulary can be reworded past every table
here; that is exactly why :mod:`stopgate.core.taint` exists and why the policy
engine composes the two. Nothing in this file references a capability it does
not implement.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from . import patterns as P
from .action import Action, ActionKind, Severity

# Base severity contributed by each action class *on its own*, before taint or
# escalation. Deliberately conservative: reading a file is not an incident.
_BASE_SEVERITY = {
    ActionKind.CREDENTIAL_ACCESS: Severity.MEDIUM,
    ActionKind.NETWORK_EGRESS: Severity.LOW,
    ActionKind.DESTRUCTIVE: Severity.HIGH,
    ActionKind.SPEND: Severity.HIGH,
    ActionKind.INSTALL: Severity.MEDIUM,
    ActionKind.PERMISSION: Severity.MEDIUM,
    ActionKind.MESSAGING: Severity.MEDIUM,
    ActionKind.WRITE: Severity.LOW,
    ActionKind.READ: Severity.NONE,
    ActionKind.OTHER: Severity.NONE,
}

# Kinds where being downstream of untrusted content is genuinely dangerous.
# These are the actions the taint layer escalates when the session is tainted.
HIGH_RISK_KINDS = frozenset(
    {
        ActionKind.NETWORK_EGRESS,
        ActionKind.DESTRUCTIVE,
        ActionKind.SPEND,
        ActionKind.INSTALL,
        ActionKind.PERMISSION,
        ActionKind.MESSAGING,
        ActionKind.CREDENTIAL_ACCESS,
    }
)

# Evaluated in priority order; the first match per table sets that kind. Order
# matters only for which reason string leads — severity uses max() over all.
_KIND_TABLES = [
    (ActionKind.DESTRUCTIVE, P.DESTRUCTIVE_PATTERNS, "destructive / irreversible operation"),
    (ActionKind.SPEND, P.SPEND_PATTERNS, "money movement"),
    (ActionKind.INSTALL, P.INSTALL_PATTERNS, "software install / download-and-run"),
    (ActionKind.PERMISSION, P.PERMISSION_PATTERNS, "permission change"),
    (ActionKind.MESSAGING, P.MESSAGING_PATTERNS, "publish / send-on-your-behalf"),
    (ActionKind.NETWORK_EGRESS, P.EGRESS_PATTERNS, "network egress"),
    (ActionKind.CREDENTIAL_ACCESS, P.CREDENTIAL_PATH_PATTERNS, "credential / secret access"),
]


@dataclass
class Classification:
    """The action-class verdict for a single :class:`Action`."""

    kinds: List[str] = field(default_factory=list)
    severity: Severity = Severity.NONE
    reasons: List[str] = field(default_factory=list)

    @property
    def primary(self) -> str:
        return self.kinds[0] if self.kinds else ActionKind.OTHER


def classify(action: Action) -> Classification:
    """Classify an action by structural pattern tables. Pure, no I/O.

    Honours an adapter-supplied ``action.kind`` (an adapter that already knows
    the tool's semantics is more reliable than our regexes), then augments it
    with anything the tables detect in the flattened call text.
    """
    text = action.text
    kinds: List[str] = []
    reasons: List[str] = []

    if action.kind and action.kind != ActionKind.OTHER:
        kinds.append(action.kind)
        reasons.append("adapter-tagged: {}".format(action.kind))

    for kind, table, label in _KIND_TABLES:
        if kind in kinds:
            continue
        if P.matches_any(text, table):
            kinds.append(kind)
            reasons.append(label)

    if not kinds:
        kinds.append(ActionKind.OTHER)

    severity = max(
        (_BASE_SEVERITY.get(k, Severity.NONE) for k in kinds),
        default=Severity.NONE,
    )
    return Classification(kinds=kinds, severity=severity, reasons=reasons)


def is_secret_material(text: str) -> bool:
    """True if *text* looks like a secret path OR contains a secret *value*.

    Used by the taint layer to decide whether a read's result is worth
    fingerprinting for egress matching.
    """
    return P.matches_any(text, P.CREDENTIAL_PATH_PATTERNS) or P.matches_any(
        text, P.SECRET_VALUE_PATTERNS
    )
