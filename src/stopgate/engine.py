r"""The policy engine — pure, deterministic, no I/O.

Given an :class:`~stopgate.core.action.Action` and the running session context
(the taint tracker), return a :class:`Decision`: ``allow`` / ``notify`` /
``block``, a severity, and a human-readable reason. It composes the two
detection layers:

  * ``(a)`` action-class — :func:`stopgate.core.detectors.classify`
  * ``(b)`` taint + dataflow — :class:`stopgate.core.taint.TaintTracker`

Tiers (from the brief):
    low     -> allow + log
    medium  -> notify
    high    -> block until approved
    tainted egress hit / irreversible -> block, show the taint graph

Promise #4 is enforced here, not by policy: irreversible actions (money,
destructive ops, publishing/sending) HARD-STOP for a human no matter what.
This module imports nothing that does I/O and never touches the network or disk.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from .core import detectors
from .core.action import Action, ActionKind, IRREVERSIBLE_KINDS, Severity
from .core.taint import Observation, TaintTracker


class Verdict:
    ALLOW = "allow"
    NOTIFY = "notify"
    BLOCK = "block"


@dataclass
class Decision:
    """The engine's ruling on one action."""

    verdict: str
    severity: Severity
    reason: str
    kinds: List[str] = field(default_factory=list)
    irreversible: bool = False
    taint_hit: bool = False
    escalated: bool = False
    observation: Optional[Observation] = None

    @property
    def blocked(self) -> bool:
        return self.verdict == Verdict.BLOCK


def _verdict_for(severity: Severity) -> str:
    if severity >= Severity.HIGH:
        return Verdict.BLOCK
    if severity == Severity.MEDIUM:
        return Verdict.NOTIFY
    return Verdict.ALLOW


class PolicyEngine:
    """Stateful only through its :class:`TaintTracker`; the ruling is pure.

    Call :meth:`evaluate` with actions in execution order. Construct a fresh
    engine per session.
    """

    def __init__(self, window: int = 6) -> None:
        self.tracker = TaintTracker(window=window)

    def evaluate(self, action: Action) -> Decision:
        cls = detectors.classify(action)
        obs = self.tracker.observe(action)

        severity = max(cls.severity, obs.added_severity)
        irreversible = bool(set(cls.kinds) & IRREVERSIBLE_KINDS)

        reasons: List[str] = []
        if cls.reasons:
            reasons.append("; ".join(cls.reasons))

        # Egress hit is the strongest signal Stopgate has: a known secret's bytes
        # are leaving the machine. Force a block regardless of vocabulary.
        if obs.taint_hit:
            severity = max(severity, Severity.CRITICAL)
            reasons.extend(r for r in obs.reasons if r.startswith("EGRESS"))
        elif obs.escalated:
            reasons.extend(
                r for r in obs.reasons if "after reading untrusted content" in r
            )

        verdict = _verdict_for(severity)

        # Promise #4: irreversible actions always stop for a human.
        if irreversible and verdict != Verdict.BLOCK:
            verdict = Verdict.BLOCK
            reasons.append(
                "irreversible action ({}) — always stops for a human".format(cls.primary)
            )

        if not reasons:
            reasons.append(
                "{} — in policy".format(", ".join(cls.kinds) or ActionKind.OTHER)
            )

        return Decision(
            verdict=verdict,
            severity=severity,
            reason=" | ".join(reasons),
            kinds=list(cls.kinds),
            irreversible=irreversible,
            taint_hit=obs.taint_hit,
            escalated=obs.escalated,
            observation=obs,
        )
