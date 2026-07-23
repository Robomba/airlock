r"""stopgate run — unattended supervision.

Wrap an agent's tool-call stream through the policy engine + taint tracker so you
can walk away: **auto-approve** in-policy / low-risk actions (don't wake the user),
and **hard-stop** the irreversible for a human no matter what a policy says.

The hard-stop invariant lives in the engine (Promise #4: irreversible actions and
egress/taint hits always resolve to BLOCK, regardless of any learned policy), so
this module never has to re-derive it — it only decides whether to wake you. A
learned policy can make Stopgate quieter; it can never unblock the real thing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, List, Optional

from .core.action import Action
from .engine import Decision, PolicyEngine, Verdict

# Called ONLY on a hard-stop. Returns True to proceed, False to skip the action.
Approver = Callable[[Action, Decision], bool]
# Called on every hard-stop (stdout today; a phone/webhook can implement it later).
Notifier = Callable[[str], None]


@dataclass
class StepOutcome:
    step: int
    tool: str
    verdict: str
    reason: str
    auto_approved: bool      # let through without waking the user
    human_prompted: bool     # a hard-stop that woke the user
    proceeded: bool          # did the action end up running


@dataclass
class RunResult:
    outcomes: List[StepOutcome] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.outcomes)

    @property
    def auto_approved(self) -> int:
        return sum(1 for o in self.outcomes if o.auto_approved)

    @property
    def hard_stops(self) -> int:
        return sum(1 for o in self.outcomes if o.human_prompted)

    @property
    def blocked(self) -> int:
        return sum(1 for o in self.outcomes if o.human_prompted and not o.proceeded)


def _deny(_a: Action, _d: Decision) -> bool:
    """Fail-safe default: with no human present, a hard-stop does NOT proceed."""
    return False


def supervise(
    actions: List[Action],
    approver: Optional[Approver] = None,
    notifier: Optional[Notifier] = None,
    engine: Optional[PolicyEngine] = None,
) -> RunResult:
    """Run the action stream under supervision. Pure and deterministic given the
    approver/notifier, so it is fully testable without a live agent."""
    engine = engine or PolicyEngine()
    approver = approver or _deny
    notifier = notifier or (lambda _m: None)

    out: List[StepOutcome] = []
    for i, action in enumerate(actions, 1):
        decision = engine.evaluate(action)
        if decision.verdict == Verdict.BLOCK:
            # HARD STOP. The engine guarantees irreversible actions and egress/taint
            # hits arrive here regardless of any policy, so this cannot be bypassed.
            notifier("HARD-STOP step {}: {} — {}".format(i, action.tool, decision.reason))
            proceeded = bool(approver(action, decision))
            out.append(StepOutcome(
                step=i, tool=action.tool, verdict=decision.verdict,
                reason=decision.reason, auto_approved=False,
                human_prompted=True, proceeded=proceeded,
            ))
        else:
            # ALLOW / NOTIFY — auto-approve, do not wake the human.
            out.append(StepOutcome(
                step=i, tool=action.tool, verdict=decision.verdict,
                reason=decision.reason, auto_approved=True,
                human_prompted=False, proceeded=True,
            ))
    return RunResult(out)


def render_run_summary(result: RunResult) -> str:
    """One-line-per-count summary printed before the full digest."""
    return (
        "\n  stopgate run — {} action(s) supervised\n"
        "    {} auto-approved (in policy / low risk — you were not interrupted)\n"
        "    {} hard-stop(s) needed a human"
        "{}\n".format(
            result.total,
            result.auto_approved,
            result.hard_stops,
            "" if result.hard_stops == 0
            else " — {} blocked (denied), {} approved".format(
                result.blocked, result.hard_stops - result.blocked),
        )
    )
