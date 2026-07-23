r"""``stopgate digest`` — the session receipt you actually want to read.

After an agent session, ``digest`` prints a short receipt. Its whole point is
different from ``report``: it leads with what Stopgate **let through, and why that
was safe** — the proof of work — not only with what it flagged. The pitch line is
*"Ran N actions unattended. K needed you. 0 touched secrets. Here's the diff."*

It reuses the Phase-1 engine and taint graph verbatim (read-only, no network of
its own) and, when a learned policy is present, uses it to move routine activity
into the "let through — safe (in policy)" section so the "needed you" list is
just the anomalies.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from .core.action import Action, ActionKind
from .engine import Decision, PolicyEngine, Verdict
from .policy import Policy, domains_of, paths_of, suppression


@dataclass
class StepView:
    """One action's line in the digest."""

    step: int
    tool: str
    decision: Decision
    suppressed_reason: Optional[str] = None
    safe_reason: str = ""          # why it was safe to let through
    attention_reason: str = ""     # why it needed a human

    @property
    def needed_you(self) -> bool:
        if self.suppressed_reason is not None:
            return False
        return self.decision.verdict in (Verdict.NOTIFY, Verdict.BLOCK)


@dataclass
class Digest:
    n_actions: int
    steps: List[StepView] = field(default_factory=list)
    engine: Optional[PolicyEngine] = None

    @property
    def let_through(self) -> List[StepView]:
        return [s for s in self.steps if not s.needed_you]

    @property
    def needed(self) -> List[StepView]:
        return [s for s in self.steps if s.needed_you]

    @property
    def secrets_out(self) -> int:
        return sum(1 for s in self.steps if s.decision.taint_hit)

    @property
    def suppressed(self) -> int:
        return sum(1 for s in self.steps if s.suppressed_reason is not None)

    @property
    def files_changed(self) -> List[str]:
        out: List[str] = []
        for s in self.steps:
            if ActionKind.WRITE in s.decision.kinds:
                out.extend(_paths_for_step(self.steps, s))
        # de-dup, preserve order
        seen = set()
        uniq = []
        for p in out:
            if p not in seen:
                seen.add(p)
                uniq.append(p)
        return uniq


def _paths_for_step(steps: List[StepView], view: StepView) -> List[str]:
    return getattr(view, "_paths", [])


def _safe_reason(action: Action, decision: Decision, suppressed: Optional[str]) -> str:
    """Why an action was safe to run without waking the user."""
    if suppressed is not None:
        return suppressed
    result = action.result
    if result is not None and result.trusted and result.content.strip():
        return "trusted source ({})".format(result.source)
    if ActionKind.NETWORK_EGRESS in decision.kinds:
        doms = domains_of(action)
        return "network call ({})".format(", ".join(doms)) if doms else "network call, no secret in payload"
    if ActionKind.CREDENTIAL_ACCESS in decision.kinds:
        return "credential read, nothing left the machine"
    if decision.kinds == [ActionKind.READ] or ActionKind.READ in decision.kinds:
        return "read-only, low risk"
    if ActionKind.WRITE in decision.kinds:
        return "local write, no egress"
    return "low risk"


def _attention_reason(view_step: int, action: Action, decision: Decision) -> str:
    """A compact reason an action needed a human — the sharp version."""
    obs = decision.observation
    if decision.taint_hit and obs is not None and obs.matched_secrets:
        origin = obs.matched_secrets[0].step
        return "a secret you read at step {} left in an outbound payload   ← this is the one".format(origin)
    if decision.escalated and obs is not None and obs.downstream_of:
        src = obs.downstream_of[0].source
        return "acted right after reading untrusted content (from {})".format(src)
    if decision.irreversible:
        return "irreversible ({}) — always stops for a human".format(decision.kinds[0] if decision.kinds else "action")
    if decision.verdict == Verdict.BLOCK:
        return "high-risk ({})".format(", ".join(decision.kinds))
    return "for your eyes ({})".format(", ".join(decision.kinds))


def analyze(actions: List[Action], policy: Optional[Policy] = None) -> Digest:
    """Run the engine over the session and build the digest view. Read-only."""
    engine = PolicyEngine()
    digest = Digest(n_actions=len(actions), engine=engine)
    for i, action in enumerate(actions, start=1):
        decision = engine.evaluate(action)
        suppressed = suppression(action, decision, policy)
        view = StepView(
            step=i,
            tool=action.tool,
            decision=decision,
            suppressed_reason=suppressed,
            safe_reason=_safe_reason(action, decision, suppressed),
            attention_reason=_attention_reason(i, action, decision),
        )
        # stash paths for the "files changed" diff without another pass
        setattr(view, "_paths", paths_of(action))
        digest.steps.append(view)
    return digest


def _group_safe(views: List[StepView]) -> List[str]:
    """Collapse the let-through list into a few human lines grouped by reason."""
    from collections import OrderedDict

    groups: "OrderedDict[str, int]" = OrderedDict()
    for v in views:
        groups[v.safe_reason] = groups.get(v.safe_reason, 0) + 1
    lines = []
    for reason, count in groups.items():
        lines.append("  {:>4}  {}".format(count, reason))
    return lines


def render_digest(digest: Digest, source_label: str, policy_label: Optional[str]) -> str:
    L: List[str] = []
    L.append("")
    L.append("  Stopgate digest — {}".format(source_label))
    L.append("  " + "─" * 58)
    L.append("")

    n = digest.n_actions
    k = len(digest.needed)
    s = digest.secrets_out
    L.append("  Ran {:,} action{} unattended. {} needed you. {} secret{} left the machine.".format(
        n, "" if n == 1 else "s", k, s, "" if s == 1 else "s"
    ))
    L.append("")

    # ---- Let through — the proof of work (leads, per the pitch) ----
    lt = digest.let_through
    L.append("  ✓ Let through — safe ({}):".format(len(lt)))
    if lt:
        for line in _group_safe(lt):
            L.append(line)
    else:
        L.append("       (nothing — every action needed you)")
    if policy_label and digest.suppressed:
        L.append("       ({} of these were suppressed as known-normal by your policy)".format(
            digest.suppressed
        ))
    L.append("")

    # ---- Needed you — the anomalies ----
    nd = digest.needed
    L.append("  ⚠ Needed you ({}):".format(len(nd)))
    if nd:
        for v in nd:
            L.append("       ▸ step {:<3} {:<6} {}".format(
                v.step, v.decision.verdict.upper(), v.attention_reason
            ))
    else:
        L.append("       (none — a clean run)")
    L.append("")

    # ---- The diff ----
    changed = digest.files_changed
    L.append("  Files changed this session:")
    if changed:
        for p in changed:
            L.append("       ~ {}".format(p))
    else:
        L.append("       (no files written)")
    L.append("")

    if policy_label:
        L.append("  Policy: {} (observe-only — never used to unblock).".format(policy_label))
    else:
        L.append("  No policy loaded — run `stopgate learn` to teach Stopgate your normal.")
    L.append("  0 of Stopgate's own network calls. Nothing was sent anywhere.")
    L.append("")
    return "\n".join(L)
