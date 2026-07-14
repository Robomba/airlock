r"""``airlock`` command-line interface.

Commands (all READ-ONLY, ZERO CONFIG to start, no network of their own):

  * ``airlock report`` — the first-60-seconds summary of what the agent has been
    doing, replayed from its existing logs (Phase 1).
  * ``airlock digest`` — a short session receipt that leads with what Airlock
    *let through and why that was safe*, not only what it flagged (Phase 2).
  * ``airlock learn``  — observe the user's own past sessions and write a
    human-editable allow-policy that suppresses known-normal activity (Phase 2).

``run``/``eval`` are intentionally NOT here yet; this CLI never advertises a
command it does not implement.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from collections import OrderedDict
from typing import Dict, List, Optional

from . import __version__
from . import policy as policymod
from .core.action import Action, ActionKind
from .digest import analyze, render_digest
from .engine import Decision, PolicyEngine, Verdict
from .logparse import parse_log
from .supervisor import supervise, render_run_summary
from .policy import Policy

def _default_fixture() -> str:
    packaged = os.path.join(os.path.dirname(__file__), "data", "sample_session.jsonl")
    if os.path.exists(packaged):
        return packaged
    return os.path.normpath(
        os.path.join(os.path.dirname(__file__), "..", "..", "tests",
                     "fixtures", "sample_session.jsonl")
    )


_DEFAULT_FIXTURE = _default_fixture()
_DOMAIN_RE = re.compile(r"https?://([^/\s:]+)", re.IGNORECASE)


def _extract_domains(action: Action) -> List[str]:
    return [m.group(1).lower() for m in _DOMAIN_RE.finditer(action.text)]


def _credential_paths(action: Action) -> List[str]:
    """Pull the concrete secret-looking paths out of an action's args."""
    from .core import patterns as P

    out = []
    for chunk in action.text.split("\n"):
        if P.matches_any(chunk, P.CREDENTIAL_PATH_PATTERNS):
            out.append(chunk.strip())
    return out


def _fmt_paths(paths: List[str], limit: int = 3) -> str:
    uniq = list(OrderedDict.fromkeys(paths))
    shown = uniq[:limit]
    s = ", ".join(shown)
    if len(uniq) > limit:
        s += ", …"
    return s


def build_report(actions: List[Action], policy: Optional[Policy] = None) -> Dict[str, object]:
    """Run the engine over the actions and tally the report. Pure aggregation.

    When a learned ``policy`` is supplied, actions it explains as known-normal
    are pulled OUT of the tallies (and counted under ``suppressed``) so the
    report shows the anomalies, not the routine. With ``policy=None`` — the
    zero-config default — nothing is suppressed and the output is unchanged.
    A policy can never suppress a taint hit, an escalation, or an irreversible
    action; that invariant lives in :func:`airlock.policy.suppression`.
    """
    engine = PolicyEngine()
    cred_reads: List[str] = []
    domains: "OrderedDict[str, int]" = OrderedDict()
    destructive = 0
    taint_hits: List[Decision] = []
    escalations: List[Decision] = []
    notify = 0
    blocked = 0
    suppressed = 0
    decisions: List[Decision] = []

    for act in actions:
        d = engine.evaluate(act)
        decisions.append(d)

        if policymod.suppression(act, d, policy) is not None:
            suppressed += 1
            continue

        if ActionKind.CREDENTIAL_ACCESS in d.kinds:
            cred_reads.extend(_credential_paths(act))
        if ActionKind.NETWORK_EGRESS in d.kinds:
            for dom in _extract_domains(act):
                domains[dom] = domains.get(dom, 0) + 1
        if ActionKind.DESTRUCTIVE in d.kinds:
            destructive += 1
        if d.taint_hit:
            taint_hits.append(d)
        elif d.escalated:
            escalations.append(d)
        if d.verdict == Verdict.NOTIFY:
            notify += 1
        elif d.verdict == Verdict.BLOCK:
            blocked += 1

    return {
        "n_actions": len(actions),
        "cred_reads": cred_reads,
        "domains": domains,
        "destructive": destructive,
        "taint_hits": taint_hits,
        "escalations": escalations,
        "notify": notify,
        "blocked": blocked,
        "suppressed": suppressed,
        "engine": engine,
        "decisions": decisions,
    }


def render_report(rep: Dict[str, object], source_label: str) -> str:
    n = rep["n_actions"]
    cred_reads: List[str] = rep["cred_reads"]
    domains: "OrderedDict[str, int]" = rep["domains"]
    destructive: int = rep["destructive"]
    taint_hits: List[Decision] = rep["taint_hits"]
    escalations: List[Decision] = rep["escalations"]

    lines: List[str] = []
    lines.append("")
    lines.append("  Scanning {} ... (no config needed, nothing sent anywhere)".format(source_label))
    lines.append("")
    lines.append("  This session — {:,} agent actions:".format(n))
    lines.append("")

    # credential-touching reads
    cred_n = len(cred_reads)
    cred_detail = "  ({})".format(_fmt_paths(cred_reads)) if cred_reads else ""
    lines.append("  {:>4}  file reads touched credentials{}".format(cred_n, cred_detail))

    # network calls
    net_calls = sum(domains.values())
    n_domains = len(domains)
    dom_detail = "  ({})".format(_fmt_paths(list(domains.keys()))) if domains else ""
    lines.append(
        "  {:>4}  network calls to {} domain{}{}".format(
            net_calls, n_domains, "" if n_domains == 1 else "s", dom_detail
        )
    )

    # destructive
    lines.append("  {:>4}  destructive commands                (no confirmation asked)".format(destructive))

    # the taint line — the headline
    n_hits = len(taint_hits)
    n_esc = len(escalations)
    if n_hits:
        lines.append(
            "  {:>4}  outbound payload carried a secret read earlier   <- this is the one".format(n_hits)
        )
    if n_esc:
        # find the distance from the reason text if present
        lines.append(
            "  {:>4}  action(s) taken shortly after reading untrusted content".format(n_esc)
        )
    if not n_hits and not n_esc:
        lines.append("  {:>4}  taint hits".format(0))

    lines.append("")

    # Show the taint graph for the sharpest finding, per the brief
    # (tainted + high -> block AND show the taint graph).
    if taint_hits or escalations:
        engine = rep["engine"]
        lines.append("  --- taint graph ------------------------------------------------")
        graph = engine.tracker.graph()
        for node in graph["nodes"]:
            lines.append(
                "   source  step {:>3}  {:<10}  {}".format(
                    node["step"], node["source"], node["summary"]
                )
            )
        for edge in graph["edges"]:
            arrow = "==>" if edge["kind"] == "egress" else "-->"
            lines.append(
                "   {}  step {} {} step {}   {}".format(
                    arrow, edge["origin_step"], "", edge["action_step"], edge["detail"]
                )
            )
        lines.append("  ----------------------------------------------------------------")
        lines.append("")

    # honest summary of what the engine would have done
    lines.append(
        "  Airlock verdicts: {} would notify, {} would block until approved.".format(
            rep["notify"], rep["blocked"]
        )
    )
    if rep.get("suppressed"):
        lines.append(
            "  {} known-normal action(s) suppressed by your policy (observe-only).".format(
                rep["suppressed"]
            )
        )
    lines.append("")
    lines.append('  Want Airlock to watch the next one?   airlock run -- claude "..."')
    lines.append("  (unattended mode ships in a later phase; report is read-only today.)")
    lines.append("")
    return "\n".join(lines)


def _resolve_log(path: Optional[str]) -> str:
    return path or os.path.normpath(_DEFAULT_FIXTURE)


def _load_log_or_die(log_path: str):
    """Shared front-door for report/digest: validate the path and parse it,
    returning ``(actions, stats)`` or raising ``_CliError`` with an exit code."""
    if not os.path.exists(log_path):
        raise _CliError("log not found: {}".format(log_path))
    if os.path.isdir(log_path):
        raise _CliError("log path is a directory, not a file: {}".format(log_path))
    # A security tool that crashes on bad input fails open. parse_log never
    # raises on malformed *lines*, but the file itself may be unreadable
    # (permissions, a special file, a race that removed it) — a clean error,
    # never a traceback.
    try:
        return parse_log(log_path)
    except OSError as exc:
        raise _CliError("could not read log {}: {}".format(log_path, exc))


class _CliError(Exception):
    """A user-facing error with a clean message (never a traceback)."""


def _resolve_policy(args: argparse.Namespace) -> "tuple[Optional[Policy], Optional[str]]":
    """Return ``(policy, label)``. ``--no-policy`` forces zero-config; an
    explicit ``--policy`` must exist; otherwise auto-discover (returns None if
    nothing is found, i.e. plain zero-config)."""
    if getattr(args, "no_policy", False):
        return None, None
    path = getattr(args, "policy", None)
    if not path:
        path = policymod.discover_policy_path()
    if not path:
        return None, None
    if not os.path.exists(path):
        raise _CliError("policy file not found: {}".format(path))
    pol = policymod.load_policy(path)
    return pol, os.path.basename(path)


def _warn_footer() -> None:
    sys.stderr.write(
        "\n  ⚠ Airlock is best-effort and can miss attacks or flag safe actions "
        "— not a guarantee; see DISCLAIMER.md.\n")


def cmd_report(args: argparse.Namespace) -> int:
    log_path = _resolve_log(args.log)
    try:
        actions, stats = _load_log_or_die(log_path)
        policy, _plabel = _resolve_policy(args)
    except _CliError as exc:
        sys.stderr.write("airlock: {}\n".format(exc))
        return 2
    label = "log {}".format(os.path.basename(log_path))
    if not actions:
        sys.stdout.write(
            "\n  No agent actions found in {} "
            "({} line(s), {} unparseable).\n\n".format(log_path, stats.lines, stats.skipped)
        )
        return 0

    rep = build_report(actions, policy=policy)
    sys.stdout.write(render_report(rep, label))
    if stats.skipped:
        sys.stdout.write(
            "  ({} of {} log line(s) were not tool calls and were skipped.)\n\n".format(
                stats.skipped, stats.lines
            )
        )
    _warn_footer()
    return 0


def cmd_digest(args: argparse.Namespace) -> int:
    log_path = _resolve_log(args.log)
    try:
        actions, stats = _load_log_or_die(log_path)
        policy, plabel = _resolve_policy(args)
    except _CliError as exc:
        sys.stderr.write("airlock: {}\n".format(exc))
        return 2
    label = "session log {}".format(os.path.basename(log_path))
    if not actions:
        sys.stdout.write(
            "\n  Nothing to digest — no agent actions in {} "
            "({} line(s), {} unparseable).\n\n".format(log_path, stats.lines, stats.skipped)
        )
        return 0
    dg = analyze(actions, policy=policy)
    sys.stdout.write(render_digest(dg, label, plabel))
    _warn_footer()
    return 0


def cmd_learn(args: argparse.Namespace) -> int:
    logs = args.log or [os.path.normpath(_DEFAULT_FIXTURE)]
    base: Optional[Policy] = None
    total = policymod.LearnStats()
    n_sessions = 0
    for log_path in logs:
        try:
            actions, _stats = _load_log_or_die(log_path)
        except _CliError as exc:
            sys.stderr.write("airlock: {}\n".format(exc))
            return 2
        if not actions:
            continue
        n_sessions += 1
        engine = PolicyEngine()
        observations = [(a, engine.evaluate(a)) for a in actions]
        base, stats = policymod.learn_policy(
            observations, sessions=n_sessions, base=base
        )
        total.actions += stats.actions
        total.harvested += stats.harvested
        total.excluded += stats.excluded

    if base is None:
        sys.stderr.write("airlock: no agent actions found in the given log(s) — nothing to learn.\n")
        return 2

    total.sessions = n_sessions
    base.meta = {
        "generated": args.now or "(local run)",
        "sessions": str(total.sessions),
        "actions": str(total.actions),
        "harvested": str(total.harvested),
        "excluded": str(total.excluded),
    }

    out_path = args.out or policymod.default_policy_path()
    try:
        policymod.save_policy(base, out_path)
    except OSError as exc:
        sys.stderr.write("airlock: could not write policy {}: {}\n".format(out_path, exc))
        return 2

    sys.stdout.write(
        "\n  Learned your normal from {} session(s), {} action(s) "
        "({} routine harvested, {} flagged/risky refused).\n".format(
            total.sessions, total.actions, total.harvested, total.excluded
        )
    )
    sys.stdout.write(
        "  Wrote allow-policy: {}\n".format(out_path)
    )
    sys.stdout.write(
        "    {} dir(s), {} file(s), {} domain(s), {} tool(s).\n".format(
            len(base.dirs), len(base.files), len(base.domains), len(base.tools)
        )
    )
    sys.stdout.write(
        "  Observe-only: it suppresses known-normal noise in report/digest, "
        "never unblocks anything.\n\n"
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="airlock",
        description="Stop watching your agent. Local-first, zero-config safety for coding agents.",
    )
    p.add_argument("--version", action="version", version="airlock {}".format(__version__))
    sub = p.add_subparsers(dest="command")

    rep = sub.add_parser(
        "report",
        help="read-only summary of what your agent has been doing (zero config)",
    )
    rep.add_argument(
        "--log",
        default=None,
        help="path to a Claude Code session/hook JSONL log "
        "(default: bundled sample session)",
    )
    _add_policy_flags(rep)
    rep.set_defaults(func=cmd_report)

    dig = sub.add_parser(
        "digest",
        help="short session receipt: what was let through and why it was safe",
    )
    dig.add_argument(
        "--log",
        default=None,
        help="path to a session/hook JSONL log (default: bundled sample session)",
    )
    _add_policy_flags(dig)
    dig.set_defaults(func=cmd_digest)

    lrn = sub.add_parser(
        "learn",
        help="observe your own past sessions and write an allow-policy (opt-in tuning)",
    )
    lrn.add_argument(
        "--log",
        action="append",
        default=None,
        metavar="PATH",
        help="a past session log to learn from; repeat to learn from several "
        "(default: bundled sample session)",
    )
    lrn.add_argument(
        "--out",
        default=None,
        help="where to write the policy (default: ./.airlock.toml if present, "
        "else ~/.airlock/policy.toml)",
    )
    lrn.add_argument(
        "--now",
        default=None,
        help=argparse.SUPPRESS,  # test hook: stamp a deterministic 'generated' date
    )
    lrn.set_defaults(func=cmd_learn)

    runp = sub.add_parser(
        "run",
        help="supervise an agent run: auto-approve in-policy, hard-stop the irreversible",
    )
    runp.add_argument("--log", default=None,
                      help="preview supervision on a recorded session (default: bundled sample)")
    runp.add_argument("--approve-all", action="store_true", help=argparse.SUPPRESS)
    runp.add_argument("--deny-all", action="store_true", help=argparse.SUPPRESS)
    runp.add_argument("cmd", nargs=argparse.REMAINDER,
                      help="-- <agent command> to gate live via the PreToolUse hook")
    _add_policy_flags(runp)
    runp.set_defaults(func=cmd_run)

    hookp = sub.add_parser(
        "hook",
        help="Claude Code PreToolUse gate: read a tool event on stdin, emit allow/ask",
    )
    hookp.add_argument(
        "--mode", choices=["observe", "enforce"], default=None,
        help="observe = log only, never block (default: $AIRLOCK_MODE, "
             "~/.airlock-mode, else enforce)",
    )
    hookp.add_argument(
        "--headless", action="store_true",
        help="nobody is at the keyboard: a hard-stop denies instead of asking",
    )
    hookp.set_defaults(func=cmd_hook)

    watchp = sub.add_parser(
        "watch",
        help="PostToolUse recorder: feed tool RESULTS into the session's dataflow "
             "state (this is what makes live cross-call exfil detection work)",
    )
    watchp.set_defaults(func=cmd_watch)

    evp = sub.add_parser(
        "eval",
        help="strict precision benchmark: false alarms vs a keyword baseline",
    )
    evp.add_argument("--json", action="store_true",
                     help="also write full per-example results to JSON")
    evp.add_argument("--out", default=None, help="JSON output path")
    evp.set_defaults(func=cmd_eval)

    return p


def cmd_run(args: argparse.Namespace) -> int:
    """Supervise an agent run: auto-approve in-policy, hard-stop the irreversible."""
    cmd = [c for c in (getattr(args, "cmd", None) or []) if c != "--"]
    if cmd:
        # Live mode. True interception of a child agent happens through Claude
        # Code's PreToolUse hook (see `airlock hook`); we do not silently run an
        # ungated agent and pretend it was watched.
        sys.stdout.write(
            "\n  Live gating runs through Claude Code's PreToolUse hook.\n"
            "  Add this to your Claude Code settings (once):\n\n"
            '      "hooks": {"PreToolUse": [{"hooks": [{"type": "command",\n'
            '                 "command": "airlock hook"}]}]}\n\n'
            "  Then every tool call in `%s ...` is gated live: in-policy actions\n"
            "  pass, and money/prod/destructive/egress stop for you.\n"
            "  To preview supervision on a recorded session: airlock run --log <file>\n\n"
            % cmd[0]
        )
        return 0
    log_path = _resolve_log(args.log)
    try:
        actions, stats = _load_log_or_die(log_path)
        policy, plabel = _resolve_policy(args)
    except _CliError as exc:
        sys.stderr.write("airlock: {}\n".format(exc))
        return 2
    if args.approve_all:
        def approver(a, d):
            return True
    elif args.deny_all or not sys.stdin.isatty():
        def approver(a, d):
            return False   # fail-safe: never auto-proceed a hard-stop
    else:
        def approver(a, d):
            try:
                ans = input("  HARD-STOP: {} — {}\n  approve? [y/N] ".format(a.tool, d.reason))
            except EOFError:
                return False
            return ans.strip().lower() in ("y", "yes")
    def notifier(m):
        sys.stderr.write("  [airlock] " + m + "\n")
    result = supervise(actions, approver=approver, notifier=notifier)
    sys.stdout.write(render_run_summary(result))
    dg = analyze(actions, policy=policy)
    sys.stdout.write(render_digest(
        dg, "supervised run of {}".format(os.path.basename(log_path)), plabel))
    _warn_footer()
    return 1 if result.blocked else 0


def _hook_emit(word: str, reason: str) -> int:
    import json
    out = {"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": word,
        "permissionDecisionReason": "airlock: " + reason}}
    sys.stdout.write(json.dumps(out))
    return 0


def _resolve_mode(flag: Optional[str]) -> str:
    """--mode, else $AIRLOCK_MODE, else ~/.airlock-mode, else enforce."""
    import os as _os
    m = (flag or _os.environ.get("AIRLOCK_MODE") or "").strip().lower()
    if not m:
        try:
            with open(_os.path.join(_os.path.expanduser("~"), ".airlock-mode")) as fh:
                m = fh.read().strip().lower()
        except OSError:
            m = ""
    return m if m in ("observe", "enforce") else "enforce"


def cmd_hook(args: argparse.Namespace) -> int:
    """Claude Code PreToolUse gate — the live seam.

    Judges the PENDING tool call against everything Airlock has already seen in
    this session (fed by ``airlock watch``; see :mod:`airlock.session`). The
    ruling is computed on a COPY of the session state, so judging an action can
    never rewrite history.

    Modes — ``--mode``, else ``$AIRLOCK_MODE``, else ``~/.airlock-mode``, else enforce:

      observe   log only, ALWAYS allow. Cannot stall an agent. Use it to build trust.
      enforce   a hard-stop surfaces to a human as "ask".
      --headless (or ``$AIRLOCK_HEADLESS=1``) nobody is at the keyboard, so a
                hard-stop becomes "deny" rather than hanging forever on a prompt
                no one will ever answer.

    Fails OPEN on internal error, deliberately: a broken guardrail must never
    brick the agent it is watching. Airlock is a safety net, not a guarantee.
    """
    import json
    import os as _os
    from .logparse import action_from_record
    from .engine import PolicyEngine, Verdict
    from . import session as _sess

    raw = sys.stdin.read()
    try:
        event = json.loads(raw) if raw.strip() else {}
    except Exception:
        event = {}
    if not isinstance(event, dict):
        event = {}

    mode = _resolve_mode(getattr(args, "mode", None))
    headless = (bool(getattr(args, "headless", False))
                or _os.environ.get("AIRLOCK_HEADLESS") == "1")
    sid = event.get("session_id")

    try:
        action = action_from_record(event)
    except Exception:
        action = None
    if action is None:
        return _hook_emit("allow", "no gate-relevant action in event")

    try:
        engine = PolicyEngine()
        engine.tracker = _sess.snapshot(_sess.load(sid))   # judge on a copy
        decision = engine.evaluate(action)
    except Exception as exc:                                # noqa: BLE001
        return _hook_emit("allow", "internal error, failing open ({})".format(exc))

    if decision.verdict != Verdict.BLOCK:
        return _hook_emit("allow", decision.reason)
    if mode == "observe":
        return _hook_emit("allow", "OBSERVE-ONLY (would hard-stop): " + decision.reason)
    if headless:
        return _hook_emit("deny", "HARD-STOP, nobody at the keyboard: " + decision.reason)
    return _hook_emit("ask", "HARD-STOP: " + decision.reason)


def cmd_watch(args: argparse.Namespace) -> int:
    """Claude Code PostToolUse recorder — where the dataflow moat is actually fed.

    PreToolUse fires BEFORE the tool runs, so it never sees a result: no result,
    no secret bytes, nothing to fingerprint. Without this half, Airlock's live
    gate could only ever pattern-match one action at a time — the very thing it
    exists to beat. ``watch`` observes the COMPLETED call (tool + result) and
    advances the persisted session state, so a secret read at step 3 is
    recognised when something tries to send it at step 19.

    Silent by design: it never blocks and never speaks.
    """
    import json
    from .logparse import action_from_record
    from . import session as _sess

    raw = sys.stdin.read()
    try:
        event = json.loads(raw) if raw.strip() else {}
    except Exception:
        return 0
    if not isinstance(event, dict):
        return 0
    try:
        action = action_from_record(event)
        if action is None:
            return 0
        sid = event.get("session_id")
        tracker = _sess.load(sid)
        tracker.observe(action)
        _sess.save(sid, tracker)
    except Exception:                                        # noqa: BLE001
        return 0        # recording must never break the agent
    return 0

def cmd_eval(args: argparse.Namespace) -> int:
    """Strict precision benchmark: false alarms vs a keyword baseline."""
    from .evalsuite import evaluate, render
    import json as _json
    res = evaluate()
    if getattr(args, "json", False):
        out = args.out or "airlock_eval_results.json"
        with open(out, "w") as f:
            _json.dump(res, f, indent=2, default=list)
        sys.stderr.write("wrote full per-example results to {}\n".format(out))
    sys.stdout.write(render(res))
    return 0 if all(c["pass"] for c in res["strict_checks"]) else 3


def _add_policy_flags(sp: argparse.ArgumentParser) -> None:
    sp.add_argument(
        "--policy",
        default=None,
        help="path to a learned allow-policy (default: auto-discover, else none)",
    )
    sp.add_argument(
        "--no-policy",
        action="store_true",
        help="ignore any learned policy and run fully zero-config",
    )


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 0
    # Last-resort guard. Airlock's core promise is that it never fails open:
    # every command already handles its own expected errors (_CliError, OSError)
    # and returns exit code 2. This backstop ensures that even an UNANTICIPATED
    # bug surfaces as a clean one-line error and a non-zero exit, never a Python
    # traceback that hands control straight back to the agent it was watching.
    # SystemExit (argparse --version/--help/parse errors) and KeyboardInterrupt
    # are BaseException, not Exception, so they still propagate untouched.
    try:
        return args.func(args)
    except _CliError as exc:
        sys.stderr.write("airlock: {}\n".format(exc))
        return 2
    except BrokenPipeError:
        # Downstream pipe closed (e.g. `airlock report | head`). Not an error.
        return 0
    except Exception as exc:  # noqa: BLE001 — deliberate catch-all backstop
        sys.stderr.write("airlock: unexpected error: {}\n".format(exc))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
