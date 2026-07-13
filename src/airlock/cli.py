r"""``airlock`` command-line interface.

Phase 1 ships one command: ``airlock report`` — READ-ONLY, ZERO CONFIG. It
replays a Claude Code session/hook log through the policy engine and prints what
the agent has been doing, in the style of the pitch's first-60-seconds report.
It cannot block, cannot break anything, and makes no network calls of its own.

Later phases (``run``, ``digest``, ``eval``) are intentionally NOT here yet;
this CLI never advertises a command it does not implement.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from collections import OrderedDict
from typing import Dict, List, Optional

from . import __version__
from .core.action import Action, ActionKind
from .engine import Decision, PolicyEngine, Verdict
from .logparse import parse_log

_DEFAULT_FIXTURE = os.path.join(
    os.path.dirname(__file__), "..", "..", "tests", "fixtures", "sample_session.jsonl"
)
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


def build_report(actions: List[Action]) -> Dict[str, object]:
    """Run the engine over the actions and tally the report. Pure aggregation."""
    engine = PolicyEngine()
    cred_reads: List[str] = []
    domains: "OrderedDict[str, int]" = OrderedDict()
    destructive = 0
    taint_hits: List[Decision] = []
    escalations: List[Decision] = []
    notify = 0
    blocked = 0
    decisions: List[Decision] = []

    for act in actions:
        d = engine.evaluate(act)
        decisions.append(d)

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
        d = taint_hits[0]
        lines.append(
            "  {:>4}  outbound payload carried a secret read earlier   <- this is the one".format(n_hits)
        )
    if n_esc:
        d = escalations[0]
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
    lines.append("")
    lines.append('  Want Airlock to watch the next one?   airlock run -- claude "..."')
    lines.append("  (unattended mode ships in a later phase; report is read-only today.)")
    lines.append("")
    return "\n".join(lines)


def cmd_report(args: argparse.Namespace) -> int:
    log_path = args.log or os.path.normpath(_DEFAULT_FIXTURE)
    if not os.path.exists(log_path):
        sys.stderr.write("airlock: log not found: {}\n".format(log_path))
        return 2
    if os.path.isdir(log_path):
        sys.stderr.write("airlock: log path is a directory, not a file: {}\n".format(log_path))
        return 2

    # A security tool that crashes on bad input fails open. parse_log never
    # raises on malformed *lines*, but the file itself may be unreadable
    # (permissions, a special file, a race that removed it) — treat that as a
    # clean error, never a traceback.
    try:
        actions, stats = parse_log(log_path)
    except OSError as exc:
        sys.stderr.write("airlock: could not read log {}: {}\n".format(log_path, exc))
        return 2
    label = "log {}".format(os.path.basename(log_path))
    if not actions:
        sys.stdout.write(
            "\n  No agent actions found in {} "
            "({} line(s), {} unparseable).\n\n".format(log_path, stats.lines, stats.skipped)
        )
        return 0

    rep = build_report(actions)
    sys.stdout.write(render_report(rep, label))
    if stats.skipped:
        sys.stdout.write(
            "  ({} of {} log line(s) were not tool calls and were skipped.)\n\n".format(
                stats.skipped, stats.lines
            )
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
    rep.set_defaults(func=cmd_report)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 0
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
