"""Phase 3 (v2): stopgate run — unattended supervision.

The safety-critical property under test: a learned policy can make Stopgate
quieter, but it can NEVER unblock an irreversible action or a secret leaving the
machine. Those always stop for a human (Promise #4).
"""

import os
import io
import json
from contextlib import redirect_stdout

from stopgate.core.action import Action, ActionKind
from stopgate.engine import PolicyEngine, Verdict
from stopgate.policy import Policy, suppression
from stopgate.logparse import parse_log
from stopgate.supervisor import supervise
from stopgate import cli

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "sample_session.jsonl")


def _benign_reads(n=3):
    return [Action(tool="Read", kind=ActionKind.READ,
                   args={"file_path": "/home/dev/app/src/mod%d.ts" % i})
            for i in range(n)]


class TestAutoApprove:
    def test_in_policy_stream_never_wakes_the_human(self):
        calls = []

        def approver(a, d):
            calls.append(a)
            return True

        result = supervise(_benign_reads(3), approver=approver)
        assert calls == []                       # human never prompted
        assert result.auto_approved == 3
        assert result.hard_stops == 0


class TestHardStop:
    def test_fixture_has_hard_stops(self):
        actions, _ = parse_log(FIXTURE)
        result = supervise(actions, approver=lambda a, d: False)  # deny
        # the poisoned-README exfil + the acted-after-untrusted steps must stop.
        assert result.hard_stops >= 1
        assert result.blocked == result.hard_stops   # deny -> none proceeded

    def test_default_approver_is_fail_safe(self):
        # No human present: a hard-stop must NOT proceed on its own.
        actions, _ = parse_log(FIXTURE)
        result = supervise(actions)               # default approver
        for o in result.outcomes:
            if o.human_prompted:
                assert o.proceeded is False

    def test_policy_can_NEVER_suppress_a_hard_stop(self):
        """The whole promise. Even a maximally-permissive policy that allow-lists
        every dir/domain/tool cannot turn a hard-stop into a silent let-through."""
        actions, _ = parse_log(FIXTURE)
        engine = PolicyEngine()
        maximal = Policy(
            dirs=["/"],
            files=[],
            domains=["docs.example.com", "api.github.com", "collect.evil.example"],
            tools=["Read", "Write", "Bash", "WebFetch", "Edit"],
        )
        hard_stops = 0
        for a in actions:
            d = engine.evaluate(a)
            if d.verdict == Verdict.BLOCK:
                hard_stops += 1
                assert suppression(a, d, maximal) is None, (
                    "a maximal policy suppressed a hard-stop: %s" % d.reason)
        assert hard_stops >= 1


class TestRunCli:
    def test_run_prints_summary_and_digest(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli.main(["run", "--log", FIXTURE, "--deny-all"])
        out = buf.getvalue()
        assert "auto-approved" in out            # the run summary
        assert "hard-stop" in out.lower()
        assert "digest" in out.lower() or "let through" in out.lower()
        assert rc in (0, 1)                       # 1 if something was blocked

    def test_run_live_mode_prints_hook_wiring_not_fake_exec(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli.main(["run", "--", "claude", "do a thing"])
        out = buf.getvalue()
        assert "PreToolUse" in out and "stopgate hook" in out
        assert rc == 0


class TestHookGate:
    def _decide(self, event):
        buf = io.StringIO()
        import sys
        old = sys.stdin
        sys.stdin = io.StringIO(json.dumps(event))
        try:
            with redirect_stdout(buf):
                cli.main(["hook"])
        finally:
            sys.stdin = old
        return json.loads(buf.getvalue())

    def test_benign_read_allows(self):
        out = self._decide({"tool_name": "Read",
                            "tool_input": {"file_path": "/home/dev/app/x.ts"}})
        assert out["hookSpecificOutput"]["permissionDecision"] == "allow"

    def test_destructive_asks(self):
        out = self._decide({"tool_name": "Bash",
                            "tool_input": {"command": "rm -rf /home/dev/app"}})
        assert out["hookSpecificOutput"]["permissionDecision"] == "ask"
