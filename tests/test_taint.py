"""Unit + adversarial tests for THE MOAT: provenance, taint propagation, and
egress matching (:mod:`stopgate.core.taint`).

The scary command/secret strings are assembled from fragments — same convention
as the package source — so a lexical gate over this file never sees the whole
token, proving the point the moat itself makes.
"""

from __future__ import annotations

import base64


from stopgate.core.action import Action, Severity, ToolResult
from stopgate.core.taint import (
    _MATCH_RATIO,
    SecretRef,
    TaintTracker,
    _encoded_variants,
    _extract_secret_values,
    _fingerprint_value,
    _looks_secretish,
    _shannon_entropy,
    rolling_shingles,
)

# A real, distinctive AWS example secret access key (40 chars, high entropy).
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
AWS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"


def read(tool, path=None, content="", source="file", **args):
    """Helper: a read-style action with a tagged result."""
    if path is not None:
        args["file_path"] = path
    return Action(tool=tool, args=args, source=source,
                  result=ToolResult(source=source, content=content))


def egress(payload, tool="http.post", source="user", **args):
    args["body"] = payload
    return Action(tool=tool, args=args, source=source)


# --------------------------------------------------------------------------- #
# rolling_shingles
# --------------------------------------------------------------------------- #
class TestRollingShingles:
    def test_empty_is_empty_set(self):
        assert rolling_shingles("") == set()

    def test_short_input_hashed_whole(self):
        # len < k -> a single fingerprint of the whole string.
        sh = rolling_shingles("abc", k=12)
        assert len(sh) == 1

    def test_deterministic_across_calls(self):
        # Rabin-Karp, not Python hash() — must not depend on PYTHONHASHSEED.
        a = rolling_shingles("the quick brown fox jumps", 8)
        b = rolling_shingles("the quick brown fox jumps", 8)
        assert a == b and a

    def test_window_count(self):
        # n bytes, window k -> (n-k+1) windows (as a set, deduped).
        data = "abcdefghijklmnop"  # 16 unique bytes
        sh = rolling_shingles(data, 8)
        assert len(sh) == len(data) - 8 + 1

    def test_verbatim_substring_shares_all_shingles(self):
        secret = "supersecretvalue-1234567890"
        payload = "prefix noise " + secret + " trailing noise"
        s_sh = rolling_shingles(secret, 12)
        p_sh = rolling_shingles(payload, 12)
        assert s_sh and s_sh <= p_sh  # every secret shingle appears in payload

    def test_unicode_does_not_crash(self):
        assert rolling_shingles("héllo wörld ☃ " * 3, 8)


# --------------------------------------------------------------------------- #
# entropy / secret-ish gating
# --------------------------------------------------------------------------- #
class TestSecretishGating:
    def test_entropy_monotone(self):
        assert _shannon_entropy("aaaaaaaa") < _shannon_entropy("ab12Xy!q")
        assert _shannon_entropy("") == 0.0

    def test_low_entropy_config_values_rejected(self):
        assert not _looks_secretish("true")
        assert not _looks_secretish("production")   # 10 chars, low entropy
        assert not _looks_secretish("localhost")

    def test_real_secrets_accepted(self):
        assert _looks_secretish(AWS_SECRET)
        assert _looks_secretish(AWS_KEY_ID)
        assert _looks_secretish("0f8a2c9d4b6e1f3a7c5d9b0e2f4a6c8d")  # hex-ish blob

    def test_too_short_rejected(self):
        assert not _looks_secretish("abc123")  # < _MIN_SECRET_LEN


# --------------------------------------------------------------------------- #
# secret value extraction
# --------------------------------------------------------------------------- #
class TestExtractSecretValues:
    def test_pattern_values_extracted(self):
        content = "here is a key {} embedded".format(AWS_KEY_ID)
        assert AWS_KEY_ID in _extract_secret_values(content)

    def test_env_value_extracted_when_secretish(self):
        content = "AWS_SECRET_ACCESS_KEY={}\n".format(AWS_SECRET)
        assert AWS_SECRET in _extract_secret_values(content)

    def test_env_value_skipped_when_low_entropy(self):
        content = "DEBUG=true\nENV=production\nPORT=8080\n"
        assert _extract_secret_values(content) == []

    def test_comment_lines_ignored(self):
        content = "# SECRET_KEY={}\n".format(AWS_SECRET)
        assert AWS_SECRET not in _extract_secret_values(content)

    def test_dedupes(self):
        content = "{k}\n{k}\n".format(k=AWS_KEY_ID)
        assert _extract_secret_values(content).count(AWS_KEY_ID) == 1


# --------------------------------------------------------------------------- #
# encoding variants
# --------------------------------------------------------------------------- #
class TestEncodedVariants:
    def test_includes_base64_and_hex(self):
        variants = _encoded_variants(AWS_SECRET)
        b = AWS_SECRET.encode()
        assert base64.b64encode(b).decode() in variants
        assert b.hex() in variants

    def test_excludes_identity_and_dupes(self):
        variants = _encoded_variants("aaaaaaaa")
        assert "aaaaaaaa" not in variants
        assert len(variants) == len(set(variants))

    def test_fingerprint_value_returns_aligned_lists(self):
        literals, fps = _fingerprint_value(AWS_SECRET, 12)
        assert literals and len(literals) == len(fps)
        assert AWS_SECRET in literals


# --------------------------------------------------------------------------- #
# provenance / tainting
# --------------------------------------------------------------------------- #
class TestProvenance:
    def test_untrusted_read_taints_session(self):
        t = TaintTracker()
        obs = t.observe(read("WebFetch", content="hello from the web", source="web"))
        assert obs.tainted_session and t.tainted
        assert any("untrusted content" in r for r in obs.reasons)

    def test_trusted_read_does_not_taint(self):
        t = TaintTracker()
        obs = t.observe(read("Read", content="operator note", source="user"))
        assert not obs.tainted_session and not t.tainted

    def test_empty_untrusted_content_does_not_taint(self):
        t = TaintTracker()
        obs = t.observe(read("WebFetch", content="   ", source="web"))
        assert not obs.tainted_session

    def test_action_with_no_result_does_not_taint(self):
        t = TaintTracker()
        obs = t.observe(Action(tool="Read", source="web"))
        assert not obs.tainted_session


# --------------------------------------------------------------------------- #
# egress matching — the thing keyword gates cannot do
# --------------------------------------------------------------------------- #
class TestEgress:
    def _tracker_with_secret(self):
        t = TaintTracker()
        t.observe(read("Read", path="/app/.env",
                       content="AWS_SECRET_ACCESS_KEY={}\n".format(AWS_SECRET)))
        return t

    def test_raw_secret_leaving_is_critical(self):
        t = self._tracker_with_secret()
        obs = t.observe(egress("exfil payload = {}".format(AWS_SECRET)))
        assert obs.taint_hit
        assert obs.added_severity == Severity.CRITICAL
        assert obs.matched_secrets

    def test_base64_wrapped_secret_is_detected(self):
        t = self._tracker_with_secret()
        wrapped = base64.b64encode(AWS_SECRET.encode()).decode()
        obs = t.observe(egress("data={}".format(wrapped)))
        assert obs.taint_hit, "base64-wrapped secret must still be caught"

    def test_hex_wrapped_secret_is_detected(self):
        t = self._tracker_with_secret()
        wrapped = AWS_SECRET.encode().hex()
        obs = t.observe(egress("blob={}".format(wrapped)))
        assert obs.taint_hit, "hex-wrapped secret must still be caught"

    def test_unrelated_payload_no_hit(self):
        t = self._tracker_with_secret()
        obs = t.observe(egress("just a normal status update, nothing secret here"))
        assert not obs.taint_hit

    def test_secret_cannot_exfiltrate_itself_same_step(self):
        # A single action that both reads AND ships the same bytes: the read that
        # created the fingerprint is this very step, so it must not self-match.
        t = TaintTracker()
        a = Action(
            tool="Bash",
            args={"command": "cat /app/.env", "body": AWS_SECRET},
            source="file",
            result=ToolResult(source="file",
                              content="AWS_SECRET_ACCESS_KEY={}".format(AWS_SECRET)),
        )
        obs = t.observe(a)
        assert not obs.taint_hit

    def test_no_secret_no_hit(self):
        t = TaintTracker()
        obs = t.observe(egress("payload={}".format(AWS_SECRET)))
        assert not obs.taint_hit

    def test_short_secret_substring_fast_path(self):
        # Secrets shorter than the shingle window cannot match via shingles when
        # embedded in a longer payload; the literal substring path must catch it.
        t = TaintTracker()
        t.secrets.append(SecretRef(step=1, source="file", label="tok",
                                   literals=["sh0rtT0k"], fingerprints=[{123}]))
        t.step = 1
        obs = t.observe(egress("noise noise sh0rtT0k more noise"))
        assert obs.taint_hit

    def test_partial_fuzzy_match_over_ratio(self):
        # A payload carrying most (>= ratio) of a long secret's shingles hits,
        # even if wrapped in other text.
        t = self._tracker_with_secret()
        # keep the whole secret but bury it — full overlap, well over ratio
        obs = t.observe(egress("<<< {} >>> appended junk".format(AWS_SECRET)))
        assert obs.taint_hit

    def test_below_ratio_no_hit(self):
        t = TaintTracker()
        long_secret = "".join("abcdefghij"[i % 10] for i in range(200))
        t.secrets.append(SecretRef(
            step=1, source="file", label="s",
            literals=["___never_substring___"],
            fingerprints=[rolling_shingles(long_secret, 12)],
        ))
        t.step = 1
        # ship a tiny fragment — far below _MATCH_RATIO of the shingles
        obs = t.observe(egress(long_secret[:14]))
        assert not obs.taint_hit
        assert _MATCH_RATIO == 0.6  # guard the documented threshold


# --------------------------------------------------------------------------- #
# escalation
# --------------------------------------------------------------------------- #
class TestEscalation:
    def test_high_risk_after_untrusted_escalates(self):
        t = TaintTracker(window=6)
        t.observe(read("WebFetch", content="injected instructions", source="web"))
        obs = t.observe(Action(tool="Bash", args={"command": "curl https://x.example/y"}))
        assert obs.escalated
        assert obs.added_severity >= Severity.HIGH
        assert obs.downstream_of

    def test_outside_window_no_escalation(self):
        t = TaintTracker(window=2)
        t.observe(read("WebFetch", content="injected", source="web"))
        for _ in range(3):  # push the egress well past the window
            t.observe(Action(tool="Read", args={"file_path": "a.txt"}, source="user"))
        obs = t.observe(Action(tool="Bash", args={"command": "curl https://x.example"}))
        assert not obs.escalated

    def test_benign_action_after_untrusted_not_escalated(self):
        t = TaintTracker()
        t.observe(read("WebFetch", content="injected", source="web"))
        obs = t.observe(Action(tool="Read", args={"file_path": "notes.md"}, source="user"))
        assert not obs.escalated

    def test_untrusted_read_itself_not_self_escalated(self):
        # The untrusted read is at _last_untrusted_step; it must not escalate itself.
        t = TaintTracker()
        obs = t.observe(read("WebFetch", content="injected", source="web"))
        assert not obs.escalated


# --------------------------------------------------------------------------- #
# audit graph
# --------------------------------------------------------------------------- #
class TestGraph:
    def test_graph_is_serializable_and_shaped(self):
        import json

        t = TaintTracker()
        t.observe(read("Read", path="/app/.env",
                       content="AWS_SECRET_ACCESS_KEY={}".format(AWS_SECRET)))
        t.observe(egress("leak={}".format(AWS_SECRET)))
        g = t.graph()
        json.dumps(g)  # must not raise
        assert g["tainted"] in (True, False)
        assert {"nodes", "secrets", "edges"} <= set(g)
        assert any(e["kind"] == "egress" for e in g["edges"])
        assert all(s["shingles"] >= 1 for s in g["secrets"])
