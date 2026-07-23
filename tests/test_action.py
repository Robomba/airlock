"""Unit + adversarial tests for the normalized action / provenance model.

Covers ``Severity``, source normalization + trust, ``ToolResult``, ``Action``
(validation, ``text``, ``outbound_bytes``), and ``flatten`` — including invalid
inputs, pathological structures, and the provenance guarantees the moat rests on.
"""

from __future__ import annotations

import pytest

from stopgate.core.action import (
    ALL_KINDS,
    IRREVERSIBLE_KINDS,
    TRUSTED_SOURCES,
    UNTRUSTED_SOURCES,
    Action,
    ActionKind,
    Severity,
    ToolResult,
    flatten,
    is_trusted,
    norm_source,
)


# --------------------------------------------------------------------------- #
# Severity
# --------------------------------------------------------------------------- #
class TestSeverity:
    def test_order_is_monotonic(self):
        assert (
            Severity.NONE
            < Severity.LOW
            < Severity.MEDIUM
            < Severity.HIGH
            < Severity.CRITICAL
        )

    def test_max_composes_votes(self):
        # max() over detector votes is how the engine escalates.
        assert max(Severity.LOW, Severity.CRITICAL, Severity.MEDIUM) is Severity.CRITICAL
        assert max([Severity.NONE, Severity.NONE]) is Severity.NONE

    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("high", Severity.HIGH),
            ("HIGH", Severity.HIGH),
            ("  critical  ", Severity.CRITICAL),
            ("Low", Severity.LOW),
            ("none", Severity.NONE),
        ],
    )
    def test_from_name_normalizes(self, raw, expected):
        assert Severity.from_name(raw) is expected

    @pytest.mark.parametrize("bad", ["bogus", "", "   ", "hi", "criticals"])
    def test_from_name_rejects_unknown(self, bad):
        with pytest.raises(ValueError):
            Severity.from_name(bad)

    def test_from_name_error_message_is_useful(self):
        with pytest.raises(ValueError, match="unknown severity"):
            Severity.from_name("nope")

    def test_from_name_accepts_enum_name_via_str(self):
        # Non-string inputs are coerced through str(); numbers won't match a name.
        with pytest.raises(ValueError):
            Severity.from_name(3)


# --------------------------------------------------------------------------- #
# Source normalization + trust
# --------------------------------------------------------------------------- #
class TestSourceTrust:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            (None, "unknown"),
            ("", "unknown"),
            ("   ", "unknown"),
            ("USER", "user"),
            ("  Web  ", "web"),
            ("System", "system"),
        ],
    )
    def test_norm_source(self, raw, expected):
        assert norm_source(raw) == expected

    def test_trusted_sources_are_trusted(self):
        for s in TRUSTED_SOURCES:
            assert is_trusted(s)
            assert is_trusted(s.upper())

    def test_untrusted_sources_are_not_trusted(self):
        for s in UNTRUSTED_SOURCES:
            assert not is_trusted(s)

    def test_unknown_defaults_to_untrusted(self):
        # Fail-closed: anything not explicitly whitelisted is untrusted.
        assert not is_trusted("unknown")
        assert not is_trusted(None)
        assert not is_trusted("")
        assert not is_trusted("definitely-not-a-real-source")

    def test_trusted_and_untrusted_are_disjoint(self):
        assert TRUSTED_SOURCES.isdisjoint(UNTRUSTED_SOURCES)

    def test_trust_is_not_lexically_spoofable_by_substring(self):
        # "user" is trusted but "attacker-user" / "user.evil" must not be.
        assert not is_trusted("attacker-user")
        assert not is_trusted("user.evil.com")
        assert not is_trusted("superuser")


# --------------------------------------------------------------------------- #
# ToolResult
# --------------------------------------------------------------------------- #
class TestToolResult:
    def test_source_normalized(self):
        assert ToolResult(source="  WEB ").source == "web"

    def test_none_content_becomes_empty_string(self):
        assert ToolResult(source="web", content=None).content == ""

    def test_non_string_content_coerced(self):
        assert ToolResult(source="web", content=1234).content == "1234"
        assert ToolResult(source="web", content=["a", "b"]).content == "['a', 'b']"

    def test_trusted_property(self):
        assert ToolResult(source="user").trusted is True
        assert ToolResult(source="web").trusted is False
        assert ToolResult(source=None).trusted is False

    def test_default_content_is_empty(self):
        assert ToolResult(source="user").content == ""


# --------------------------------------------------------------------------- #
# Action: validation
# --------------------------------------------------------------------------- #
class TestActionValidation:
    def test_minimal_action(self):
        a = Action(tool="read_file")
        assert a.tool == "read_file"
        assert a.args == {}
        assert a.kind == ActionKind.OTHER
        assert a.source == "user"
        assert a.result is None

    def test_tool_is_stripped(self):
        assert Action(tool="  read_file  ").tool == "read_file"

    @pytest.mark.parametrize("bad", ["", "   ", "\t\n"])
    def test_empty_tool_rejected(self, bad):
        with pytest.raises(ValueError, match="non-empty string"):
            Action(tool=bad)

    @pytest.mark.parametrize("bad", [None, 123, ["x"], {"a": 1}])
    def test_non_string_tool_rejected(self, bad):
        with pytest.raises(ValueError):
            Action(tool=bad)

    def test_none_args_becomes_dict(self):
        assert Action(tool="t", args=None).args == {}

    @pytest.mark.parametrize("bad", [["a"], "str", 5, ("x",)])
    def test_non_dict_args_rejected(self, bad):
        with pytest.raises(TypeError, match="must be a dict"):
            Action(tool="t", args=bad)

    def test_source_normalized(self):
        assert Action(tool="t", source="  WEB ").source == "web"

    def test_falsy_kind_defaults_to_other(self):
        assert Action(tool="t", kind="").kind == ActionKind.OTHER


# --------------------------------------------------------------------------- #
# Action: text + outbound_bytes
# --------------------------------------------------------------------------- #
class TestActionText:
    def test_text_includes_tool_and_args(self):
        a = Action(tool="shell", args={"cmd": "ls -la", "cwd": "/tmp"})
        t = a.text
        assert "shell" in t
        assert "ls -la" in t
        assert "/tmp" in t

    def test_text_flattens_nested(self):
        a = Action(tool="t", args={"env": {"KEY": "val"}, "list": [1, "two"]})
        t = a.text
        assert "KEY" in t and "val" in t and "two" in t

    def test_text_is_string_even_when_empty_args(self):
        assert isinstance(Action(tool="t").text, str)

    def test_outbound_prefers_payload_fields(self):
        a = Action(
            tool="http.post",
            args={"url": "http://sink.local/x", "body": "canary-DEADBEEF"},
        )
        ob = a.outbound_bytes
        assert "canary-DEADBEEF" in ob
        # The URL is NOT payload — a filename echoing a secret name shouldn't count.
        assert "sink.local" not in ob

    def test_outbound_falls_back_to_all_args_when_no_payload_field(self):
        a = Action(tool="t", args={"foo": "bar", "baz": "qux"})
        ob = a.outbound_bytes
        assert "bar" in ob and "qux" in ob

    def test_outbound_ignores_none_payload(self):
        a = Action(tool="t", args={"body": None, "data": "real"})
        assert a.outbound_bytes.strip() == "real"

    @pytest.mark.parametrize(
        "key", ["body", "data", "payload", "content", "text", "message", "json"]
    )
    def test_all_payload_keys_recognized(self, key):
        a = Action(tool="t", args={key: "PAYLOAD_MARKER", "url": "http://x"})
        assert "PAYLOAD_MARKER" in a.outbound_bytes
        assert "http://x" not in a.outbound_bytes


# --------------------------------------------------------------------------- #
# Action kinds
# --------------------------------------------------------------------------- #
class TestActionKinds:
    def test_spend_token_is_real_at_runtime(self):
        # The split literal "pay"+"ment" must reconstitute the real word.
        assert ActionKind.SPEND == "pay" + "ment"

    def test_irreversible_kinds_hard_stop_set(self):
        assert ActionKind.SPEND in IRREVERSIBLE_KINDS
        assert ActionKind.DESTRUCTIVE in IRREVERSIBLE_KINDS
        assert ActionKind.MESSAGING in IRREVERSIBLE_KINDS
        # Reversible kinds must NOT be in the hard-stop set.
        assert ActionKind.READ not in IRREVERSIBLE_KINDS
        assert ActionKind.WRITE not in IRREVERSIBLE_KINDS

    def test_irreversible_is_subset_of_all(self):
        assert IRREVERSIBLE_KINDS <= ALL_KINDS

    def test_all_kinds_are_unique(self):
        values = [
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
        ]
        assert len(values) == len(set(values)) == len(ALL_KINDS)


# --------------------------------------------------------------------------- #
# flatten
# --------------------------------------------------------------------------- #
class TestFlatten:
    def test_scalars(self):
        assert flatten("hello") == ["hello"]
        assert flatten(42) == ["42"]
        assert flatten(3.5) == ["3.5"]

    def test_bool_before_int(self):
        # bool is a subclass of int; must render as True/False not 1/0.
        assert flatten(True) == ["True"]
        assert flatten(False) == ["False"]

    def test_none_is_skipped(self):
        assert flatten(None) == []
        assert flatten([None, "x", None]) == ["x"]

    def test_dict_emits_keys_and_values(self):
        out = flatten({"k": "v"})
        assert "k" in out and "v" in out

    def test_nested_collections(self):
        out = flatten({"a": [1, {"b": (2, 3)}], "c": {4, 5}})
        # Order isn't guaranteed for sets; assert membership.
        for tok in ("a", "1", "b", "2", "3", "c", "4", "5"):
            assert tok in out

    def test_custom_object_stringified(self):
        class Weird:
            def __str__(self):
                return "WEIRD_REPR"

        assert "WEIRD_REPR" in flatten(Weird())

    def test_cyclic_structure_is_bounded(self):
        d = {}
        d["self"] = d
        out = flatten(d)  # must terminate, not hang
        assert isinstance(out, list)

    def test_cyclic_list_is_bounded(self):
        lst = []
        lst.append(lst)
        out = flatten(lst)
        assert isinstance(out, list)

    def test_deeply_nested_does_not_recurse_overflow(self):
        # Iterative flatten must handle depth that would blow a recursive stack.
        deep = cur = {}
        for _ in range(20000):
            nxt = {}
            cur["n"] = nxt
            cur = nxt
        out = flatten(deep)  # no RecursionError
        assert isinstance(out, list)

    def test_empty_containers(self):
        assert flatten({}) == []
        assert flatten([]) == []
        assert flatten(set()) == []
