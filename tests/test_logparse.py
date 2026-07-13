"""Unit + adversarial tests for the log adapter (:mod:`airlock.logparse`).

The adapter turns whatever a Claude Code session/hook wrote to disk into
normalized :class:`Action` objects. Its hard contract: it is a security-tool
boundary, so a malformed line must NEVER propagate an exception — it is skipped
and counted. These tests exercise the recognized record shapes, provenance /
kind inference, content coercion, and a battery of hostile / malformed inputs.
"""

from __future__ import annotations

import io
import json
import os
import tempfile

import pytest

from airlock.core.action import ActionKind
from airlock.logparse import (
    ParseStats,
    _coerce_content,
    _infer_kind,
    _infer_source,
    action_from_record,
    parse_log,
)


def _write_jsonl(lines):
    """Write an iterable of raw strings as a temp .jsonl; return its path."""
    fd, path = tempfile.mkstemp(suffix=".jsonl")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        for ln in lines:
            fh.write(ln + "\n")
    return path


# --------------------------------------------------------------------------- #
# record shapes -> Action
# --------------------------------------------------------------------------- #
class TestActionFromRecord:
    def test_tool_input_result_shape(self):
        rec = {"tool": "Read", "input": {"file_path": "/a/.env"},
               "result": {"source": "file", "content": "K=v"}}
        a = action_from_record(rec)
        assert a is not None
        assert a.tool == "Read"
        assert a.args["file_path"] == "/a/.env"
        assert a.result is not None and a.result.source == "file"

    def test_tool_name_response_shape(self):
        rec = {"tool_name": "Bash", "tool_input": {"command": "ls"},
               "tool_response": "a\nb"}
        a = action_from_record(rec)
        assert a is not None and a.tool == "Bash"
        assert a.result is not None and a.result.content == "a\nb"

    def test_type_tool_use_shape(self):
        rec = {"type": "tool_use", "name": "WebFetch", "input": {"url": "https://x/"}}
        a = action_from_record(rec)
        assert a is not None and a.tool == "WebFetch"
        assert a.source == "web"

    def test_non_dict_record_skipped(self):
        assert action_from_record(["not", "a", "dict"]) is None
        assert action_from_record("string") is None
        assert action_from_record(None) is None

    def test_missing_tool_skipped(self):
        assert action_from_record({"input": {"x": 1}}) is None

    def test_non_string_tool_skipped(self):
        assert action_from_record({"tool": 123}) is None
        assert action_from_record({"tool": ["Read"]}) is None

    def test_pure_message_event_skipped(self):
        # An assistant text turn with no tool must not become an action.
        assert action_from_record({"type": "assistant", "content": "hi"}) is None
        assert action_from_record({"type": "user", "text": "do X"}) is None

    def test_message_event_with_tool_still_parsed(self):
        # If a "message"-typed record nonetheless carries a tool, keep it.
        rec = {"type": "message", "tool": "Read", "input": {"file_path": "a"}}
        assert action_from_record(rec) is not None

    def test_non_dict_args_wrapped(self):
        a = action_from_record({"tool": "t", "input": "raw-string-args"})
        assert a is not None and a.args == {"value": "raw-string-args"}

    def test_top_level_source_honoured(self):
        rec = {"tool": "custom", "input": {}, "result": "text", "source": "web"}
        a = action_from_record(rec)
        assert a is not None and a.source == "web"
        assert a.result is not None and not a.result.trusted

    def test_explicit_result_source_beats_inference(self):
        # Read tool would infer "file", but an explicit source wins.
        rec = {"tool": "Read", "input": {"file_path": "a"},
               "result": {"source": "web", "content": "x"}}
        a = action_from_record(rec)
        assert a.source == "web"

    def test_result_only_created_when_present(self):
        a = action_from_record({"tool": "Read", "input": {"file_path": "a"}})
        assert a is not None and a.result is None

    def test_explicit_kind_honoured(self):
        rec = {"tool": "weird", "kind": ActionKind.SPEND, "input": {}}
        a = action_from_record(rec)
        assert a is not None and a.kind == ActionKind.SPEND


# --------------------------------------------------------------------------- #
# provenance / kind inference
# --------------------------------------------------------------------------- #
class TestInference:
    @pytest.mark.parametrize(
        "tool,expected",
        [
            ("WebFetch", "web"),
            ("websearch", "web"),
            ("Browser", "web"),
            ("mcp__server__tool", "mcp"),
            ("mcp.things", "mcp"),
            ("Read", "file"),
            ("Grep", "file"),
            ("Glob", "file"),
            ("Bash", "shell"),
            ("shell", "shell"),
            ("Write", "user"),
            ("Edit", "user"),
            ("some_unknown_tool", "user"),
        ],
    )
    def test_infer_source(self, tool, expected):
        assert _infer_source(tool, None, {}) == expected

    def test_infer_source_explicit_wins(self):
        assert _infer_source("Read", "web", {}) == "web"

    @pytest.mark.parametrize(
        "tool,expected",
        [
            ("Read", ActionKind.READ),
            ("WebFetch", ActionKind.READ),
            ("Write", ActionKind.WRITE),
            ("MultiEdit", ActionKind.WRITE),
            ("Bash", ActionKind.OTHER),
            ("mystery", ActionKind.OTHER),
        ],
    )
    def test_infer_kind(self, tool, expected):
        assert _infer_kind(tool) == expected


# --------------------------------------------------------------------------- #
# content coercion (incl. the depth guard that fixed a fail-open crash)
# --------------------------------------------------------------------------- #
class TestCoerceContent:
    def test_none_is_empty(self):
        assert _coerce_content(None) == ""

    def test_string_passthrough(self):
        assert _coerce_content("hi") == "hi"

    def test_dict_content_key(self):
        assert _coerce_content({"content": "body"}) == "body"

    def test_dict_stdout_key(self):
        assert _coerce_content({"stdout": "out"}) == "out"

    def test_dict_without_known_key_json_dumps(self):
        out = _coerce_content({"weird": "shape"})
        assert "weird" in out and "shape" in out

    def test_list_joined(self):
        assert _coerce_content(["a", "b"]) == "a\nb"

    def test_number_stringified(self):
        assert _coerce_content(42) == "42"

    def test_deeply_nested_does_not_crash(self):
        # Regression: a pathologically nested response used to blow the stack.
        d = cur = {}
        for _ in range(5000):
            nxt = {}
            cur["content"] = nxt
            cur = nxt
        cur["content"] = "deep"
        out = _coerce_content(d)  # must not raise RecursionError
        assert isinstance(out, str)


# --------------------------------------------------------------------------- #
# parse_log: file-level, malformed lines, the never-raise contract
# --------------------------------------------------------------------------- #
class TestParseLog:
    def test_parses_valid_lines(self):
        path = _write_jsonl([
            json.dumps({"tool": "Read", "input": {"file_path": "a"}}),
            json.dumps({"tool_name": "Bash", "tool_input": {"command": "ls"}}),
        ])
        try:
            actions, stats = parse_log(path)
            assert len(actions) == 2
            assert stats.parsed == 2 and stats.skipped == 0 and stats.lines == 2
        finally:
            os.unlink(path)

    def test_blank_lines_ignored_not_counted(self):
        path = _write_jsonl(["", "   ",
                             json.dumps({"tool": "Read", "input": {}})])
        try:
            actions, stats = parse_log(path)
            assert len(actions) == 1 and stats.lines == 1
        finally:
            os.unlink(path)

    def test_malformed_json_skipped_and_counted(self):
        path = _write_jsonl(["{not json", "also [bad",
                             json.dumps({"tool": "Read", "input": {}})])
        try:
            actions, stats = parse_log(path)
            assert len(actions) == 1
            assert stats.skipped == 2 and stats.parsed == 1
        finally:
            os.unlink(path)

    def test_non_tool_records_skipped(self):
        path = _write_jsonl([
            json.dumps({"type": "assistant", "content": "thinking"}),
            json.dumps({"tool": "Read", "input": {}}),
        ])
        try:
            actions, stats = parse_log(path)
            assert len(actions) == 1 and stats.skipped == 1
        finally:
            os.unlink(path)

    def test_json_top_level_list_skipped(self):
        path = _write_jsonl([json.dumps([1, 2, 3])])
        try:
            actions, stats = parse_log(path)
            assert actions == [] and stats.skipped == 1
        finally:
            os.unlink(path)

    def test_pathological_line_never_raises(self):
        # A deeply nested response on a single line must be skipped-or-parsed,
        # never crash the whole parse (fail-open is worse than useless).
        d = cur = {}
        for _ in range(8000):
            nxt = {}
            cur["content"] = nxt
            cur = nxt
        cur["content"] = "deep"
        path = _write_jsonl([json.dumps({"tool": "Read", "result": d})])
        try:
            actions, stats = parse_log(path)  # must return, not raise
            assert stats.lines == 1
        finally:
            os.unlink(path)

    def test_invalid_utf8_replaced_not_raised(self):
        fd, path = tempfile.mkstemp(suffix=".jsonl")
        with os.fdopen(fd, "wb") as fh:
            fh.write(b'{"tool": "Read", "input": {"x": "\xff\xfe"}}\n')
        try:
            actions, stats = parse_log(path)  # errors="replace" -> no crash
            assert stats.lines == 1
        finally:
            os.unlink(path)

    def test_missing_file_raises_oserror(self):
        # File-open failure is the ONE thing parse_log may propagate; the CLI
        # catches it. (Bad *lines* never raise; a bad *path* is a real error.)
        with pytest.raises(OSError):
            parse_log("/no/such/path/really.jsonl")

    def test_empty_file_is_clean(self):
        path = _write_jsonl([])
        try:
            actions, stats = parse_log(path)
            assert actions == [] and stats.lines == 0
        finally:
            os.unlink(path)


class TestParseStats:
    def test_defaults_zero(self):
        s = ParseStats()
        assert s.lines == 0 and s.parsed == 0 and s.skipped == 0
