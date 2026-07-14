r"""Parse a Claude Code session / hook log (JSONL) into normalized Actions.

This is the ADAPTER for the ``report`` command: it turns whatever the agent
already wrote to disk into :class:`~airlock.core.action.Action` objects the
engine can reason about. It is intentionally forgiving — logs vary across
Claude Code versions, hooks, and SDKs — and it never raises on a malformed
line (a security tool that crashes on bad input fails open, which is worse than
useless). Unparseable lines are skipped and counted.

Recognized per-line shapes (any subset of keys)::

    {"tool": "Read", "input": {"file_path": "..."}, "result": {"source": "file", "content": "..."}}
    {"tool_name": "Bash", "tool_input": {"command": "..."}, "tool_response": "..."}
    {"type": "tool_use", "name": "WebFetch", "input": {...}}

Provenance: an explicit ``source`` on the result is honoured; otherwise it is
inferred from the tool (WebFetch/WebSearch -> web, mcp__* -> mcp, local file
reads -> file, everything else -> user). A real adapter tags provenance at the
boundary; this inference is a best-effort fallback so ``report`` works on raw
logs with zero config.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from .core.action import Action, ActionKind, ToolResult

# Tool-name -> (default kind, default result source). Case-insensitive prefix.
_WEB_TOOLS = {"webfetch", "websearch", "browser", "fetch"}
_READ_TOOLS = {"read", "grep", "glob", "cat", "view", "readfile"}
_WRITE_TOOLS = {"write", "edit", "multiedit", "notebookedit", "applypatch"}
_SHELL_TOOLS = {"bash", "shell", "run", "exec", "sh", "command"}


def _get(d: Dict[str, Any], *keys: str, default: Any = None) -> Any:
    for k in keys:
        if k in d and d[k] is not None:
            return d[k]
    return default


def _infer_source(tool: str, explicit: Optional[str], args: Dict[str, Any]) -> str:
    if explicit:
        return str(explicit)
    t = tool.lower()
    if t.startswith("mcp__") or t.startswith("mcp."):
        return "mcp"
    if any(t.startswith(w) or t == w for w in _WEB_TOOLS):
        return "web"
    if any(t.startswith(r) or t == r for r in _READ_TOOLS):
        return "file"
    if any(t.startswith(s) or t == s for s in _SHELL_TOOLS):
        return "shell"
    # Writes, edits, and unknown local tools are the operator's own actions.
    return "user"


def _infer_kind(tool: str) -> str:
    t = tool.lower()
    if any(t.startswith(r) or t == r for r in _READ_TOOLS) or any(
        t.startswith(w) or t == w for w in _WEB_TOOLS
    ):
        return ActionKind.READ
    if any(t.startswith(w) or t == w for w in _WRITE_TOOLS):
        return ActionKind.WRITE
    return ActionKind.OTHER


_MAX_CONTENT_DEPTH = 200  # guard against pathologically nested tool responses


def _coerce_content(resp: Any, _depth: int = 0) -> str:
    # A hostile/broken log can nest a response thousands of levels deep; a naive
    # recursive walk would blow the Python stack and crash the report (fail-open
    # for a security tool). Cap the depth and stringify whatever remains.
    if _depth >= _MAX_CONTENT_DEPTH:
        # NB: do NOT str()/json.dumps() the remainder here. The whole point of the
        # cap is that `resp` may still be thousands of levels deep, and both of
        # those recurse per level — which would blow the stack in the very branch
        # that exists to prevent blowing the stack. (This shipped: it only passed
        # locally because arm64 happens to have a bigger stack than CI's x86.)
        if isinstance(resp, (dict, list, tuple)):
            return "<content truncated: nesting deeper than {}>".format(
                _MAX_CONTENT_DEPTH)
        return str(resp) if resp is not None else ""
    if resp is None:
        return ""
    if isinstance(resp, str):
        return resp
    if isinstance(resp, dict):
        # common shapes: {"content": "..."} / {"output": "..."} / {"stdout": "..."}
        for k in ("content", "output", "stdout", "text", "result", "body"):
            if k in resp and resp[k] is not None:
                return _coerce_content(resp[k], _depth + 1)
        try:
            return json.dumps(resp, ensure_ascii=False)
        except RecursionError:
            return "<content truncated: nesting too deep to encode>"
        except (TypeError, ValueError):
            try:
                return str(resp)
            except RecursionError:
                return "<content truncated: nesting too deep to render>"
    if isinstance(resp, (list, tuple)):
        return "\n".join(_coerce_content(x, _depth + 1) for x in resp)
    return str(resp)


def action_from_record(rec: Dict[str, Any]) -> Optional[Action]:
    """Build an :class:`Action` from one parsed log record, or ``None`` to skip."""
    if not isinstance(rec, dict):
        return None
    tool = _get(rec, "tool", "tool_name", "name", "toolName")
    if not tool or not isinstance(tool, str):
        return None
    # Skip non-tool events (assistant text, user turns, etc.).
    ev_type = str(_get(rec, "type", default="")).lower()
    if ev_type in {"message", "text", "assistant", "user", "system"} and "tool" not in rec:
        return None

    args = _get(rec, "input", "tool_input", "args", "arguments", "parameters", default={})
    if not isinstance(args, dict):
        args = {"value": args}

    raw_result = _get(rec, "result", "tool_response", "response", "output", "tool_result")
    explicit_source = None
    content = ""
    if isinstance(raw_result, dict):
        explicit_source = _get(raw_result, "source", "provenance")
        content = _coerce_content(_get(raw_result, "content", "output", "text", "body",
                                       default=raw_result))
    elif raw_result is not None:
        content = _coerce_content(raw_result)
    # allow a top-level source too
    explicit_source = explicit_source or _get(rec, "source", "provenance")

    source = _infer_source(tool, explicit_source, args)
    kind = _get(rec, "kind") or _infer_kind(tool)

    result = None
    if raw_result is not None or explicit_source is not None:
        result = ToolResult(source=source, content=content)

    try:
        return Action(tool=tool, args=args, kind=kind, source=source, result=result)
    except (ValueError, TypeError):
        return None


@dataclass
class ParseStats:
    lines: int = 0
    parsed: int = 0
    skipped: int = 0


# --------------------------------------------------------------------------- #
# Claude Code's OWN session transcript
# --------------------------------------------------------------------------- #
# This is the format people actually have: ~/.claude/projects/<cwd>/<uuid>.jsonl.
# It is NOT flat. A tool call lives inside an assistant message's content blocks
# ({"type":"tool_use","id":...,"name":"Bash","input":{...}}) and its RESULT arrives
# on a LATER line, keyed by tool_use_id (plus a richer top-level "toolUseResult").
#
# Airlock's flat reader saw none of this: pointing `airlock report` at a real
# session printed "0 actions, N unparseable". The flagship, zero-config command
# did nothing on the only log format its users own. This normalises the transcript
# into the flat records the rest of the parser already understands -- and, crucially,
# re-attaches each result to its call, because the result is where the secret bytes
# are, and without it the dataflow layer has nothing to fingerprint.


def _tool_result_text(block, rec):
    """Pull the result payload for a tool_result block, preferring Claude Code's
    richer top-level ``toolUseResult`` (it carries e.g. the file's actual content
    for a Read, which is exactly what the taint layer needs)."""
    tur = rec.get("toolUseResult")
    if isinstance(tur, (dict, list)) and tur:
        return tur
    return block.get("content")


def _cc_flat_records(path):
    """Return flat records for a Claude Code transcript, or None if it isn't one."""
    calls = []          # [(tool_use_id, {"tool_name":..., "tool_input":...})]
    results = {}        # tool_use_id -> result payload
    looks_like_cc = False
    try:
        with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
            for line in fh:
                line = line.lstrip("\ufeff").strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                if not isinstance(rec, dict):
                    continue
                msg = rec.get("message")
                if not isinstance(msg, dict):
                    continue
                content = msg.get("content")
                if not isinstance(content, list):
                    continue
                for block in content:
                    if not isinstance(block, dict):
                        continue
                    btype = block.get("type")
                    if btype == "tool_use" and block.get("name"):
                        looks_like_cc = True
                        calls.append((block.get("id"), {
                            "tool_name": block.get("name"),
                            "tool_input": block.get("input") or {},
                        }))
                    elif btype == "tool_result":
                        looks_like_cc = True
                        tid = block.get("tool_use_id")
                        if tid is not None:
                            results[tid] = _tool_result_text(block, rec)
    except OSError:
        return None
    if not looks_like_cc:
        return None                      # a plain flat log: leave it alone
    flat = []
    for tid, call in calls:
        if tid in results and results[tid] is not None:
            call = dict(call, tool_response=results[tid])
        flat.append(call)
    return flat

def parse_log(path: str) -> Tuple[List[Action], ParseStats]:
    """Parse a JSONL log file into actions. Never raises on bad lines."""
    actions: List[Action] = []
    stats = ParseStats()

    # Claude Code's own transcript is nested, and its tool RESULTS arrive on later
    # lines. Normalise it first; a plain flat log returns None and falls through.
    try:
        flat = _cc_flat_records(path)
    except Exception:
        flat = None
    if flat is not None:
        for rec in flat:
            stats.lines += 1
            try:
                act = action_from_record(rec)
            except Exception:
                act = None
            if act is None:
                stats.skipped += 1
                continue
            actions.append(act)
        return actions, stats
    # ``utf-8-sig`` transparently drops a byte-order mark at the start of the
    # file; we also lstrip a stray U+FEFF per line so a BOM surviving into the
    # text (e.g. logs concatenated from several BOM-prefixed files) can't make
    # ``json.loads`` choke and SILENTLY DROP the agent's first action — for a
    # security tool, quietly skipping the very read that touched a secret is a
    # fail-open we refuse. ``str.strip()`` does not remove the BOM; do it here.
    with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
        for line in fh:
            line = line.lstrip("﻿").strip()
            if not line:
                continue
            stats.lines += 1
            try:
                rec = json.loads(line)
                act = action_from_record(rec)
            except Exception:
                # The module contract is that a malformed line never propagates:
                # a security tool that crashes on bad input hands control straight
                # back to the agent. Anything a single record can throw (bad JSON,
                # a pathological structure, an unexpected type) is skipped + counted,
                # never raised.
                stats.skipped += 1
                continue
            if act is None:
                stats.skipped += 1
                continue
            actions.append(act)
            stats.parsed += 1
    return actions, stats
