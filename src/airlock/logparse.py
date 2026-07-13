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
        except (TypeError, ValueError):
            return str(resp)
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


def parse_log(path: str) -> Tuple[List[Action], ParseStats]:
    """Parse a JSONL log file into actions. Never raises on bad lines."""
    actions: List[Action] = []
    stats = ParseStats()
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
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
