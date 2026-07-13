# Airlock — Test Report

**Suite:** `python3 -m pytest -q` → **232 passed** (0.25s).
Deterministic across `PYTHONHASHSEED` (Rabin-Karp, not `hash()`); clean under
`-W error::DeprecationWarning`.

## Hardening round 3 — what changed

Rounds 1–2 built out the core suite. Round 3 closed the two **completely
untested modules**, fixed a **fail-open crash**, and cleared a **build gap**.

### Bug fixed (fail-open, real)

`logparse.parse_log` promised in its docstring to *never raise on a malformed
line* — but it only guarded `json.loads`, not the record → `Action` build. A
single log line carrying a **deeply nested JSON response** blew the Python stack
in the recursive `_coerce_content`, raising `RecursionError`. `cli.cmd_report`
catches only `OSError`, so `airlock report` on a hostile/broken log **crashed
with a traceback** — the worst outcome for a security tool (control hands straight
back to the agent).

Fixes:
- `_coerce_content` is now **depth-bounded** (`_MAX_CONTENT_DEPTH = 200`) and
  stringifies whatever remains; also catches `TypeError`/`ValueError` on the
  `json.dumps` fallback.
- `parse_log`'s per-line body now catches **any** exception, skipping + counting
  the line — honoring the module contract. The only exception it still
  propagates is a **file-open `OSError`** (a bad path is a real error, and the
  CLI already handles it cleanly with exit code 2).

Regression tests: `test_logparse.py::TestParseLog::test_pathological_line_never_raises`,
`TestCoerceContent::test_deeply_nested_does_not_crash`,
`test_cli.py::TestCmdReport::test_malformed_lines_do_not_crash`.

### Build gap fixed

`pyproject.toml` declared `readme = "README.md"` but the file did not exist —
`setuptools` emitted `File 'README.md' cannot be found` and shipped an empty
long-description. Added a real `README.md`; metadata prep is now clean.

## Coverage added this round

- **`test_logparse.py` (new, ~45 tests)** — every recognized record shape
  (`tool`/`input`/`result`, `tool_name`/`tool_input`/`tool_response`,
  `type: tool_use`), provenance + kind inference tables, content coercion, and a
  full battery of malformed / hostile inputs: non-dict records, missing/non-string
  tool, pure message events, top-level JSON lists, invalid UTF-8 (→ replaced),
  blank lines, the pathological-nesting regression, and the missing-file `OSError`.
- **`test_cli.py` (new, ~24 tests)** — argv parsing (`--version`, no-command help,
  unknown subcommand), `build_report` aggregation (counts, taint hits, domain
  tally, destructive count, empty input), `render_report` (exfil-with-graph,
  benign-no-graph, empty), and the `cmd_report` error paths: missing log (exit 2),
  directory-as-log (exit 2), empty log, noise-only log, malformed lines. Runs the
  bundled canonical exfil scenario end-to-end and asserts it blocks.

## What was already covered (rounds 1–2, still green)

- **`test_action.py`** — `Severity` ordering / `from_name` validation, source
  normalization + trust (fail-closed; not substring-spoofable), `ToolResult` /
  `Action` validation, `text` / `outbound_bytes` payload isolation, and `flatten`
  (cyclic, 20k-deep, custom objects, empty containers).
- **`test_detectors.py`** — every action class fires on a real (runtime-assembled)
  malicious string; composition + `max`-severity; adapter-tag honouring; and the
  "never crash on odd input" fail-safe (None/int/float/list/dict/object, huge
  text, unicode).
- **`test_taint.py`** — the moat: rolling shingles, entropy / secret-ish gating,
  secret-value extraction, encoding variants, provenance/taint, **egress matching**
  (raw / base64 / hex / partial-fuzzy / short-substring / below-ratio / self-read),
  escalation windowing, and a serializable audit graph.
- **`test_engine.py`** — tier mapping, Promise #4 (irreversible always blocks),
  egress-carries-secret → CRITICAL block, escalation → HIGH block, per-session
  isolation, configurable window.

## Adversarial / edge cases exercised

Reworded and base64/hex-wrapped exfil; secret shorter than the shingle window;
payload below the match ratio; a read that ships its own bytes in the same step;
cyclic and 20 000-deep arg structures; 8 000-deep JSON response line; invalid
UTF-8 bytes; non-dict / non-string / message-only log records; substring trust
spoofing (`superuser`, `attacker-user`); unknown provenance (fail-closed).

## What remains (not test gaps — noted for honesty)

- **Packaging of the default fixture.** `airlock report` with no `--log` falls
  back to `tests/fixtures/sample_session.jsonl`, which is not shipped in the
  wheel. Installed, that path returns a clean *"log not found"* (exit 2) rather
  than a demo — a **safe fail**, but a rough first-run UX. A later phase should
  bundle a sample under the package and point the default at it. Not changed here
  (behavior is safe; it's a design/packaging decision, not a robustness hole).
- `pyproject.toml` `package-data` references `eval/dataset/*.jsonl`, which does
  not exist yet — a harmless empty glob until the `eval` phase lands.
- `run` / `digest` / `eval` commands are deliberately unimplemented and
  unadvertised; nothing to test until they ship.

**Verdict:** the engine and core are pure and fully exercised; the two I/O-edge
modules (log adapter, CLI) are now covered including their fail-open paths; the
one real crash bug is fixed with regression tests. No meaningful test gaps remain
for the shipped surface.
