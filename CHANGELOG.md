# Changelog

## 0.3.0

Output budgets, from an audit of 3,344 real tool calls across 34 sessions: decompiles were 53% of all tool-output text (p99 38k chars), and a result stays in the conversation, re-read on every later turn, until it's compacted.

- `decompile_function` and `get_function_instructions` are windowed: `max_lines` (150 and 200 by default) starting at `start_line` (1-based). When anything is left out, a last line says so -- `(lines 1-150 of 612 shown; next: start_line=151)` -- and a `start_line` past the end is an error. **Behavior change:** a long function no longer comes back whole by default; pass a large `max_lines` for that.
- `get_references_to(address, limit=100)`: capped (the largest real result was 43k chars). When cut off, a note gives the total, how many functions the references come from, and (when any function has more than one) the ten with the most.
- `get_references_to` accepts a symbol name as well as an address. A name used to reach Ghidra as `None` and fail with a Java "Ambiguous overloads ... getReferencesTo(NoneType)" error (9 times in the audit).
- `dump_bytes` rewritten. **Behavior change:** 16 bytes a row as `address  hex  ascii`, without the per-byte INSTR/DATA/UNDEF labels that made each line about 3x longer; `classify=True` puts them back as a compact I/D/./U row. The range can be `end` (inclusive, as before) or `length`, and defaults to 64 bytes; it's capped at 4096 with a note saying where to continue. `start`/`end` now also accept symbol names.
- `find_symbol` leaves out a mangled label (`?Foo@@...`) at the same address as a function that also matched, with a count of how many. In one real result, 62% of lines were these duplicates.
- Every tool now rejects argument names it doesn't declare. FastMCP ignored them, so `find_symbol(query="X", filter="function")` dropped `query` and returned 101 lines of symbols containing "function".
- Every read tool takes an optional `program`: it switches the active program first (sticky, same as `switch_active_program`), so a lookup in another program is one call instead of two. The audit found 236 switch calls, 57 of them back-and-forth A->B->A switches.
- `switch_active_program` with a name that isn't in the project now fails with the closest matching paths (case and folder mismatches included) instead of a Java `FileNotFoundException`.
- "No function at X" now names the nearest function before (with its end address) and after, and points at `get_instructions_around` for looking at code with no function.
- Tests in `tests/test_token_budget.py` (17) run the tools through a real FastMCP instance against the fixture.

## 0.2.5

- Fixed `apply_struct_member`: it rejected every struct that actually lived in a program, because the check tested `isinstance(struct_dt, StructureDataType)` -- `StructureDataType` is only Ghidra's in-memory builder class used before a struct is resolved into a data type manager; once resolved (including right after `create_struct`), Ghidra hands structs back as `StructureDB`, which does not subclass it. Both implement the `Structure` interface, so the check now tests against that instead, matching what `get_struct`/`list_structs` already did. Regression test in `tests/test_error_hints.py` creates a struct and applies a member to it (the previously-broken path); the rest of that module intentionally forbids `project.save`, so this test registers its own fixture that allows it.

## 0.2.4

- Added `find_field_uses(offset, start="", end="", register="", limit=100)`: every instruction with a `[register + offset]` memory operand, i.e. every use of a struct field at a known byte offset. It works on the raw displacement, so the field does not need to be defined in a struct first (`get_references_to` only sees addresses, and `find_field_dispatch_callers` only matches vtable-style dispatch). `offset` is hex or decimal and may be negative. `register` keeps only operands based on that register; `start`/`end` bound the scan (recommended on a large program, since every instruction in range is walked); output is `address  function  instruction`, capped at `limit` with a note when cut off. Immediates (`PUSH 0x14`), absolute addresses (`[0x013c5db8]`) and SIB scale factors (`[EBX+ESI*4+8]` matches 8, not 4) are not counted. Matches every struct with a field at that offset, so narrow by register or range and check the hits. No match returns an explicit message. Tests in `tests/test_find_field_uses.py` compare against an independent text oracle over the fixture and patch in instructions for the negative-offset and SIB cases.

## 0.2.3

- Added `get_data_at(address, count=1)`: read-only view of what data type Ghidra has at an address, for `count` consecutive code units (max 1000, says so when capped). Each line is `address  length  type  value  label`; instructions show as `instruction`, undefined bytes as `undefined`, and an address in the middle of a unit reports the unit's start. Unmapped addresses raise an error with a next-step hint. Groundwork for `set_data_types`: audit a range before and after retyping it. Tests in `tests/test_get_data_at.py`.

## 0.2.2

- Security: refreshed `uv.lock` to clear every advisory `pip-audit` reported against the locked dependencies (42 findings across 8 packages: `anyio`, `cryptography`, `idna`, `mcp`, `pydantic-settings`, `pyjwt`, `python-multipart`, `starlette`). Notable jumps: `cryptography` 48.0.0 -> 50.0.1, `starlette` 1.0.0 -> 1.6.0, `mcp` 1.27.1 -> 1.30.0, `anyio` 4.13.0 -> 4.15.1, `pyjwt` 2.12.1 -> 2.14.0, `python-multipart` 0.0.27 -> 0.0.32. `pip-audit` on the new lock: no known vulnerabilities.
- `mcp` is now constrained to `>=1.28.1,<2` (was `>=1.26`). 1.28.1 carries the fix for the newest `mcp` advisory, and the upper bound keeps `uv lock --upgrade` from silently moving to the 2.x line, a different API that needs its own migration (`mcp` 2.x also swaps `httpx` for `httpx2`).
- Verified with the unit suite (39 passed) in a fresh environment built from the new lock, plus a start-up check: the streamable-http server initialises under `mcp` 1.30.0.

## 0.2.1

- Added `get_instructions_around(address, before=5, after=5)`: a window of disassembly around an address, like `grep -B/-A`, instead of `get_function_instructions` dumping the whole containing function (hundreds of lines for a big one) when only a few instructions are wanted. Each line is `address  raw bytes  instruction`, the instruction containing the address is marked `=>`, a flow type is shown only when it isn't plain fall-through, and a `...` line marks bytes between two instructions that aren't disassembled. An address in the middle of an instruction resolves to the instruction containing it. Counts are capped at 200 and say so. No instruction at the address raises an error that points at `dump_bytes` (data) and `create_function` / `redisassemble_instruction` (code Ghidra hasn't defined). Tests in `tests/test_instructions_around.py` run the tool through a real FastMCP instance.

## 0.2.0

- `get_function_instructions` now includes each instruction's operands (e.g. `MOV EAX,dword ptr [EBP + -0x4]`), not just the bare mnemonic -- a listing of `MOV`/`PUSH`/`CALL` with no operands couldn't be used to follow data or control flow. Flow type is still shown only when it isn't plain fall-through. Added a test against the real fixture program.
- Tool failures are now real tool errors with a next-step hint, instead of `"[... failed]"` strings returned as if they were successful results. `No function at <addr>` now points at `create_function`; an unresolvable name points at `find_symbol`; a failed decompile points at `get_function_instructions` / `extend_function_body` / `fix_vc6_call_terminators`; a missing struct or member type points at `list_structs` / `create_struct`; `create_function` where one already exists points at `decompile_function` / `rename_function`. Any tool called with no active program now raises `No active program. Call switch_active_program first` instead of an `AttributeError` on `None`.
- Removed unreachable `"[... failed]"` fallbacks in `rename_function`, `set_function_comment`, `apply_struct_member`, `create_struct`, `extend_function_body` and `redisassemble_instruction` (any failure already propagated as an exception). `redisassemble_instruction` now rejects an unparseable address instead of passing `None` to Ghidra.
- Fixed `create_function` ending its transaction twice on the "could not disassemble" path (explicit `endTransaction` plus the `finally`).
- Added `tests/test_error_hints.py`, which calls the real registered tool functions and asserts each error names its recovery tool.
- Results now reach clients as plain text instead of a JSON wrapper. FastMCP sends a structured-output copy of every return value (`{"result": "..."}`), and Claude Code showed that copy, so each decompile arrived with escaped `\n` and `\"` throughout (630 of 679 decompiles in real transcripts). All tools are registered with `structured_output=False`. `list_functions`, `find_symbol`, `get_references_to`, `get_function_calls`, `list_structs` and `fix_vc6_call_terminators` returned `list[dict]`/`dict` and now return compact text: one line per item (`address  name  ...`) or one summary line, with an explicit message for an empty result. **Breaking for any non-Claude consumer that parsed the old JSON.** `list_functions` and `find_symbol` now also say when they stopped at `limit`.
- Added `tests/test_result_shape.py`, which runs the tools through a real FastMCP instance and asserts the protocol output is a single plain `TextContent`.

## 0.1.7

- Fixed 403s when exposing the server behind a reverse proxy on a real domain (e.g. Caddy, for use as a claude.ai custom connector): `FastMCP`'s DNS-rebinding protection (auto-enabled since `MCP_HOST` defaults to loopback) hardcodes `allowed_origins` to localhost/127.0.0.1/::1 only, which silently rejected any request carrying a real `Origin` header regardless of a proxy-side `Host` header rewrite (`Host` and `Origin` are validated independently). `server.py` now passes an explicit `TransportSecuritySettings` including the real domain in both `allowed_hosts` and `allowed_origins`. Documented the proxy + allowlist requirements together in the README, since fixing only one side still 421s/403s.
- Removed `GHIDRA_READ_ONLY` support (env var, `server.py` gating, README docs) — it wasn't working correctly; deferring a proper read-only implementation to a later pass rather than shipping a broken one. Write tools are now always registered.

## 0.1.6

- `switch_program`/`switch_active_program` accept a folder-qualified path (e.g. `libs/chkesp`) for a program nested in a project subfolder, not just root-level filenames. `list_programs` now recurses into subfolders too, returning nested entries in that same `subfolder/name` form so callers know exactly what to pass back in. No tests yet.

## 0.1.5

- Added `find_symbol(filter, limit=100, include_dynamic=False)`: finds address(es) for a label/symbol by name substring -- the reverse of the address->name lookups the other tools already do. Motivating case: knowing a label name from prior RE work (or from another tool's output) but needing its address to feed into `decompile_function`/`get_references_to`/etc. Excludes Ghidra's auto-generated default names (`DAT_xxx`, `LAB_xxx`) by default via `getAllSymbols(False)`, so results default to symbols someone actually named -- pass `include_dynamic=True` to search those too.

## 0.1.4

- Added `create_function(address, name="")`: defines a new function at an address Ghidra's auto-analysis never bound to a function boundary. Motivating case: code only reachable via a computed jump table (`JMP [reg*4+table]`-style dispatch) is frequently left as raw INSTR/UNDEF bytes with no function -- `decompile_function`, `get_function_instructions`, and friends all fail on it (`No function at <addr>`) even though the code is live and executes. Disassembles at the address first if not already done, then creates the function via `CreateFunctionCmd` (body auto-determined by following control flow from the entry point -- the same operation as Ghidra's own "Create Function" GUI action). `set_function_signature` was confirmed live not to auto-create (requires an existing function), which is what motivated adding this directly.

## 0.1.3

- Capped the "Parallel Decompiler" shared thread pool (`generic.concurrent.GThreadPool`, used by `ghidra.app.decompiler.parallel.ParallelDecompiler`) to `GHIDRA_MAX_DECOMPILE_THREADS` (default 2), set right after `pyghidra.start()`. It defaults its max thread count to `Runtime.availableProcessors()` — one native `decompile` subprocess per thread — which on a system with SMT/hyperthreading counts *logical* processors, not physical cores (16 vs. 8 on the machine this was found on). Live-confirmed: `analyzeAll()` spawned 10 simultaneous native `decompile` processes analyzing one small (~370KB) DLL, OOM-killing the whole cgroup (11GB aggregate peak, 4.4GB swap peak) and thrashing the host badly enough to be unreachable over SSH until the kernel OOM-killer finished. CPU count is a sane default for parallelism, not for memory. 3 new tests, `tests/test_decompiler_thread_cap.py`.

## 0.1.2

- Added `analyze_existing_program(name)`: runs auto-analysis on a program already present in the active project (e.g. a prior `import_and_analyze` call that completed the import+save but was interrupted — OOM-killed, in the real case that motivated this — before analysis itself finished), without re-importing it. Re-running `import_and_analyze` on an already-present filename fails with `ghidra.util.exception.FileInUseException`, even when nothing is actually still holding the file open — this opens the existing `DomainFile` via the same mechanism `switch_active_program` already uses instead of re-importing.
- New `unanalyzed_small_program` fixture in `tests/conftest.py` (imports+saves the existing `xtoa.obj` fixture without running analysis) and `tests/test_analyze_existing_program.py`, 3 tests.

## 0.1.1

- Fixed `GHIDRA_INSTALL_DIR` default (in both `server.py`'s fallback and the README config table) to match the Ghidra install's new location under `~/opt/ghidra_12.1.2_PUBLIC` after the Fedora migration. The `pyghidra` source path in `pyproject.toml` was updated the same way, and the venv was rebuilt against it.
- Removed hardcoded personal-machine paths from defaults, since this is a public repo: `GHIDRA_INSTALL_DIR` no longer silently falls back to any specific machine's path — it's now required, and the server raises a clear error if it's unset. `GHIDRA_PROJECT_PATH` now defaults to the current working directory instead of a hardcoded `/data/Code`. `tests/conftest.py` now skips (with a clear message) instead of defaulting `GHIDRA_INSTALL_DIR` to a personal path.
- Removed `pyghidra` from `[project.dependencies]`/`[tool.uv.sources]` entirely — its path is machine-specific and doesn't belong in a committed, reproducible lockfile. It's now installed imperatively via `uv pip install "$GHIDRA_INSTALL_DIR/Ghidra/Features/PyGhidra/pypkg"` (documented in the README), so `pyproject.toml`/`uv.lock` no longer contain any personal path at all. Note this means a plain `uv sync` will uninstall it again — use `uv sync --inexact` for subsequent syncs.

## 0.1.0

- Initial release.
