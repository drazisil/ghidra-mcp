# Changelog

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
