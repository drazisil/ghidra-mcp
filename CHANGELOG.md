# Changelog

## 0.1.1

- Fixed `GHIDRA_INSTALL_DIR` default (in both `server.py`'s fallback and the README config table) to match the Ghidra install's new location under `~/opt/ghidra_12.1.2_PUBLIC` after the Fedora migration. The `pyghidra` source path in `pyproject.toml` was updated the same way, and the venv was rebuilt against it.
- Removed hardcoded personal-machine paths from defaults, since this is a public repo: `GHIDRA_INSTALL_DIR` no longer silently falls back to any specific machine's path — it's now required, and the server raises a clear error if it's unset. `GHIDRA_PROJECT_PATH` now defaults to the current working directory instead of a hardcoded `/data/Code`. `tests/conftest.py` now skips (with a clear message) instead of defaulting `GHIDRA_INSTALL_DIR` to a personal path.
- Removed `pyghidra` from `[project.dependencies]`/`[tool.uv.sources]` entirely — its path is machine-specific and doesn't belong in a committed, reproducible lockfile. It's now installed imperatively via `uv pip install "$GHIDRA_INSTALL_DIR/Ghidra/Features/PyGhidra/pypkg"` (documented in the README), so `pyproject.toml`/`uv.lock` no longer contain any personal path at all. Note this means a plain `uv sync` will uninstall it again — use `uv sync --inexact` for subsequent syncs.

## 0.1.0

- Initial release.
