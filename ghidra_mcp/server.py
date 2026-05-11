"""
ghidra_mcp.server — MCP server entry point.

Starts PyGhidra once, opens the Ghidra project once, and keeps it open for
the lifetime of the process. All tools share the same program handle.

Configuration via environment variables:
  GHIDRA_INSTALL_DIR    path to Ghidra installation
  GHIDRA_PROJECT_PATH   directory containing the .gpr project
  GHIDRA_PROJECT_NAME   project name (no extension)
  GHIDRA_PROGRAM_NAME   program file name inside the project (e.g. MCity_d.exe)
  GHIDRA_READ_ONLY      set to 1 to open the project read-only (coexists with Ghidra GUI;
                        write tools are unavailable but all read tools work)
"""
from __future__ import annotations

import os
import sys
import atexit

# ── Bootstrap PyGhidra before any Ghidra imports ────────────────────────────
ghidra_install = os.environ.get(
    "GHIDRA_INSTALL_DIR",
    "/home/drazisil/ghidra_12.0.3_PUBLIC",
)
os.environ.setdefault("GHIDRA_INSTALL_DIR", ghidra_install)

import pyghidra
pyghidra.start()

# ── Ghidra project open ──────────────────────────────────────────────────────
from ghidra.base.project import GhidraProject  # noqa: E402

_PROJECT_PATH = os.environ.get("GHIDRA_PROJECT_PATH", "/data/Code")
_PROJECT_NAME = os.environ.get("GHIDRA_PROJECT_NAME", "yoink32")
_PROGRAM_NAME = os.environ.get("GHIDRA_PROGRAM_NAME", "MCity_d.exe")
_READ_ONLY = os.environ.get("GHIDRA_READ_ONLY", "0").strip() in ("1", "true", "yes")

try:
    _project: GhidraProject = GhidraProject.openProject(_PROJECT_PATH, _PROJECT_NAME, _READ_ONLY)
    _program = _project.openProgram("/", _PROGRAM_NAME, _READ_ONLY)
except Exception as e:
    if "LockException" in str(e) or "LockException" in type(e).__name__:
        print(
            f"ghidra-mcp: project '{_PROJECT_NAME}' is locked by another process "
            f"(Ghidra GUI is probably open). "
            f"Either close Ghidra and restart, or set GHIDRA_READ_ONLY=1 to coexist (read tools only).",
            file=sys.stderr,
        )
        sys.exit(3)
    raise


def _cleanup():
    try:
        _project.close(_program)
    except Exception:
        pass
    try:
        _project.close()
    except Exception:
        pass


atexit.register(_cleanup)


_open_programs: dict[str, object] = {_PROGRAM_NAME: _program}


def get_program():
    return _program


def get_project():
    return _project


def switch_program(name: str) -> str:
    """Open (or reuse) a program by filename and make it the active program."""
    global _program
    if name in _open_programs:
        _program = _open_programs[name]
        return f"Switched to already-open program: {name}"
    opened = _project.openProgram("/", name, _READ_ONLY)
    _open_programs[name] = opened
    _program = opened
    return f"Opened and switched to: {name}"


# ── MCP server ───────────────────────────────────────────────────────────────
from mcp.server.fastmcp import FastMCP  # noqa: E402

_mcp_host = os.environ.get("MCP_HOST", "127.0.0.1")
_mcp_port = int(os.environ.get("MCP_PORT", "8765"))

_mode_note = (
    "Running read-only — write tools are unavailable (Ghidra GUI may be open)."
    if _READ_ONLY else
    "Write tools are available and create their own transactions."
)

mcp = FastMCP(
    "ghidra",
    instructions=(
        "Ghidra MCP server for MCity_d.exe reverse engineering. "
        "Addresses are 32-bit hex strings (e.g. '0055e190'). "
        "Function names are case-sensitive. "
        f"{_mode_note}"
    ),
    host=_mcp_host,
    port=_mcp_port,
)

from ghidra_mcp.tools import read, write, vc6_fixes  # noqa: E402

read.register(mcp, get_program)
if not _READ_ONLY:
    write.register(mcp, get_program, get_project)
    vc6_fixes.register(mcp, get_program, get_project)


@mcp.tool()
def switch_active_program(program_name: str) -> str:
    """
    Switch the active Ghidra program.
    Pass the filename as it appears in the project (e.g. 'authlogin.dll', 'MCity_d.exe').
    The program must already be in the project.
    """
    return switch_program(program_name)


if __name__ == "__main__":
    transport = os.environ.get("MCP_TRANSPORT", "stdio")
    mcp.run(transport=transport)
