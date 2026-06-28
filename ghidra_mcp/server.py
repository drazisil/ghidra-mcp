"""
ghidra_mcp.server — MCP server entry point.

Starts PyGhidra once. Project and program are optional at startup — use the
list_projects, switch_active_project, list_programs, and switch_active_program
tools to set them at runtime.

Configuration via environment variables:
  GHIDRA_INSTALL_DIR    path to Ghidra installation
  GHIDRA_PROJECT_PATH   directory containing .gpr projects (default: /data/Code)
  GHIDRA_PROJECT_NAME   (optional) project to open at startup
  GHIDRA_PROGRAM_NAME   (optional) program to open at startup, requires GHIDRA_PROJECT_NAME
  GHIDRA_READ_ONLY      set to 1 to open projects read-only (coexists with Ghidra GUI;
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
_READ_ONLY = os.environ.get("GHIDRA_READ_ONLY", "0").strip() in ("1", "true", "yes")

_project: GhidraProject | None = None
_program = None

_PROJECT_NAME = os.environ.get("GHIDRA_PROJECT_NAME")
_PROGRAM_NAME = os.environ.get("GHIDRA_PROGRAM_NAME")

if _PROJECT_NAME:
    try:
        _project = GhidraProject.openProject(_PROJECT_PATH, _PROJECT_NAME, _READ_ONLY)
        if _PROGRAM_NAME:
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
    for proj in _open_projects.values():
        try:
            proj.close()
        except Exception:
            pass


atexit.register(_cleanup)


_open_programs: dict[str, object] = ({_PROGRAM_NAME: _program} if _PROGRAM_NAME and _program else {})
_open_projects: dict[str, object] = ({_PROJECT_NAME: _project} if _PROJECT_NAME and _project else {})


def get_program():
    return _program


def get_project():
    return _project


def switch_program(name: str) -> str:
    """Open (or reuse) a program by filename and make it the active program."""
    global _program
    if _project is None:
        raise ValueError("No active project. Call switch_active_project or create_project first.")
    if name in _open_programs:
        _program = _open_programs[name]
        return f"Switched to already-open program: {name}"
    opened = _project.openProgram("/", name, _READ_ONLY)
    _open_programs[name] = opened
    _program = opened
    return f"Opened and switched to: {name}"


def switch_project(name: str) -> str:
    """Open (or reuse) a project by name and make it the active project."""
    global _project, _program, _open_programs
    if name in _open_projects:
        _project = _open_projects[name]
        _open_programs.clear()
        _program = None
        return f"Switched to already-open project: {name}"
    opened = GhidraProject.openProject(_PROJECT_PATH, name, _READ_ONLY)
    _open_projects[name] = opened
    _project = opened
    _open_programs.clear()
    _program = None
    return f"Opened and switched to project: {name}"


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
        "Ghidra MCP server. "
        "Use list_projects to see available projects, switch_active_project or create_project to open one, "
        "then list_programs and switch_active_program to load a program. "
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


@mcp.tool()
def switch_active_project(project_name: str) -> str:
    """
    Switch the active Ghidra project.
    Pass the project name as it appears on disk (e.g. 'yoink32', 'retail', 'raw').
    All projects are assumed to be in the same directory as the current project.
    Switching clears the open program cache — call switch_active_program after switching.
    """
    return switch_project(project_name)


@mcp.tool()
def import_and_analyze(file_path: str) -> str:
    """
    Import a binary file into the active Ghidra project and run auto-analysis on it.
    Pass the absolute path to the file on disk (e.g. '/data/Downloads/MCity_d.exe').
    After import, the new program becomes the active program.
    Returns the name of the imported program.
    Requires write access (GHIDRA_READ_ONLY must not be set).
    """
    if _project is None:
        raise ValueError("No active project. Call switch_active_project or create_project first.")
    if _READ_ONLY:
        raise ValueError("Cannot import in read-only mode. Restart without GHIDRA_READ_ONLY=1.")

    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.program.util import GhidraProgramUtilities
    from ghidra.app.script import GhidraScriptUtil
    from java.io import File  # noqa: F401

    global _program

    binary = File(file_path)
    program = _project.importProgram(binary)
    if program is None:
        raise ValueError(f"Ghidra could not import '{file_path}' — unsupported format or already imported.")

    _project.saveAs(program, "/", program.getName(), True)

    GhidraScriptUtil.acquireBundleHostReference()
    try:
        flat_api = FlatProgramAPI(program)
        if GhidraProgramUtilities.shouldAskToAnalyze(program):
            flat_api.analyzeAll(program)
            GhidraProgramUtilities.markProgramAnalyzed(program)
    finally:
        GhidraScriptUtil.releaseBundleHostReference()

    name = program.getName()
    _open_programs[name] = program
    _program = program
    return f"Imported and analyzed '{name}'. It is now the active program."


@mcp.tool()
def create_project(project_name: str) -> str:
    """
    Create a new Ghidra project in the same directory as the current project and switch to it.
    Pass the new project name (e.g. 'cleanroom'). The project must not already exist.
    After creation it becomes the active project with no programs loaded.
    """
    global _project, _program, _open_programs
    created = GhidraProject.createProject(_PROJECT_PATH, project_name, False)
    _open_projects[project_name] = created
    _project = created
    _open_programs.clear()
    _program = None
    return f"Created and switched to new project: {project_name}"


@mcp.tool()
def save_program() -> str:
    """
    Save the currently active program to the active Ghidra project.
    """
    if _program is None:
        raise ValueError("No active program. Call switch_active_program first.")
    _project.save(_program)
    return f"Saved '{_program.getName()}' to project."


@mcp.tool()
def list_programs() -> str:
    """
    List all programs stored in the active Ghidra project.
    """
    if _project is None:
        raise ValueError("No active project. Call switch_active_project or create_project first.")
    root = _project.getRootFolder()
    files = root.getFiles()
    if not files:
        return "No programs in active project."
    return "\n".join(f.getName() for f in files)


@mcp.tool()
def list_projects() -> str:
    """
    List all Ghidra projects available in the project directory.
    """
    import glob
    pattern = os.path.join(_PROJECT_PATH, "*.gpr")
    gprs = glob.glob(pattern)
    if not gprs:
        return f"No projects found in {_PROJECT_PATH}."
    return "\n".join(os.path.splitext(os.path.basename(p))[0] for p in sorted(gprs))


if __name__ == "__main__":
    transport = os.environ.get("MCP_TRANSPORT", "stdio")
    mcp.run(transport=transport)
