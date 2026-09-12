"""
ghidra_mcp.server — MCP server entry point.

Starts PyGhidra once. Project and program are optional at startup — use the
list_projects, switch_active_project, list_programs, and switch_active_program
tools to set them at runtime.

Configuration via environment variables:
  GHIDRA_INSTALL_DIR    path to Ghidra installation (required, no default — every
                        installation lives somewhere different)
  GHIDRA_PROJECT_PATH   directory containing .gpr projects (default: current working
                        directory)
  GHIDRA_PROJECT_NAME   (optional) project to open at startup
  GHIDRA_PROGRAM_NAME   (optional) program to open at startup, requires GHIDRA_PROJECT_NAME
"""
from __future__ import annotations

import os
import sys
import atexit

# ── Bootstrap PyGhidra before any Ghidra imports ────────────────────────────
ghidra_install = os.environ.get("GHIDRA_INSTALL_DIR")
if not ghidra_install:
    raise RuntimeError(
        "GHIDRA_INSTALL_DIR is not set. Point it at your Ghidra installation, e.g. "
        "GHIDRA_INSTALL_DIR=/path/to/ghidra_12.1.2_PUBLIC"
    )
os.environ.setdefault("GHIDRA_INSTALL_DIR", ghidra_install)

import pyghidra
pyghidra.start()

# ── Cap parallel decompiler threads ──────────────────────────────────────────
# ParallelDecompiler (ghidra.app.decompiler.parallel.ParallelDecompiler, used
# by analyzeAll()'s Decompiler Parameter ID / Call Convention / Switch
# analyzers) runs on a shared thread pool named "Parallel Decompiler"
# (generic.concurrent.GThreadPool), whose size defaults to
# Runtime.availableProcessors() -- one native `decompile` subprocess per
# thread. On a many-core machine that's spawned N simultaneous native
# processes, each using 1-2GB+ RSS; live-confirmed this OOM-killed the
# whole cgroup with 9 of them at once (11GB aggregate peak) and, separately,
# thrashed the host badly enough to be unreachable over SSH until the kernel
# OOM-killer finished. availableProcessors() is a sane default for CPU
# parallelism, not for memory -- cap it explicitly rather than trust the two
# to coincide. Tune via GHIDRA_MAX_DECOMPILE_THREADS if this machine can
# spare more (or less).
from generic.concurrent import GThreadPool  # noqa: E402
_MAX_DECOMPILE_THREADS = int(os.environ.get("GHIDRA_MAX_DECOMPILE_THREADS", "2"))
GThreadPool.getSharedThreadPool("Parallel Decompiler").setMaxThreadCount(_MAX_DECOMPILE_THREADS)

# ── Ghidra project open ──────────────────────────────────────────────────────
from ghidra.base.project import GhidraProject  # noqa: E402

_PROJECT_PATH = os.environ.get("GHIDRA_PROJECT_PATH", os.getcwd())

_project: GhidraProject | None = None
_program = None

_PROJECT_NAME = os.environ.get("GHIDRA_PROJECT_NAME")
_PROGRAM_NAME = os.environ.get("GHIDRA_PROGRAM_NAME")

if _PROJECT_NAME:
    try:
        _project = GhidraProject.openProject(_PROJECT_PATH, _PROJECT_NAME, False)
        if _PROGRAM_NAME:
            _program = _project.openProgram("/", _PROGRAM_NAME, False)
    except Exception as e:
        if "LockException" in str(e) or "LockException" in type(e).__name__:
            print(
                f"ghidra-mcp: project '{_PROJECT_NAME}' is locked by another process "
                f"(Ghidra GUI is probably open). Close Ghidra and restart.",
                file=sys.stderr,
            )
            sys.exit(3)
        raise


def _cleanup():
    if _project is not None:
        try:
            _project.close()
        except Exception:
            pass


atexit.register(_cleanup)


_open_programs: dict[str, object] = ({_PROGRAM_NAME: _program} if _PROGRAM_NAME and _program else {})
_project_name: str | None = _PROJECT_NAME if _PROJECT_NAME and _project else None


def get_program():
    return _program


def get_project():
    return _project


def switch_program(name: str) -> str:
    """Open (or reuse) a program by filename and make it the active program.

    `name` may include a folder path relative to the project root, using
    forward slashes (e.g. 'libs/chkesp') for a program nested in a
    subfolder -- matching the paths list_programs() returns for those.
    A bare name (no slash) is looked up at the project root, as before.
    """
    global _program
    if _project is None:
        raise ValueError("No active project. Call switch_active_project or create_project first.")
    if name in _open_programs:
        _program = _open_programs[name]
        return f"Switched to already-open program: {name}"
    if "/" in name:
        folder_path, prog_name = name.rsplit("/", 1)
        folder_path = "/" + folder_path
    else:
        folder_path, prog_name = "/", name
    opened = _project.openProgram(folder_path, prog_name, False)
    _open_programs[name] = opened
    _program = opened
    return f"Opened and switched to: {name}"


def _close_active_project() -> None:
    """Release the current project's lock (if any) before opening a different one."""
    global _project, _program, _project_name, _open_programs
    if _project is not None:
        try:
            _project.close()
        except Exception:
            pass
    _project = None
    _program = None
    _project_name = None
    _open_programs.clear()


def switch_project(name: str) -> str:
    """Open a project by name and make it the active project.

    Closes the previously active project first so its lock file is
    released — Ghidra projects are exclusive-locked while open, so without
    this a long-running server would accumulate locks on every project it
    ever switched away from, blocking the Ghidra GUI (or another process)
    from opening them.
    """
    global _project, _project_name
    if name == _project_name and _project is not None:
        return f"Already on project: {name}"
    _close_active_project()
    _project = GhidraProject.openProject(_PROJECT_PATH, name, False)
    _project_name = name
    return f"Opened and switched to project: {name}"


# ── MCP server ───────────────────────────────────────────────────────────────
from mcp.server.fastmcp import FastMCP  # noqa: E402
from mcp.server.transport_security import TransportSecuritySettings  # noqa: E402

_mcp_host = os.environ.get("MCP_HOST", "127.0.0.1")
_mcp_port = int(os.environ.get("MCP_PORT", "8765"))

# FastMCP auto-enables DNS-rebinding protection whenever host is a loopback
# address, with a hardcoded allowed_origins of localhost/127.0.0.1/::1 only
# (mcp/server/fastmcp/server.py). That silently 403s any request proxied in
# under a real domain (e.g. via Caddy, for claude.ai's "custom connector"
# feature) even though the Host header itself was already fixed up by the
# proxy -- the Origin header is checked separately and has no such fixup.
_mcp_transport_security = TransportSecuritySettings(
    enable_dns_rebinding_protection=True,
    allowed_hosts=["127.0.0.1:*", "localhost:*", "[::1]:*", "mc.drazisil.com:*"],
    allowed_origins=[
        "http://127.0.0.1:*", "http://localhost:*", "http://[::1]:*",
        "https://claude.ai",
    ],
)

mcp = FastMCP(
    "ghidra",
    instructions=(
        "Ghidra MCP server. "
        "Use list_projects to see available projects, switch_active_project or create_project to open one, "
        "then list_programs and switch_active_program to load a program. "
        "Function names are case-sensitive. "
        "Write tools are available and create their own transactions."
    ),
    host=_mcp_host,
    port=_mcp_port,
    transport_security=_mcp_transport_security,
)

from ghidra_mcp.tools import read, write, vc6_fixes, pdb_tools  # noqa: E402

read.register(mcp, get_program)
write.register(mcp, get_program, get_project)
vc6_fixes.register(mcp, get_program, get_project)
pdb_tools.register(mcp, get_program, get_project)


@mcp.tool()
def switch_active_program(program_name: str) -> str:
    """
    Switch the active Ghidra program.
    Pass the filename as it appears in the project (e.g. 'authlogin.dll', 'MCity_d.exe'),
    or a folder-qualified path for one nested in a subfolder (e.g. 'libs/chkesp') --
    see list_programs() for the exact paths to use.
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
    """
    if _project is None:
        raise ValueError("No active project. Call switch_active_project or create_project first.")

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
def analyze_existing_program(name: str) -> str:
    """
    Run auto-analysis on a program ALREADY present in the active project
    (e.g. imported by a prior import_and_analyze call that itself
    completed the import+save but then failed/was interrupted before
    analysis finished) -- without re-importing it.

    Use this instead of import_and_analyze when list_programs already
    shows the file but list_functions/decompile_function return nothing
    for it: import_and_analyze's saveAs step conflicts with the file
    already being present (FileInUseException), even though nothing is
    actually still holding it open.

    Saves the analyzed result back to the project.
    """
    if _project is None:
        raise ValueError("No active project. Call switch_active_project or create_project first.")

    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.program.util import GhidraProgramUtilities
    from ghidra.app.script import GhidraScriptUtil

    switch_program(name)
    program = _program

    GhidraScriptUtil.acquireBundleHostReference()
    try:
        flat_api = FlatProgramAPI(program)
        if not GhidraProgramUtilities.shouldAskToAnalyze(program):
            return f"'{name}' is already marked analyzed -- nothing to do."
        flat_api.analyzeAll(program)
        GhidraProgramUtilities.markProgramAnalyzed(program)
    finally:
        GhidraScriptUtil.releaseBundleHostReference()

    _project.save(program)
    return f"Analyzed and saved '{name}'."


@mcp.tool()
def create_project(project_name: str) -> str:
    """
    Create a new Ghidra project in the same directory as the current project and switch to it.
    Pass the new project name (e.g. 'cleanroom'). The project must not already exist.
    After creation it becomes the active project with no programs loaded.
    Closes the previously active project first (see switch_project).
    """
    global _project, _project_name
    _close_active_project()
    _project = GhidraProject.createProject(_PROJECT_PATH, project_name, False)
    _project_name = project_name
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


def _list_domain_files(folder, path_prefix: str = "") -> list[str]:
    """Recursively collect display names for every file in this folder and
    its subfolders. Nested files are returned as 'subfolder/name' (matching
    the path format switch_program() accepts), so callers can tell where a
    program actually lives instead of only seeing root-level ones."""
    names = [f"{path_prefix}{f.getName()}" for f in folder.getFiles()]
    for sub in folder.getFolders():
        names.extend(_list_domain_files(sub, f"{path_prefix}{sub.getName()}/"))
    return names


@mcp.tool()
def list_programs() -> str:
    """
    List all programs stored in the active Ghidra project, including ones
    nested in subfolders (shown as 'subfolder/name' -- pass that same path
    to switch_active_program to open it).
    """
    if _project is None:
        raise ValueError("No active project. Call switch_active_project or create_project first.")
    root = _project.getRootFolder()
    names = _list_domain_files(root)
    if not names:
        return "No programs in active project."
    return "\n".join(names)


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
