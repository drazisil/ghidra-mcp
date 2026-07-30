"""
Shared pytest fixtures for ghidra-mcp tests.

Starts PyGhidra once per test session (it can only be started once per
process). Each test that needs a program gets its own throwaway Ghidra
project under pytest's tmp_path, so tests never touch a real project or
its locks.
"""
from __future__ import annotations

import os

os.environ.setdefault("GHIDRA_INSTALL_DIR", "/home/drazisil/ghidra_12.1.2_PUBLIC")

import pytest

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "slow: real end-to-end tests against large binaries (full analysis, PDB fetch)"
    )


@pytest.fixture(scope="session", autouse=True)
def _pyghidra_session():
    import pyghidra
    pyghidra.start()


def _import_and_analyze(project, binary_path: str):
    from java.io import File as JFile
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.program.util import GhidraProgramUtilities
    from ghidra.app.script import GhidraScriptUtil

    binary = JFile(binary_path)
    program = project.importProgram(binary)
    assert program is not None, f"Ghidra could not import {binary_path!r}"
    project.saveAs(program, "/", program.getName(), True)

    GhidraScriptUtil.acquireBundleHostReference()
    try:
        flat_api = FlatProgramAPI(program)
        if GhidraProgramUtilities.shouldAskToAnalyze(program):
            flat_api.analyzeAll(program)
            GhidraProgramUtilities.markProgramAnalyzed(program)
    finally:
        GhidraScriptUtil.releaseBundleHostReference()

    return program


@pytest.fixture()
def small_program(tmp_path):
    """
    A tiny (~5KB), fast-to-analyze COFF object -- a real MSVC-compiled kernel
    CRT function (xtoa), not a synthetic stub. Good for write-tool tests that
    just need *a* real function to operate on, where analysis speed matters
    more than binary size/complexity.
    """
    from ghidra.base.project import GhidraProject

    project = GhidraProject.createProject(str(tmp_path), "test", False)
    program = _import_and_analyze(project, os.path.join(FIXTURES_DIR, "xtoa.obj"))
    try:
        yield program
    finally:
        project.close()


@pytest.fixture(scope="session")
def analyzed_ntoskrnl(tmp_path_factory):
    """
    Full analysis of the real XP SP3 ntoskrnl.exe (5.1.2600.5512). Session-scoped
    and marked via the tests that use it (see @pytest.mark.slow) because a full
    analysis pass over a kernel-sized binary takes several minutes -- this fixture
    exists so multiple slow tests in one run don't each pay that cost separately.
    """
    from ghidra.base.project import GhidraProject

    binary_path = "/data/Downloads/i386-binaries/ntoskrnl.exe"
    if not os.path.exists(binary_path):
        pytest.skip(f"period-correct ntoskrnl.exe not present at {binary_path!r}")

    project_dir = tmp_path_factory.mktemp("ntoskrnl_proj")
    project = GhidraProject.createProject(str(project_dir), "ntoskrnl_test", False)
    program = _import_and_analyze(project, binary_path)
    try:
        yield program
    finally:
        project.close()
