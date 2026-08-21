"""
Tests for analyze_existing_program's underlying Ghidra API sequence
(server.py's FastMCP tool functions aren't convenient to invoke directly
outside a running server, same reasoning as test_write_tools.py).

Root cause this tool fixes: import_and_analyze's saveAs step conflicts
with FileInUseException when a program of that name already exists in the
project (e.g. a prior import_and_analyze call completed the import+save
but was interrupted -- OOM-killed, in one real case -- before analysis
itself finished), even though nothing is actually still holding the file
open. analyze_existing_program opens the already-present program via
project.openProgram (no re-import, no saveAs) and runs analysis directly.
"""
from __future__ import annotations

import os

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


def test_unanalyzed_fixture_has_not_been_marked_analyzed(unanalyzed_small_program):
    """Sanity check on the fixture itself: confirms it really wasn't run
    through analyzeAll/markProgramAnalyzed, so the later assertion that
    analyze_existing_program's logic flips this is meaningful. Raw
    function count isn't the right signal here -- Ghidra's basic import
    step already creates a handful of functions from the COFF object's own
    symbol table before any real analysis pass runs."""
    from ghidra.program.util import GhidraProgramUtilities

    _project, program = unanalyzed_small_program
    assert GhidraProgramUtilities.shouldAskToAnalyze(program)


def test_analyze_existing_program_marks_analyzed_and_adds_functions(unanalyzed_small_program):
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.program.util import GhidraProgramUtilities
    from ghidra.app.script import GhidraScriptUtil

    project, program = unanalyzed_small_program
    name = program.getName()
    functions_before = program.getFunctionManager().getFunctionCount()

    # Re-open by name instead of reusing the fixture's own handle, mirroring
    # exactly what analyze_existing_program's switch_program(name) call does
    # -- this is the real path (open-existing, not re-import).
    reopened = project.openProgram("/", name, False)

    GhidraScriptUtil.acquireBundleHostReference()
    try:
        flat_api = FlatProgramAPI(reopened)
        assert GhidraProgramUtilities.shouldAskToAnalyze(reopened)
        flat_api.analyzeAll(reopened)
        GhidraProgramUtilities.markProgramAnalyzed(reopened)
    finally:
        GhidraScriptUtil.releaseBundleHostReference()

    assert not GhidraProgramUtilities.shouldAskToAnalyze(reopened)
    assert reopened.getFunctionManager().getFunctionCount() >= functions_before


def test_reimporting_an_already_present_program_conflicts(unanalyzed_small_program):
    """Confirms the actual failure mode analyze_existing_program exists to
    avoid: re-running the import_and_analyze-style saveAs against a
    filename already present in the project raises, since the fixture's
    own `program` handle is still open/held (mirroring switch_program's
    _open_programs cache keeping a real checkout alive in the live bug)."""
    import pytest
    from java.io import File as JFile

    project, program = unanalyzed_small_program
    name = program.getName()

    reimported = project.importProgram(JFile(os.path.join(FIXTURES_DIR, "xtoa.obj")))
    assert reimported is not None
    with pytest.raises(Exception):
        project.saveAs(reimported, "/", name, True)
    # No manual release here -- reimported was acquired via
    # project.importProgram(), and the fixture's own project.close() in
    # teardown already releases everything the project tracks; releasing
    # it ourselves with the wrong consumer object just breaks that.
