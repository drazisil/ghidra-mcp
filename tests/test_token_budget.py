"""
Tests for the output budgets added after auditing real sessions: windowed
decompile/instruction listings, capped references, the compact dump_bytes
format, mangled-label folding in find_symbol, strict argument names, the
per-call `program` argument, and next-step hints on misses.

Runs the real registered tools through a real FastMCP instance against the
tiny analyzed COFF fixture, so assertions are on what a client receives.
"""
from __future__ import annotations

import asyncio

import pytest
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from mcp.types import TextContent


def _server(small_program, switch_program=None):
    from ghidra_mcp.tools import read
    from ghidra_mcp.util import forbid_extra_arguments

    mcp = FastMCP("budget-test")
    read.register(mcp, lambda: small_program, switch_program)
    forbid_extra_arguments(mcp)

    def run(tool: str, **arguments) -> str:
        result = asyncio.run(mcp.call_tool(tool, arguments))
        assert isinstance(result, list) and len(result) == 1 and isinstance(result[0], TextContent), result
        return result[0].text

    return run


@pytest.fixture
def call(small_program):
    return _server(small_program)


def _biggest_function(program):
    listing = program.getListing()
    best = max(
        program.getFunctionManager().getFunctions(True),
        key=lambda fn: len(list(listing.getInstructions(fn.getBody(), True))),
    )
    return best, str(best.getEntryPoint())


# ── decompile_function / get_function_instructions windows ─────────────────

def test_decompile_small_window_says_what_was_cut(small_program, call):
    _, addr = _biggest_function(small_program)
    full = call("decompile_function", name_or_address=addr, max_lines=10_000).splitlines()
    assert not full[-1].startswith("(lines"), "an uncut decompile must not carry a note"
    assert len(full) > 4, "fixture function too small for a window test"

    text = call("decompile_function", name_or_address=addr, max_lines=3).splitlines()

    assert text[:3] == full[:3]
    assert text[3] == f"(lines 1-3 of {len(full)} shown; next: start_line=4)"


def test_decompile_last_window_says_it_is_the_end(small_program, call):
    _, addr = _biggest_function(small_program)
    full = call("decompile_function", name_or_address=addr, max_lines=10_000).splitlines()

    text = call("decompile_function", name_or_address=addr, start_line=len(full) - 1).splitlines()

    assert text[:2] == full[-2:]
    assert text[2] == f"(lines {len(full) - 1}-{len(full)} of {len(full)} shown; this is the end)"


def test_decompile_start_past_end_is_an_error(small_program, call):
    _, addr = _biggest_function(small_program)
    with pytest.raises(ToolError, match="past the end"):
        call("decompile_function", name_or_address=addr, start_line=100_000)


def test_instructions_window_keeps_header_and_notes_rest(small_program, call):
    fn, addr = _biggest_function(small_program)
    total = len(list(small_program.getListing().getInstructions(fn.getBody(), True)))
    assert total > 2

    text = call("get_function_instructions", name_or_address=addr, max_lines=2).splitlines()

    assert text[0] == f"{fn.getName()} @ {fn.getEntryPoint()}"
    assert len(text) == 4
    assert text[3] == f"(instructions 1-2 of {total} shown; next: start_line=3)"


# ── get_references_to limit ────────────────────────────────────────────────

def test_references_limit_reports_total_and_top_functions(small_program, call):
    ref_mgr = small_program.getReferenceManager()
    target = None
    for fn in small_program.getFunctionManager().getFunctions(True):
        if sum(1 for _ in ref_mgr.getReferencesTo(fn.getEntryPoint())) >= 2:
            target = fn.getEntryPoint()
            break
    if target is None:
        # Any address with 2+ references will do (data, labels).
        for addr in ref_mgr.getReferenceDestinationIterator(small_program.getMemory(), True):
            if sum(1 for _ in ref_mgr.getReferencesTo(addr)) >= 2:
                target = addr
                break
    if target is None:
        pytest.skip("fixture has no address with 2+ references")
    total = sum(1 for _ in ref_mgr.getReferencesTo(target))

    text = call("get_references_to", address=str(target), limit=1).splitlines()

    assert len(text) == 2
    assert text[1].startswith(f"(first 1 of {total} references shown")
    assert "Most references:" in text[1]


# ── dump_bytes ─────────────────────────────────────────────────────────────

def _entry(small_program):
    return next(iter(small_program.getFunctionManager().getFunctions(True))).getEntryPoint()


def test_dump_bytes_rows_of_16_with_ascii(small_program, call):
    start = _entry(small_program)
    raw = [small_program.getMemory().getByte(start.add(i)) & 0xFF for i in range(20)]

    lines = call("dump_bytes", start=str(start), length=20).splitlines()

    assert len(lines) == 2
    assert lines[0].startswith(f"{start}  " + " ".join(f"{b:02x}" for b in raw[:16]))
    assert lines[1].startswith(f"{start.add(16)}  " + " ".join(f"{b:02x}" for b in raw[16:]))
    ascii_part = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in raw[:16])
    assert lines[0].endswith("  " + ascii_part)


def test_dump_bytes_end_is_inclusive_and_default_is_64(small_program, call):
    start = _entry(small_program)
    assert len(call("dump_bytes", start=str(start), end=str(start.add(16))).splitlines()) == 2
    assert len(call("dump_bytes", start=str(start)).splitlines()) == 4


def test_dump_bytes_classify_marks_instruction_start(small_program, call):
    start = _entry(small_program)

    lines = call("dump_bytes", start=str(start), length=4, classify=True).splitlines()

    assert len(lines) == 2
    assert lines[1].split()[0] == "I"


def test_dump_bytes_rejects_end_and_length_together(small_program, call):
    start = _entry(small_program)
    with pytest.raises(ToolError, match="not both"):
        call("dump_bytes", start=str(start), end=str(start.add(4)), length=4)


def test_dump_bytes_caps_large_ranges(small_program, call):
    start = _entry(small_program)

    lines = call("dump_bytes", start=str(start), length=5000).splitlines()

    assert lines[-1].startswith("(capped at 4096 bytes; asked for 5000.")
    assert len(lines) == 4096 // 16 + 1


# ── find_symbol mangled-label folding ──────────────────────────────────────

def test_find_symbol_folds_mangled_label_at_function(small_program, call):
    from ghidra.program.model.symbol import SourceType

    fn = next(iter(small_program.getFunctionManager().getFunctions(True)))
    tx = small_program.startTransaction("test add mangled label")
    try:
        small_program.getSymbolTable().createLabel(
            fn.getEntryPoint(), f"?{fn.getName()}@@YAXXZ", SourceType.IMPORTED
        )
    finally:
        small_program.endTransaction(tx, True)

    text = call("find_symbol", filter=fn.getName())

    assert "@@YAXXZ" not in text
    assert f"{fn.getEntryPoint()}  {fn.getName()}  Function" in text
    assert text.splitlines()[-1] == "(1 mangled label(s) at the same address as a listed function omitted)"


def test_find_symbol_keeps_mangled_label_when_only_it_matches(small_program, call):
    from ghidra.program.model.symbol import SourceType

    fn = next(iter(small_program.getFunctionManager().getFunctions(True)))
    tx = small_program.startTransaction("test add mangled label")
    try:
        small_program.getSymbolTable().createLabel(fn.getEntryPoint(), "?zzOnlyHere@@YAXXZ", SourceType.IMPORTED)
    finally:
        small_program.endTransaction(tx, True)

    assert "?zzOnlyHere@@YAXXZ" in call("find_symbol", filter="zzOnlyHere")


# ── strict argument names ──────────────────────────────────────────────────

def test_unknown_argument_is_rejected_not_ignored(call):
    with pytest.raises(ToolError, match="query"):
        call("find_symbol", filter="x", query="DynamicTex_AllocImage")


# ── per-call program ───────────────────────────────────────────────────────

def test_program_argument_switches_first(small_program):
    switched = []
    run = _server(small_program, switch_program=switched.append)

    run("list_functions", program="other.dll")

    assert switched == ["other.dll"]


def test_program_argument_without_switcher_is_an_error(call):
    with pytest.raises(ToolError, match="switch_active_program"):
        call("list_functions", program="other.dll")


# ── hints on misses ────────────────────────────────────────────────────────

def test_no_function_error_names_nearest_function(small_program, call):
    fm = small_program.getFunctionManager()
    last = None
    for fn in fm.getFunctions(True):
        last = fn
    gap = last.getBody().getMaxAddress().add(1)
    if fm.getFunctionContaining(gap) is not None or small_program.getMemory().getBlock(gap) is None:
        pytest.skip("no mapped gap after the fixture's last function")

    with pytest.raises(ToolError, match=f"nearest before: {last.getName()} @ {last.getEntryPoint()}"):
        call("decompile_function", name_or_address=str(gap))


def test_suggest_program_paths_finds_case_and_folder_mismatches():
    from ghidra_mcp.util import suggest_program_paths

    paths = ["MCity_d.exe", "libs/chkesp", "dao350.dll"]

    assert "MCity_d.exe" in suggest_program_paths("mcity_d.exe", paths)
    assert "libs/chkesp" in suggest_program_paths("chkesp", paths)
    assert suggest_program_paths("zzz", paths) == "The project has 3 programs; list_programs shows them."
