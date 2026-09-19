"""
Tests for get_instructions_around: a window of disassembly around an address.

Runs the real registered tool through a real FastMCP instance against the
tiny analyzed COFF fixture, so the assertions are on what a client receives.
"""
from __future__ import annotations

import asyncio

import pytest
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from mcp.types import TextContent


@pytest.fixture
def around(small_program):
    from ghidra_mcp.tools import read

    mcp = FastMCP("around-test")
    read.register(mcp, lambda: small_program)

    def run(**arguments) -> str:
        result = asyncio.run(mcp.call_tool("get_instructions_around", arguments))
        assert isinstance(result, list) and len(result) == 1 and isinstance(result[0], TextContent), result
        return result[0].text

    return run


def _first_function_instructions(program, at_least: int):
    listing = program.getListing()
    for fn in program.getFunctionManager().getFunctions(True):
        instrs = list(listing.getInstructions(fn.getBody(), True))
        if len(instrs) >= at_least:
            return fn, instrs
    pytest.skip(f"fixture has no function with {at_least}+ instructions")


def _raw(instr) -> str:
    return " ".join(f"{b & 0xFF:02x}" for b in instr.getBytes())


def test_window_marks_the_target_between_its_neighbours(small_program, around):
    _, instrs = _first_function_instructions(small_program, 4)
    prev, target, nxt = instrs[1], instrs[2], instrs[3]

    lines = around(address=str(target.getAddress()), before=1, after=1).splitlines()

    assert len(lines) == 4  # header + 3 instructions
    assert lines[1].startswith("   ") and str(prev.getAddress()) in lines[1]
    assert lines[2].startswith("=> ") and str(target.getAddress()) in lines[2]
    assert lines[3].startswith("   ") and str(nxt.getAddress()) in lines[3]


def test_each_line_carries_the_raw_bytes_and_instruction_text(small_program, around):
    _, instrs = _first_function_instructions(small_program, 3)
    target = instrs[1]

    line = around(address=str(target.getAddress()), before=0, after=0).splitlines()[1]

    assert _raw(target) in line
    assert str(target) in line
    assert line.index(_raw(target)) < line.index(str(target))


def test_zero_context_shows_only_the_target(small_program, around):
    _, instrs = _first_function_instructions(small_program, 2)

    lines = around(address=str(instrs[0].getAddress()), before=0, after=0).splitlines()

    assert len(lines) == 2 and lines[1].startswith("=> ")


def test_header_names_the_containing_function(small_program, around):
    fn, instrs = _first_function_instructions(small_program, 2)

    header = around(address=str(instrs[0].getAddress()), before=0, after=0).splitlines()[0]

    assert f"in {fn.getName()} @ {fn.getEntryPoint()}" in header


def test_address_inside_an_instruction_resolves_to_that_instruction(small_program, around):
    _, instrs = _first_function_instructions(small_program, 2)
    multi_byte = next((i for i in instrs if i.getLength() > 1), None)
    if multi_byte is None:
        pytest.skip("fixture has no multi-byte instruction")
    inside = multi_byte.getAddress().add(1)

    text = around(address=str(inside), before=0, after=0)

    assert f"inside the instruction starting at {multi_byte.getAddress()}" in text
    assert text.splitlines()[1].startswith(f"=> {multi_byte.getAddress()}")


def test_window_stops_at_the_first_instruction_in_the_program(small_program, around):
    first = small_program.getListing().getInstructions(True).next()

    lines = around(address=str(first.getAddress()), before=5, after=0).splitlines()

    assert len(lines) == 2, "nothing can precede the first instruction, so only header + target"
    assert lines[1].startswith("=> ")


def test_counts_over_the_cap_are_clamped_and_reported(small_program, around):
    _, instrs = _first_function_instructions(small_program, 2)

    text = around(address=str(instrs[0].getAddress()), before=10_000, after=10_000)

    assert "before capped at 200; asked for 10000" in text
    assert "after capped at 200; asked for 10000" in text


def test_negative_counts_are_rejected(small_program, around):
    _, instrs = _first_function_instructions(small_program, 2)

    with pytest.raises(ToolError, match="0 or greater"):
        around(address=str(instrs[0].getAddress()), before=-1, after=0)


def test_address_with_no_instruction_hints_dump_bytes(around):
    with pytest.raises(ToolError) as exc:
        around(address="0xdeadbeef")

    assert "No instruction at" in str(exc.value)
    assert "dump_bytes" in str(exc.value)
