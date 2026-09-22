"""
Tests for get_data_at: what data type Ghidra has at an address.

Runs the real registered tool through a real FastMCP instance against the
tiny analyzed COFF fixture.
"""
from __future__ import annotations

import asyncio

import pytest
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from mcp.types import TextContent


@pytest.fixture
def data_at(small_program):
    from ghidra_mcp.tools import read

    mcp = FastMCP("data-at-test")
    read.register(mcp, lambda: small_program)

    def run(**arguments) -> str:
        result = asyncio.run(mcp.call_tool("get_data_at", arguments))
        assert isinstance(result, list) and len(result) == 1 and isinstance(result[0], TextContent), result
        return result[0].text

    return run


def _make_data(program, addr, data_type):
    """Clear whatever is at addr and define `data_type` there."""
    tx = program.startTransaction("test create data")
    try:
        listing = program.getListing()
        listing.clearCodeUnits(addr, addr.add(data_type.getLength() - 1), False)
        listing.createData(addr, data_type)
    finally:
        program.endTransaction(tx, True)


def _first_instruction(program):
    return program.getListing().getInstructions(True).next()


def test_instruction_is_reported_as_an_instruction(small_program, data_at):
    instr = _first_instruction(small_program)

    line = data_at(address=str(instr.getAddress())).splitlines()[0]

    assert line.startswith(str(instr.getAddress()))
    assert "instruction" in line
    assert str(instr) in line


def test_defined_float_shows_type_length_and_value(small_program, data_at):
    from ghidra.program.model.data import FloatDataType

    addr = _first_instruction(small_program).getAddress()
    _make_data(small_program, addr, FloatDataType.dataType)

    line = data_at(address=str(addr)).splitlines()[0]

    assert line.startswith(str(addr))
    assert "float" in line
    assert "   4" in line


def test_count_lists_consecutive_units(small_program, data_at):
    from ghidra.program.model.data import FloatDataType

    addr = _first_instruction(small_program).getAddress()
    _make_data(small_program, addr, FloatDataType.dataType)
    _make_data(small_program, addr.add(4), FloatDataType.dataType)

    lines = data_at(address=str(addr), count=2).splitlines()

    assert len(lines) == 2
    assert lines[0].startswith(str(addr)) and lines[1].startswith(str(addr.add(4)))


def test_address_inside_a_unit_reports_the_unit_start(small_program, data_at):
    from ghidra.program.model.data import DoubleDataType

    addr = _first_instruction(small_program).getAddress()
    _make_data(small_program, addr, DoubleDataType.dataType)

    lines = data_at(address=str(addr.add(3))).splitlines()

    assert f"is inside the unit starting at {addr}" in lines[0]
    assert lines[1].startswith(str(addr)) and "double" in lines[1]


def test_count_over_the_cap_is_clamped_and_reported(small_program, data_at):
    addr = _first_instruction(small_program).getAddress()

    text = data_at(address=str(addr), count=100_000)

    assert "count capped at 1000; asked for 100000" in text


def test_count_below_one_is_rejected(small_program, data_at):
    addr = _first_instruction(small_program).getAddress()

    with pytest.raises(ToolError, match="1 or greater"):
        data_at(address=str(addr), count=0)


def test_unmapped_address_is_rejected_with_a_hint(small_program, data_at):
    with pytest.raises(ToolError, match="No memory at"):
        data_at(address="0xfffffff0")
