"""
Tests for find_field_uses: every instruction that reaches `[register + offset]`.

Runs the real registered tool through a real FastMCP instance against the
tiny analyzed COFF fixture. The expected addresses come from an independent
oracle -- a regex over each instruction's printed text -- not from the tool's
own operand walk, so the two have to agree on real MSVC output.
"""
from __future__ import annotations

import asyncio
import re
from collections import Counter

import pytest
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from mcp.types import TextContent

# `[EAX + 0x14]`, `[EBP + -0x4]`, `[ESI + EDI*0x4 + 0x8]`: a register-based
# memory operand carrying a displacement. A bare `[0x1234]` has no register.
_DISPLACEMENT = re.compile(r"\[[A-Z]{2,3}(?: \+ [A-Z]{2,3}\*0x[0-9a-f]+)? \+ (-?)0x([0-9a-f]+)\]")


@pytest.fixture
def find_uses(small_program):
    from ghidra_mcp.tools import read

    mcp = FastMCP("find-field-uses-test")
    read.register(mcp, lambda: small_program)

    def run(**arguments) -> str:
        result = asyncio.run(mcp.call_tool("find_field_uses", arguments))
        assert isinstance(result, list) and len(result) == 1 and isinstance(result[0], TextContent), result
        return result[0].text

    return run


def _displacements(program) -> dict:
    """{signed offset: [instruction, ...]} for every register+displacement operand in the program."""
    found: dict[int, list] = {}
    for instr in program.getListing().getInstructions(True):
        for sign, digits in _DISPLACEMENT.findall(str(instr)):
            found.setdefault(-int(digits, 16) if sign else int(digits, 16), []).append(instr)
    return found


def _most_used_positive_offset(program) -> int:
    counts = Counter({off: len(instrs) for off, instrs in _displacements(program).items() if off > 0})
    if not counts:
        pytest.skip("fixture has no register+positive-displacement operand")
    return counts.most_common(1)[0][0]


def _addresses_in(output: str) -> list[str]:
    return [line.split()[0] for line in output.splitlines() if re.match(r"^[0-9a-f]{6,}\s", line)]


def test_finds_the_same_instructions_as_the_text_oracle(small_program, find_uses):
    offset = _most_used_positive_offset(small_program)
    expected = sorted(str(i.getAddress()) for i in _displacements(small_program)[offset])

    output = find_uses(offset=hex(offset))

    assert sorted(_addresses_in(output)) == expected


def test_each_line_names_the_address_function_and_instruction(small_program, find_uses):
    offset = _most_used_positive_offset(small_program)
    instr = _displacements(small_program)[offset][0]
    fn = small_program.getFunctionManager().getFunctionContaining(instr.getAddress())

    line = next(l for l in find_uses(offset=hex(offset)).splitlines() if l.startswith(str(instr.getAddress())))

    assert str(instr) in line
    assert (fn.getName() if fn else "(no function)") in line


def test_negative_offset_matches_locals(small_program, find_uses):
    """`MOV EAX,[EBP-4]`: the fixture has no local-variable access of its own, so patch one in."""
    addr = _patch_in_instruction(small_program, "8b 45 fc")
    assert "[EBP + -0x4]" in str(small_program.getListing().getInstructionAt(addr))

    by_signed = _addresses_in(find_uses(offset="-4", start=str(addr), end=str(addr.add(2))))
    by_hex = _addresses_in(find_uses(offset="-0x4", start=str(addr), end=str(addr.add(2))))

    assert by_signed == by_hex == [str(addr)]


def test_offset_accepts_decimal_and_hex(small_program, find_uses):
    offset = _most_used_positive_offset(small_program)

    assert _addresses_in(find_uses(offset=str(offset))) == _addresses_in(find_uses(offset=hex(offset)))


def test_plain_immediates_are_not_field_uses(small_program, find_uses):
    """`ADD ESP,0x10` / `PUSH 0x10` are scalars, not memory operands."""
    immediates = []
    for instr in small_program.getListing().getInstructions(True):
        text = str(instr)
        if "[" not in text and re.search(r"\b0x[0-9a-f]+\b", text):
            immediates.append(instr)
    if not immediates:
        pytest.skip("fixture has no immediate-only instruction")
    reported = set()
    for off in _displacements(small_program):
        reported.update(_addresses_in(find_uses(offset=hex(off))))

    assert not reported & {str(i.getAddress()) for i in immediates}


def test_register_filter_keeps_only_that_base_register(small_program, find_uses):
    offset = _most_used_positive_offset(small_program)
    by_register: dict[str, list] = {}
    for instr in _displacements(small_program)[offset]:
        reg = re.search(r"\[([A-Z]{2,3})", str(instr)).group(1)
        by_register.setdefault(reg, []).append(instr)
    reg = next(iter(by_register))
    expected = sorted(str(i.getAddress()) for i in by_register[reg])

    output = find_uses(offset=hex(offset), register=reg.lower())

    assert sorted(_addresses_in(output)) == expected


def test_range_limits_the_scan(small_program, find_uses):
    offset = _most_used_positive_offset(small_program)
    hits = sorted(_displacements(small_program)[offset], key=lambda i: i.getAddress().getOffset())
    first = hits[0]
    end = first.getMaxAddress()

    output = find_uses(offset=hex(offset), start=str(first.getAddress()), end=str(end))

    assert _addresses_in(output) == [str(first.getAddress())]


def test_limit_stops_the_list_and_says_so(small_program, find_uses):
    offset = _most_used_positive_offset(small_program)
    total = len(_displacements(small_program)[offset])
    if total < 2:
        pytest.skip("fixture's most-used offset has only one use")

    output = find_uses(offset=hex(offset), limit=1)

    assert len(_addresses_in(output)) == 1
    assert "limit" in output.lower() and str(total) not in output.splitlines()[0]


def test_no_match_says_so_instead_of_returning_nothing(small_program, find_uses):
    unused = 0x7FFF0
    assert unused not in _displacements(small_program)

    output = find_uses(offset=hex(unused))

    assert "no instruction" in output.lower()
    assert hex(unused) in output.lower()


def test_unparseable_offset_is_an_error_with_a_hint(find_uses):
    with pytest.raises(ToolError) as excinfo:
        find_uses(offset="banana")

    assert "offset" in str(excinfo.value).lower() and "0x" in str(excinfo.value)


def test_unknown_register_is_an_error_with_a_hint(small_program, find_uses):
    offset = _most_used_positive_offset(small_program)

    with pytest.raises(ToolError) as excinfo:
        find_uses(offset=hex(offset), register="notareg")

    assert "notareg" in str(excinfo.value)


def test_limit_below_one_is_rejected(find_uses):
    with pytest.raises(ToolError):
        find_uses(offset="0x14", limit=0)


def _patch_in_instruction(program, hex_bytes: str):
    """Overwrite the first instruction's bytes with `hex_bytes` and disassemble them there."""
    from ghidra.app.cmd.disassemble import DisassembleCommand
    from ghidra.program.model.address import AddressSet
    from jpype import JByte

    raw = bytes.fromhex(hex_bytes)
    addr = program.getListing().getInstructions(True).next().getAddress()
    tx = program.startTransaction("test patch instruction")
    try:
        program.getListing().clearCodeUnits(addr, addr.add(len(raw) - 1), False)
        program.getMemory().setBytes(addr, [JByte(b if b < 128 else b - 256) for b in raw])
        DisassembleCommand(addr, AddressSet(addr, addr.add(len(raw) - 1)), True).applyTo(program)
    finally:
        program.endTransaction(tx, True)
    return addr


def test_sib_scale_is_not_mistaken_for_a_displacement(small_program, find_uses):
    """`MOV EAX,[EBX+ESI*4+8]`: 4 is the scale, 8 is the displacement."""
    addr = _patch_in_instruction(small_program, "8b 44 b3 08")
    assert "ESI*0x4" in str(small_program.getListing().getInstructionAt(addr)).replace(" ", "")

    as_scale = _addresses_in(find_uses(offset="4", start=str(addr), end=str(addr.add(3))))
    as_disp = _addresses_in(find_uses(offset="8", start=str(addr), end=str(addr.add(3))))

    assert as_scale == []
    assert as_disp == [str(addr)]
