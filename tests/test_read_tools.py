"""
Tests for the read tools in ghidra_mcp/tools/read.py: find_symbol.

These call the same Ghidra API sequence the registered MCP tool uses
(FastMCP tool functions aren't convenient to invoke directly outside a
running server), against a real, tiny, analyzed COFF object -- not mocks.
"""
from __future__ import annotations


def _first_function(program):
    fn_mgr = program.getFunctionManager()
    for fn in fn_mgr.getFunctions(True):
        return fn
    raise AssertionError("fixture program has no functions")


def _find_symbol(program, filter: str, limit: int = 100, include_dynamic: bool = False):
    sym_tbl = program.getSymbolTable()
    results = []
    for sym in sym_tbl.getAllSymbols(include_dynamic):
        name = sym.getName()
        if filter.lower() not in name.lower():
            continue
        results.append({
            "name": name,
            "address": str(sym.getAddress()),
            "type": str(sym.getSymbolType()),
        })
        if len(results) >= limit:
            break
    return results


def test_find_symbol_matches_existing_function(small_program):
    fn = _first_function(small_program)

    matches = _find_symbol(small_program, fn.getName())

    assert len(matches) == 1
    assert matches[0]["name"] == fn.getName()
    assert matches[0]["address"] == str(fn.getEntryPoint())
    assert matches[0]["type"] == "Function"


def test_find_symbol_case_insensitive_substring(small_program):
    fn = _first_function(small_program)
    needle = fn.getName()[:3].upper()

    matches = _find_symbol(small_program, needle)

    assert any(m["name"] == fn.getName() for m in matches)


def test_find_symbol_finds_user_defined_label(small_program):
    from ghidra.program.model.symbol import SourceType

    fn = _first_function(small_program)
    addr = fn.getEntryPoint().add(1)
    sym_tbl = small_program.getSymbolTable()

    tx = small_program.startTransaction("test add label")
    try:
        sym_tbl.createLabel(addr, "my_custom_label", SourceType.USER_DEFINED)
    finally:
        small_program.endTransaction(tx, True)

    matches = _find_symbol(small_program, "my_custom_label")

    assert len(matches) == 1
    assert matches[0]["address"] == str(addr)
    assert matches[0]["type"] == "Label"


def test_find_symbol_no_match_returns_empty(small_program):
    matches = _find_symbol(small_program, "definitely_not_a_real_symbol_name_xyz")

    assert matches == []


def test_find_symbol_respects_limit(small_program):
    from ghidra.program.model.symbol import SourceType

    fn = _first_function(small_program)
    sym_tbl = small_program.getSymbolTable()

    tx = small_program.startTransaction("test add labels for limit")
    try:
        for i in range(5):
            sym_tbl.createLabel(fn.getEntryPoint().add(i + 1), f"limit_test_label_{i}", SourceType.USER_DEFINED)
    finally:
        small_program.endTransaction(tx, True)

    matches = _find_symbol(small_program, "limit_test_label", limit=3)

    assert len(matches) == 3


def test_instruction_listing_line_includes_operands(small_program):
    """get_function_instructions must render operands, not just the mnemonic.

    Mirrors the tool's per-instruction formatting (`f"{instr}"`); an
    instruction with operands must print more than its bare mnemonic.
    """
    fn = _first_function(small_program)
    listing = small_program.getListing()

    with_operands = [
        i for i in listing.getInstructions(fn.getBody(), True)
        if i.getNumOperands() > 0 and i.getDefaultOperandRepresentation(0)
    ]
    assert with_operands, "fixture function has no instruction with operands"

    for instr in with_operands:
        rendered = str(instr)
        assert rendered != instr.getMnemonicString()
        assert instr.getDefaultOperandRepresentation(0) in rendered
