"""
Tests that tool failures are raised as real errors (so FastMCP reports them with
isError) and that each one tells the caller the next step to take.

Unlike the other test modules these call the real registered tool functions:
register() is handed a tiny stand-in for FastMCP that just records the
decorated functions, then the tests invoke them against the real fixture
program.
"""
from __future__ import annotations

import pytest


class _CapturingMCP:
    def __init__(self):
        self.tools = {}

    def tool(self, *args, **kwargs):
        def decorator(fn):
            self.tools[fn.__name__] = fn
            return fn
        return decorator


@pytest.fixture
def tools(small_program):
    from ghidra_mcp.tools import read, write, vc6_fixes

    mcp = _CapturingMCP()

    def get_program():
        return small_program

    class _NoSaveProject:
        def save(self, program):
            raise AssertionError("failure paths must not reach project.save")

    def get_project():
        return _NoSaveProject()

    read.register(mcp, get_program)
    write.register(mcp, get_program, get_project)
    vc6_fixes.register(mcp, get_program, get_project)
    return mcp.tools


def _first_function(program):
    for fn in program.getFunctionManager().getFunctions(True):
        return fn
    raise AssertionError("fixture program has no functions")


NO_FUNCTION_ADDRESS = "0xdeadbeef"


def test_resolve_function_no_function_hints_create_function(small_program):
    from ghidra_mcp.util import resolve_function

    with pytest.raises(ValueError) as exc:
        resolve_function(small_program, NO_FUNCTION_ADDRESS)

    assert "No function at" in str(exc.value)
    assert "create_function" in str(exc.value)


def test_resolve_address_unknown_name_hints_find_symbol(small_program):
    from ghidra_mcp.util import resolve_address

    with pytest.raises(ValueError) as exc:
        resolve_address(small_program, "definitely_not_a_symbol_xyz")

    assert "find_symbol" in str(exc.value)


def test_decompile_function_no_function_hints_create_function(tools):
    with pytest.raises(ValueError) as exc:
        tools["decompile_function"](NO_FUNCTION_ADDRESS)

    assert "create_function" in str(exc.value)


def test_get_struct_unknown_name_hints_list_structs(tools):
    with pytest.raises(ValueError) as exc:
        tools["get_struct"]("NoSuchStructAnywhere")

    assert "list_structs" in str(exc.value)


def test_create_function_where_one_exists_points_at_decompile_and_rename(small_program, tools):
    fn = _first_function(small_program)

    with pytest.raises(ValueError) as exc:
        tools["create_function"](str(fn.getEntryPoint()))

    message = str(exc.value)
    assert "already exists" in message
    assert "decompile_function" in message
    assert "rename_function" in message


def test_apply_struct_member_unknown_struct_hints_list_structs(tools):
    with pytest.raises(ValueError) as exc:
        tools["apply_struct_member"]("NoSuchStructAnywhere", 0, "int", "field")

    message = str(exc.value)
    assert "list_structs" in message
    assert "create_struct" in message


def test_apply_struct_member_accepts_a_resolved_struct(small_program):
    # create_struct resolves the new struct into the program's data type
    # manager, which hands it back as StructureDB rather than the in-memory
    # StructureDataType builder class -- apply_struct_member must accept
    # that too (regression: it used to reject every already-resolved struct).
    # Needs its own fixture (not `tools` above): that one forbids
    # project.save, but these two tools save on success.
    from ghidra_mcp.tools import read, write

    mcp = _CapturingMCP()

    def get_program():
        return small_program

    class _SaveableProject:
        def save(self, program):
            pass

    def get_project():
        return _SaveableProject()

    read.register(mcp, get_program)
    write.register(mcp, get_program, get_project)
    tools = mcp.tools

    tools["create_struct"]("RegressionStruct", 8)
    tools["create_struct"]("RegressionMember", 4)

    tools["apply_struct_member"]("RegressionStruct", 0, "RegressionMember", "field0")

    listing = tools["get_struct"]("RegressionStruct")
    assert "field0" in listing
