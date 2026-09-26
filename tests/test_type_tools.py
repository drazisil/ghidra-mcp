"""
Tests for the vtable-typing tools: pointer/array member types in
apply_struct_member, resize_struct, and create_function_definition.

Runs the real registered tools through a real FastMCP instance against the
tiny analyzed COFF fixture, so assertions are on what a client receives.
"""
from __future__ import annotations

import asyncio

import pytest
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from mcp.types import TextContent


@pytest.fixture
def call(small_program):
    from ghidra_mcp.tools import read, write
    from ghidra_mcp.util import forbid_extra_arguments

    class _SaveableProject:
        def save(self, program):
            pass

    mcp = FastMCP("type-tools-test")
    read.register(mcp, lambda: small_program)
    write.register(mcp, lambda: small_program, lambda: _SaveableProject())
    forbid_extra_arguments(mcp)

    def run(tool: str, **arguments) -> str:
        result = asyncio.run(mcp.call_tool(tool, arguments))
        assert isinstance(result, list) and len(result) == 1 and isinstance(result[0], TextContent), result
        return result[0].text

    return run


def _field_line(layout: str, offset: int) -> str:
    for line in layout.splitlines():
        if line.strip().startswith(f"[{offset:>6}]"):
            return line
    raise AssertionError(f"no field at {offset} in:\n{layout}")


# ── apply_struct_member: pointer / array types ─────────────────────────────

def test_pointer_member_to_existing_struct(call):
    call("create_struct", name="Pointee", size=8)
    call("create_struct", name="Holder", size=8)

    call("apply_struct_member", struct_name="Holder", offset=0, type_name="Pointee *", member_name="p")

    assert "Pointee *" in _field_line(call("get_struct", name="Holder"), 0)


def test_array_of_builtin_type(call):
    call("create_struct", name="WithArray", size=16)

    call("apply_struct_member", struct_name="WithArray", offset=4, type_name="char[8]", member_name="buf")

    line = _field_line(call("get_struct", name="WithArray"), 4)
    assert "char[8]" in line and "buf" in line


def test_pointer_to_pointer(call):
    call("create_struct", name="PP", size=4)

    call("apply_struct_member", struct_name="PP", offset=0, type_name="PP * *", member_name="pp")

    assert "PP * *" in _field_line(call("get_struct", name="PP"), 0)


def test_unknown_base_type_names_it(call):
    call("create_struct", name="Holder2", size=4)
    with pytest.raises(ToolError, match="'NoSuchType' not found"):
        call("apply_struct_member", struct_name="Holder2", offset=0, type_name="NoSuchType *", member_name="x")


# ── resize_struct ──────────────────────────────────────────────────────────

def test_grow_keeps_fields(call):
    call("create_struct", name="Growable", size=1)
    call("apply_struct_member", struct_name="Growable", offset=0, type_name="char", member_name="c")

    assert "1 -> 8" in call("resize_struct", name="Growable", size=8)

    layout = call("get_struct", name="Growable")
    assert "8 bytes" in layout.splitlines()[0]
    assert "c" in _field_line(layout, 0)


def test_grow_empty_placeholder_to_exact_size(call):
    # A struct with no fields (like a /Demangler class placeholder) reports
    # length 1; growing it must land on the requested size, not size - 1 + 1.
    call("create_struct", name="Placeholder", size=0)

    out = call("resize_struct", name="Placeholder", size=4)

    assert "empty" in out and "-> 4 bytes" in out
    assert "4 bytes" in call("get_struct", name="Placeholder").splitlines()[0]


def test_shrink_refused_when_it_cuts_a_field(call):
    call("create_struct", name="Shrinky", size=8)
    call("apply_struct_member", struct_name="Shrinky", offset=4, type_name="int", member_name="tail")

    with pytest.raises(ToolError, match="tail @ 4"):
        call("resize_struct", name="Shrinky", size=6)


def test_shrink_allowed_over_undefined_bytes(call):
    call("create_struct", name="Shrinky2", size=8)
    call("apply_struct_member", struct_name="Shrinky2", offset=0, type_name="int", member_name="head")

    assert "8 -> 4" in call("resize_struct", name="Shrinky2", size=4)


def test_resize_unknown_struct(call):
    with pytest.raises(ToolError, match="list_structs"):
        call("resize_struct", name="NoSuchStruct", size=4)


# ── create_function_definition ─────────────────────────────────────────────

def test_definition_from_signature_used_as_vtable_slot(call):
    out = call(
        "create_function_definition",
        name="Slot_EnumResources",
        signature="void f(void * cb, void * ctx)",
        calling_convention="__thiscall",
    )
    assert "Slot_EnumResources" in out and "__thiscall" in out

    call("create_struct", name="Iface_vftable", size=8)
    call("apply_struct_member", struct_name="Iface_vftable", offset=4,
         type_name="Slot_EnumResources *", member_name="EnumResources")

    line = _field_line(call("get_struct", name="Iface_vftable"), 4)
    assert "Slot_EnumResources *" in line and "EnumResources" in line


def test_definition_from_function_copies_its_signature(small_program, call):
    fn = next(iter(small_program.getFunctionManager().getFunctions(True)))

    out = call("create_function_definition", name="CopiedSig", from_function=str(fn.getEntryPoint()))

    assert "CopiedSig" in out
    params = fn.getSignature().getArguments()
    assert out.count(",") == max(len(params) - 1, 0)


def test_definition_needs_exactly_one_source(call):
    with pytest.raises(ToolError, match="exactly one"):
        call("create_function_definition", name="X")
    with pytest.raises(ToolError, match="exactly one"):
        call("create_function_definition", name="X", from_function="0", signature="void f(void)")


def test_definition_duplicate_name_refused(call):
    call("create_function_definition", name="Dup", signature="void f(void)")
    with pytest.raises(ToolError, match="already exists"):
        call("create_function_definition", name="Dup", signature="void f(void)")


def test_definition_unknown_calling_convention_lists_valid(call):
    with pytest.raises(ToolError, match="__stdcall"):
        call("create_function_definition", name="BadCC", signature="void f(void)",
             calling_convention="__nope")
