"""
Tests for retype_this_aliases (ghidra_mcp/tools/retype.py).

The fixture is a tiny CRT object with no C++ classes, so these cover the parts
that can be checked without one: the COPY/CAST tracing logic (against stand-in
varnodes carrying real PcodeOp opcodes), the struct-pointer gate, and the tool's
argument errors and no-op paths. The end-to-end retype -- a real derived-class
constructor whose `this` is a class pointer -- needs a binary with such
a function and is not covered here.
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


class _Varnode:
    """Just enough of a Ghidra Varnode for _traces_to_this."""

    def __init__(self, high=None, op=None):
        self._high = high
        self._op = op

    def getHigh(self):
        return self._high

    def getDef(self):
        return self._op


class _Op:
    def __init__(self, opcode, source):
        self._opcode = opcode
        self._source = source

    def getOpcode(self):
        return self._opcode

    def getInput(self, i):
        assert i == 0
        return self._source


class _HighVar:
    def equals(self, other):
        return self is other


@pytest.fixture
def ops():
    from ghidra.program.model.pcode import PcodeOp

    return PcodeOp


@pytest.fixture
def tools(small_program):
    from ghidra_mcp.tools import retype

    mcp = _CapturingMCP()

    class _NoSaveProject:
        def save(self, program):
            raise AssertionError("a run that changes nothing must not reach project.save")

    retype.register(mcp, lambda: small_program, lambda: _NoSaveProject())
    return mcp.tools


def _first_function(program):
    for fn in program.getFunctionManager().getFunctions(True):
        return fn
    raise AssertionError("fixture program has no functions")


def test_this_itself_traces_to_this(ops):
    from ghidra_mcp.tools.retype import _traces_to_this

    this_hv = _HighVar()
    assert _traces_to_this(_Varnode(high=this_hv), this_hv, (ops.COPY, ops.CAST))


def test_copy_and_cast_chain_traces_to_this(ops):
    from ghidra_mcp.tools.retype import _traces_to_this

    # this -> CAST -> temp -> COPY -> local, the shape of `local_8 = (GUI *)this;`
    this_hv = _HighVar()
    this_vn = _Varnode(high=this_hv)
    temp = _Varnode(high=_HighVar(), op=_Op(ops.CAST, this_vn))
    local = _Varnode(high=_HighVar(), op=_Op(ops.COPY, temp))
    assert _traces_to_this(local, this_hv, (ops.COPY, ops.CAST))


def test_other_definitions_do_not_trace_to_this(ops):
    from ghidra_mcp.tools.retype import _traces_to_this

    this_hv = _HighVar()
    copy_ops = (ops.COPY, ops.CAST)
    this_vn = _Varnode(high=this_hv)

    # Arithmetic on `this` (a field address) is not a copy of it.
    field_addr = _Varnode(high=_HighVar(), op=_Op(ops.INT_ADD, this_vn))
    assert not _traces_to_this(field_addr, this_hv, copy_ops)

    # A phi merge could carry another value; so could a value live on entry.
    merged = _Varnode(high=_HighVar(), op=_Op(ops.MULTIEQUAL, this_vn))
    assert not _traces_to_this(merged, this_hv, copy_ops)
    assert not _traces_to_this(_Varnode(high=_HighVar()), this_hv, copy_ops)

    # A copy of some other variable.
    other = _Varnode(high=_HighVar())
    assert not _traces_to_this(_Varnode(high=_HighVar(), op=_Op(ops.COPY, other)), this_hv, copy_ops)


def test_cyclic_chain_terminates(ops):
    from ghidra_mcp.tools.retype import _traces_to_this

    # A def cycle must hit the depth cap, not recurse forever.
    this_hv = _HighVar()
    a = _Varnode(high=_HighVar())
    b = _Varnode(high=_HighVar(), op=_Op(ops.COPY, a))
    a._op = _Op(ops.COPY, b)
    assert not _traces_to_this(a, this_hv, (ops.COPY, ops.CAST))


def test_is_struct_pointer_gate(small_program):
    from ghidra.program.model.data import PointerDataType, StructureDataType, CategoryPath, Undefined4DataType
    from ghidra_mcp.tools.retype import _is_struct_pointer

    struct = StructureDataType(CategoryPath("/"), "GateStruct", 8)
    assert _is_struct_pointer(PointerDataType(struct))
    assert not _is_struct_pointer(PointerDataType(Undefined4DataType()))
    assert not _is_struct_pointer(struct)


def test_named_function_must_be_thiscall(small_program, tools):
    fn = _first_function(small_program)
    tx = small_program.startTransaction("test set cc")
    try:
        fn.setCallingConvention("__cdecl")
    finally:
        small_program.endTransaction(tx, True)

    with pytest.raises(ValueError) as exc:
        tools["retype_this_aliases"](str(fn.getEntryPoint()))

    assert "set_calling_convention" in str(exc.value)


def test_function_and_range_are_exclusive(tools):
    with pytest.raises(ValueError):
        tools["retype_this_aliases"]("anything", start="00401000")


def test_scan_with_no_class_typed_this_changes_nothing(tools):
    # The fixture has no class-typed `this`, so every scan is a no-op and must
    # not save (the _NoSaveProject above enforces that).
    summary = tools["retype_this_aliases"]()
    assert summary.startswith("retyped=0 functions_changed=0 ")
    assert tools["retype_this_aliases"](dry_run=True).startswith("retyped=0 ")
