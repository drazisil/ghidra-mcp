"""
Tests for the write tools in ghidra_mcp/tools/write.py: rename_function,
set_calling_convention, set_function_signature.

These call the same Ghidra API sequences the registered MCP tools use
(FastMCP tool functions aren't convenient to invoke directly outside a
running server), against a real, tiny, analyzed COFF object -- not mocks.
"""
from __future__ import annotations


def _first_function(program):
    fn_mgr = program.getFunctionManager()
    for fn in fn_mgr.getFunctions(True):
        return fn
    raise AssertionError("fixture program has no functions")


def test_rename_function(small_program):
    from ghidra.program.model.symbol import SourceType

    fn = _first_function(small_program)
    old_name = fn.getName()

    tx = small_program.startTransaction("test rename")
    try:
        fn.setName("renamed_by_test", SourceType.USER_DEFINED)
    finally:
        small_program.endTransaction(tx, True)

    assert fn.getName() == "renamed_by_test"
    assert fn.getName() != old_name


def test_set_calling_convention_valid(small_program):
    fn = _first_function(small_program)

    tx = small_program.startTransaction("test set cc")
    try:
        fn.setCallingConvention("__cdecl")
    finally:
        small_program.endTransaction(tx, True)

    assert fn.getCallingConventionName() == "__cdecl"


def test_set_calling_convention_invalid_raises(small_program):
    import pytest

    fn = _first_function(small_program)

    tx = small_program.startTransaction("test set cc invalid")
    raised = False
    try:
        fn.setCallingConvention("not_a_real_convention")
    except Exception:
        raised = True
    finally:
        small_program.endTransaction(tx, False)

    assert raised, "setCallingConvention should reject an unknown convention name"


def test_set_function_signature(small_program):
    from ghidra.app.util.parser import FunctionSignatureParser
    from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
    from ghidra.program.model.symbol import SourceType
    from ghidra.util.task import ConsoleTaskMonitor

    fn = _first_function(small_program)
    dtm = small_program.getDataTypeManager()

    parser = FunctionSignatureParser(dtm, None)
    new_sig = parser.parse(
        fn.getSignature(), "int renamed_via_signature(int a, char * b)"
    )

    # preserveCallingConvention=True, forceSetName=True -- see write.py's set_function_signature
    # for why the 3-arg constructor's default (RENAME_IF_DEFAULT) isn't used here.
    cmd = ApplyFunctionSignatureCmd(
        fn.getEntryPoint(), new_sig, SourceType.USER_DEFINED, True, True
    )
    monitor = ConsoleTaskMonitor()
    tx = small_program.startTransaction("test set signature")
    try:
        success = cmd.applyTo(small_program, monitor)
    finally:
        small_program.endTransaction(tx, success)

    assert success, cmd.getStatusMsg()
    assert fn.getName() == "renamed_via_signature"
    params = fn.getParameters()
    assert len(params) == 2
    assert str(params[0].getDataType()) == "int"
    assert str(params[1].getDataType()) == "char *"


def test_set_function_signature_rejects_calling_convention_keyword(small_program):
    """
    Documents a real, verified parser limitation (not a bug in our tool):
    FunctionSignatureParser rejects an embedded calling-convention keyword
    in either position, with "Can't resolve return type". Calling convention
    must be set via set_calling_convention instead.
    """
    from ghidra.app.util.parser import FunctionSignatureParser

    fn = _first_function(small_program)
    dtm = small_program.getDataTypeManager()
    parser = FunctionSignatureParser(dtm, None)

    for bad_sig in (
        "void __cdecl f(int a)",
        "__cdecl void f(int a)",
    ):
        raised = False
        try:
            parser.parse(fn.getSignature(), bad_sig)
        except Exception:
            raised = True
        assert raised, f"expected parse failure for {bad_sig!r}"
