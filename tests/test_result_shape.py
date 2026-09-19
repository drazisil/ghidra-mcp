"""
Tests that tool results reach the client as plain text.

FastMCP wraps a tool's return value as structured output by default
(`{"result": ...}`), and Claude Code shows that JSON copy instead of the text
-- escaped newlines and quotes around every decompile. Every tool is
registered with structured_output=False so only plain text is sent, and the
tools that used to return list/dict now return compact text lines.

These run the read tools through a real FastMCP instance, so they check what
the protocol layer actually emits, not just the Python return type.
"""
from __future__ import annotations

import asyncio

import pytest
from mcp.server.fastmcp import FastMCP
from mcp.types import TextContent


@pytest.fixture
def call(small_program):
    from ghidra_mcp.tools import read, vc6_fixes, write

    mcp = FastMCP("shape-test")

    def get_program():
        return small_program

    def get_project():
        raise AssertionError("read-only shape tests must not save")

    read.register(mcp, get_program)
    write.register(mcp, get_program, get_project)
    vc6_fixes.register(mcp, get_program, get_project)

    def run(tool: str, arguments: dict):
        return asyncio.run(mcp.call_tool(tool, arguments))

    return run


def _first_function(program):
    for fn in program.getFunctionManager().getFunctions(True):
        return fn
    raise AssertionError("fixture program has no functions")


def _text_of(result) -> str:
    """Assert `result` is plain text content only (no structured copy) and return it."""
    assert isinstance(result, list), f"expected unstructured content list, got {type(result).__name__}: {result!r}"
    assert len(result) == 1 and isinstance(result[0], TextContent), result
    return result[0].text


def test_decompile_returns_plain_text_not_json_wrapper(small_program, call):
    fn = _first_function(small_program)

    text = _text_of(call("decompile_function", {"name_or_address": str(fn.getEntryPoint())}))

    assert not text.startswith('{"result"')
    assert "\n" in text and "\\n" not in text


def test_list_functions_is_one_line_per_function(small_program, call):
    fn = _first_function(small_program)

    text = _text_of(call("list_functions", {}))

    assert not text.lstrip().startswith(("{", "["))
    assert text.splitlines()[0].startswith(f"{fn.getEntryPoint()}  {fn.getName()}  ")


def test_list_functions_says_when_truncated(small_program, call):
    total = sum(1 for _ in small_program.getFunctionManager().getFunctions(True))
    if total < 2:
        pytest.skip("fixture has fewer than 2 functions")

    text = _text_of(call("list_functions", {"limit": 1}))

    assert "showing first 1" in text


def test_list_functions_no_match_is_explicit(call):
    text = _text_of(call("list_functions", {"filter": "zzz_no_such_function_zzz"}))

    assert "No functions match" in text


def test_find_symbol_lines_and_no_match(small_program, call):
    fn = _first_function(small_program)

    text = _text_of(call("find_symbol", {"filter": fn.getName()}))
    assert f"{fn.getEntryPoint()}  {fn.getName()}  Function" in text

    none = _text_of(call("find_symbol", {"filter": "zzz_no_such_symbol_zzz"}))
    assert "No symbols match" in none


def test_get_references_to_and_calls_are_text(small_program, call):
    fn = _first_function(small_program)

    refs = _text_of(call("get_references_to", {"address": str(fn.getEntryPoint())}))
    calls = _text_of(call("get_function_calls", {"name_or_address": str(fn.getEntryPoint())}))

    for text in (refs, calls):
        assert not text.lstrip().startswith(("{", "["))


def test_list_structs_is_text(call):
    text = _text_of(call("list_structs", {}))

    assert not text.lstrip().startswith(("{", "["))
