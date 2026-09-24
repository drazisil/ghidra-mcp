"""
Shared utilities: address resolution, range clearing, instruction helpers.
"""
from __future__ import annotations


def resolve_address(program, name_or_address: str):
    """
    Resolve a function name or hex address string to a Ghidra Address.
    Tries address parse first; falls back to symbol lookup.
    Raises ValueError if nothing is found.
    """
    addr_fact = program.getAddressFactory()
    func_mgr = program.getFunctionManager()
    sym_tbl = program.getSymbolTable()

    # Try as hex address
    try:
        addr = addr_fact.getAddress(name_or_address)
        if addr is not None:
            return addr
    except Exception:
        pass

    # Try symbol table lookup
    syms = sym_tbl.getSymbols(name_or_address)
    for sym in syms:
        return sym.getAddress()

    # Try function name scan (slower, catches demangled names)
    for fn in func_mgr.getFunctions(True):
        if fn.getName() == name_or_address:
            return fn.getEntryPoint()

    raise ValueError(
        f"Cannot resolve {name_or_address!r} as an address or symbol name. "
        f"Use find_symbol('<substring>') to look up a name, or pass a hex address like '0055e190'."
    )


def resolve_function(program, name_or_address: str):
    """
    Resolve a name or hex address to a Ghidra Function.
    Raises ValueError if not found or address has no function.
    """
    addr = resolve_address(program, name_or_address)
    func_mgr = program.getFunctionManager()
    fn = func_mgr.getFunctionAt(addr)
    if fn is None:
        fn = func_mgr.getFunctionContaining(addr)
    if fn is None:
        raise ValueError(
            f"No function at {addr} (from {name_or_address!r}). {_nearest_functions(func_mgr, addr)}"
            f"If this is live code Ghidra never bound to a function (e.g. a jump-table target), "
            f"call create_function('{addr}') first, then retry. To look at the code without a "
            f"function, use get_instructions_around('{addr}'); for bytes, dump_bytes."
        )
    return fn


def _nearest_functions(func_mgr, addr) -> str:
    """Name the closest function on each side of `addr`, so a miss says where to look next."""
    parts = []
    before = func_mgr.getFunctions(addr, False)
    if before.hasNext():
        fn = before.next()
        parts.append(f"nearest before: {fn.getName()} @ {fn.getEntryPoint()} (ends {fn.getBody().getMaxAddress()})")
    after = func_mgr.getFunctions(addr, True)
    if after.hasNext():
        fn = after.next()
        parts.append(f"nearest after: {fn.getName()} @ {fn.getEntryPoint()}")
    return ("; ".join(parts) + ". ") if parts else ""


def forbid_extra_arguments(mcp) -> None:
    """
    Make every registered tool reject argument names it doesn't declare.

    FastMCP's argument models ignore unknown keys by default, so a call like
    find_symbol(query="X", filter="function") silently dropped `query` and ran
    a search nobody asked for. Call this after every tool is registered.
    """
    for tool in mcp._tool_manager.list_tools():
        base = tool.fn_metadata.arg_model
        strict = type(base.__name__, (base,), {"model_config": {**base.model_config, "extra": "forbid"}})
        tool.fn_metadata.arg_model = strict
        tool.parameters["additionalProperties"] = False


def truncation_note(shown_from: int, shown_to: int, total: int, unit: str, how: str) -> str:
    """One trailing line telling the caller the output was cut and how to get the rest."""
    return f"({unit} {shown_from}-{shown_to} of {total} shown; {how})"


def clear_range(program, start_addr, end_addr):
    """
    Clear (un-define) all code units in [start_addr, end_addr].
    Must be called inside an open transaction.
    """
    from ghidra.program.model.address import AddressSet
    listing = program.getListing()
    addr_set = AddressSet(start_addr, end_addr)
    listing.clearCodeUnits(start_addr, end_addr, False)


def is_ret(instruction) -> bool:
    """Return True if the instruction is a RET/RETN."""
    if instruction is None:
        return False
    mnemonic = instruction.getMnemonicString().upper()
    return mnemonic in ("RET", "RETN", "RETF")


def suggest_program_paths(name: str, paths: list[str]) -> str:
    """Closest program paths to a name that didn't open, so the retry needs no list_programs call."""
    import difflib

    by_base = {}
    for path in paths:
        by_base.setdefault(path.rsplit("/", 1)[-1].lower(), path)
    wanted = name.rsplit("/", 1)[-1].lower()
    close = [p for p in paths if p.lower() == name.lower() or p.rsplit("/", 1)[-1].lower() == wanted]
    close += [by_base[b] for b in difflib.get_close_matches(wanted, list(by_base), n=5, cutoff=0.5)]
    close = list(dict.fromkeys(close))
    if close:
        return "Did you mean: " + ", ".join(close) + "? (names are case-sensitive; nested programs need their folder path)"
    return f"The project has {len(paths)} programs; list_programs shows them."
