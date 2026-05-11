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

    raise ValueError(f"Cannot resolve address or name: {name_or_address!r}")


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
        raise ValueError(f"No function at {addr} (from {name_or_address!r})")
    return fn


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
