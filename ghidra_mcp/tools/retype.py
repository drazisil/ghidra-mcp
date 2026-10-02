"""
Retyping tools: fix locals the decompiler types as something other than what
they were assigned from.

  - retype_this_aliases(): in __thiscall functions, give every local that only
    ever holds a copy of `this` the type of `this`.
"""
from __future__ import annotations

# A chain of COPY/CAST ops from a local back to `this` is short in practice
# (`local_8 = (GUI *)this`, maybe one more hop). The cap only guards against a
# pathological loop in the SSA graph.
_MAX_TRACE_DEPTH = 8


def _traces_to_this(vn, this_hv, copy_ops, depth: int = 0) -> bool:
    """
    True if varnode `vn` is `this` itself, or is defined purely by a COPY/CAST
    chain that ends at `this`.

    The decompiler renders `local_8 = (GUI *)this;` as `this -> CAST -> unique
    temp -> COPY -> local_8` when the types differ, and as a bare COPY when they
    match, so both ops have to be followed. Anything else (arithmetic, a load, a
    phi merge, a call result, a value live on entry) means the local holds
    something other than a plain copy of `this`.
    """
    if vn is None or depth > _MAX_TRACE_DEPTH:
        return False
    hv = vn.getHigh()
    if hv is not None and hv.equals(this_hv):
        return True
    op = vn.getDef()
    if op is None or op.getOpcode() not in copy_ops:
        return False
    return _traces_to_this(op.getInput(0), this_hv, copy_ops, depth + 1)


def _is_struct_pointer(data_type) -> bool:
    """True for `Foo *` where Foo (through any typedefs) is a struct/class."""
    from ghidra.program.model.data import Pointer, Structure, TypeDef

    if not isinstance(data_type, Pointer):
        return False
    target = data_type.getDataType()
    while isinstance(target, TypeDef):
        target = target.getBaseDataType()
    return isinstance(target, Structure)


def _alias_locals(high_function, this_sym):
    """
    Every non-parameter local of `high_function` whose every definition is a
    plain copy of `this`. Requiring *every* def is the guard against compiler
    stack-slot reuse: a slot that holds `this` and later something else is left alone.
    """
    from ghidra.program.model.pcode import HighLocal, PcodeOp

    copy_ops = (PcodeOp.COPY, PcodeOp.CAST)
    this_hv = this_sym.getHighVariable()
    found = []
    for sym in high_function.getLocalSymbolMap().getSymbols():
        if sym.isParameter():
            continue
        hv = sym.getHighVariable()
        if hv is None or not isinstance(hv, HighLocal):
            continue
        instances = hv.getInstances()
        if len(instances) == 0:
            continue
        if all(_traces_to_this(vn, this_hv, copy_ops) for vn in instances):
            found.append(sym)
    return found


def register(mcp, get_program, get_project):
    """Register the retyping tools onto the FastMCP instance."""

    @mcp.tool(structured_output=False)
    def retype_this_aliases(
        name_or_address: str = "",
        start: str = "",
        end: str = "",
        dry_run: bool = False,
        max_passes: int = 3,
        timeout: int = 60,
        limit: int = 100,
    ) -> str:
        """
        Retype locals that are plain copies of `this` in __thiscall functions.

        Derived-class constructors and methods typically open with
        `local_8 = (GUI *)this; GUI::OnBegin((GUI *)this);`. Ghidra types the
        local from the first callee it is passed to (the base class), so the
        copy of `this` shows as a cast to the base type. A copy of a pointer
        should carry the pointer's own type: this gives every such local the
        type of the function's `this` parameter. The base-class cast then shows
        only where it is real, at the call.

        A local is retyped only if every definition of it is a COPY/CAST chain
        back to `this` (so a stack slot the compiler reuses for something else
        is left alone), and only in functions whose `this` is already a
        struct/class pointer (set the class on `this` first, e.g. with
        set_function_signature; an `undefined4`/`void *` `this` has nothing to
        propagate). The new type is written as user-defined, so the decompiler
        stops re-inferring the base type on the next pass. Functions are
        re-decompiled and re-checked up to `max_passes` times, since a
        retype can expose a second alias.

        name_or_address: one function (name or hex address). Blank scans every
          __thiscall function, optionally bounded by `start`/`end` (hex
          addresses; recommended on a big program, since each function is decompiled).
        dry_run: report what would change without writing anything.
        timeout: per-function decompile timeout in seconds.
        limit: maximum change lines listed (the summary line is always complete).

        Returns one summary line of counts (retyped, functions_changed, scanned,
        skipped_untyped_this, decompile_failed, update_failed), then one line
        per local: `function  local: old type -> new type`.
        """
        from ghidra.app.decompiler import DecompInterface
        from ghidra.program.model.pcode import HighFunctionDBUtil
        from ghidra.program.model.symbol import SourceType
        from ghidra.util.task import ConsoleTaskMonitor
        from ghidra_mcp.util import resolve_address, resolve_function, truncation_note

        if max_passes < 1:
            raise ValueError("max_passes must be 1 or greater.")
        if limit < 1:
            raise ValueError("limit must be 1 or greater.")

        program = get_program()
        project = get_project()
        func_mgr = program.getFunctionManager()
        monitor = ConsoleTaskMonitor()

        if name_or_address:
            if start or end:
                raise ValueError("Pass a function, or a start/end range, not both.")
            fn = resolve_function(program, name_or_address)
            if fn.getCallingConventionName() != "__thiscall":
                raise ValueError(
                    f"{fn.getName()} @ {fn.getEntryPoint()} is {fn.getCallingConventionName()}, not "
                    f"__thiscall. Use set_calling_convention first if it really is a method."
                )
            candidates = [fn]
        else:
            first = resolve_address(program, start) if start else None
            last = resolve_address(program, end) if end else None
            if first is not None and last is not None and first.compareTo(last) > 0:
                raise ValueError(f"start {first} is after end {last}. Swap them, or leave one blank.")
            candidates = []
            for fn in func_mgr.getFunctions(True):
                entry = fn.getEntryPoint()
                if first is not None and entry.compareTo(first) < 0:
                    continue
                if last is not None and entry.compareTo(last) > 0:
                    continue
                if fn.getCallingConventionName() == "__thiscall":
                    candidates.append(fn)

        scanned = 0
        skipped_untyped_this = 0
        decompile_failed = 0
        update_failed = 0
        retyped = 0
        functions_changed = 0
        lines = []
        failures = []

        ifc = DecompInterface()
        ifc.openProgram(program)
        try:
            for fn in candidates:
                scanned += 1
                changed_here = 0
                for _ in range(max_passes):
                    result = ifc.decompileFunction(fn, timeout, monitor)
                    if not result.decompileCompleted():
                        decompile_failed += 1
                        break
                    high_function = result.getHighFunction()
                    if high_function is None:
                        decompile_failed += 1
                        break

                    this_sym = high_function.getLocalSymbolMap().getParamSymbol(0)
                    if this_sym is None:
                        skipped_untyped_this += 1
                        break
                    this_type = this_sym.getDataType()
                    if not _is_struct_pointer(this_type):
                        skipped_untyped_this += 1
                        break

                    todo = [
                        sym for sym in _alias_locals(high_function, this_sym)
                        if not sym.getDataType().isEquivalent(this_type)
                    ]
                    if not todo:
                        break

                    if dry_run:
                        for sym in todo:
                            retyped += 1
                            changed_here += 1
                            lines.append(
                                f"  {fn.getEntryPoint()}  {fn.getName()}  {sym.getName()}: "
                                f"{sym.getDataType().getName()} -> {this_type.getName()}"
                            )
                        break

                    tx = program.startTransaction(f"retype this aliases: {fn.getName()}")
                    committed = False
                    applied = 0
                    try:
                        for sym in todo:
                            old_name = sym.getDataType().getName()
                            try:
                                HighFunctionDBUtil.updateDBVariable(
                                    sym, None, this_type, SourceType.USER_DEFINED
                                )
                            except Exception as e:
                                update_failed += 1
                                failures.append(
                                    f"  {fn.getEntryPoint()}  {fn.getName()}  {sym.getName()}: "
                                    f"could not retype ({e})"
                                )
                                continue
                            applied += 1
                            lines.append(
                                f"  {fn.getEntryPoint()}  {fn.getName()}  {sym.getName()}: "
                                f"{old_name} -> {this_type.getName()}"
                            )
                        committed = True
                    finally:
                        program.endTransaction(tx, committed)

                    retyped += applied
                    changed_here += applied
                    if applied == 0:
                        break
                if changed_here:
                    functions_changed += 1
        finally:
            ifc.closeProgram()
            ifc.dispose()

        if retyped and not dry_run:
            project.save(program)

        summary = (
            f"retyped={retyped} functions_changed={functions_changed} scanned={scanned} "
            f"skipped_untyped_this={skipped_untyped_this} decompile_failed={decompile_failed} "
            f"update_failed={update_failed}"
        )
        if dry_run:
            summary += " dry_run=True (nothing written)"
        detail = lines + failures
        if len(detail) > limit:
            detail = detail[:limit] + [
                truncation_note(1, limit, len(lines) + len(failures), "lines", "raise `limit`, or narrow with start/end")
            ]
        return "\n".join([summary] + detail)
