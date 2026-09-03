"""
Read-only Ghidra tools: decompile, list functions, instructions, structs,
byte dumps, cross-references, callees.
"""
from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass


def register(mcp, get_program):
    """Register all read tools onto the FastMCP instance."""

    @mcp.tool()
    def decompile_function(name_or_address: str) -> str:
        """
        Decompile a function and return the C source.
        Pass a function name (e.g. 'GameSetup_Init') or hex address (e.g. '0055e190').
        """
        from ghidra.app.decompiler import DecompInterface
        from ghidra.util.task import ConsoleTaskMonitor
        from ghidra_mcp.util import resolve_function

        program = get_program()
        fn = resolve_function(program, name_or_address)

        ifc = DecompInterface()
        ifc.openProgram(program)
        try:
            result = ifc.decompileFunction(fn, 60, ConsoleTaskMonitor())
            if result.decompileCompleted():
                return result.getDecompiledFunction().getC()
            return f"[decompile failed: {result.getErrorMessage()}]"
        finally:
            ifc.closeProgram()
            ifc.dispose()

    @mcp.tool()
    def list_functions(filter: str = "", limit: int = 100) -> list[dict]:
        """
        List functions, optionally filtered by a substring of the name.
        Returns [{name, address, size}]. Default limit 100.
        """
        from ghidra_mcp.util import resolve_address

        program = get_program()
        func_mgr = program.getFunctionManager()

        results = []
        for fn in func_mgr.getFunctions(True):
            name = fn.getName()
            if filter and filter.lower() not in name.lower():
                continue
            results.append({
                "name": name,
                "address": str(fn.getEntryPoint()),
                "size": fn.getBody().getNumAddresses(),
            })
            if len(results) >= limit:
                break
        return results

    @mcp.tool()
    def get_function_instructions(name_or_address: str) -> str:
        """
        List all instructions in a function with address, mnemonic, and flow type.
        Pass a function name or hex address.
        """
        from ghidra_mcp.util import resolve_function

        program = get_program()
        fn = resolve_function(program, name_or_address)
        listing = program.getListing()

        lines = [f"{fn.getName()} @ {fn.getEntryPoint()}"]
        body = fn.getBody()
        instr_iter = listing.getInstructions(body, True)
        for instr in instr_iter:
            flow = instr.getFlowType()
            suffix = "" if flow.isFallthrough() else f" {flow}"
            lines.append(f"  {instr.getAddress()}  {instr.getMnemonicString():<12}{suffix}")
        return "\n".join(lines)

    @mcp.tool()
    def get_struct(name: str) -> str:
        """
        Return the layout of a named struct/typedef: offsets, field types, field names, total size.
        """
        from java.util import ArrayList
        from ghidra.program.model.data import Structure, TypedefDataType

        program = get_program()
        dtm = program.getDataTypeManager()

        results = ArrayList()
        dtm.findDataTypes(name, results)

        if results.isEmpty():
            return f"[no data type named {name!r}]"

        dt = results[0]
        # Unwrap typedef if needed
        while isinstance(dt, TypedefDataType):
            dt = dt.getDataType()

        if not isinstance(dt, Structure):
            return f"{name} is {type(dt).__name__}, not a struct (size={dt.getLength()})"

        lines = [f"struct {dt.getName()}  // {dt.getLength()} bytes"]
        for component in dt.getDefinedComponents():
            lines.append(
                f"  [{component.getOffset():>6}] {component.getDataType().getName():<30} {component.getFieldName() or '(unnamed)'}"
            )
        return "\n".join(lines)

    @mcp.tool()
    def list_structs(filter: str = "") -> list[dict]:
        """
        List all struct data types, optionally filtered by name substring.
        Returns [{name, size, category}].
        """
        from ghidra.program.model.data import Structure

        program = get_program()
        dtm = program.getDataTypeManager()

        results = []
        for dt in dtm.getAllDataTypes():
            if not isinstance(dt, Structure):
                continue
            name = dt.getName()
            if filter and filter.lower() not in name.lower():
                continue
            results.append({
                "name": name,
                "size": dt.getLength(),
                "category": str(dt.getCategoryPath()),
            })
        return sorted(results, key=lambda x: x["name"])

    @mcp.tool()
    def dump_bytes(start: str, end: str) -> str:
        """
        Hex dump a memory range with per-byte classification (INSTR/DATA/UNDEF).
        Pass hex addresses for start and end (inclusive).
        """
        program = get_program()
        addr_fact = program.getAddressFactory()
        listing = program.getListing()
        memory = program.getMemory()

        start_addr = addr_fact.getAddress(start)
        end_addr = addr_fact.getAddress(end)

        lines = []
        addr = start_addr
        row_bytes = []
        row_labels = []
        row_start = addr

        def flush_row():
            if not row_bytes:
                return
            hex_part = " ".join(f"{b:02x}" for b in row_bytes)
            label_part = " ".join(f"{l:>4}" for l in row_labels)
            lines.append(f"{row_start}  {hex_part:<48}  {label_part}")

        while addr <= end_addr:
            try:
                b = memory.getByte(addr) & 0xFF
            except Exception:
                b = 0
                row_bytes.append(b)
                row_labels.append("????")
                addr = addr.add(1)
                if len(row_bytes) == 8:
                    flush_row()
                    row_bytes = []
                    row_labels = []
                    row_start = addr
                continue

            cu = listing.getCodeUnitAt(addr)
            if cu is None:
                label = "UNDEF"
            else:
                cu_type = type(cu).__name__
                if "Instruction" in cu_type:
                    label = "INSTR"
                elif "Data" in cu_type:
                    label = "DATA"
                else:
                    label = "???"

            row_bytes.append(b)
            row_labels.append(label)
            addr = addr.add(1)

            if len(row_bytes) == 8:
                flush_row()
                row_bytes = []
                row_labels = []
                row_start = addr

        flush_row()
        return "\n".join(lines)

    @mcp.tool()
    def get_references_to(address: str) -> list[dict]:
        """
        Return all cross-references (XREFs) to an address.
        Returns [{from_address, ref_type, from_function}].
        """
        program = get_program()
        addr_fact = program.getAddressFactory()
        ref_mgr = program.getReferenceManager()
        func_mgr = program.getFunctionManager()

        addr = addr_fact.getAddress(address)
        results = []
        for ref in ref_mgr.getReferencesTo(addr):
            from_addr = ref.getFromAddress()
            owner = func_mgr.getFunctionContaining(from_addr)
            results.append({
                "from_address": str(from_addr),
                "ref_type": str(ref.getReferenceType()),
                "from_function": owner.getName() if owner else "(none)",
                "from_function_address": str(owner.getEntryPoint()) if owner else "?",
            })
        return results

    @mcp.tool()
    def get_function_calls(name_or_address: str) -> list[dict]:
        """
        Return all functions called by the given function (direct callees).
        Returns [{callee_name, callee_address, call_site}].
        """
        from ghidra_mcp.util import resolve_function

        program = get_program()
        fn = resolve_function(program, name_or_address)
        ref_mgr = program.getReferenceManager()
        func_mgr = program.getFunctionManager()
        listing = program.getListing()

        results = []
        body = fn.getBody()
        instr_iter = listing.getInstructions(body, True)
        for instr in instr_iter:
            flow = instr.getFlowType()
            if not flow.isCall():
                continue
            for ref in ref_mgr.getReferencesFrom(instr.getAddress()):
                if ref.getReferenceType().isCall():
                    target = ref.getToAddress()
                    callee = func_mgr.getFunctionAt(target)
                    results.append({
                        "callee_name": callee.getName() if callee else "(unnamed)",
                        "callee_address": str(target),
                        "call_site": str(instr.getAddress()),
                    })
        return results

    @mcp.tool()
    def find_field_dispatch_callers(
        offsets: str,
        start: str = "",
        end: str = "",
        timeout: int = 20,
    ) -> str:
        """
        Bulk-scan decompiled function bodies for indirect calls dispatched through
        a cached struct-field offset.

        Use this when a singleton/interface object's vtable-dispatched methods are
        invisible to get_references_to (indirect/vtable calls have no resolvable
        xref) but you know some *other* class caches a pointer to that singleton
        into one of its own fields at a known byte offset. This scans every
        function in the given address range and reports any whose decompiled C
        text contains BOTH an indirect-call expression (the
        "(**(code **)(...))(...)" shape the decompiler renders for vtable calls)
        AND a reference to one of the given offsets -- i.e. candidate call sites
        where that cached field gets read back and dispatched through.

        offsets: comma-separated hex/decimal field offsets, e.g. "0x36,0x1b6,0xed"
        start/end: optional hex address bounds (e.g. "004e0000"/"00500000") to
        limit the scan -- strongly recommended, since decompiling every function
        in the whole program is slow. Leave blank to scan everything.
        timeout: per-function decompile timeout in seconds.

        Returns one line per match: address, function name, matched offsets.
        This is a heuristic (text-pattern match on decompiled output, not real
        data-flow analysis) -- verify each match with decompile_function.
        """
        import re
        from ghidra.app.decompiler import DecompInterface
        from ghidra.util.task import ConsoleTaskMonitor

        def parse_offset(s: str) -> int:
            s = s.strip()
            return int(s, 16) if s.lower().startswith("0x") else int(s)

        offset_list = [parse_offset(o) for o in offsets.split(",") if o.strip()]
        offset_patterns = [(o, re.compile(r"(?<![0-9a-fA-Fx])0x%x\b" % o)) for o in offset_list]
        indirect_call_pattern = re.compile(r"\(\*\*\(code \*\*\)")

        program = get_program()
        func_mgr = program.getFunctionManager()
        addr_fact = program.getAddressFactory()

        start_addr = addr_fact.getAddress(start) if start else None
        end_addr = addr_fact.getAddress(end) if end else None

        ifc = DecompInterface()
        ifc.openProgram(program)
        monitor = ConsoleTaskMonitor()

        matches = []
        total = 0
        try:
            for fn in func_mgr.getFunctions(True):
                entry = fn.getEntryPoint()
                if start_addr is not None and entry.compareTo(start_addr) < 0:
                    continue
                if end_addr is not None and entry.compareTo(end_addr) > 0:
                    continue
                total += 1
                try:
                    result = ifc.decompileFunction(fn, timeout, monitor)
                except Exception:
                    continue
                if not result.decompileCompleted():
                    continue
                c_src = result.getDecompiledFunction().getC()
                if not indirect_call_pattern.search(c_src):
                    continue
                hit_offsets = [o for o, pat in offset_patterns if pat.search(c_src)]
                if hit_offsets:
                    matches.append((str(entry), fn.getName(), [hex(h) for h in hit_offsets]))
        finally:
            ifc.closeProgram()
            ifc.dispose()

        header = f"Scanned {total} functions."
        if not matches:
            return f"{header} No matches found."
        lines = [header, f"Found {len(matches)} candidate matches:"]
        for addr, name, hits in matches:
            lines.append(f"  {addr}  {name}  offsets={hits}")
        return "\n".join(lines)

    @mcp.tool()
    def search_strings(query: str, max_results: int = 100) -> str:
        """
        Search for defined string data in the program whose value contains `query` (case-insensitive).
        Returns up to `max_results` matches as 'address: value' lines.
        Pass query='' to list all defined strings (up to max_results).
        """
        program = get_program()
        needle = query.lower()
        results = []

        listing = program.getListing()
        data_iter = listing.getDefinedData(True)

        for data in data_iter:
            try:
                if not data.hasStringValue():
                    continue
                value = data.getValue()
                if not isinstance(value, str):
                    value = str(value)
                if needle in value.lower():
                    addr = data.getAddress()
                    results.append(f"{addr}: {value!r}")
                    if len(results) >= max_results:
                        break
            except Exception:
                continue

        if not results:
            return f"[no strings found matching {query!r}]"
        return "\n".join(results)
