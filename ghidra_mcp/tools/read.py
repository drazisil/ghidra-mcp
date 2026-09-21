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

    @mcp.tool(structured_output=False)
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
            raise ValueError(
                f"Decompile of {fn.getName()} @ {fn.getEntryPoint()} failed: {result.getErrorMessage()}. "
                f"Inspect the raw instructions with get_function_instructions; if the body is cut off "
                f"after a CALL __chkesp, extend_function_body or fix_vc6_call_terminators repairs it."
            )
        finally:
            ifc.closeProgram()
            ifc.dispose()

    @mcp.tool(structured_output=False)
    def list_functions(filter: str = "", limit: int = 100) -> str:
        """
        List functions, optionally filtered by a substring of the name.
        One line per function: `address  name  size`. Default limit 100; says so
        when the list was cut off.
        """
        program = get_program()
        func_mgr = program.getFunctionManager()

        results = []
        truncated = False
        for fn in func_mgr.getFunctions(True):
            name = fn.getName()
            if filter and filter.lower() not in name.lower():
                continue
            if len(results) >= limit:
                truncated = True
                break
            results.append(f"{fn.getEntryPoint()}  {name}  {fn.getBody().getNumAddresses()}")

        if not results:
            return f"No functions match {filter!r}." if filter else "No functions in this program."
        if truncated:
            results.append(f"(showing first {limit}; narrow with `filter` or raise `limit`)")
        return "\n".join(results)

    @mcp.tool(structured_output=False)
    def get_function_instructions(name_or_address: str) -> str:
        """
        List all instructions in a function with address, mnemonic, operands, and
        flow type (flow type is shown only when it isn't plain fall-through).
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
            lines.append(f"  {instr.getAddress()}  {instr}{suffix}")
        return "\n".join(lines)

    @mcp.tool(structured_output=False)
    def get_instructions_around(address: str, before: int = 5, after: int = 5) -> str:
        """
        Show a window of disassembly around an address, like grep -B/-A: `before`
        instructions ahead of it, the instruction containing it (marked `=>`),
        and `after` instructions following -- without dumping the whole function.
        Each line is `address  raw bytes  instruction`. A flow type is appended
        only when it isn't plain fall-through, and a `...` line marks bytes
        between two instructions that aren't disassembled (data or undefined).
        Defaults 5 and 5, each capped at 200. Pass a hex address or a name; it
        works inside a function or not, as long as an instruction is there.
        """
        from ghidra_mcp.util import resolve_address

        max_context = 200
        if before < 0 or after < 0:
            raise ValueError("before and after must be 0 or greater.")
        notes = []
        if before > max_context:
            notes.append(f"(before capped at {max_context}; asked for {before})")
            before = max_context
        if after > max_context:
            notes.append(f"(after capped at {max_context}; asked for {after})")
            after = max_context

        program = get_program()
        listing = program.getListing()
        addr = resolve_address(program, address)
        target = listing.getInstructionContaining(addr)
        if target is None:
            raise ValueError(
                f"No instruction at {addr}. Use dump_bytes to see what is there; if it should be "
                f"code, create_function or redisassemble_instruction can define it."
            )

        preceding = []
        cur = target
        for _ in range(before):
            cur = cur.getPrevious()
            if cur is None:
                break
            preceding.append(cur)
        preceding.reverse()

        following = []
        cur = target
        for _ in range(after):
            cur = cur.getNext()
            if cur is None:
                break
            following.append(cur)

        def render(instr, marker: str) -> str:
            raw = " ".join(f"{b & 0xFF:02x}" for b in instr.getBytes())
            flow = instr.getFlowType()
            suffix = "" if flow.isFallthrough() else f" {flow}"
            return f"{marker} {instr.getAddress()}  {raw:<23}  {instr}{suffix}"

        owner = program.getFunctionManager().getFunctionContaining(addr)
        where = f"in {owner.getName()} @ {owner.getEntryPoint()}" if owner else "(not inside a function)"
        header = f"{addr} {where}"
        if not target.getAddress().equals(addr):
            header += f"; inside the instruction starting at {target.getAddress()}"

        lines = [header]
        previous = None
        for instr in preceding + [target] + following:
            if previous is not None:
                gap = instr.getAddress().getOffset() - previous.getMaxAddress().getOffset() - 1
                if gap > 0:
                    lines.append(f"     ... {gap} bytes not disassembled")
            marker = "=>" if instr.getAddress().equals(target.getAddress()) else "  "
            lines.append(render(instr, marker))
            previous = instr
        return "\n".join(lines + notes)

    @mcp.tool(structured_output=False)
    def find_field_uses(
        offset: str, start: str = "", end: str = "", register: str = "", limit: int = 100
    ) -> str:
        """
        Find every instruction that reaches a memory operand `[register + offset]`,
        i.e. every use of a struct field at a known byte offset. Works on the raw
        displacement, so it does not need the field to be defined in a struct.
        `offset` is a hex or decimal byte offset ('0x14', '20', '-0x4'). `register`
        (e.g. 'edi') keeps only operands based on that register. `start`/`end`
        (hex addresses) bound the scan -- strongly recommended on a big program,
        because this walks every instruction in range. Each line is
        `address  function  instruction`. Plain immediates (`PUSH 0x14`,
        `ADD ESP,0x14`), absolute addresses (`[0x013c5db8]`) and SIB scale factors
        (`[EAX*0x4]`) do not count. Default limit 100; says so when the list was cut off.
        Matches every struct with a field at that offset -- narrow with `register`
        or a range, and check the hits.
        """
        from ghidra.program.model.address import AddressSet
        from ghidra.program.model.lang import OperandType, Register
        from ghidra.program.model.scalar import Scalar
        from ghidra_mcp.util import resolve_address

        try:
            wanted = int(offset, 0)
        except (TypeError, ValueError):
            raise ValueError(
                f"Cannot read offset {offset!r} as a number. Pass a hex or decimal byte offset "
                f"like '0x14', '20' or '-0x4'."
            )
        if limit < 1:
            raise ValueError("limit must be 1 or greater.")

        program = get_program()
        base_reg = None
        if register:
            base_reg = program.getLanguage().getRegister(register) or program.getLanguage().getRegister(
                register.upper()
            )
            if base_reg is None:
                raise ValueError(
                    f"Unknown register {register!r} for this program's processor. "
                    f"Pass a name like 'edi' or 'ESI', or leave register blank to match any base."
                )

        # A program can hold several address spaces (overlay blocks such as
        # .debug$T), so a whole-program min..max range isn't a valid AddressSet.
        # No bounds means "all code"; one bound means "to the end/start of its space".
        first = resolve_address(program, start) if start else None
        last = resolve_address(program, end) if end else None
        if first is not None and last is not None and first.compareTo(last) > 0:
            raise ValueError(f"start {first} is after end {last}. Swap them, or leave one blank.")
        if first is None and last is not None:
            first = last.getAddressSpace().getMinAddress()
        if last is None and first is not None:
            last = first.getAddressSpace().getMaxAddress()
        scan = None if first is None else AddressSet(first, last)

        def displacement_matches(instr, op_index: int) -> bool:
            """True if this operand's displacement (not a SIB scale) equals `wanted`."""
            previous = None
            found = False
            for part in instr.getDefaultOperandRepresentationList(op_index):
                if isinstance(part, Scalar):
                    scaled = isinstance(previous, str) and previous.rstrip().endswith("*")
                    if not scaled and wanted in (part.getSignedValue(), part.getValue()):
                        found = True
                previous = part
            return found

        def based_on(instr, op_index: int) -> bool:
            regs = [o for o in instr.getOpObjects(op_index) if isinstance(o, Register)]
            if not regs:
                return False
            return base_reg is None or any(r.equals(base_reg) for r in regs)

        listing = program.getListing()
        func_mgr = program.getFunctionManager()
        hits = []
        truncated = False
        for instr in listing.getInstructions(True) if scan is None else listing.getInstructions(scan, True):
            for i in range(instr.getNumOperands()):
                if not instr.getOperandType(i) & OperandType.DYNAMIC:
                    continue
                if displacement_matches(instr, i) and based_on(instr, i):
                    if len(hits) == limit:
                        truncated = True
                        break
                    owner = func_mgr.getFunctionContaining(instr.getAddress())
                    where = owner.getName() if owner else "(no function)"
                    hits.append(f"{instr.getAddress()}  {where}  {instr}")
                    break
            if truncated:
                break

        if not hits:
            scope = f" in {first}..{last}" if scan is not None else ""
            via = f" based on {base_reg.getName()}" if base_reg else ""
            return f"No instruction{scope} uses a memory operand{via} with offset {hex(wanted)}."
        if truncated:
            hits.append(f"(stopped at limit {limit}; raise limit, or narrow with start/end/register)")
        return "\n".join(hits)

    @mcp.tool(structured_output=False)
    def get_data_at(address: str, count: int = 1) -> str:
        """
        Show the data type Ghidra has at an address, for `count` consecutive code
        units (default 1, max 1000) -- use a larger count to audit a range.
        Each line is `address  length  type  value  label`; the first unit is the
        one containing the address (its start is shown if that differs), and
        instructions are listed as `instruction`. Undefined bytes show as `undefined`.
        Pass a hex address or a name.
        """
        from ghidra_mcp.util import resolve_address

        max_count = 1000
        if count < 1:
            raise ValueError("count must be 1 or greater.")
        notes = []
        if count > max_count:
            notes.append(f"(count capped at {max_count}; asked for {count})")
            count = max_count

        program = get_program()
        listing = program.getListing()
        symbols = program.getSymbolTable()
        addr = resolve_address(program, address)
        unit = listing.getCodeUnitContaining(addr)
        if unit is None:
            raise ValueError(
                f"No memory at {addr}. Use list_programs / dump_bytes to check the address is inside a mapped block."
            )

        lines = []
        if not unit.getAddress().equals(addr):
            lines.append(f"{addr} is inside the unit starting at {unit.getAddress()}")
        for _ in range(count):
            if unit is None:
                notes.append("(end of memory reached)")
                break
            start = unit.getAddress()
            sym = symbols.getPrimarySymbol(start)
            label = sym.getName() if sym is not None else ""
            if listing.getInstructionAt(start) is not None:
                kind, value = "instruction", str(unit)
            else:
                kind = unit.getDataType().getName()
                value = unit.getDefaultValueRepresentation()
            lines.append(f"{start}  {unit.getLength():>4}  {kind:<12}  {value}  {label}".rstrip())
            unit = listing.getCodeUnitAfter(start)
        return "\n".join(lines + notes)

    @mcp.tool(structured_output=False)
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
            raise ValueError(
                f"No data type named {name!r}. Use list_structs(filter='<substring>') to find struct names."
            )

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

    @mcp.tool(structured_output=False)
    def list_structs(filter: str = "") -> str:
        """
        List all struct data types, optionally filtered by name substring.
        One line per struct, sorted by name: `name  size  category`.
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
            results.append((name, f"{name}  {dt.getLength()}  {dt.getCategoryPath()}"))
        if not results:
            return f"No structs match {filter!r}." if filter else "No structs in this program."
        return "\n".join(line for _, line in sorted(results))

    @mcp.tool(structured_output=False)
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

    @mcp.tool(structured_output=False)
    def get_references_to(address: str) -> str:
        """
        Return all cross-references (XREFs) to an address.
        One line per reference: `from_address  ref_type  from_function @ from_function_address`
        (`(none)` when the reference isn't inside a function).
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
            owner_text = f"{owner.getName()} @ {owner.getEntryPoint()}" if owner else "(none)"
            results.append(f"{from_addr}  {ref.getReferenceType()}  {owner_text}")
        if not results:
            return f"No references to {address}."
        return "\n".join(results)

    @mcp.tool(structured_output=False)
    def get_function_calls(name_or_address: str) -> str:
        """
        Return all functions called by the given function (direct callees).
        One line per call: `call_site -> callee_name @ callee_address`.
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
                    callee_name = callee.getName() if callee else "(unnamed)"
                    results.append(f"{instr.getAddress()} -> {callee_name} @ {target}")
        if not results:
            return f"{fn.getName()} @ {fn.getEntryPoint()} makes no direct calls."
        return "\n".join(results)

    @mcp.tool(structured_output=False)
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

    @mcp.tool(structured_output=False)
    def find_symbol(filter: str, limit: int = 100, include_dynamic: bool = False) -> str:
        """
        Find address(es) for a label/symbol by name (the reverse of an
        address->name lookup). `filter` matches as a case-insensitive substring.
        One line per symbol: `address  name  type`. Default limit 100; says so
        when the list was cut off.

        By default, Ghidra's auto-generated default labels (e.g. 'DAT_0055e190',
        'LAB_0055e190') are excluded so results stay to symbols someone actually
        named -- user-defined labels, imports, exports, functions. Pass
        include_dynamic=True to also search those default names.
        """
        program = get_program()
        sym_tbl = program.getSymbolTable()

        results = []
        truncated = False
        for sym in sym_tbl.getAllSymbols(include_dynamic):
            name = sym.getName()
            if filter.lower() not in name.lower():
                continue
            if len(results) >= limit:
                truncated = True
                break
            results.append(f"{sym.getAddress()}  {name}  {sym.getSymbolType()}")

        if not results:
            return f"No symbols match {filter!r}."
        if truncated:
            results.append(f"(showing first {limit}; narrow `filter` or raise `limit`)")
        return "\n".join(results)

    @mcp.tool(structured_output=False)
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
