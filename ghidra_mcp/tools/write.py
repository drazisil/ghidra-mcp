"""
Write tools: rename functions, set signatures, apply struct members.
Each tool opens and commits its own transaction.
"""
from __future__ import annotations


def register(mcp, get_program, get_project):
    """Register all write tools onto the FastMCP instance."""

    @mcp.tool(structured_output=False)
    def rename_function(address: str, new_name: str) -> str:
        """
        Rename the function at the given hex address.
        Example: rename_function('0055e190', 'GameSetup_Init')
        """
        from ghidra.program.model.symbol import SourceType
        from ghidra_mcp.util import resolve_function

        program = get_program()
        project = get_project()
        fn = resolve_function(program, address)
        old_name = fn.getName()

        tx = program.startTransaction(f"rename {old_name} -> {new_name}")
        success = False
        try:
            fn.setName(new_name, SourceType.USER_DEFINED)
            success = True
        finally:
            program.endTransaction(tx, success)

        # Reaching here means setName didn't raise (any failure propagates as a
        # tool error), so the transaction committed.
        project.save(program)
        return f"Renamed {fn.getEntryPoint()} : {old_name!r} → {new_name!r}"

    @mcp.tool(structured_output=False)
    def create_function(address: str, name: str = "") -> str:
        """
        Create a new function at the given hex address.

        For code Ghidra's auto-analysis never bound to a function boundary --
        most commonly a computed jump table (`JMP [reg*4+table]`-style
        dispatch), which auto-analysis frequently leaves as raw INSTR/UNDEF
        bytes even though the code is live and executes. decompile_function,
        get_function_instructions, extend_function_body, etc. all fail on
        such an address with "No function at <addr>" until a function
        boundary exists. Disassembles at the address first if needed, then
        creates the function with its body auto-determined by following
        control flow from the entry point (the same operation as Ghidra's
        own "Create Function" GUI action / CreateFunctionCmd). Pass an
        optional name; omitted, Ghidra assigns the default FUN_<addr> name.
        """
        from ghidra.app.cmd.function import CreateFunctionCmd
        from ghidra.app.cmd.disassemble import DisassembleCommand
        from ghidra.program.model.symbol import SourceType
        from ghidra.util.task import ConsoleTaskMonitor

        program = get_program()
        project = get_project()
        monitor = ConsoleTaskMonitor()
        listing = program.getListing()
        func_mgr = program.getFunctionManager()
        addr_fact = program.getAddressFactory()

        addr = addr_fact.getAddress(address)
        if addr is None:
            raise ValueError(f"Cannot parse address {address!r}. Pass a hex address like '0055e190'.")

        existing = func_mgr.getFunctionAt(addr)
        if existing is not None:
            raise ValueError(
                f"A function already exists at {addr}: {existing.getName()!r}. "
                f"Use decompile_function to view it or rename_function to rename it."
            )

        tx = program.startTransaction(f"create_function @ {address}")
        success = False
        status_msg = ""
        disasm_note = ""
        try:
            if listing.getInstructionAt(addr) is None:
                disasm_cmd = DisassembleCommand(addr, None, True)
                disasm_ok = disasm_cmd.applyTo(program, monitor)
                if not disasm_ok or listing.getInstructionAt(addr) is None:
                    # The finally block below ends the transaction (success is still False).
                    raise ValueError(
                        f"create_function failed at {address}: could not disassemble "
                        f"({disasm_cmd.getStatusMsg()!r}) -- no instruction at {addr} to build a function from. "
                        f"Use dump_bytes to check whether these bytes are code or data."
                    )
                disasm_note = " (disassembled first)"
            # Explicit null body forces CreateFunctionCmd's body-by-flow-analysis
            # path (follow control flow from entry to find the real extent) --
            # the single-Address constructor was confirmed live to sometimes
            # produce a degenerate near-empty body instead.
            from ghidra.program.model.symbol import SourceType as _SourceType
            cmd = CreateFunctionCmd(None, addr, None, _SourceType.USER_DEFINED)
            success = cmd.applyTo(program, monitor)
            status_msg = cmd.getStatusMsg()
        finally:
            program.endTransaction(tx, success)

        if not success:
            raise ValueError(
                f"create_function failed at {address}{disasm_note}: {status_msg}. "
                f"Use dump_bytes to check the surrounding bytes, or redisassemble_instruction to force re-disassembly."
            )

        fn = func_mgr.getFunctionAt(addr)
        if fn is None:
            raise ValueError(f"create_function reported success but no function was found at {addr} afterward")
        if fn.getBody().getNumAddresses() <= 4:
            return (
                f"[create_function] created {fn.getName()} @ {fn.getEntryPoint()} but body is "
                f"only {fn.getBody().getNumAddresses()} bytes{disasm_note} -- almost certainly "
                f"degenerate, not a real function boundary. Investigate before trusting it."
            )

        if name:
            tx2 = program.startTransaction(f"rename new function @ {address}")
            success2 = False
            try:
                fn.setName(name, SourceType.USER_DEFINED)
                success2 = True
            finally:
                program.endTransaction(tx2, success2)

        project.save(program)
        return f"Created function {fn.getName()} @ {fn.getEntryPoint()}, body {fn.getBody().getNumAddresses()} bytes"

    @mcp.tool(structured_output=False)
    def set_function_comment(name_or_address: str, comment: str) -> str:
        """
        Set the plate (header) comment on a function.
        """
        from ghidra.program.model.listing import CodeUnit
        from ghidra_mcp.util import resolve_function

        program = get_program()
        project = get_project()
        fn = resolve_function(program, name_or_address)
        listing = program.getListing()
        cu = listing.getCodeUnitAt(fn.getEntryPoint())

        tx = program.startTransaction(f"comment {fn.getName()}")
        success = False
        try:
            cu.setComment(CodeUnit.PLATE_COMMENT, comment)
            success = True
        finally:
            program.endTransaction(tx, success)

        project.save(program)
        return f"Comment set on {fn.getName()} @ {fn.getEntryPoint()}"

    @mcp.tool(structured_output=False)
    def apply_struct_member(
        struct_name: str,
        offset: int,
        type_name: str,
        member_name: str,
    ) -> str:
        """
        Place a field into a struct at the given byte offset.
        Clears conflicting undefined bytes first (replaceAtOffset requires undefined1).
        Example: apply_struct_member('cNPS_GameServer', 1760, 'cUserList', 'mUserList_Added')
        """
        from java.util import ArrayList
        from ghidra.program.model.data import Structure, TypedefDataType

        program = get_program()
        project = get_project()
        dtm = program.getDataTypeManager()

        # Resolve struct
        struct_results = ArrayList()
        dtm.findDataTypes(struct_name, struct_results)
        if struct_results.isEmpty():
            raise ValueError(
                f"Struct {struct_name!r} not found. Use list_structs(filter='<substring>') to find it, "
                f"or create_struct to make it."
            )
        struct_dt = struct_results[0]
        while isinstance(struct_dt, TypedefDataType):
            struct_dt = struct_dt.getDataType()
        # Structs already resolved into the program come back as StructureDB, not
        # StructureDataType (the latter is only the in-memory pre-resolve builder).
        # Both implement the Structure interface, so check against that instead.
        if not isinstance(struct_dt, Structure):
            raise ValueError(f"{struct_name!r} is a {type(struct_dt).__name__}, not a struct.")

        # Resolve member type
        type_results = ArrayList()
        dtm.findDataTypes(type_name, type_results)
        if type_results.isEmpty():
            raise ValueError(
                f"Member type {type_name!r} not found. Use list_structs(filter='<substring>') for "
                f"struct types; names are case-sensitive."
            )
        member_type = type_results[0]

        member_size = member_type.getLength()
        end_offset = offset + member_size - 1

        tx = dtm.startTransaction(f"apply {member_name} @ [{offset}]")
        success = False
        try:
            # Clear the range to undefined1 so replaceAtOffset accepts it
            for i in range(offset, offset + member_size):
                existing = struct_dt.getComponentAt(i)
                if existing is not None:
                    edt = existing.getDataType()
                    if edt.getName() != "undefined1":
                        struct_dt.clearAtOffset(i)

            struct_dt.replaceAtOffset(offset, member_type, member_size, member_name, "")
            success = True
        finally:
            dtm.endTransaction(tx, success)

        project.save(program)
        return (
            f"Applied {type_name} {member_name} at [{offset}] in {struct_name} "
            f"(size={member_size})"
        )

    @mcp.tool(structured_output=False)
    def create_struct(name: str, size: int, category: str = "/") -> str:
        """
        Create a new empty struct data type of the given size.
        category: data type manager path, e.g. '/NPS' or '/' for root.
        """
        from ghidra.program.model.data import StructureDataType, CategoryPath

        program = get_program()
        project = get_project()
        dtm = program.getDataTypeManager()

        cat_path = CategoryPath(category)
        new_struct = StructureDataType(cat_path, name, size, dtm)

        tx = dtm.startTransaction(f"create struct {name}")
        success = False
        try:
            dtm.addDataType(new_struct, None)
            success = True
        finally:
            dtm.endTransaction(tx, success)

        project.save(program)
        return f"Created struct {name} ({size} bytes) in {category}"

    @mcp.tool(structured_output=False)
    def set_calling_convention(name_or_address: str, convention: str) -> str:
        """
        Set a function's calling convention (e.g. '__cdecl', '__stdcall', '__thiscall', '__fastcall').
        Valid names are defined by the program's compiler spec; on failure the error lists
        the actual valid names for this program rather than a generic guess.
        Useful for functions Ghidra decompiles with 'unaff_' registers because it guessed the
        wrong convention (e.g. a function that really expects a caller-supplied register input).
        """
        from ghidra_mcp.util import resolve_function

        program = get_program()
        project = get_project()
        fn = resolve_function(program, name_or_address)
        old = fn.getCallingConventionName()

        tx = program.startTransaction(f"set calling convention {fn.getName()} -> {convention}")
        success = False
        error = None
        try:
            fn.setCallingConvention(convention)
            success = True
        except Exception as e:
            error = str(e)
        finally:
            program.endTransaction(tx, success)

        if success:
            project.save(program)
            return f"{fn.getName()} @ {fn.getEntryPoint()}: calling convention {old!r} -> {convention!r}"

        compiler_spec = program.getCompilerSpec()
        valid = ", ".join(str(m.getName()) for m in compiler_spec.getCallingConventions())
        raise ValueError(
            f"Cannot set calling convention {convention!r} on {fn.getName()}: {error}. "
            f"Valid conventions for this program: {valid}"
        )

    @mcp.tool(structured_output=False)
    def set_function_signature(name_or_address: str, signature: str) -> str:
        """
        Set a function's return type, name, and parameters from a C-style declaration string
        (no calling-convention keyword — the parser rejects '__cdecl'/'__stdcall'/etc. in either
        position with 'Can't resolve return type'; use set_calling_convention for that separately).
        Example: set_function_signature('0055e190', 'int GameSetup_Init(int argc, char **argv)')
        The name in the string may differ from the function's current name; the function is renamed
        to match.
        """
        from ghidra.app.util.parser import FunctionSignatureParser
        from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
        from ghidra.program.model.symbol import SourceType
        from ghidra.util.task import ConsoleTaskMonitor
        from ghidra_mcp.util import resolve_function

        program = get_program()
        project = get_project()
        fn = resolve_function(program, name_or_address)
        dtm = program.getDataTypeManager()

        parser = FunctionSignatureParser(dtm, None)
        try:
            new_sig = parser.parse(fn.getSignature(), signature)
        except Exception as e:
            raise ValueError(f"Could not parse signature {signature!r}: {e}")

        # preserveCallingConvention=True (this tool never parses one out of the string;
        # use set_calling_convention for that), forceSetName=True (the 3-arg constructor
        # defaults to FunctionRenameOption.RENAME_IF_DEFAULT, silently skipping the rename
        # whenever the function already has a non-default name -- verified against a real
        # COFF-sourced symbol, not a FUN_ placeholder. Force it so the rename this tool
        # documents actually happens.)
        cmd = ApplyFunctionSignatureCmd(
            fn.getEntryPoint(), new_sig, SourceType.USER_DEFINED, True, True
        )
        monitor = ConsoleTaskMonitor()

        tx = program.startTransaction(f"set signature {fn.getName()}")
        success = False
        try:
            success = cmd.applyTo(program, monitor)
        finally:
            program.endTransaction(tx, success)

        if success:
            project.save(program)
            return f"Signature applied at {fn.getEntryPoint()}: {signature}"
        raise ValueError(f"set_function_signature failed at {fn.getEntryPoint()}: {cmd.getStatusMsg()}")
