"""
VC6 MSVC fix pipeline:
  - fix_vc6_call_terminators(): extend truncated function bodies + re-disassemble __chkesp call sites
  - extend_function_body(): single-function body extension
  - redisassemble_instruction(): clear + re-disassemble one instruction
"""
from __future__ import annotations


def register(mcp, get_program, get_project):

    @mcp.tool()
    def fix_vc6_call_terminators(chkesp_address: str = "") -> dict:
        """
        Fix the __chkesp CALL_TERMINATOR problem in VC6 debug builds.

        Two-pass pipeline:
          Pass 1 — body extension: for every function whose last in-body instruction
                   is CALL __chkesp, force-disassemble forward and extend the body to
                   include the fall-through path.
          Pass 2 — re-disassembly: for every CALL __chkesp site where the fall-through
                   is now a valid instruction, clear + re-disassemble so Ghidra recomputes
                   FlowType from scratch (→ UNCONDITIONAL_CALL instead of CALL_TERMINATOR).

        chkesp_address: hex address of __chkesp (optional — found by name if omitted).
        Returns {extended: N, redisassembled: N, skipped: N}.
        """
        from ghidra.program.model.address import AddressSet
        from ghidra.app.cmd.disassemble import DisassembleCommand
        from ghidra.util.task import ConsoleTaskMonitor
        from ghidra_mcp.util import resolve_address, is_ret

        program = get_program()
        project = get_project()
        monitor = ConsoleTaskMonitor()
        listing = program.getListing()
        func_mgr = program.getFunctionManager()
        ref_mgr = program.getReferenceManager()
        addr_fact = program.getAddressFactory()

        # Locate __chkesp
        if chkesp_address:
            chkesp_addr = addr_fact.getAddress(chkesp_address)
        else:
            chkesp_addr = resolve_address(program, "__chkesp")

        # Collect all call sites to __chkesp
        call_sites = []
        for ref in ref_mgr.getReferencesTo(chkesp_addr):
            if ref.getReferenceType().isCall():
                call_sites.append(ref.getFromAddress())

        extended = 0
        skipped_extend = 0

        # ── Pass 1: body extension ──────────────────────────────────────────────
        tx = program.startTransaction("fix_vc6: extend truncated function bodies")
        success = False
        try:
            for call_addr in call_sites:
                instr = listing.getInstructionAt(call_addr)
                if instr is None:
                    skipped_extend += 1
                    continue

                flow = instr.getFlowType()
                if not str(flow).startswith("CALL_TERMINATOR"):
                    continue  # already fixed or not the problem

                fn = func_mgr.getFunctionContaining(call_addr)
                if fn is None:
                    skipped_extend += 1
                    continue

                # Fall-through address = call_addr + instruction length
                fall_addr = call_addr.add(instr.getLength())

                # Force-disassemble from fall_addr
                fall_instr = listing.getInstructionAt(fall_addr)
                if fall_instr is None:
                    cmd = DisassembleCommand(fall_addr, None, True)
                    cmd.applyTo(program, monitor)
                    fall_instr = listing.getInstructionAt(fall_addr)

                if fall_instr is None:
                    skipped_extend += 1
                    continue

                # Walk forward to the next RET to find the extent we need to cover
                end_addr = fall_addr
                cur = fall_instr
                for _ in range(256):  # safety limit
                    if is_ret(cur):
                        end_addr = cur.getAddress()
                        break
                    nxt = cur.getNext()
                    if nxt is None:
                        break
                    cur = nxt

                # Extend function body
                try:
                    new_body = fn.getBody().union(AddressSet(fall_addr, end_addr))
                    fn.setBody(new_body)
                    extended += 1
                except Exception:
                    skipped_extend += 1

            success = True
        finally:
            program.endTransaction(tx, success)

        # ── Pass 2: re-disassembly ──────────────────────────────────────────────
        redisassembled = 0
        skipped_redisasm = 0

        tx2 = program.startTransaction("fix_vc6: re-disassemble __chkesp call sites")
        success2 = False
        try:
            for call_addr in call_sites:
                instr = listing.getInstructionAt(call_addr)
                if instr is None:
                    skipped_redisasm += 1
                    continue

                flow = instr.getFlowType()
                if not str(flow).startswith("CALL_TERMINATOR"):
                    continue

                # Check fall-through is now a valid instruction
                fall_addr = call_addr.add(instr.getLength())
                fall_instr = listing.getInstructionAt(fall_addr)
                if fall_instr is None:
                    skipped_redisasm += 1
                    continue

                # Clear + re-disassemble
                listing.clearCodeUnits(call_addr, call_addr, False)
                cmd = DisassembleCommand(call_addr, None, True)
                cmd.applyTo(program, monitor)

                re_instr = listing.getInstructionAt(call_addr)
                if re_instr is not None and not str(re_instr.getFlowType()).startswith("CALL_TERMINATOR"):
                    redisassembled += 1
                else:
                    skipped_redisasm += 1

            success2 = True
        finally:
            program.endTransaction(tx2, success2)

        if success2:
            project.save(program)

        return {
            "extended": extended,
            "redisassembled": redisassembled,
            "skipped_extend": skipped_extend,
            "skipped_redisasm": skipped_redisasm,
            "total_call_sites": len(call_sites),
        }

    @mcp.tool()
    def extend_function_body(function_address: str) -> str:
        """
        Extend a single function's body past a CALL __chkesp terminator.
        Useful for the multi-chkesp edge case where the pipeline skips a function.
        Pass the function's entry point as a hex address.
        """
        from ghidra.program.model.address import AddressSet
        from ghidra.app.cmd.disassemble import DisassembleCommand
        from ghidra.util.task import ConsoleTaskMonitor
        from ghidra_mcp.util import resolve_function, is_ret

        program = get_program()
        project = get_project()
        monitor = ConsoleTaskMonitor()
        listing = program.getListing()

        fn = resolve_function(program, function_address)
        body = fn.getBody()

        # Find all CALL_TERMINATOR instructions in this function
        terminator_addrs = []
        for instr in listing.getInstructions(body, True):
            if str(instr.getFlowType()).startswith("CALL_TERMINATOR"):
                terminator_addrs.append(instr.getAddress())

        if not terminator_addrs:
            return f"{fn.getName()} @ {fn.getEntryPoint()}: no CALL_TERMINATOR instructions found"

        tx = program.startTransaction(f"extend body: {fn.getName()}")
        success = False
        extended_count = 0
        try:
            for call_addr in terminator_addrs:
                instr = listing.getInstructionAt(call_addr)
                fall_addr = call_addr.add(instr.getLength())

                fall_instr = listing.getInstructionAt(fall_addr)
                if fall_instr is None:
                    cmd = DisassembleCommand(fall_addr, None, True)
                    cmd.applyTo(program, monitor)
                    fall_instr = listing.getInstructionAt(fall_addr)

                if fall_instr is None:
                    continue

                end_addr = fall_addr
                cur = fall_instr
                for _ in range(256):
                    if is_ret(cur):
                        end_addr = cur.getAddress()
                        break
                    nxt = cur.getNext()
                    if nxt is None:
                        break
                    cur = nxt

                try:
                    new_body = fn.getBody().union(AddressSet(fall_addr, end_addr))
                    fn.setBody(new_body)
                    extended_count += 1
                except Exception as e:
                    pass  # OverlappingFunctionException — skip this site

            success = True
        finally:
            program.endTransaction(tx, success)

        if success:
            project.save(program)
            return (
                f"{fn.getName()} @ {fn.getEntryPoint()}: "
                f"extended {extended_count}/{len(terminator_addrs)} terminator sites"
            )
        return f"[extend_function_body failed for {fn.getName()}]"

    @mcp.tool()
    def redisassemble_instruction(address: str) -> str:
        """
        Clear and re-disassemble the instruction at the given address.
        Forces Ghidra to recompute FlowType from scratch.
        """
        from ghidra.app.cmd.disassemble import DisassembleCommand
        from ghidra.util.task import ConsoleTaskMonitor

        program = get_program()
        project = get_project()
        monitor = ConsoleTaskMonitor()
        listing = program.getListing()
        addr_fact = program.getAddressFactory()

        addr = addr_fact.getAddress(address)

        tx = program.startTransaction(f"re-disassemble {address}")
        success = False
        try:
            listing.clearCodeUnits(addr, addr, False)
            cmd = DisassembleCommand(addr, None, True)
            cmd.applyTo(program, monitor)
            success = True
        finally:
            program.endTransaction(tx, success)

        if success:
            project.save(program)
            instr = listing.getInstructionAt(addr)
            if instr:
                return f"{addr}: {instr.getMnemonicString()} → FlowType={instr.getFlowType()}"
            return f"{addr}: re-disassembled (instruction not readable after)"
        return f"[redisassemble_instruction failed at {address}]"
