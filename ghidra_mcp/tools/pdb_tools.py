"""
PDB loading: apply a Microsoft PDB's symbols, data types, and function signatures
to the active program.

Drives ghidra.app.util.pdb.pdbapplicator.DefaultPdbApplicator directly via its
applyNoAnalysisState() method, rather than going through the GUI's PdbUniversalAnalyzer
/ LoadPdbTask path. That path splits work across multiple background commands
scheduled on AutoAnalysisManager (types+symbols now, function internals later, a
final reporting pass later still) that share state through a session-scoped cache
(TransientProgramProperties, SCOPE.ANALYSIS_SESSION) -- which only exists while a
real GUI-driven analysis session is active. Called standalone (no such session),
it throws "No active analysis session". applyNoAnalysisState() is the applicator's
own documented alternative for exactly this case ("should only be used when not
processing in an analysis state") -- it does pre-work, data types, main symbols,
disassembly, and function internals in one direct call on one applicator instance,
with no cross-phase shared state required. All classes involved are public API.

Only handles PDB 7.0 (RSDS signature). The older PDB 2.0 (NB10 signature,
VC6-era) format is out of scope for this loader.
"""
from __future__ import annotations


def register(mcp, get_program, get_project):

    @mcp.tool()
    def load_pdb(pdb_path: str, control: str = "ALL") -> str:
        """
        Load a Microsoft PDB file (PDB 7.0 / RSDS format only) and apply its symbols,
        data types, and function signatures to the current program.

        pdb_path: absolute path to the .pdb file on disk.
        control: 'ALL' (default — symbols, data types, and function signatures),
                 'DATA_TYPES_ONLY', or 'PUBLIC_SYMBOLS_ONLY'.

        Does NOT handle the older PDB 2.0 (NB10 signature) format used by VC6-era
        binaries -- check the program's CodeView debug directory signature first
        if unsure.
        """
        from java.io import File as JFile
        from ghidra.app.util.bin.format.pdb2.pdbreader import PdbParser, PdbReaderOptions
        from ghidra.app.util.pdb.pdbapplicator import (
            DefaultPdbApplicator,
            PdbApplicatorOptions,
            PdbApplicatorControl,
        )
        from ghidra.app.util.importer import MessageLog
        from ghidra.util.task import ConsoleTaskMonitor

        program = get_program()
        project = get_project()
        if program is None:
            raise ValueError("No active program. Call switch_active_program first.")

        pdb_file = JFile(pdb_path)
        if not pdb_file.exists():
            raise ValueError(f"PDB file not found: {pdb_path!r}")

        try:
            control_enum = PdbApplicatorControl.valueOf(control)
        except Exception:
            valid = ", ".join(str(c) for c in PdbApplicatorControl.values())
            raise ValueError(f"Invalid control {control!r}. Valid values: {valid}")

        monitor = ConsoleTaskMonitor()
        reader_options = PdbReaderOptions()
        applicator_options = PdbApplicatorOptions()
        applicator_options.setProcessingControl(control_enum)
        log = MessageLog()

        pdb = PdbParser.parse(pdb_file, reader_options, monitor)
        tx = program.startTransaction(f"load PDB {pdb_file.getName()}")
        success = False
        try:
            pdb.deserialize()
            applicator = DefaultPdbApplicator(
                pdb, program, program.getDataTypeManager(), program.getImageBase(),
                applicator_options, monitor, log,
            )
            applicator.applyNoAnalysisState()
            success = True
        finally:
            program.endTransaction(tx, success)
            pdb.close()

        project.save(program)
        summary = f"Loaded PDB {pdb_file.getName()} ({control}) onto {program.getName()}."
        if log.hasMessages():
            summary += f"\n{log}"
        return summary
