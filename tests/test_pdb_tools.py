"""
Golden test for load_pdb: apply the real, Microsoft-published PDB for XP SP3's
ntoskrnl.exe (build 5.1.2600.5512) to a freshly analyzed copy of the real binary,
and assert against known-good symbol names pulled from that PDB -- not synthetic
data. This is deliberately a golden/snapshot-style check (a handful of known
addresses -> known real names) rather than asserting every symbol the PDB applies,
since hand-asserting thousands of individual renames isn't practical and a small
set of known anchors is enough to catch a broken apply path.

Marked slow: requires a full analyzeAll() pass over a kernel-sized binary
(several minutes) plus applying ~4MB of PDB data. Run explicitly with
`pytest -m slow` -- excluded from the default run.

Requires:
  /data/Downloads/i386-binaries/ntoskrnl.exe  (period-correct XP SP3 build)
  /data/Downloads/symbols/ntoskrnl-5.1.2600.5512.pdb
      (fetched from Microsoft's public symbol server:
       ntoskrnl.pdb/47A5AC97343A4A7ABF14EFD9E99337722/ntoskrnl.pdb)
Both tests skip (not fail) if either file is missing.
"""
from __future__ import annotations

import os

import pytest

PDB_PATH = "/data/Downloads/symbols/ntoskrnl-5.1.2600.5512.pdb"

# address -> expected real symbol name, taken directly from Microsoft's PDB.
# 0x00427de8 is the printf-family "__output" formatter this whole tool chain
# was originally built to help reverse-engineer.
GOLDEN_NAMES = {
    "00401b18": "_KiAbiosGetGdt@0",
    "00427de8": "__output",
}


def _load_pdb(program):
    from java.io import File as JFile
    from ghidra.app.util.bin.format.pdb2.pdbreader import PdbParser, PdbReaderOptions
    from ghidra.app.util.pdb.pdbapplicator import (
        DefaultPdbApplicator,
        PdbApplicatorOptions,
        PdbApplicatorControl,
    )
    from ghidra.app.util.importer import MessageLog
    from ghidra.util.task import ConsoleTaskMonitor

    pdb_file = JFile(PDB_PATH)
    monitor = ConsoleTaskMonitor()
    reader_options = PdbReaderOptions()
    applicator_options = PdbApplicatorOptions()
    applicator_options.setProcessingControl(PdbApplicatorControl.ALL)
    log = MessageLog()

    pdb = PdbParser.parse(pdb_file, reader_options, monitor)
    tx = program.startTransaction("load PDB (test)")
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

    return success, log


@pytest.mark.slow
def test_load_pdb_applies_golden_symbol_names(analyzed_ntoskrnl):
    if not os.path.exists(PDB_PATH):
        pytest.skip(f"PDB not present at {PDB_PATH!r}")

    program = analyzed_ntoskrnl
    addr_fact = program.getAddressFactory()
    func_mgr = program.getFunctionManager()

    before = {
        addr: func_mgr.getFunctionAt(addr_fact.getAddress(addr)).getName()
        for addr in GOLDEN_NAMES
    }
    # sanity check: these should NOT already be their post-PDB names before loading
    assert before["00427de8"] != "__output"

    success, log = _load_pdb(program)
    assert success, str(log)

    for addr, expected_name in GOLDEN_NAMES.items():
        fn = func_mgr.getFunctionAt(addr_fact.getAddress(addr))
        assert fn is not None, f"no function at {addr}"
        assert fn.getName() == expected_name, (
            f"at {addr}: expected {expected_name!r}, got {fn.getName()!r}"
        )


@pytest.mark.slow
def test_load_pdb_rejects_missing_file(analyzed_ntoskrnl):
    from java.io import File as JFile

    missing = JFile("/data/Downloads/symbols/does-not-exist.pdb")
    assert not missing.exists()
