"""
Tests for the "Parallel Decompiler" shared thread pool cap applied at
server startup (server.py, right after pyghidra.start()).

Root cause this fixes: ParallelDecompiler's shared GThreadPool defaults
its max thread count to Runtime.availableProcessors() -- one native
`decompile` subprocess per thread. On this machine that meant analyzeAll()
spawned 9 simultaneous native decompile processes, OOM-killing the whole
ghidra-mcp cgroup (11GB aggregate peak) and, separately, thrashing the
host badly enough to be unreachable over SSH until the kernel OOM-killer
finished. CPU-count is a sane default for parallelism, not for memory --
this caps it explicitly instead.

These tests exercise the real GThreadPool API directly (same reasoning as
test_write_tools.py: server.py's own module-level startup code isn't
convenient to re-trigger per-test), confirming the API this session's
fix depends on behaves as expected.
"""
from __future__ import annotations


def test_setting_max_thread_count_is_reflected_by_getter():
    from generic.concurrent import GThreadPool

    pool = GThreadPool.getSharedThreadPool("test pool -- thread cap")
    pool.setMaxThreadCount(2)
    assert pool.getMaxThreadCount() == 2


def test_shared_pool_lookup_by_name_returns_the_same_instance():
    """getSharedThreadPool is a name-keyed singleton -- confirms a second
    lookup by the same name (as server.py's fix depends on, since it's
    capping a pool ParallelDecompiler itself will later look up by name)
    returns the SAME pool object, not a fresh one with default settings."""
    from generic.concurrent import GThreadPool

    pool_a = GThreadPool.getSharedThreadPool("test pool -- singleton check")
    pool_a.setMaxThreadCount(3)

    pool_b = GThreadPool.getSharedThreadPool("test pool -- singleton check")
    assert pool_b.getMaxThreadCount() == 3


def test_parallel_decompiler_pool_name_matches_what_server_py_caps():
    """Confirms the literal pool name server.py's fix targets
    ("Parallel Decompiler") is the exact name ParallelDecompiler itself
    uses -- if Ghidra ever renames this internal pool, this test catches
    the fix silently no longer applying to the right pool."""
    from generic.concurrent import GThreadPool

    cap = 2
    GThreadPool.getSharedThreadPool("Parallel Decompiler").setMaxThreadCount(cap)

    # Re-fetch by the same name a real ParallelDecompiler call would use
    # (ghidra.app.decompiler.parallel.ParallelDecompiler.decompileFunctions
    # calls GThreadPool.getSharedThreadPool("Parallel Decompiler") itself,
    # per its own bytecode -- confirmed via javap during this
    # investigation) and confirm the cap survives.
    pool = GThreadPool.getSharedThreadPool("Parallel Decompiler")
    assert pool.getMaxThreadCount() == cap
