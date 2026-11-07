"""Four workers do their CPU work while holding one shared lock.

Finding: "Workers take turns instead of running in parallel". Four processes are alive and each
one is busy now and then, but together they never use more than one core: their busy stretches
interleave. Typical causes: a `multiprocessing.Lock` or `Manager`, a file lock, SQLite.
Rule: at least 3 sibling processes alive, total CPU about 1 core, and almost never two of them busy
in the same sample.
"""

import multiprocessing
import os
import time

from _truth import Truth, burn_python, now_ms

context = multiprocessing.get_context("fork")
# Created before the pool, so the forked workers inherit it
lock = context.Lock()


def update_shared_index(rounds: int) -> dict:
    start, cpu_start = now_ms(), time.process_time()
    for _ in range(rounds):
        with lock:
            burn_python(0.3)
    return {
        "pid": os.getpid(),
        "start": start,
        "end": now_ms(),
        "cpu_seconds": time.process_time() - cpu_start,
    }


truth = Truth(__doc__)
with context.Pool(4) as pool:
    time.sleep(1.5)
    with truth.phase("4 workers, one lock", checks=[{"type": "stack", "function": "Pool.map"}]):
        results = pool.map(update_shared_index, [8] * 4, chunksize=1)

for result in results:
    truth.add_phase(
        {
            "name": f"worker {result['pid']} takes turns on the lock",
            **result,
            "checks": [{"type": "cpu"}],
            "finding": "serialized_workers",
        }
    )
truth.save()
