"""A pool with 8 workers gets 12 tasks in chunks of 4, so only 3 workers ever do anything.

Finding: "Pool too big for the work". Five of the eight workers idle through the whole pool phase.
Unlike a straggler tail, the missing parallelism is there from the start: too few tasks, or a
`chunksize` that packs the work into fewer chunks than there are workers.
Rule: over a pool phase, fewer than 60% of the live workers are busy on average.
"""

import multiprocessing
import os
import time

from _truth import Truth, burn_python, now_ms


def score(seconds: float) -> dict:
    start, cpu_start = now_ms(), time.process_time()
    burn_python(seconds)
    return {
        "pid": os.getpid(),
        "start": start,
        "end": now_ms(),
        "cpu_seconds": time.process_time() - cpu_start,
    }


truth = Truth(__doc__)
with multiprocessing.get_context("fork").Pool(8) as pool:
    time.sleep(1.5)
    with truth.phase(
        "8 workers, 3 chunks",
        checks=[{"type": "stack", "function": "Pool.map"}],
        finding="undersized_pool",
    ) as phase:
        results = pool.map(score, [1.25] * 12, chunksize=4)
        phase["worker_pids"] = [p.pid for p in pool._pool]
        phase["busy_pids"] = sorted({r["pid"] for r in results})

truth.save()
