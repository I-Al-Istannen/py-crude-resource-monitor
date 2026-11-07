"""Four worker processes each start one GIL-free thread per core.

Finding: "Too many threads for the cores". The machine has N cores, but the workers run 4 x N busy
threads. Each thread gets about a quarter of a core and the total stays at N cores: the extra
threads bought nothing but context switches. Typical cause: numpy/BLAS, polars or torch starting a
thread pool per process. Fix: `OMP_NUM_THREADS`/`POLARS_MAX_THREADS` = cores / workers.
Rule: busy threads (> 0.05 cores) summed over the process tree exceed 1.5 x the cores, while each
of them gets less than 0.5 cores.
"""

import multiprocessing
import os
import time

from _truth import Truth, burn_native, now_ms, run_in_threads

CORES = os.cpu_count()


def compress_partition(seconds: float) -> dict:
    start, cpu_start = now_ms(), time.process_time()
    threads = run_in_threads(CORES, burn_native, seconds)
    return {
        "pid": os.getpid(),
        "start": start,
        "end": now_ms(),
        "cpu_seconds": time.process_time() - cpu_start,
        "threads": threads,
    }


truth = Truth(__doc__)
with multiprocessing.get_context("fork").Pool(4) as pool:
    time.sleep(1.5)
    results = pool.map(compress_partition, [6] * 4, chunksize=1)

for result in results:
    truth.add_phase(
        {
            "name": f"worker {result['pid']} with {CORES} threads",
            **result,
            "checks": [{"type": "cpu"}],
            "finding": "thread_oversubscription",
        }
    )
truth.save()
