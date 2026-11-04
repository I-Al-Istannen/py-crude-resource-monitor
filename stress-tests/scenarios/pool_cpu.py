"""A multiprocessing pool spreads CPU-bound work over four worker processes.

Shows: child processes are discovered automatically, each worker's CPU usage and stack is recorded
separately, and the parent is visibly idle while it waits in `pool.map`.
"""

import multiprocessing
import os
import time

from _truth import Truth, burn_python, measure_thread

truth = Truth(__doc__)


def burn_worker(seconds: float) -> dict:
    record = measure_thread(burn_python, seconds)
    record["pid"] = os.getpid()
    return record


with multiprocessing.get_context("fork").Pool(4) as pool:
    # Let the profiler attach to the workers before they start working
    time.sleep(1.5)
    with truth.phase(
        "parent waiting in pool.map",
        checks=[{"type": "cpu"}, {"type": "stack", "function": "Pool.map"}],
    ):
        results = pool.map(burn_worker, [4] * 4, chunksize=1)

for result in results:
    truth.add_phase(
        {
            "name": f"pool worker {result['pid']} in burn_python",
            "pid": result["pid"],
            "start": result["start"],
            "end": result["end"],
            "cpu_seconds": result["cpu_seconds"],
            "checks": [{"type": "cpu"}, {"type": "stack", "function": "burn_python"}],
        }
    )

truth.check({"type": "cpu_integral"})
truth.save()
