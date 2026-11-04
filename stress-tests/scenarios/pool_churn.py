"""A long-running process recreates its worker pool over and over, like a program that starts a new
multiprocessing pool for every batch.

Shows: the profile gets one file per worker process, more than a hundred in total. The Firefox
export packs workers that never ran at the same time into shared tracks, so it shows as many
worker tracks as the pool has workers, without losing any of their CPU time.
"""

import multiprocessing
import resource

from _truth import Truth, burn_python

POOL_SIZE = 4
RUNS = 30

truth = Truth(__doc__)

with truth.phase(
    f"pool of {POOL_SIZE} recreated {RUNS} times",
    checks=[{"type": "firefox_lanes", "max_tracks": POOL_SIZE}, {"type": "firefox_cpu_total"}],
) as phase:
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    for _ in range(RUNS):
        with multiprocessing.get_context("fork").Pool(POOL_SIZE) as pool:
            pool.map(burn_python, [0.5] * POOL_SIZE, chunksize=1)
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    phase["children_cpu_seconds"] = (after.ru_utime + after.ru_stime) - (
        before.ru_utime + before.ru_stime
    )

truth.save()
