"""`Pool.map` collects every result in the parent before returning any of them.

Finding: "Parent piles up Pool.map results". 40 tasks return 20 MiB each. The parent's main thread
waits in `Pool.map` all along, but its memory grows by ~800 MiB while the pool's result handler
thread receives the results. `imap_unordered` with processing as results arrive, or writing the
results from the workers, keeps the parent flat.
Rule: the parent's memory grows during a pool phase while its main thread waits in `Pool.map` (or
`ApplyResult.wait`) and the growth samples show `_handle_results` active.
"""

import multiprocessing
import os
import time

from _truth import MiB, Truth, burn_python, rss_bytes


def make_result(index: int) -> bytes:
    burn_python(0.4)
    # Random, so the parent really has to hold every byte
    return os.urandom(20 * MiB)


truth = Truth(__doc__)

with multiprocessing.get_context("fork").Pool(4) as pool:
    # Let the profiler attach to the workers before they start working
    time.sleep(1.5)
    with truth.phase(
        "parent waits in Pool.map while 40 x 20 MiB results arrive",
        checks=[{"type": "stack", "function": "Pool.map"}],
        finding="pool_results_pileup",
    ) as phase:
        phase["rss_before"] = rss_bytes()
        results = pool.map(make_result, range(40), chunksize=1)

with truth.phase("parent holds all results", checks=[{"type": "memory"}]):
    time.sleep(2)

del results
truth.save()
