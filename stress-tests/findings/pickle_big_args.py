"""Every task sends a large list of dicts to a worker, which does almost nothing with it.

Finding: "Pickling big arguments to workers". The parent's task handler thread spends its time
pickling the arguments (`ForkingPickler.dumps`) and the workers spend theirs unpickling them
(`SimpleQueue.get`), not in `summarize`. Sharing the data through fork (a global set before the pool
starts), shared memory, or sending a path instead avoids it.
Rule: more than 10% of the CPU of a pool's processes is spent in multiprocessing's pickling frames.
"""

import multiprocessing
import time

from _truth import Truth


def summarize(rows: list) -> int:
    return len(rows)


rows = [{"id": i, "value": i * 0.5, "tag": "abc"} for i in range(1_000_000)]
truth = Truth(__doc__)

with multiprocessing.get_context("fork").Pool(4) as pool:
    time.sleep(1.5)
    with truth.phase(
        "40 tasks, each sending 1M dicts",
        checks=[{"type": "cpu"}],
        finding="pickling_big_arguments",
    ):
        pool.map(summarize, [rows] * 40, chunksize=1)

truth.save()
