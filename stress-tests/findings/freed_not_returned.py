"""Most of a million small objects are freed again, but the RSS stays where it was.

Finding: "Freed but not returned to the OS". Afterwards the process idles in the same function as
before the work and keeps only every 50th object, yet its RSS barely drops: the survivors are spread
over almost every pymalloc pool, so the allocator cannot give any of them back to the operating
system. That is fragmentation, not a leak, and "memory stays high" alone cannot tell them apart.
Rule: the process is back at the stack it idled in before the work, with its RSS still far above
what it was then.
"""

import gc
import sys
import time

from _truth import Truth, rss_bytes

truth = Truth(__doc__)


def wait_for_requests(seconds: float):
    time.sleep(seconds)


def handle_request() -> list:
    records = [{"id": i, "name": f"user-{i}", "score": i * 0.5} for i in range(1_000_000)]
    # Only a few records end up in a long-lived cache, the rest are garbage once we return
    return records[::50]


with truth.phase(
    "idle before", checks=[{"type": "memory"}, {"type": "stack", "function": "wait_for_requests"}]
):
    wait_for_requests(2)

with truth.phase("handle_request: 1M records, keeps every 50th") as phase:
    cache = handle_request()
    gc.collect()

with truth.phase(
    "idle after, 2% of the records alive",
    checks=[{"type": "memory"}, {"type": "stack", "function": "wait_for_requests"}],
    finding="freed_not_returned",
) as phase:
    phase["live_records"] = len(cache)
    phase["live_bytes_estimate"] = sum(
        sys.getsizeof(r) + sys.getsizeof(r["name"]) + sys.getsizeof(r["score"]) for r in cache
    )
    wait_for_requests(4)

truth.save()
