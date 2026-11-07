"""Dropping a dict with 4 million entries takes about a second of pure CPU.

Finding: "Slow teardown of large objects". A CPU burst lines up exactly with a large drop in
memory, and the stack shows `reset_cache` with nothing below it: the deallocation runs in C, inside
the line that drops the last reference.
Rule: a CPU burst of more than 0.5 s that coincides with a memory drop of more than 100 MiB.
"""

import time

from _truth import Truth

truth = Truth(__doc__)


class Service:
    def __init__(self):
        self.cache = {}

    def warm_cache(self):
        self.cache = {i: (i, str(i)) for i in range(4_000_000)}

    def reset_cache(self):
        self.cache = {}


service = Service()
with truth.phase("warm_cache"):
    service.warm_cache()

with truth.phase("holding the cache", checks=[{"type": "memory"}]):
    time.sleep(2)

with truth.phase("reset_cache frees it", finding="slow_teardown") as phase:
    service.reset_cache()

with truth.phase("after the reset", checks=[{"type": "memory"}]):
    time.sleep(2)

truth.save()
