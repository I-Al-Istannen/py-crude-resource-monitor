"""400 threads with 200-frame deep stacks make every stack sample expensive.

Finding: "The sampler can't keep up". Reading all those stacks takes longer than the sampling
interval, so samples arrive late and the real interval stretches. Every timing-based finding in this
region becomes less reliable. At the default 250 ms the profiler keeps up; run it with
`--interval 20` to see it fall behind (on a 16-core machine: about 35 samples in 6 s instead of 300).
Rule: the median time between samples is more than 1.5 x the configured interval.
"""

import threading
import time

from _truth import Truth, burn_python

THREADS, DEPTH = 400, 200
truth = Truth(__doc__)
stop = threading.Event()


def descend(depth: int):
    if depth:
        descend(depth - 1)
    else:
        stop.wait()


threads = [threading.Thread(target=descend, args=(DEPTH,)) for _ in range(THREADS)]
for thread in threads:
    thread.start()

with truth.phase(
    f"{THREADS} threads, {DEPTH} frames deep, main thread busy",
    checks=[{"type": "stack", "function": "burn_python"}],
    finding="sampler_overload",
) as phase:
    phase["threads"], phase["depth"] = THREADS, DEPTH
    burn_python(6)

stop.set()
for thread in threads:
    thread.join()
truth.save()
