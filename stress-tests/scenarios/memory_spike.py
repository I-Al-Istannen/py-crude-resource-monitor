"""Short-lived memory spikes that fall between two samples.

Shows a limitation: the profiler only sees the RSS at sampling time. A spike shorter than the
sampling interval is usually missed entirely, even if it is what gets the process OOM-killed.
"""

import resource
import time

from _truth import MiB, Truth, rss_bytes, touched_buffer

truth = Truth(__doc__)


def spiky_transform():
    for _ in range(3):
        buffer = touched_buffer(400 * MiB)
        del buffer
        time.sleep(1.3)


with truth.phase("baseline", checks=[{"type": "memory"}]):
    time.sleep(2)

with truth.phase("3 spikes of 400 MiB", checks=[{"type": "peak_missed"}]) as phase:
    phase["baseline_rss"] = rss_bytes()
    spiky_transform()
    # ru_maxrss is the peak RSS of the process lifetime, in KiB on Linux
    phase["peak_rss"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024

truth.save()
