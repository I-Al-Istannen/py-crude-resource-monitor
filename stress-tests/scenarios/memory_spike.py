"""Short-lived memory spikes that fall between two samples.

Shows: a spike shorter than the sampling interval is missed by the samples, even if it is what gets
the process OOM-killed. The memory sampler measures memory far more often and catches it.
"""

import resource
import time

from _truth import MiB, Truth, rss_bytes, touched_buffer

truth = Truth(__doc__)


def spiky_transform():
    for _ in range(3):
        buffer = touched_buffer(400 * MiB)
        # Allocating takes about 20 ms. Holding the memory a bit longer is still far shorter than
        # the sampling interval, but makes sure the memory sampler measures the peak.
        time.sleep(0.02)
        del buffer
        time.sleep(1.3)


with truth.phase("baseline", checks=[{"type": "memory"}]):
    time.sleep(2)

with truth.phase("3 spikes of 400 MiB", checks=[{"type": "memory_peak"}, {"type": "firefox_memory_peak"}]) as phase:
    phase["baseline_rss"] = rss_bytes()
    spiky_transform()
    # ru_maxrss is the peak RSS of the process lifetime, in KiB on Linux
    phase["peak_rss"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024

truth.save()
