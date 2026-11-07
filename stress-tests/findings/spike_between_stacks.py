"""A 300 MiB spike of ~50 ms inside `build_lookup`, between two slower functions.

Finding: "Peak between stack samples". The fast memory sampler sees the peak, but the stack samples
on either side of it show `parse_rows` and `write_rows`, which did not allocate it. The viewer
should show the bracketing stacks and their distance from the peak instead of blaming either one.
Rule: a peak in the memory samples more than 20% above both neighbouring stack samples.
"""

import resource
import time

from _truth import MiB, Truth, burn_python, now_ms, rss_bytes, touched_buffer

truth = Truth(__doc__)


def parse_rows():
    burn_python(0.6)


def build_lookup():
    table = touched_buffer(300 * MiB)
    time.sleep(0.03)
    del table


def write_rows():
    burn_python(0.6)


with truth.phase("baseline", checks=[{"type": "memory"}]):
    time.sleep(2)

with truth.phase(
    "4 x parse_rows, 300 MiB spike in build_lookup, write_rows",
    checks=[{"type": "memory_peak"}],
    finding="peak_between_stack_samples",
) as phase:
    phase["baseline_rss"] = rss_bytes()
    phase["spikes"] = []
    for _ in range(4):
        parse_rows()
        start = now_ms()
        build_lookup()
        phase["spikes"].append({"function": "build_lookup", "start": start, "end": now_ms()})
        write_rows()
    phase["peak_rss"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024

truth.save()
