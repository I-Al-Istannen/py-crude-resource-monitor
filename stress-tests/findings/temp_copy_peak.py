"""`copy.deepcopy` of a large structure briefly doubles the memory, three times.

Finding: "Peak from a temporary copy". Memory jumps by about the size of the data while
`snapshot_state` runs `deepcopy` and falls back once the copy is discarded. The peak, not the steady
state, decides whether this fits into a container.
Rule: memory grows by more than 50% of the RSS while a known copying function is sampled
(`deepcopy`, `to_pandas`, `concat`, `sorted`, `np.array`, ...) and falls back within seconds.
"""

import copy
import resource
import time

from _truth import Truth, rss_bytes

truth = Truth(__doc__)


def load_state() -> dict:
    return {i: [i, str(i), (i, i + 1)] for i in range(500_000)}


def snapshot_state(state: dict) -> dict:
    return copy.deepcopy(state)


def count_changes(before: dict, after: dict) -> int:
    return sum(before[k] != after[k] for k in before)


with truth.phase("load_state"):
    state = load_state()

with truth.phase("holding the state", checks=[{"type": "memory"}]):
    time.sleep(2)

with truth.phase(
    "3 x snapshot_state + count_changes",
    checks=[{"type": "growth_attribution", "function": "deepcopy"}, {"type": "memory_peak"}],
    finding="temporary_copy_peak",
) as phase:
    phase["baseline_rss"] = rss_bytes()
    for _ in range(3):
        snapshot = snapshot_state(state)
        count_changes(state, snapshot)
        del snapshot
        time.sleep(1)
    phase["peak_rss"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024

truth.save()
