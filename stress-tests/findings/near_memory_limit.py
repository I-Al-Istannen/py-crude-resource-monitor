"""Memory grows to 80% of the container's memory limit and stays there.

Finding: "Close to the container limit". Without the limit the curve looks harmless, with it this
run is one larger input away from being OOM-killed.
Rule: peak memory of the process tree above 80% of the cgroup's `memory.max`. The profiler does not
record the limit yet.

Run it with a limit: `DOCKER_RUN_ARGS="--memory 1g" ./run.sh --findings near_memory_limit`. The
profiler shares the container, so the target leaves room for it. Without a limit, the scenario
allocates 500 MiB and records that there was none: the viewer should then say it can't tell.
"""

import time
from pathlib import Path

from _truth import MiB, Truth, rss_bytes, touched_buffer


def cgroup_memory_limit() -> int | None:
    try:
        value = Path("/sys/fs/cgroup/memory.max").read_text().strip()
    except OSError:
        return None
    return None if value == "max" else int(value)


def load_inputs(target: int) -> list:
    chunks = []
    while rss_bytes() + 25 * MiB < target:
        chunks.append(touched_buffer(25 * MiB))
        time.sleep(0.1)
    return chunks


truth = Truth(__doc__)
limit = cgroup_memory_limit()

with truth.phase("load_inputs up to 80% of the limit") as phase:
    phase["memory_limit"] = limit
    data = load_inputs(int(0.8 * limit) if limit else 500 * MiB)

with truth.phase(
    "holding the inputs", checks=[{"type": "memory"}], finding="near_memory_limit"
) as phase:
    phase["memory_limit"] = limit
    time.sleep(3)

truth.save()
