"""One GIL-free thread per core, under a CPU quota of the container.

Finding: "Capped by a CPU quota". The threads could use every core, but the process flat-tops at
the quota (e.g. 2.5 cores), with every thread getting an equal small share. Without knowing the
quota, it looks like the program doesn't scale.
Rule: total CPU flat at the cgroup's `cpu.max` quota while more threads than that are busy. The
profiler does not record the quota yet.

Run it with a quota: `DOCKER_RUN_ARGS="--cpus 2.5" ./run.sh --findings cpu_quota`. Without one, the
threads get every core and the scenario records that there was no quota.
"""

import os
from pathlib import Path

from _truth import Truth, burn_native, run_in_threads


def cgroup_cpu_quota() -> float | None:
    try:
        quota, period = Path("/sys/fs/cgroup/cpu.max").read_text().split()
    except OSError:
        return None
    return None if quota == "max" else int(quota) / int(period)


truth = Truth(__doc__)
with truth.phase(
    f"{os.cpu_count()} threads hashing",
    checks=[{"type": "cpu"}],
    finding="cpu_quota",
) as phase:
    phase["cpu_quota"] = cgroup_cpu_quota()
    phase["threads"] = run_in_threads(os.cpu_count(), burn_native, 6)

truth.save()
