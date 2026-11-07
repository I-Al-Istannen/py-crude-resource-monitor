"""Calls a tiny shell command 10000 times in a loop.

Finding: "Many short-lived subprocesses". Each child lives for a few milliseconds, far less than a
sampling interval, so most are never seen. The parent's stack (`lookup_hostname → subprocess.run`)
and the total CPU of the children (from the ground truth) show where the time goes.
Rule: more than N children with lifetimes below 1 s, or a parent spending most samples in
`subprocess.run`/`Popen.wait`. Warn that sampling may miss most of the children.
"""

import os
import resource
import subprocess

from _truth import Truth

truth = Truth(__doc__)


def lookup_hostname() -> int:
    child = subprocess.Popen(["sh", "-c", "cat /etc/hostname > /dev/null"])
    child.wait()
    return child.pid


with truth.phase(
    "10000 x subprocess",
    checks=[{"type": "stack", "function": "lookup_hostname"}, {"type": "child_coverage"}],
    finding="subprocess_storm",
) as phase:
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    phase["child_pids"] = [lookup_hostname() for _ in range(10_000)]
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    phase["children_cpu_seconds"] = (after.ru_utime + after.ru_stime) - (
        before.ru_utime + before.ru_stime
    )

truth.save()
