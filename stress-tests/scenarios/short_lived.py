"""Many short-lived Python child processes, each running for a fraction of a second.

Shows a limitation: processes are discovered when a sample is taken. Children that live shorter
than one sampling interval are missed if no sample falls into their lifetime, and the CPU time a
child uses after its last sample is lost. Their CPU usage is still part of the global graph.
"""

import resource
import subprocess
import sys

from _truth import Truth

truth = Truth(__doc__)

with truth.phase("40 Python children, ~0.2 s each", checks=[{"type": "child_coverage"}]) as phase:
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    pids = []
    for _ in range(40):
        child = subprocess.Popen([sys.executable, "_burn.py", "0.2"])
        child.wait()
        pids.append(child.pid)
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    phase["child_pids"] = pids
    phase["children_cpu_seconds"] = (after.ru_utime + after.ru_stime) - (
        before.ru_utime + before.ru_stime
    )

truth.save()
