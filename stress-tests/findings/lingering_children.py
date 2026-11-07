"""A job's helper processes outlive it: one keeps running, one is orphaned by a double fork.

Finding: "Orphaned or lingering children". `export_report` returns, but the `sleep` it started
keeps running, and a daemonized grandchild that burns CPU is reparented away from the tree (to PID
1, or the closest subreaper), where the profiler may lose track of it.
Rule: a child is still alive long after the stack that started it is gone, or its parent PID
changes to a process outside the tree.
"""

import json
import os
import subprocess
import time

from _truth import Truth, burn_python, measure_thread, now_ms

truth = Truth(__doc__)


def start_daemon(seconds: float) -> int:
    """Classic double fork: the grandchild is reparented once the intermediate child exits."""
    read, write = os.pipe()
    intermediate = os.fork()
    if intermediate == 0:
        os.setsid()
        if os.fork() == 0:
            os.close(read)
            os.write(write, json.dumps({"pid": os.getpid()}).encode() + b"\n")
            record = measure_thread(burn_python, seconds)
            os.write(write, json.dumps(record).encode() + b"\n")
            os._exit(0)
        os._exit(0)
    os.close(write)
    os.waitpid(intermediate, 0)
    return read


def export_report():
    helper = subprocess.Popen(["sleep", "8"])
    daemon = start_daemon(6)
    return helper, daemon


with truth.phase("export_report") as phase:
    helper, daemon_pipe = export_report()

with os.fdopen(daemon_pipe) as pipe:
    daemon_pid = json.loads(pipe.readline())["pid"]
    start = now_ms()
    with truth.phase("job done, children still running", finding="lingering_children") as phase:
        phase["lingering_pid"] = helper.pid
        phase["orphaned_pid"] = daemon_pid
        time.sleep(7)
    daemon_record = json.loads(pipe.readline())
helper.wait()

truth.add_phase(
    {
        "name": "orphaned daemon burning CPU",
        "pid": daemon_pid,
        "start": start,
        "end": daemon_record["end"],
        "child_pids": [daemon_pid],
        "children_cpu_seconds": daemon_record["cpu_seconds"],
        "checks": [{"type": "child_coverage"}],
        "finding": "orphaned_child",
    }
)
truth.save()
