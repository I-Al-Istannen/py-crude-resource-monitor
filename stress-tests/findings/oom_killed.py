"""A worker is SIGKILLed at its memory peak, the way the kernel's OOM killer would do it.

Finding: "Killed by the OOM killer". The worker's memory climbs and its last sample is at the
peak. There is no traceback and no exception, the parent only sees exit code -9. Here the parent
sends the signal: a real OOM kill needs a memory limit on the container, which would also apply to
the profiler. To the profiler, both look the same.
Rule: a process ends by SIGKILL within about a second of its highest memory. Needs the exit status
of every process, which the profile does not record yet.
"""

import multiprocessing
import os
import signal
import time

from _truth import MiB, Truth, now_ms, rss_bytes, touched_buffer

LIMIT = 700 * MiB


def load_everything():
    # Give the profiler time to discover us
    time.sleep(1)
    chunks = []
    while True:
        chunks.append(touched_buffer(50 * MiB))
        time.sleep(0.25)


truth = Truth(__doc__)
child = multiprocessing.get_context("fork").Process(target=load_everything)
start = now_ms()
child.start()
while rss_bytes(child.pid) < LIMIT:
    time.sleep(0.01)
killed_at = now_ms()
os.kill(child.pid, signal.SIGKILL)
child.join()

truth.add_phase(
    {
        "name": "worker grows until it is killed",
        "pid": child.pid,
        "start": start,
        "end": killed_at,
        "killed_at": killed_at,
        "limit": LIMIT,
        "exit_code": child.exitcode,
        "checks": [{"type": "growth_attribution", "function": "load_everything"}],
        "finding": "oom_killed",
    }
)
with truth.phase("parent after the kill", checks=[{"type": "cpu"}]):
    time.sleep(2)
truth.save()
