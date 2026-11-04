"""Forked workers inherit a large buffer from their parent (copy-on-write).

Shows a limitation: every process reports its RSS, which includes the pages it shares with its
parent. The per-process numbers are each correct, but adding them up (as you would when eyeballing
the graph) counts the shared buffer once per process. PSS, which splits shared pages between their
users, is the actual footprint.
"""

import multiprocessing
import os
import time

from _truth import MiB, Truth, now_ms, pss_bytes, rss_bytes, touched_buffer

truth = Truth(__doc__)
SHARED = touched_buffer(600 * MiB)


def worker(ready, stop):
    # Only reads nothing and writes nothing, so all inherited pages stay shared
    time.sleep(0.5)
    ready.put({"pid": os.getpid(), "rss": rss_bytes(), "pss": pss_bytes()})
    stop.wait()


with truth.phase("parent alone with 600 MiB", checks=[{"type": "memory"}]):
    time.sleep(2)

context = multiprocessing.get_context("fork")
ready, stop = context.Queue(), context.Event()
workers = [context.Process(target=worker, args=(ready, stop)) for _ in range(4)]
for process in workers:
    process.start()
members = [ready.get() for _ in workers]

start = now_ms()
time.sleep(3)
end = now_ms()
members.append({"pid": os.getpid(), "rss": rss_bytes(), "pss": pss_bytes()})

for member in members[:-1]:
    truth.add_phase(
        {
            "name": f"forked worker {member['pid']}",
            "pid": member["pid"],
            "start": start,
            "end": end,
            "rss": member["rss"],
            "checks": [{"type": "memory"}],
        }
    )
truth.add_phase(
    {
        "name": "parent + 4 forked workers",
        "pid": os.getpid(),
        "start": start,
        "end": end,
        "members": members,
        "checks": [{"type": "shared_overcount"}],
    }
)

stop.set()
for process in workers:
    process.join()
truth.save()
