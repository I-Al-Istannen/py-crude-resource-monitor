"""Waiting for a result by polling a queue in a tight loop, then the same wait done properly.

Finding: "Busy polling". The process uses a full core while its stack never leaves
`wait_for_result → get_nowait`, and nothing else (memory, disk) moves. The blocking `get()` in the
second phase waits just as long for free.
Rule: more than 0.8 cores while more than 90% of the samples are in the same polling frames, with
memory and disk I/O flat.
"""

import queue
import threading
import time

from _truth import Truth

truth = Truth(__doc__)


def produce_later(results: queue.Queue, delay: float):
    time.sleep(delay)
    results.put("done")


def wait_for_result(results: queue.Queue):
    while True:
        try:
            return results.get_nowait()
        except queue.Empty:
            pass


def wait_for_result_blocking(results: queue.Queue):
    return results.get()


with truth.phase(
    "polling with get_nowait",
    checks=[{"type": "cpu"}, {"type": "stack", "function": "wait_for_result"}],
    finding="busy_polling",
):
    results = queue.Queue()
    threading.Thread(target=produce_later, args=(results, 4)).start()
    wait_for_result(results)

with truth.phase(
    "blocking get", checks=[{"type": "cpu"}, {"type": "stack", "function": "wait_for_result_blocking"}]
):
    results = queue.Queue()
    threading.Thread(target=produce_later, args=(results, 4)).start()
    wait_for_result_blocking(results)

truth.save()
