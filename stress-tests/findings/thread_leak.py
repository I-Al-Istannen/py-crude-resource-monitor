"""Every request starts a heartbeat thread that is never stopped.

Finding: "Thread leak". The thread count of the process rises by one per request, to about 80,
while CPU and memory barely move. Every leaked thread idles in `heartbeat → sleep`.
Rule: the number of threads of a process rises (nearly) monotonically by more than 20.
"""

import threading
import time

from _truth import Truth, thread_count

truth = Truth(__doc__)


def heartbeat(request_id: int):
    while True:
        time.sleep(0.5)


def handle_request(request_id: int):
    threading.Thread(target=heartbeat, args=(request_id,), daemon=True).start()
    time.sleep(0.1)


with truth.phase("80 requests", finding="thread_leak") as phase:
    phase["thread_counts"] = []
    for request_id in range(80):
        handle_request(request_id)
        phase["thread_counts"].append(thread_count())

truth.save()
