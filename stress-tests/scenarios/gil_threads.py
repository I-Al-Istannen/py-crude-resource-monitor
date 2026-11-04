"""Four threads run concurrently, first holding the GIL, then releasing it.

Shows: with pure Python code, four "parallel" threads only get one core between them, which the
per-thread CPU numbers make visible. Once the work releases the GIL (hashlib on large buffers),
the same four threads use four cores.
"""

import hashlib
import time

from _truth import MiB, Truth, burn_python, run_in_threads

DATA = b"x" * (32 * MiB)


def hash_loop(seconds: float):
    # hashlib releases the GIL while hashing large buffers
    deadline = time.perf_counter() + seconds
    while time.perf_counter() < deadline:
        hashlib.sha256(DATA).digest()


truth = Truth(__doc__)

with truth.phase(
    "4 threads, pure Python (GIL-bound)",
    checks=[
        {"type": "cpu"},
        {"type": "thread_cpu"},
        {"type": "firefox_thread_cpu"},
        {"type": "stack", "function": "burn_python"},
    ],
) as phase:
    phase["threads"] = run_in_threads(4, burn_python, 4)

with truth.phase("pause", checks=[{"type": "cpu"}]):
    time.sleep(2)

with truth.phase(
    "4 threads, hashlib (GIL released)",
    checks=[
        {"type": "cpu"},
        {"type": "thread_cpu"},
        {"type": "firefox_thread_cpu"},
        {"type": "stack", "function": "hash_loop"},
    ],
) as phase:
    phase["threads"] = run_in_threads(4, hash_loop, 4)

truth.check({"type": "cpu_integral"})
truth.save()
