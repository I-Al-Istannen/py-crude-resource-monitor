"""Ground-truth recording shared by all scenarios.

Every scenario splits its run into phases. For each phase it records what *really* happened,
measured from inside the process (CPU time from the kernel, RSS/PSS from /proc), and which
checks the suite should run against the profiler's samples for that time window.
"""

import hashlib
import json
import os
import threading
import time
from contextlib import contextmanager

PAGE_SIZE = os.sysconf("SC_PAGE_SIZE")
MiB = 1024 * 1024


def now_ms() -> float:
    # The profiler timestamps its samples with the wall clock, so we do the same
    return time.time() * 1000


def rss_bytes(pid="self") -> int:
    with open(f"/proc/{pid}/statm") as f:
        return int(f.read().split()[1]) * PAGE_SIZE


def pss_bytes(pid="self") -> int:
    """Proportional set size: shared pages are split evenly between the processes sharing them."""
    with open(f"/proc/{pid}/smaps_rollup") as f:
        for line in f:
            if line.startswith("Pss:"):
                return int(line.split()[1]) * 1024
    raise RuntimeError("No Pss in smaps_rollup")


def touched_buffer(size: int) -> bytearray:
    """Allocates `size` bytes and writes to every page, so they are actually resident."""
    buffer = bytearray(size)
    buffer[::PAGE_SIZE] = b"\x01" * len(range(0, size, PAGE_SIZE))
    return buffer


def burn_python(seconds: float) -> int:
    """Pure Python busy loop. Holds the GIL the whole time."""
    deadline = time.perf_counter() + seconds
    counter = 0
    while time.perf_counter() < deadline:
        counter += 1
    return counter


_NATIVE_DATA = b"x" * (8 * MiB)


def burn_native(seconds: float):
    """Busy loop in C code that releases the GIL (hashing a large buffer)."""
    deadline = time.perf_counter() + seconds
    while time.perf_counter() < deadline:
        hashlib.sha256(_NATIVE_DATA).digest()


def thread_count(pid="self") -> int:
    with open(f"/proc/{pid}/status") as f:
        for line in f:
            if line.startswith("Threads:"):
                return int(line.split()[1])
    raise RuntimeError("No Threads in status")


def io_counters(pid="self") -> dict[str, int]:
    """Bytes read and written: `rchar`/`wchar` count every read/write call, `read_bytes`/
    `write_bytes` only what actually went to or came from the storage device."""
    with open(f"/proc/{pid}/io") as f:
        return {key: int(value) for key, value in (line.split(": ") for line in f)}


def measure_thread(fn, *args) -> dict:
    """Runs `fn` on the current thread and returns the thread's own CPU time while doing so."""
    start, cpu_start = now_ms(), time.thread_time()
    fn(*args)
    return {
        "name": threading.current_thread().name,
        "native_id": threading.get_native_id(),
        "start": start,
        "end": now_ms(),
        "cpu_seconds": time.thread_time() - cpu_start,
    }


def run_in_threads(count: int, fn, *args) -> list[dict]:
    """Runs `fn` on `count` threads. Returns the CPU time of the main thread, which only waits for
    them, followed by the CPU time of every worker."""
    results = [None] * count

    def target(index):
        results[index] = measure_thread(fn, *args)

    threads = [
        threading.Thread(target=target, args=(i,), name=f"worker-{i}") for i in range(count)
    ]

    def start_and_join():
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    return [measure_thread(start_and_join)] + results


class Truth:
    def __init__(self, description: str):
        self.path = os.environ["STRESS_TRUTH"]
        self.data = {"pid": os.getpid(), "description": description, "phases": [], "checks": []}
        # Give the profiler time to attach and take its first samples, which never carry a CPU
        # value (CPU usage is a difference between two samples)
        time.sleep(1)

    @contextmanager
    def phase(self, name: str, checks=(), pid=None, finding=None):
        """`finding` names what a viewer should detect in this phase (only for findings/)."""
        record = {"name": name, "pid": pid or os.getpid(), "checks": list(checks)}
        if finding:
            record["finding"] = finding
        cpu_start = time.process_time()
        record["start"] = now_ms()
        yield record
        record["end"] = now_ms()
        record.setdefault("cpu_seconds", time.process_time() - cpu_start)
        record.setdefault("rss", rss_bytes())
        self.add_phase(record)

    def add_phase(self, record: dict):
        self.data["phases"].append(record)

    def check(self, check: dict):
        """A check that is not tied to a single phase, e.g. CPU time over the whole run."""
        self.data["checks"].append(check)

    def save(self):
        self.data["total_cpu_seconds"] = time.process_time()
        with open(self.path, "w") as f:
            json.dump(self.data, f, indent=2)
