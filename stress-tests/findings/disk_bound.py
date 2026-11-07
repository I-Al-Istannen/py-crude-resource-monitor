"""Writes a file with an fsync per MiB for 4 s, then keeps reading it back from the disk for 3 s.

Finding: "Disk-bound phase". CPU stays low while the disk write and then read throughput is high:
the phase is waiting on storage, not computing.
Rule: less than 0.3 cores while the disk throughput of the process is above a few tens of MiB/s.
"""

import os
import tempfile
import time

from _truth import MiB, Truth, io_counters

truth = Truth(__doc__)
CHUNK = b"\xab" * MiB


def write_export(path: str, seconds: float):
    deadline = time.perf_counter() + seconds
    with open(path, "wb") as f:
        while time.perf_counter() < deadline:
            f.write(CHUNK)
            f.flush()
            os.fsync(f.fileno())


def verify_export(path: str, seconds: float):
    deadline = time.perf_counter() + seconds
    with open(path, "rb") as f:
        while time.perf_counter() < deadline:
            # Drop the file from the page cache, so every pass has to read it from the disk
            os.posix_fadvise(f.fileno(), 0, 0, os.POSIX_FADV_DONTNEED)
            f.seek(0)
            while f.read(MiB):
                pass


path = os.path.join(tempfile.gettempdir(), "disk_bound.bin")
with truth.phase(
    "write_export: fsync per MiB",
    checks=[{"type": "stack", "function": "write_export"}],
    finding="disk_bound_write",
) as phase:
    before = io_counters()
    write_export(path, 4)
    phase["write_bytes"] = io_counters()["write_bytes"] - before["write_bytes"]

with truth.phase(
    "verify_export: read it back, uncached",
    checks=[{"type": "stack", "function": "verify_export"}],
    finding="disk_bound_read",
) as phase:
    before = io_counters()
    verify_export(path, 3)
    phase["read_bytes"] = io_counters()["read_bytes"] - before["read_bytes"]

os.remove(path)
truth.save()
