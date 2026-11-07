"""Four workers each read the whole 256 MiB input file, but only process their quarter of it.

Finding: "Every worker reads the whole input". The workers all issue reads for the full file.
Most of them are served by the page cache, so the profiler's disk counters (`read_bytes`, only
what came from the storage device) show the file roughly once. Detecting this needs `rchar`, the
bytes requested by read calls, which the profiler does not record yet. The ground truth has both.
Rule: sibling workers each read about the same, large number of bytes (by `rchar`).
"""

import multiprocessing
import os
import tempfile
import time

from _truth import MiB, Truth, burn_python, io_counters, now_ms

PATH = os.path.join(tempfile.gettempdir(), "workers_reread_input.bin")
WORKERS = 4


def process_partition(index: int) -> dict:
    start, before = now_ms(), io_counters()
    with open(PATH, "rb") as f:
        data = f.read()
    part = len(data) // WORKERS
    burn_python(1)  # "processing" data[index * part : (index + 1) * part]
    after = io_counters()
    return {
        "pid": os.getpid(),
        "start": start,
        "end": now_ms(),
        "rchar": after["rchar"] - before["rchar"],
        "read_bytes": after["read_bytes"] - before["read_bytes"],
    }


with open(PATH, "wb") as f:
    f.write(os.urandom(256 * MiB))
    f.flush()
    os.fsync(f.fileno())
    # As if the input had been written long ago: not in the page cache
    os.posix_fadvise(f.fileno(), 0, 0, os.POSIX_FADV_DONTNEED)

truth = Truth(__doc__)
with multiprocessing.get_context("fork").Pool(WORKERS) as pool:
    time.sleep(1.5)
    results = pool.map(process_partition, range(WORKERS), chunksize=1)

for result in results:
    truth.add_phase(
        {
            "name": f"worker {result['pid']} reads the whole input",
            **result,
            "checks": [],
            "finding": "workers_reread_input",
        }
    )
os.remove(PATH)
truth.save()
