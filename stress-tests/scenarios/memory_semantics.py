"""What "memory" means: resident pages, no matter who allocated them.

Shows: reserving address space does not count, touching it does. Memory allocated by native code
(here: libc malloc via ctypes, like C extensions do) is fully visible, even though Python-level
tools like tracemalloc do not see any of it.
"""

import ctypes
import mmap
import time
import tracemalloc

from _truth import MiB, PAGE_SIZE, Truth

truth = Truth(__doc__)
tracemalloc.start()

with truth.phase("baseline", checks=[{"type": "memory"}]):
    time.sleep(2)

with truth.phase("1 GiB mmap reserved, untouched", checks=[{"type": "memory"}]) as phase:
    region = mmap.mmap(-1, 1024 * MiB)
    time.sleep(2)
    phase["note"] = "1024 MiB of address space reserved"

with truth.phase("1 GiB mmap touched", checks=[{"type": "memory"}]):
    for offset in range(0, len(region), PAGE_SIZE):
        region[offset] = 1
    time.sleep(2)

with truth.phase("mmap released", checks=[{"type": "memory"}]):
    region.close()
    time.sleep(2)

with truth.phase("400 MiB via native malloc", checks=[{"type": "memory"}]) as phase:
    libc = ctypes.CDLL(None)
    libc.malloc.restype = ctypes.c_void_p
    size = 400 * MiB
    pointer = libc.malloc(size)
    ctypes.memset(pointer, 1, size)
    time.sleep(2)
    traced, _ = tracemalloc.get_traced_memory()
    phase["note"] = f"tracemalloc sees {traced / MiB:.1f} MiB of Python allocations"

truth.save()
