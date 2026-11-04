"""Python code calls into a C library (zlib) that does all the work, profiled with `--native`.

Shows: with native stacks, samples show which C functions run below the Python frame that called
them. Without them, all the time would be attributed to the Python line calling `zlib.compress`.
"""

import os
import zlib

from _truth import Truth, now_ms

truth = Truth(__doc__)

DATA = os.urandom(256 * 1024) * 16


def compress_loop(seconds: float):
    deadline = now_ms() + seconds * 1000
    while now_ms() < deadline:
        zlib.compress(DATA, 9)


with truth.phase(
    "compress_loop calling zlib.compress",
    checks=[
        {"type": "cpu"},
        {"type": "stack", "function": "compress_loop"},
        {"type": "native_stack", "caller": "compress_loop", "function": "deflate", "library": "libz"},
    ],
):
    compress_loop(4)

truth.save()
