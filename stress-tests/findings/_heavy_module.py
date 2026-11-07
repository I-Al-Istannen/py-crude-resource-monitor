"""Helper for import_cost: a module that does real work at import time."""

import time

from _truth import burn_python, now_ms

IMPORT_START = now_ms()


def build_lookup_table() -> dict:
    burn_python(2.5)
    return {i: i * i for i in range(1000)}


TABLE = build_lookup_table()
IMPORT_END = now_ms()


def transform(value: int) -> dict:
    import os

    time.sleep(0.5)
    return {"pid": os.getpid(), "start": IMPORT_START, "end": IMPORT_END}
