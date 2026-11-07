"""Six well-known slow patterns, one per phase.

Finding: "Known slow code patterns". Each phase spends most of its samples in a frame from a table
of known-slow signatures: `re` compiling more distinct patterns than its cache holds, `deepcopy`
per request, an expensive `__repr__` formatted for a disabled log level, `inspect.stack()`, `json`
decoding of a large payload per call, and a Python lambda in polars' `map_elements` (skipped if
polars is not installed).
Rule: more than X% of the CPU in a selection is spent under a frame from the table, shown with a
short explanation of the pattern and the usual fix.
"""

import copy
import inspect
import json
import logging
import re
import time

from _truth import Truth

truth = Truth(__doc__)
log = logging.getLogger("app")
log.setLevel(logging.INFO)


def for_seconds(seconds: float, fn, *args):
    deadline = time.perf_counter() + seconds
    while time.perf_counter() < deadline:
        fn(*args)


def validate_fields(names: list[str]):
    # 2000 distinct patterns, more than re's cache of 512, so every call compiles again
    for i, name in enumerate(names):
        re.match(f"^field_{i}_[a-z]+$", name)


DEFAULTS = {f"option_{i}": {"value": i, "tags": [str(i)] * 5} for i in range(2000)}


def handle_request():
    return copy.deepcopy(DEFAULTS)


class State:
    def __init__(self):
        self.items = list(range(20_000))

    def __repr__(self):
        return "State(" + ", ".join(str(i) for i in self.items) + ")"


def step(state: State):
    # Evaluated even though DEBUG is disabled
    log.debug(f"state after step: {state!r}")


def caller_name():
    return inspect.stack()[1].function


PAYLOAD = json.dumps([{"id": i, "name": f"item-{i}", "tags": ["a", "b"]} for i in range(100_000)])


def parse_payload():
    return json.loads(PAYLOAD)


phases = [
    ("re: 2000 distinct patterns", "_compile", validate_fields, [f"field_{i}_x" for i in range(2000)]),
    ("deepcopy per request", "deepcopy", handle_request),
    ("expensive __repr__ for a disabled log level", "State.__repr__", step, State()),
    ("inspect.stack() for the caller's name", "stack", caller_name),
    ("json.loads of a 6 MiB payload", "JSONDecoder.decode", parse_payload),
]
for name, function, fn, *args in phases:
    with truth.phase(
        name, checks=[{"type": "stack", "function": function, "min_fraction": 0.6}],
        finding=f"slow_pattern:{function}",
    ):
        for_seconds(3, fn, *args)

try:
    import polars as pl
except ImportError:
    pl = None
if pl is not None:
    frame = pl.DataFrame({"x": range(1_000_000)})
    with truth.phase(
        "polars map_elements with a Python lambda",
        checks=[{"type": "stack", "function": "Series.map_elements", "min_fraction": 0.6}],
        finding="slow_pattern:map_elements",
    ):
        for_seconds(
            3,
            lambda: frame.select(pl.col("x").map_elements(lambda x: x * 2, return_dtype=pl.Int64)),
        )

truth.save()
