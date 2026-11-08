"""A polars group-by query runs on polars' own thread pool, profiled with `--native all`.

Shows: the work happens on Rust threads that never run Python code, so py-spy only captures them
with `--native all`. The process uses several cores while the Python main thread just waits for
`collect` to return. Polars' Rust function names are demangled.
"""

import polars as pl

from _truth import Truth, now_ms

truth = Truth(__doc__)

ROWS = 10_000_000
data = pl.DataFrame({"value": pl.int_range(ROWS, eager=True)}).with_columns(
    key=pl.col("value") % 1000
)


def run_query(seconds: float):
    deadline = now_ms() + seconds * 1000
    while now_ms() < deadline:
        (
            data.lazy()
            .with_columns(scaled=(pl.col("value") * 3).sin())
            .group_by("key")
            .agg(pl.col("scaled").sum(), pl.col("value").std())
            .collect()
        )


with truth.phase(
    "group_by on polars' thread pool",
    checks=[
        {"type": "cpu"},
        {"type": "stack", "function": "run_query"},
        {
            "type": "native_thread",
            "library": "_polars_runtime",
            "thread": "async-executor",
            # Rust paths, so the names are demangled
            "function": "::",
        },
    ],
):
    run_query(5)

truth.check({"type": "cpu_integral"})
truth.save()
