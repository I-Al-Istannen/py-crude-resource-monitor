"""The unit tests of polars, run by pytest-xdist on four workers, with native stacks.

Shows: a real test suite of a data-science library. The workers are discovered, their CPU time and
peak memory add up to what the kernel counted for the process tree, and the samples show the test
being run. With `--native all` polars' Rust threads, which never run Python, are captured too.
"""

from _project import run_project

run_project(
    __doc__,
    "pytest -n 4 on polars' tests",
    [
        "python3", "-m", "pytest", "-q", "-n", "4", "-p", "no:cacheprovider",
        "tests/unit/operations", "tests/unit/dataframe",
    ],  # fmt: skip
    cwd="/work/polars/py-polars",
    ok_exit_codes=(0, 1),
    min_processes=5,
    # Thousands of tiny tests, so a lot of the time goes to collection and to the scheduling of
    # xdist, which is slow with this many tests. On CI that is most of the run.
    stack=("pytest_runtest_protocol", 0.1),
)
