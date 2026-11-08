"""The tests of pandas' groupby, reshape and frame, on four pytest-xdist workers.

Shows: a long run of a suite with a lot of memory use, where the memory of the workers grows as
the tests allocate frames.
"""

from _project import run_project

run_project(
    __doc__,
    "pytest -n 4 on pandas' tests",
    [
        "python3", "-m", "pytest", "-q", "-n", "4", "-p", "no:cacheprovider",
        "pandas/tests/groupby", "pandas/tests/reshape", "pandas/tests/frame",
    ],  # fmt: skip
    # From there, pytest finds pandas' conftest.py, which adds options the workers need
    cwd="/usr/local/lib/python3.12/site-packages",
    ok_exit_codes=(0, 1),
    min_processes=5,
    stack=("pytest_runtest_protocol", 0.5),
)
