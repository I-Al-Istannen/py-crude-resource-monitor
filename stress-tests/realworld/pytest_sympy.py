"""SymPy's polynomial tests, on four pytest-xdist workers.

Shows: pure Python computer algebra, which is CPU-bound and has deep stacks. Every worker keeps
one core busy.
"""

from _project import run_project

run_project(
    __doc__,
    "pytest -n 4 on sympy.polys",
    [
        "python3", "-m", "pytest", "-q", "-n", "4", "-p", "no:cacheprovider", "--pyargs",
        "sympy.polys",
    ],  # fmt: skip
    ok_exit_codes=(0, 1),
    min_processes=5,
    stack=("pytest_runtest_protocol", 0.5),
)
