"""The tests of scikit-learn's ensembles, trees and linear models, on four pytest-xdist workers.

Shows: a machine-learning test suite, where the workers start more processes (joblib's loky
workers) that come and go while the tests run.
"""

from _project import run_project

run_project(
    __doc__,
    "pytest -n 4 on scikit-learn's tests",
    [
        "python3", "-m", "pytest", "-q", "-n", "4", "-p", "no:cacheprovider", "--pyargs",
        "sklearn.ensemble", "sklearn.tree", "sklearn.linear_model",
    ],  # fmt: skip
    ok_exit_codes=(0, 1),
    min_processes=5,
    stack=("pytest_runtest_protocol", 0.5),
)
