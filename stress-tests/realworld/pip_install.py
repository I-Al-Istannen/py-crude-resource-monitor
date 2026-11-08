"""pip installs four packages into a fresh virtual environment, from wheels on the disk.

Shows: a run that is mostly waiting for and spawning other programs, with short-lived children and
little CPU use.
"""

import tempfile
import sys

from _project import run_project

env = tempfile.mkdtemp()
script = f"""
import subprocess, sys
subprocess.run([sys.executable, "-m", "venv", "{env}"], check=True)
subprocess.run(
    ["{env}/bin/pip", "install", "-q", "--no-index", "--find-links", "/work/wheels",
     "django", "requests", "sqlalchemy", "pydantic"],
    check=True,
)
"""
run_project(
    __doc__,
    "venv and pip install",
    [sys.executable, "-c", script],
    min_processes=2,
)
