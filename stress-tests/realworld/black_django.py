"""black checks the formatting of Django's source tree with a pool of four worker processes.

Shows: a process pool started by a command line tool. The parent only schedules the work, the
workers do the formatting, and the samples show them in black's formatting functions.
"""

from _project import run_project

run_project(
    __doc__,
    "black --check --workers 4 on Django",
    ["black", "--check", "-q", "--workers", "4", "/work/django"],
    # 1: files would be reformatted
    ok_exit_codes=(0, 1),
    min_processes=5,
    stack=("format_file_contents", 0.8),
)
