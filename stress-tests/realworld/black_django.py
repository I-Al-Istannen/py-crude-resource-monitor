"""black checks the formatting of Django's source tree with a pool of four worker processes.

Shows: a process pool started by a command line tool. The parent only schedules the work, the
workers do the formatting, and the samples show them in the pool's worker loop. The black wheels
for some platforms are compiled with mypyc, so black's own functions are not Python frames there.
"""

from _project import run_project

run_project(
    __doc__,
    "black --check --workers 4 on Django",
    ["black", "--check", "-q", "--workers", "4", "/work/django"],
    # 1: files would be reformatted
    ok_exit_codes=(0, 1),
    min_processes=5,
    stack=("_process_worker", 0.8),
)
