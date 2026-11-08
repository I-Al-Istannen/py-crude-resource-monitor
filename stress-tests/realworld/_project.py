"""Runs a real project under the profiler and records the ground truth of its whole process tree.

The scenario is the profiled process: it starts the project as a subprocess and waits for it. The
kernel adds up the CPU time of every process the project started (`RUSAGE_CHILDREN`), and keeps the
peak RSS of the biggest one. Both are compared with what the profiler recorded for the tree.
"""

import os
import resource
import subprocess

from _truth import Truth

CHECKS = ["exit_code", "tree_cpu", "tree_peak_memory"]


def run_project(
    description: str,
    name: str,
    command: list[str],
    *,
    cwd: str | None = None,
    ok_exit_codes: tuple[int, ...] = (0,),
    min_processes: int,
    stack: tuple[str, float] | None = None,
):
    """Runs `command` and records what it really did.

    `ok_exit_codes` are the exit codes that mean the project ran. Failing tests of a project are not
    a problem of the profiler, but a crash of the project is, as it changes what we measure.
    `min_processes` is the number of Python processes the profile has to contain.
    `stack` is a function and the fraction of the samples of busy worker processes that has to be
    in it.
    """
    truth = Truth(description)
    checks = [{"type": check} for check in CHECKS]
    checks.append({"type": "processes", "min": min_processes})
    if stack:
        function, fraction = stack
        checks.append({"type": "tree_stack", "function": function, "min_fraction": fraction})
    with truth.phase(name, checks=checks) as phase:
        before = resource.getrusage(resource.RUSAGE_CHILDREN)
        result = subprocess.run(command, cwd=cwd, env={**os.environ, "PYTHONUNBUFFERED": "1"})
        after = resource.getrusage(resource.RUSAGE_CHILDREN)
        phase["children_cpu_seconds"] = (
            after.ru_utime - before.ru_utime + after.ru_stime - before.ru_stime
        )
        # The high-water mark of the biggest child, in KiB
        phase["children_peak_rss"] = after.ru_maxrss * 1024
        phase["exit_code"] = result.returncode
        phase["ok_exit_codes"] = list(ok_exit_codes)
    truth.check({"type": "firefox_cpu_total"})
    truth.save()
