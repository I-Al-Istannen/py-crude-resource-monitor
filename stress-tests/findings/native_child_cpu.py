"""A busy shell loop as a child process, while the Python parent waits for it.

Finding: "CPU in non-Python child processes". The child uses a full core but never yields a Python
stack, because it is not a Python process. It should be labelled as such, not as a failed stack
capture, and its CPU should count toward the parent's `subprocess.run` call.
Rule: a child process with CPU but no successful stack capture, whose executable is not Python.
"""

import os
import subprocess

from _truth import Truth


truth = Truth(__doc__)


def convert_with_shell() -> tuple[int, float]:
    # `:` is a shell builtin, so the loop never starts another process
    child = subprocess.Popen(["sh", "-c", "while :; do :; done"])
    try:
        child.wait(timeout=4)
    except subprocess.TimeoutExpired:
        child.kill()
    _, _, usage = os.wait4(child.pid, 0)
    child.returncode = -9
    return child.pid, usage.ru_utime + usage.ru_stime


with truth.phase(
    "parent in convert_with_shell, child busy",
    checks=[{"type": "child_cpu"}, {"type": "stack", "function": "convert_with_shell"}],
    finding="non_python_child",
) as phase:
    phase["child_pid"], phase["child_cpu_seconds"] = convert_with_shell()

truth.save()
