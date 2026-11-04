"""Child processes that are not direct Python children of a Python process.

Shows: a Python grandchild started through a shell is still found and profiled. A non-Python child
has no stacks, as py-spy cannot attach to it, but its resources are still recorded.
"""

import json
import os
import subprocess
import sys
import tempfile
import time

from _truth import Truth

truth = Truth(__doc__)

with truth.phase("idle", checks=[{"type": "cpu"}]):
    time.sleep(3)

with truth.phase(
    "non-Python child `yes > /dev/null`",
    checks=[{"type": "child_cpu"}, {"type": "global_cpu_delta", "baseline": "idle"}],
) as phase:
    child = subprocess.Popen(["yes"], stdout=subprocess.DEVNULL)
    time.sleep(4)
    child.kill()
    _, _, usage = os.wait4(child.pid, 0)
    child.returncode = -9
    phase["child_pid"] = child.pid
    phase["child_cpu_seconds"] = usage.ru_utime + usage.ru_stime

with tempfile.NamedTemporaryFile(suffix=".json") as output:
    # The trailing `true` prevents the shell from replacing itself with Python via exec
    subprocess.run(["sh", "-c", f'"{sys.executable}" _burn.py 4 "{output.name}"; true'], check=True)
    record = json.load(output)

truth.add_phase(
    {
        **record,
        "name": "Python grandchild started through `sh -c`",
        "checks": [{"type": "cpu"}, {"type": "stack", "function": "burn_python"}],
    }
)
truth.save()
