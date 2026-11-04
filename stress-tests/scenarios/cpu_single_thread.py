"""A single thread alternates between sleeping and a pure Python busy loop.

Shows: the CPU graph matches real CPU time, and samples taken while the CPU is busy point at the
function burning it.
"""

import time

from _truth import Truth, burn_python, measure_thread

truth = Truth(__doc__)

with truth.phase("sleeping", checks=[{"type": "cpu"}]):
    time.sleep(3)

with truth.phase(
    "busy loop in burn_python",
    checks=[
        {"type": "cpu"},
        {"type": "firefox_thread_cpu"},
        {"type": "stack", "function": "burn_python"},
    ],
) as phase:
    phase["threads"] = [measure_thread(burn_python, 4)]

with truth.phase("sleeping again", checks=[{"type": "cpu"}]):
    time.sleep(2)

truth.check({"type": "cpu_integral"})
truth.save()
