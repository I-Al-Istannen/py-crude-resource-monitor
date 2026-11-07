"""20 CPU bursts of about 120 ms in `score_candidates`, separated by idle waits.

Finding: "Stack samples too sparse for the event". At the default 250 ms interval most bursts get
zero or one stack sample, so any attribution of them rests on very few samples. The CPU graph
still shows them (averaged), the call tree barely.
Rule: a finding or burst shorter than 3 sampling intervals gets a low-confidence label, with a
suggestion to record at a higher rate.
"""

import time

from _truth import Truth, burn_python, now_ms

truth = Truth(__doc__)
# Irregular gaps, so the bursts don't line up with the sampling interval
GAPS = [0.41, 0.53, 0.37, 0.66, 0.45, 0.58, 0.39, 0.62, 0.47, 0.51]


def score_candidates():
    burn_python(0.12)


with truth.phase("20 short bursts", checks=[{"type": "cpu"}], finding="sparse_stacks") as phase:
    phase["bursts"] = []
    for i in range(20):
        start = now_ms()
        score_candidates()
        phase["bursts"].append({"start": start, "end": now_ms()})
        time.sleep(GAPS[i % len(GAPS)])

truth.save()
