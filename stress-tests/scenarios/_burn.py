"""Helper child process: burns CPU for argv[1] seconds and optionally writes its ground truth to
the JSON file argv[2]."""

import json
import os
import sys
import time

from _truth import burn_python, measure_thread

seconds = float(sys.argv[1])
output = sys.argv[2] if len(sys.argv) > 2 else None

if output:
    # Give the profiler time to discover and attach to us before the measured work starts
    time.sleep(1)
record = measure_thread(burn_python, seconds)
record["pid"] = os.getpid()
if output:
    with open(output, "w") as f:
        json.dump(record, f)
