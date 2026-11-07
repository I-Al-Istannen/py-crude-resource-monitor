"""After the main code ends, the interpreter needs 4 more seconds to exit.

Finding: "Slow shutdown". The last part of the run is spent outside the program's main code: first
the main thread waits in `threading._shutdown` for a non-daemon `uploader` thread, then an `atexit`
handler, `flush_metrics`, burns CPU.
Rule: the last seconds of a process are spent in `_shutdown`, `atexit` handlers, finalizers or
`Pool.join`/`terminate`.
"""

import atexit
import os
import threading

from _truth import Truth, burn_python, now_ms

truth = Truth(__doc__)
timeline = {}
done = threading.Event()


def save_truth():
    pid = os.getpid()
    truth.add_phase(
        {
            "name": "threading._shutdown waits for the uploader",
            "pid": pid,
            "start": timeline["main_end"],
            "end": timeline["uploader_end"],
            "checks": [{"type": "stack", "function": "_shutdown", "min_fraction": 0.8}],
            "finding": "slow_shutdown",
        }
    )
    truth.add_phase(
        {
            "name": "atexit: flush_metrics",
            "pid": pid,
            "start": timeline["flush_start"],
            "end": timeline["flush_end"],
            "checks": [{"type": "stack", "function": "flush_metrics"}],
            "finding": "slow_shutdown",
        }
    )
    truth.save()


def flush_metrics():
    timeline["flush_start"] = now_ms()
    burn_python(2)
    timeline["flush_end"] = now_ms()


def upload_remaining():
    done.wait()
    burn_python(2)
    timeline["uploader_end"] = now_ms()


# atexit runs its handlers in reverse order, so the truth is saved last
atexit.register(save_truth)
atexit.register(flush_metrics)
threading.Thread(target=upload_remaining, name="uploader").start()

with truth.phase("main work", checks=[{"type": "stack", "function": "burn_python"}]):
    burn_python(2)
timeline["main_end"] = now_ms()
done.set()
