"""The program profiled by the `exit_race` check in suite.py: many threads, exits right away."""

import sys
import threading
import time

for _ in range(16):
    threading.Thread(target=time.sleep, args=(60,), daemon=True).start()
time.sleep(0.02)
sys.exit(3)
