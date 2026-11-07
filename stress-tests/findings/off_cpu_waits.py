"""The process spends its time waiting on five different things, using almost no CPU.

Finding: "Waiting, broken down by cause". The thread is active but below 0.2 cores, so the
innermost frame says what it waits for: the network (`readinto` of an HTTP response), a lock, a
`time.sleep`, a subprocess (`wait`) or `select`. A flame graph by CPU shows none of this.
Waits inside C functions (`lock.acquire`, `select.select`) only show the calling Python frame,
`--native` would show the system call below it.
Rule: active stack samples with less than 0.2 cores, grouped by their innermost frame into
network, lock, sleep, subprocess, select and file I/O.
"""

import select
import subprocess
import sys
import threading
import time
import urllib.request

from _truth import Truth

SERVER = """
import http.server, time
class Slow(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        time.sleep(3)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"report")
    def log_message(self, *args):
        pass
http.server.HTTPServer(("127.0.0.1", 8765), Slow).serve_forever()
"""


def fetch_report():
    with urllib.request.urlopen("http://127.0.0.1:8765/report") as response:
        return response.read()


def update_shared_state(lock: threading.Lock):
    with lock:
        pass


def backoff():
    time.sleep(3)


def run_converter():
    subprocess.run(["sleep", "3"], check=True)


def wait_for_input(pipe):
    select.select([pipe], [], [], 3)


truth = Truth(__doc__)
server = subprocess.Popen([sys.executable, "-c", SERVER])
time.sleep(1)

with truth.phase(
    "network: fetch_report",
    checks=[{"type": "cpu"}, {"type": "stack", "function": "fetch_report"}],
    finding="off_cpu_network",
):
    fetch_report()

lock = threading.Lock()
lock.acquire()
threading.Timer(3, lock.release).start()
with truth.phase(
    "lock held by another thread",
    checks=[{"type": "cpu"}, {"type": "stack", "function": "update_shared_state"}],
    finding="off_cpu_lock",
):
    update_shared_state(lock)

with truth.phase(
    "time.sleep in backoff",
    checks=[{"type": "cpu"}, {"type": "stack", "function": "backoff"}],
    finding="off_cpu_sleep",
):
    backoff()

with truth.phase(
    "subprocess: run_converter",
    checks=[{"type": "cpu"}, {"type": "stack", "function": "run_converter"}],
    finding="off_cpu_subprocess",
):
    run_converter()

with truth.phase(
    "select on an idle pipe",
    checks=[{"type": "cpu"}, {"type": "stack", "function": "wait_for_input"}],
    finding="off_cpu_select",
):
    with subprocess.Popen(["sleep", "5"], stdout=subprocess.PIPE) as idle:
        wait_for_input(idle.stdout)
        idle.kill()

server.kill()
server.wait()
truth.save()
