"""Stack sampling helper for `--tachyon`.

Uses the `_remote_debugging` module behind CPython 3.15's sampling profiler (Tachyon). It can only
sample processes running the same Python minor version as itself.

If `--pause` is passed, the processes are paused while their stacks are captured.

Protocol: once started, the helper writes `{"ready": true}`. Then, for every request line
`{"pids": [pid], "forget": [pid]}` read from stdin, it writes one response line
`{"traces": {pid: {"ok": [StackTrace]} | {"err": str}}, "logs": [{"level": str, "message": str}]}`.
It samples the processes in `pids` and stops sampling all others. The processes in `forget` are
new processes that reuse the pid of an old one. The traces have the shape of `StackTrace` in
`types.rs`.
"""

import json
import os
import signal
import sys

import _remote_debugging as rd

# See `profiling.sampling.constants`. `ALL` computes both the GIL and the on-CPU status.
PROFILING_MODE_ALL = 3
# Like `MAX_ATTACH_ATTEMPTS` in `stacktraces.rs`
MAX_ATTACH_ATTEMPTS = 5
STDLIB_DIR = f"/lib/python{sys.version_info.major}.{sys.version_info.minor}/"


def short_filename(filename):
    for marker in ("/site-packages/", "/dist-packages/", STDLIB_DIR):
        if marker in filename:
            return filename.rsplit(marker, 1)[1]
    return os.path.basename(filename)


def line_number(location):
    # A `LocationInfo` (lineno, end_lineno, col_offset, end_col_offset), a line number or `None`
    if location is None:
        return 0
    if isinstance(location, int):
        return location
    return location[0]


def thread_name(pid, thread):
    if thread.status & rd.THREAD_STATUS_MAIN_THREAD:
        return "MainThread"
    # Since 3.14, CPython names OS threads after their `threading.Thread`, truncated to 15 bytes
    # on Linux. `_remote_debugging` does not read the Python name. Not available on macOS.
    try:
        with open(f"/proc/{pid}/task/{thread.thread_id}/comm") as f:
            return f.read().strip()
    except OSError:
        return None


def convert(pid, interpreters):
    traces = []
    for interpreter in interpreters:
        for thread in interpreter.threads:
            frames = [
                {
                    "name": frame.funcname,
                    "filename": frame.filename,
                    "module": None,
                    "short_filename": short_filename(frame.filename),
                    "line": line_number(frame.location),
                    "is_entry": False,
                }
                for frame in thread.frame_info
            ]
            traces.append(
                {
                    "pid": pid,
                    # The native thread id. `_remote_debugging` does not read the Python one.
                    "thread_id": thread.thread_id,
                    "thread_name": thread_name(pid, thread),
                    "os_thread_id": thread.thread_id,
                    # Always false with `--pause`, as the threads are stopped. Nothing reads it.
                    "active": bool(thread.status & rd.THREAD_STATUS_ON_CPU),
                    "owns_gil": bool(thread.status & rd.THREAD_STATUS_HAS_GIL),
                    "waiting_for_gil": bool(thread.status & rd.THREAD_STATUS_GIL_REQUESTED),
                    "frames": frames,
                    "process_info": None,
                }
            )
    return traces


class Sampler:
    def __init__(self, pause):
        self.pause = pause
        self.unwinders = {}
        # Processes we could not attach to, with the number of failed attempts and the last error
        self.failed_attaches = {}
        self.logs = []

    def log(self, level, message):
        self.logs.append({"level": level, "message": message})

    def sync(self, pids, forget):
        for pid in forget:
            self.unwinders.pop(pid, None)
            self.failed_attaches.pop(pid, None)
        pids = set(pids)
        for known in (self.unwinders, self.failed_attaches):
            for pid in known.keys() - pids:
                del known[pid]

        for pid in sorted(pids - self.unwinders.keys()):
            attempts, _ = self.failed_attaches.get(pid, (0, None))
            if attempts >= MAX_ATTACH_ATTEMPTS:
                continue
            try:
                self.unwinders[pid] = rd.RemoteUnwinder(
                    pid,
                    all_threads=True,
                    mode=PROFILING_MODE_ALL,
                    skip_non_matching_threads=False,
                    cache_frames=True,
                )
                self.failed_attaches.pop(pid, None)
                self.log("info", f"Attached to process {pid}")
            except Exception as e:
                attempts += 1
                self.failed_attaches[pid] = (attempts, f"{type(e).__name__}: {e}")
                if attempts >= MAX_ATTACH_ATTEMPTS:
                    self.log(
                        "warn",
                        f"Giving up on capturing stacks of process {pid} after {attempts} "
                        f"attempts, it is probably not a Python {sys.version_info.major}."
                        f"{sys.version_info.minor} process: {e}",
                    )
                else:
                    self.log("debug", f"Error attaching to process {pid} (attempt {attempts}): {e}")

    def capture(self, unwinder):
        if not self.pause:
            return unwinder.get_stack_trace()
        unwinder.pause_threads()
        try:
            return unwinder.get_stack_trace()
        finally:
            unwinder.resume_threads()

    def sample(self, pids):
        traces = {}
        for pid in pids:
            unwinder = self.unwinders.get(pid)
            if unwinder is not None:
                try:
                    traces[pid] = {"ok": convert(pid, self.capture(unwinder))}
                except Exception as e:
                    self.log("info", f"Sample error {pid}: {e!r}")
                    traces[pid] = {"err": f"{type(e).__name__}: {e}"}
                continue
            match self.failed_attaches.get(pid):
                case (attempts, error) if attempts >= MAX_ATTACH_ATTEMPTS:
                    traces[pid] = {"err": f"Not a Python process: {error}"}
                case (_, error):
                    traces[pid] = {"err": f"Not attached yet: {error}"}
                case None:
                    traces[pid] = {"err": "Not attached"}
        return traces


def main():
    # CTRL+C reaches the whole process group, but the monitor still needs us to finish
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    sampler = Sampler(pause="--pause" in sys.argv[1:])
    print(json.dumps({"ready": True}), flush=True)
    for line in sys.stdin:
        request = json.loads(line)
        sampler.sync(request["pids"], request["forget"])
        traces = sampler.sample(request["pids"])
        print(json.dumps({"traces": traces, "logs": sampler.logs}), flush=True)
        sampler.logs = []


if __name__ == "__main__":
    main()
