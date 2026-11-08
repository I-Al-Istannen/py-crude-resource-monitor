#!/usr/bin/env python3
"""Runs the stress-test scenarios under the profiler and compares its samples with ground truth.

Each scenario in `scenarios/` records what really happened (see `scenarios/_truth.py`). This script
profiles it, then evaluates every check the scenario asked for against the recorded samples:

- `pass`/`FAIL`: the profiler should get this right, a failure is a bug or regression
- `limitation`: a known blind spot of sampling RSS and CPU, reproduced on purpose
- `info`: a limitation check whose effect did not show up in this run (they are probabilistic)
- `expected`: a pattern a viewer should point out in this phase (only for `--findings`)

With `--findings`, it runs the scenarios in `findings/` instead: reproducers for the patterns the
viewer should detect, with the phases where each one occurs.

With `--realworld`, it profiles real projects (see `realworld/`) and compares the samples of their
whole process tree with what the kernel counted for it.

Only meaningful on Linux, as the ground truth is read from /proc.
"""

import argparse
import gzip
import json
import os
import shutil
import statistics
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import zstandard

HERE = Path(__file__).resolve().parent
SCENARIOS = HERE / "scenarios"
FINDINGS = HERE / "findings"
REALWORLD = HERE / "realworld"
MiB = 1024 * 1024

PASS, FAIL, LIMITATION, INFO, EXPECTED = "pass", "FAIL", "limitation", "info", "expected"

# Extra arguments for `profile` per scenario
PROFILER_ARGS = {
    "native_stacks": ["--native"],
    "polars_query": ["--native", "all"],
    "fork_shared": ["--pss"],
    "pytest_polars": ["--native", "all"],
}
# The pid of the Firefox track with the total PSS, which is not a real process
PSS_TOTAL_PID = 2**32 - 1
# A scenario that takes longer than this, e.g. because a worker hangs, is stopped
SCENARIO_TIMEOUT_SECONDS = 300


@dataclass
class Result:
    phase: str
    check: str
    status: str
    expected: str
    measured: str


def cpu_count() -> int:
    # sysinfo counts the CPUs listed in /proc/stat, so we do the same
    with open("/proc/stat") as f:
        return sum(1 for line in f if line.startswith("cpu") and line[3].isdigit())


def within(measured: float, expected: float, absolute: float, relative: float) -> bool:
    return abs(measured - expected) <= max(absolute, relative * abs(expected))


def mib(value: float) -> str:
    return f"{value / MiB:.0f} MiB"


def read_samples(file: Path) -> list[dict]:
    """The samples of a sample file, with the frames of every thread resolved from its stack."""
    frames: list[dict] = []
    stacks: list[list[dict]] = []  # the frames of every stack, innermost first
    samples = []
    if file.suffix == ".zst":
        decompressor = zstandard.ZstdDecompressor()
        content = decompressor.stream_reader(file.read_bytes(), read_across_frames=True).read()
    else:
        content = file.read_bytes()
    for line in content.decode().splitlines():
        if not line:
            continue
        data = json.loads(line)
        # Stack lines also have a "frame" key, so check for them first
        if "stack" in data:
            assert data["stack"] == len(stacks), line
            callers = [] if data["parent"] is None else stacks[data["parent"]]
            stacks.append([frames[data["frame"]], *callers])
        elif "frame" in data:
            assert data["frame"] == len(frames), line
            frames.append(data)
        else:
            for trace in data["stacktraces"]:
                if trace.get("stack") is not None:
                    trace["frames"] = stacks[trace["stack"]]
            samples.append(data)
    return samples


class Profile:
    def __init__(self, directory: Path, interval: int, cpus: int, binary: str):
        self.directory = directory
        self.interval = interval
        self.cpus = cpus
        self.binary = binary
        self._firefox: dict[str, dict] = {}
        self.processes: dict[int, list[dict]] = {}
        self.global_samples: list[dict] = []
        for file in [*directory.glob("*.json"), *directory.glob("*.json.zst")]:
            samples = read_samples(file)
            name = file.name.removesuffix(".zst").removesuffix(".json")
            if name == "global":
                self.global_samples = samples
            else:
                self.processes[int(name)] = samples

    def window(self, pid: int, start: float, end: float) -> list[dict]:
        """Samples whose measurement interval lies completely within [start, end].

        A sample's CPU value covers the interval before it, and the first sample of a process or
        thread never has one, so we skip the first two intervals.
        """
        samples = self.global_samples if pid == "global" else self.processes.get(pid, [])
        # Lines written after a process exited have no measurement interval
        samples = [s for s in samples if not s.get("exited")]
        return [s for s in samples if start + 2 * self.interval <= s["time"] <= end]

    def process_cores(self, sample: dict) -> float:
        return sample["resources"]["cpu_core_percent"] / 100

    @staticmethod
    def thread_cores(sample: dict, native_id: int) -> float | None:
        # Thread CPU is *not* normalized (100% = one core busy)
        thread = sample["resources"]["thread_resources"].get(str(native_id))
        return None if thread is None else thread["cpu"] / 100

    def firefox(self, memory: str = "rss") -> dict:
        """Exports the profile in the Firefox Profiler format, with the memory graphs showing
        `memory`. Sample times of threads are converted to absolute timestamps."""
        if memory not in self._firefox:
            suffix = "" if memory == "rss" else f"-{memory}"
            output = self.directory.parent / f"firefox{suffix}.json.gz"
            subprocess.run(
                [self.binary, "export", "firefox", "--memory", memory, str(self.directory), str(output)],
                check=True,
                capture_output=True,
            )  # fmt: skip
            firefox = json.loads(gzip.decompress(output.read_bytes()))
            for thread in firefox["threads"]:
                time = firefox["meta"]["startTime"]
                thread["absolute_times"] = []
                for delta in thread["samples"]["timeDeltas"]:
                    time += delta
                    thread["absolute_times"].append(time)
            self._firefox[memory] = firefox
        return self._firefox[memory]

    def firefox_threads(self) -> list[dict]:
        return self.firefox()["threads"]

    def firefox_memory(self, pid: int, memory: str = "rss") -> list[tuple[float, float]]:
        """The memory graph of a process in the Firefox export as (absolute time, bytes)"""
        firefox = self.firefox(memory)
        counter = next(
            c for c in firefox["counters"] if c["category"] == "Memory" and c["pid"] == str(pid)
        )
        time, value, graph = firefox["meta"]["startTime"], 0.0, []
        for delta, count in zip(counter["samples"]["timeDeltas"], counter["samples"]["count"]):
            time += delta
            value += count
            graph.append((time, value))
        return graph

    def cpu_seconds(self, samples: list[dict]) -> float:
        """Integrates the CPU usage of consecutive samples of one process over time. The first
        sample covers the time since the previous tick, about one interval."""
        if not samples:
            return 0.0
        total = self.process_cores(samples[0]) * self.interval / 1000
        for previous, current in zip(samples, samples[1:]):
            total += self.process_cores(current) * (current["time"] - previous["time"]) / 1000
        return total


def has_frame(sample: dict, function: str) -> bool:
    # Threads without a stack, e.g. native ones that never ran Python code, have no frames
    return any(
        frame["name"] == function
        for trace in sample["stacktraces"]
        for frame in trace.get("frames", [])
    )


def duration_seconds(record: dict) -> float:
    return (record["end"] - record["start"]) / 1000


# Checks. Each one gets the profile, the scenario's ground truth, the phase record and the check
# definition and returns (status, expected, measured).


def check_cpu(profile, truth, phase, check):
    samples = profile.window(phase["pid"], phase["start"], phase["end"])
    if not samples:
        return FAIL, "samples in phase", "none"
    measured = statistics.mean(profile.process_cores(s) for s in samples)
    expected = phase["cpu_seconds"] / duration_seconds(phase)
    status = PASS if within(measured, expected, 0.15, 0.1) else FAIL
    return status, f"{expected:.2f} cores", f"{measured:.2f} cores ({len(samples)} samples)"


def check_thread_cpu(profile, truth, phase, check):
    expected, measured, status = [], [], PASS
    for thread in phase["threads"]:
        samples = profile.window(phase["pid"], thread["start"], thread["end"])
        values = [v for s in samples if (v := profile.thread_cores(s, thread["native_id"])) is not None]
        truth_cores = thread["cpu_seconds"] / duration_seconds(thread)
        expected.append(f"{truth_cores:.2f}")
        if not values:
            measured.append("-")
            status = FAIL
            continue
        tool_cores = statistics.mean(values)
        measured.append(f"{tool_cores:.2f}")
        if not within(tool_cores, truth_cores, 0.1, 0.1):
            status = FAIL
    return status, " / ".join(expected) + " cores", " / ".join(measured) + " cores"


def check_firefox_thread_cpu(profile, truth, phase, check):
    """Per-thread CPU usage as shown by the Firefox Profiler export (`threadCPUDelta`)."""
    expected, measured, status = [], [], PASS
    for thread in phase["threads"]:
        exported = next(
            t
            for t in profile.firefox_threads()
            if t["pid"] == str(phase["pid"])
            and (t["isMainThread"] if thread["name"] == "MainThread" else t["name"] == thread["name"])
        )
        times, deltas = exported["absolute_times"], exported["samples"]["threadCPUDelta"]
        cores = [
            # threadCPUDelta is in µs of CPU time since the previous sample
            delta / 1000 / (time - previous)
            for previous, time, delta in zip(times, times[1:], deltas[1:])
            if thread["start"] + 2 * profile.interval <= time <= thread["end"]
        ]
        truth_cores = thread["cpu_seconds"] / duration_seconds(thread)
        tool_cores = statistics.mean(cores) if cores else float("nan")
        expected.append(f"{truth_cores:.2f}")
        measured.append(f"{tool_cores:.2f}")
        if not within(tool_cores, truth_cores, 0.1, 0.1):
            status = FAIL
    return status, " / ".join(expected) + " cores", " / ".join(measured) + " cores"


def check_stack(profile, truth, phase, check):
    function, minimum = check["function"], check.get("min_fraction", 0.9)
    samples = profile.window(phase["pid"], phase["start"], phase["end"])
    if not samples:
        return FAIL, f"samples in {function}", "no samples"
    hits = sum(has_frame(s, function) for s in samples)
    status = PASS if hits / len(samples) >= minimum else FAIL
    return (
        status,
        f">= {minimum:.0%} of samples in {function}",
        f"{hits / len(samples):.0%} ({hits}/{len(samples)})",
    )


def check_native_stack(profile, truth, phase, check):
    """Samples show the native `function` from `library` running below the Python `caller`."""
    caller, function, library = check["caller"], check["function"], check["library"]
    samples = profile.window(phase["pid"], phase["start"], phase["end"])
    if not samples:
        return FAIL, "samples in phase", "none"

    def native_below_caller(trace):
        # Frames are ordered from the innermost one outwards
        names = [frame["name"] for frame in trace["frames"]]
        if caller not in names:
            return False
        return any(
            frame["name"] == function and library in frame["filename"]
            for frame in trace["frames"][: names.index(caller)]
        )

    hits = sum(any(native_below_caller(t) for t in s["stacktraces"]) for s in samples)
    status = PASS if hits / len(samples) >= 0.9 else FAIL
    return (
        status,
        f">= 90% of samples in {library} {function} below {caller}",
        f"{hits / len(samples):.0%} ({hits}/{len(samples)})",
    )


def check_native_thread(profile, truth, phase, check):
    """Samples contain a thread without any Python frames that runs code from `library`. py-spy
    only captures such threads with `--native all`. If given, one of the thread's frames must be
    named like `function`, which also shows that the name was demangled."""
    library, function = check["library"], check.get("function", "")
    samples = profile.window(phase["pid"], phase["start"], phase["end"])
    if not samples:
        return FAIL, "samples in phase", "none"

    def native_only(trace):
        filenames = [frame["filename"] for frame in trace["frames"]]
        return (
            not any(f.endswith(".py") for f in filenames)
            and any(library in f for f in filenames)
            and any(function in frame["name"] for frame in trace["frames"])
        )

    hits = sum(any(native_only(t) for t in s["stacktraces"]) for s in samples)
    status = PASS if hits / len(samples) >= 0.9 else FAIL
    return (
        status,
        f">= 90% of samples with a {library} thread without Python frames"
        + (f" in {function}" if function else ""),
        f"{hits / len(samples):.0%} ({hits}/{len(samples)})",
    )


def check_memory(profile, truth, phase, check):
    samples = profile.window(phase["pid"], phase["start"], phase["end"])
    if not samples:
        return FAIL, "samples in phase", "none"
    measured = statistics.median(s["resources"]["memory"] for s in samples)
    expected = phase["rss"]
    status = PASS if within(measured, expected, 10 * MiB, 0.05) else FAIL
    return status, f"RSS {mib(expected)}", f"{mib(measured)} ({len(samples)} samples)"


def check_growth_attribution(profile, truth, phase, check):
    """How much of the memory growth happened between samples that show `function` running."""
    function = check["function"]
    samples = [
        s
        for s in profile.processes.get(phase["pid"], [])
        if phase["start"] - 1.5 * profile.interval <= s["time"] <= phase["end"] + profile.interval
    ]
    growth = attributed = 0
    for previous, current in zip(samples, samples[1:]):
        delta = current["resources"]["memory"] - previous["resources"]["memory"]
        if delta > 0:
            growth += delta
            attributed += delta if has_frame(current, function) else 0
    if growth == 0:
        return FAIL, f"growth in {function}", "no growth seen"
    status = PASS if attributed / growth >= 0.9 else FAIL
    return (
        status,
        f">= 90% of growth in {function}",
        f"{attributed / growth:.0%} of {mib(growth)}",
    )


def check_memory_peak(profile, truth, phase, check):
    """The highest memory between the samples, measured by the fast memory sampler"""
    samples = [
        s
        for s in profile.processes.get(phase["pid"], [])
        if phase["start"] <= s["time"] <= phase["end"] + profile.interval
    ]
    sampled = max(s["resources"]["memory"] for s in samples)
    in_between = [
        m["memory"]
        for s in samples
        for m in s.get("memory_samples", [])
        if phase["start"] <= m["time"] <= phase["end"]
    ]
    measured, expected = max([sampled, *in_between]), phase["peak_rss"]
    status = PASS if within(measured, expected, 10 * MiB, 0.05) else FAIL
    return (
        status,
        f"peak RSS {mib(expected)}",
        f"highest value {mib(measured)} (samples alone: {mib(sampled)})",
    )


def check_firefox_memory_peak(profile, truth, phase, check):
    """The highest value of the memory graph in the Firefox export"""
    graph = profile.firefox_memory(phase["pid"])
    measured = max(v for t, v in graph if phase["start"] <= t <= phase["end"])
    expected = phase["peak_rss"]
    status = PASS if within(measured, expected, 10 * MiB, 0.05) else FAIL
    return status, f"peak RSS {mib(expected)}", f"graph peaks at {mib(measured)}"


def check_pss_total(profile, truth, phase, check):
    """The PSS of all members adds up to their real footprint"""
    total = 0
    for member in phase["members"]:
        samples = profile.window(member["pid"], phase["start"], phase["end"])
        values = [s["resources"]["pss"] for s in samples if "pss" in s["resources"]]
        if not values:
            return FAIL, f"PSS of {member['pid']}", "none"
        total += statistics.median(values)
    expected = sum(m["pss"] for m in phase["members"])
    status = PASS if within(total, expected, 10 * MiB, 0.05) else FAIL
    return status, f"sum of PSS {mib(expected)}", f"sum of PSS {mib(total)}"


def check_firefox_pss_total(profile, truth, phase, check):
    """With `--memory pss`, the Firefox track with the total PSS shows the real footprint"""
    graph = profile.firefox_memory(PSS_TOTAL_PID, memory="pss")
    values = [
        v
        for t, v in graph
        if phase["start"] + 2 * profile.interval <= t <= phase["end"]
    ]
    if not values:
        return FAIL, "PSS track values in phase", "none"
    measured = statistics.median(values)
    expected = sum(m["pss"] for m in phase["members"])
    status = PASS if within(measured, expected, 10 * MiB, 0.05) else FAIL
    return status, f"sum of PSS {mib(expected)}", f"PSS track {mib(measured)}"


def check_shared_overcount(profile, truth, phase, check):
    graphed = 0
    for member in phase["members"]:
        samples = profile.window(member["pid"], phase["start"], phase["end"])
        if not samples:
            return FAIL, f"samples for {member['pid']}", "none"
        graphed += statistics.median(s["resources"]["memory"] for s in samples)
    footprint = sum(m["pss"] for m in phase["members"])
    status = LIMITATION if graphed > 1.5 * footprint else INFO
    return (
        status,
        f"real footprint (sum of PSS) {mib(footprint)}",
        f"sum of all graphs {mib(graphed)} ({graphed / footprint:.1f}x)",
    )


def check_child_cpu(profile, truth, phase, check):
    """CPU usage of a child process that is not necessarily a Python process."""
    samples = profile.window(phase["child_pid"], phase["start"], phase["end"])
    expected = phase["child_cpu_seconds"] / duration_seconds(phase)
    if not samples:
        return FAIL, f"child using {expected:.2f} cores", "no data for child"
    measured = statistics.mean(profile.process_cores(s) for s in samples)
    status = PASS if within(measured, expected, 0.15, 0.1) else FAIL
    return (
        status,
        f"child using {expected:.2f} cores",
        f"{measured:.2f} cores ({len(samples)} samples)",
    )


def check_read_calls(profile, truth, phase, check):
    """Bytes requested by read calls, including page cache hits. The counter is a running total,
    so we take the difference between the last sample before the phase and the first one after.
    Processes can exit right after the phase, so we fall back to their last sample."""
    samples = profile.processes.get(phase["pid"], [])
    before = [s for s in samples if s["time"] <= phase["start"]]
    after = [s for s in samples if s["time"] >= phase["end"]] or samples[-1:]
    expected = phase["rchar"]
    if not before or after[0] is before[-1]:
        return FAIL, f"read calls of {mib(expected)}", "no samples around phase"
    first, last = before[-1]["resources"], after[0]["resources"]
    if "total_read_call_bytes" not in first:
        return FAIL, f"read calls of {mib(expected)}", "not recorded"
    measured = last["total_read_call_bytes"] - first["total_read_call_bytes"]
    status = PASS if within(measured, expected, 4 * MiB, 0.05) else FAIL
    # For comparison: the disk counters cover the interval before each sample
    start, end = before[-1]["time"], after[0]["time"]
    disk = sum(s["resources"]["disk_read_bytes"] for s in samples if start < s["time"] <= end)
    return status, f"read calls of {mib(expected)}", f"{mib(measured)} (disk: {mib(disk)})"


def check_global_cpu_delta(profile, truth, phase, check):
    baseline_phase = next(p for p in truth["phases"] if p["name"] == check["baseline"])

    def global_cores(record):
        samples = profile.window("global", record["start"], record["end"])
        return statistics.mean(profile.process_cores(s) for s in samples)

    measured = global_cores(phase) - global_cores(baseline_phase)
    expected = phase["child_cpu_seconds"] / duration_seconds(phase)
    status = PASS if within(measured, expected, 0.3, 0.15) else FAIL
    return status, f"global +{expected:.2f} cores", f"global +{measured:.2f} cores"


def check_child_coverage(profile, truth, phase, check):
    children = set(phase["child_pids"])
    seen = children & profile.processes.keys()
    attributed = sum(
        profile.cpu_seconds(
            [s for s in profile.processes[pid] if phase["start"] <= s["time"] <= phase["end"]]
        )
        for pid in seen
    )
    expected = phase["children_cpu_seconds"]
    status = LIMITATION if attributed < 0.5 * expected else INFO
    return (
        status,
        f"{len(children)} children, {expected:.2f} CPU-s",
        f"{len(seen)} seen, {attributed:.2f} CPU-s attributed",
    )


def check_firefox_lanes(profile, truth, phase, check):
    """Number of tracks the worker processes take up in the Firefox export."""
    workers = len(profile.processes) - 1
    tracks = [
        t
        for t in profile.firefox_threads()
        if t["isMainThread"] and t["pid"] not in (str(truth["pid"]), "0")
    ]
    status = PASS if len(tracks) <= check["max_tracks"] else FAIL
    return (
        status,
        f"<= {check['max_tracks']} tracks for {workers} workers",
        f"{len(tracks)} tracks",
    )


def check_firefox_cpu_total(profile, truth, phase, check):
    """The Firefox export contains the CPU time of all processes, even if they share tracks.

    It only has tracks for threads that were in a stack at some point, so CPU time of threads
    py-spy never saw is missing. That is the case for native threads that never run Python code
    (BLAS, OpenMP) unless `--native all` is given, and for threads that exit between two samples.
    This is a limitation as long as all CPU time of the threads with a stack is there."""
    raw = sum(profile.cpu_seconds(samples) for samples in profile.processes.values())
    exported = sum(
        sum(t["samples"].get("threadCPUDelta") or []) / 1e6
        for t in profile.firefox_threads()
        if t["pid"] not in ("0", str(PSS_TOTAL_PID))
    )
    expected = f"{raw:.2f} CPU-s in the profile"
    measured = f"{exported:.2f} CPU-s exported"
    if within(exported, raw, 0.5, 0.05):
        return PASS, expected, measured

    visible = 0.0
    for samples in profile.processes.values():
        with_stack = {
            str(trace["os_thread_id"])
            for sample in samples
            for trace in sample["stacktraces"]
            if trace.get("os_thread_id")
        }
        for previous, current in zip(samples, samples[1:]):
            seconds = (current["time"] - previous["time"]) / 1000
            visible += seconds * sum(
                thread["cpu"] / 100
                for thread_id, thread in current["resources"]["thread_resources"].items()
                if thread_id in with_stack
            )
    measured += f" ({visible:.2f} CPU-s ran in threads with a stack)"
    status = LIMITATION if within(exported, visible, 0.5, 0.05) else FAIL
    return status, expected, measured


def check_cpu_integral(profile, truth, phase, check):
    measured = profile.cpu_seconds(profile.processes.get(truth["pid"], []))
    expected = truth["total_cpu_seconds"]
    status = PASS if within(measured, expected, 0.25, 0.1) else FAIL
    return status, f"{expected:.2f} CPU-s", f"{measured:.2f} CPU-s"


def tree_samples(profile, phase) -> dict[int, list[dict]]:
    """The samples of all processes of the profiled tree during the phase"""
    end = phase["end"] + profile.interval
    return {
        pid: [s for s in samples if phase["start"] <= s["time"] <= end]
        for pid, samples in profile.processes.items()
    }


def check_exit_code(profile, truth, phase, check):
    expected, measured = phase["ok_exit_codes"], phase["exit_code"]
    status = PASS if measured in expected else FAIL
    return status, "exit code " + " or ".join(map(str, expected)), f"exit code {measured}"


def check_tree_cpu(profile, truth, phase, check):
    """The CPU time of all processes of the tree adds up to what the kernel counted for them. Each
    process loses up to one sampling interval at its end, so the allowed difference grows with the
    number of processes."""
    tree = {pid: samples for pid, samples in tree_samples(profile, phase).items() if samples}
    measured = sum(profile.cpu_seconds(samples) for samples in tree.values())
    expected = phase["children_cpu_seconds"] + phase["cpu_seconds"]
    absolute = max(1.0, 0.25 * profile.interval / 1000 * len(tree))
    status = PASS if within(measured, expected, absolute, 0.15) else FAIL
    return (
        status,
        f"{expected:.1f} CPU-s counted by the kernel",
        f"{measured:.1f} CPU-s in {len(tree)} processes",
    )


def check_tree_peak_memory(profile, truth, phase, check):
    """The highest RSS of any process of the tree, including the one between the samples, is close
    to the high-water mark of the biggest process that the kernel kept."""
    measured = 0
    for samples in tree_samples(profile, phase).values():
        for sample in samples:
            measured = max(measured, sample["resources"]["memory"])
            for memory_sample in sample.get("memory_samples", []):
                measured = max(measured, memory_sample["memory"])
    expected = phase["children_peak_rss"]
    # Short peaks can fall between two memory measurements, so we only expect to be close
    status = PASS if 0.85 * expected <= measured <= 1.1 * expected + 10 * MiB else FAIL
    return status, f"biggest process peaked at {mib(expected)}", f"highest RSS {mib(measured)}"


def check_processes(profile, truth, phase, check):
    """The profile contains the Python processes the project started"""
    seen = [
        pid
        for pid, samples in tree_samples(profile, phase).items()
        if any(s["stacktraces"] for s in samples)
    ]
    status = PASS if len(seen) >= check["min"] else FAIL
    return status, f">= {check['min']} Python processes", f"{len(seen)} processes with stacks"


def check_tree_stack(profile, truth, phase, check):
    """Busy processes other than the one running the project are mostly inside `function`."""
    function, minimum = check["function"], check["min_fraction"]
    busy = [
        s
        for pid, samples in tree_samples(profile, phase).items()
        if pid != truth["pid"]
        for s in samples
        if s["resources"]["cpu_core_percent"] >= 50 and s["stacktraces"]
    ]
    if not busy:
        return FAIL, f"busy samples in {function}", "no busy samples"
    hits = sum(has_frame(s, function) for s in busy)
    status = PASS if hits / len(busy) >= minimum else FAIL
    return (
        status,
        f">= {minimum:.0%} of busy samples in {function}",
        f"{hits / len(busy):.0%} ({hits}/{len(busy)})",
    )


CHECKS = {
    "cpu": check_cpu,
    "thread_cpu": check_thread_cpu,
    "firefox_thread_cpu": check_firefox_thread_cpu,
    "stack": check_stack,
    "native_stack": check_native_stack,
    "native_thread": check_native_thread,
    "memory": check_memory,
    "growth_attribution": check_growth_attribution,
    "memory_peak": check_memory_peak,
    "firefox_memory_peak": check_firefox_memory_peak,
    "pss_total": check_pss_total,
    "firefox_pss_total": check_firefox_pss_total,
    "shared_overcount": check_shared_overcount,
    "child_cpu": check_child_cpu,
    "read_calls": check_read_calls,
    "global_cpu_delta": check_global_cpu_delta,
    "child_coverage": check_child_coverage,
    "firefox_lanes": check_firefox_lanes,
    "firefox_cpu_total": check_firefox_cpu_total,
    "cpu_integral": check_cpu_integral,
    "exit_code": check_exit_code,
    "tree_cpu": check_tree_cpu,
    "tree_peak_memory": check_tree_peak_memory,
    "processes": check_processes,
    "tree_stack": check_tree_stack,
}


def run_scenario(name: str, directory: Path, args, cpus: int) -> tuple[str, list[Result]]:
    output = args.output / name
    shutil.rmtree(output, ignore_errors=True)
    output.mkdir(parents=True)
    profile_dir, truth_file = output / "profile", output / "truth.json"

    command = [
        args.binary, "profile", "py-spy", "--yes",
        "--interval", str(args.interval),
        "--output-dir", str(profile_dir),
        *PROFILER_ARGS.get(name, []),
        "--", sys.executable, str(directory / f"{name}.py"),
    ]  # fmt: skip
    environment = {
        **os.environ,
        "STRESS_TRUTH": str(truth_file),
        "RUST_LOG": "py_crude_resource_monitor=warn",
        # For `_truth`, when running the scenarios in findings/
        "PYTHONPATH": str(SCENARIOS),
    }
    process = subprocess.Popen(
        command,
        cwd=directory,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        log, _ = process.communicate(timeout=SCENARIO_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        # The profiler stops the scenario and writes its samples on SIGTERM
        process.terminate()
        log, _ = process.communicate()
        (output / "profiler.log").write_text(log)
        failure = Result("-", "run", FAIL, f"done in {SCENARIO_TIMEOUT_SECONDS} s", "timed out")
        return "", [failure]
    (output / "profiler.log").write_text(log)
    if process.returncode != 0 or not truth_file.exists():
        failure = Result("-", "run", FAIL, "exit code 0", f"exit code {process.returncode}")
        return "", [failure]

    subprocess.run(
        [args.binary, "export", "html", str(profile_dir), str(output / "report.html")],
        capture_output=True,
    )

    truth = json.loads(truth_file.read_text())
    profile = Profile(profile_dir, args.interval, cpus, args.binary)
    results = []
    for phase in truth["phases"]:
        for check in phase["checks"]:
            results.append(run_check(profile, truth, phase, check))
        if "finding" in phase:
            results.append(
                Result(phase["name"], "finding", EXPECTED, phase["finding"], "no detector yet")
            )
    for check in truth["checks"]:
        results.append(run_check(profile, truth, None, check))
    return truth["description"], results


def run_check(profile, truth, phase, check) -> Result:
    """Runs a check. A check that crashes, e.g. because the profile has no samples in a phase,
    fails instead of losing the results of all scenarios."""
    phase_name = phase["name"] if phase else "whole run"
    try:
        status, expected, measured = CHECKS[check["type"]](profile, truth, phase, check)
    except Exception as e:
        status, expected, measured = FAIL, "-", f"crashed: {type(e).__name__}: {e}"
    return Result(phase_name, check["type"], status, expected, measured)


def format_table(results: list[Result]) -> str:
    rows = [("status", "phase", "check", "ground truth", "profiler")]
    rows += [(r.status, r.phase, r.check, r.expected, r.measured) for r in results]
    widths = [max(len(row[i]) for row in rows) for i in range(len(rows[0]))]
    lines = ["| " + " | ".join(c.ljust(w) for c, w in zip(row, widths)) + " |" for row in rows]
    lines.insert(1, "|" + "|".join("-" * (w + 2) for w in widths) + "|")
    return "\n".join(lines)


def main():
    findings, realworld = "--findings" in sys.argv, "--realworld" in sys.argv
    directory = FINDINGS if findings else REALWORLD if realworld else SCENARIOS
    available = sorted(p.stem for p in directory.glob("*.py") if not p.name.startswith("_"))
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("scenarios", nargs="*", help=f"default: all of {', '.join(available)}")
    parser.add_argument("--findings", action="store_true", help="run the scenarios in findings/")
    parser.add_argument(
        "--realworld", action="store_true", help="run the real projects in realworld/"
    )
    parser.add_argument("--binary", default="py-crude-resource-monitor")
    # Some projects only run for a few seconds, so sample more often
    default_interval = 100 if realworld else 250
    parser.add_argument(
        "--interval", type=int, default=default_interval, help="sampling interval in ms"
    )
    output = HERE / "results"
    if findings or realworld:
        output /= "findings" if findings else "realworld"
    parser.add_argument("--output", type=Path, default=output)
    args = parser.parse_args()
    if unknown := set(args.scenarios) - set(available):
        parser.error(f"unknown scenarios: {', '.join(sorted(unknown))}")

    cpus = cpu_count()
    summary = [f"# Stress-test results\n\n{cpus} CPUs, sampling every {args.interval} ms\n"]
    failed = False
    for name in args.scenarios or available:
        print(f"Running {name}...", file=sys.stderr, flush=True)
        description, results = run_scenario(name, directory, args, cpus)
        failed |= any(r.status == FAIL for r in results)
        section = f"## {name}\n\n{description.strip()}\n\n{format_table(results)}\n"
        print(section, flush=True)
        summary.append(section)

    (args.output / "summary.md").write_text("\n".join(summary))
    print(f"Profiles, HTML reports and summary.md are in {args.output}", file=sys.stderr)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
