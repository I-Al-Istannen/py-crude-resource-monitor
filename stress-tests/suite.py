#!/usr/bin/env python3
"""Runs the stress-test scenarios under the profiler and compares its samples with ground truth.

Each scenario in `scenarios/` records what really happened (see `scenarios/_truth.py`). This script
profiles it, then evaluates every check the scenario asked for against the recorded samples:

- `pass`/`FAIL`: the profiler should get this right, a failure is a bug or regression
- `limitation`: a known blind spot of sampling RSS and CPU, reproduced on purpose
- `info`: a limitation check whose effect did not show up in this run (they are probabilistic)

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

HERE = Path(__file__).resolve().parent
SCENARIOS = HERE / "scenarios"
MiB = 1024 * 1024

PASS, FAIL, LIMITATION, INFO = "pass", "FAIL", "limitation", "info"

# Extra arguments for `profile` per scenario
PROFILER_ARGS = {
    "native_stacks": ["--native"],
    "polars_query": ["--native", "all"],
    "fork_shared": ["--pss"],
}
# The pid of the Firefox track with the total PSS, which is not a real process
PSS_TOTAL_PID = 2**32 - 1


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


class Profile:
    def __init__(self, directory: Path, interval: int, cpus: int, binary: str):
        self.directory = directory
        self.interval = interval
        self.cpus = cpus
        self.binary = binary
        self._firefox = None
        self.processes: dict[int, list[dict]] = {}
        self.global_samples: list[dict] = []
        for file in directory.glob("*.json"):
            samples = [json.loads(line) for line in file.read_text().splitlines() if line]
            if file.stem == "global":
                self.global_samples = samples
            else:
                self.processes[int(file.stem)] = samples

    def window(self, pid: int, start: float, end: float) -> list[dict]:
        """Samples whose measurement interval lies completely within [start, end].

        A sample's CPU value covers the interval before it, and the first sample of a process or
        thread never has one, so we skip the first two intervals.
        """
        samples = self.global_samples if pid == "global" else self.processes.get(pid, [])
        return [s for s in samples if start + 2 * self.interval <= s["time"] <= end]

    def process_cores(self, sample: dict) -> float:
        # Process CPU is normalized to all cores (100% = every core busy)
        return sample["resources"]["cpu"] * self.cpus / 100

    @staticmethod
    def thread_cores(sample: dict, native_id: int) -> float | None:
        # Thread CPU is *not* normalized (100% = one core busy)
        thread = sample["resources"]["thread_resources"].get(str(native_id))
        return None if thread is None else thread["cpu"] / 100

    def firefox(self) -> dict:
        """Exports the profile in the Firefox Profiler format. Sample times of threads are
        converted to absolute timestamps."""
        if self._firefox is None:
            output = self.directory.parent / "firefox.json.gz"
            subprocess.run(
                [self.binary, "export", "firefox", str(self.directory), str(output)],
                check=True,
                capture_output=True,
            )
            self._firefox = json.loads(gzip.decompress(output.read_bytes()))
            for thread in self._firefox["threads"]:
                time = self._firefox["meta"]["startTime"]
                thread["absolute_times"] = []
                for delta in thread["samples"]["timeDeltas"]:
                    time += delta
                    thread["absolute_times"].append(time)
        return self._firefox

    def firefox_threads(self) -> list[dict]:
        return self.firefox()["threads"]

    def firefox_memory(self, pid: int) -> list[tuple[float, float]]:
        """The memory graph of a process in the Firefox export as (absolute time, bytes)"""
        firefox = self.firefox()
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
    return any(
        frame["name"] == function for trace in sample["stacktraces"] for frame in trace["frames"]
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
    """The Firefox track with the total PSS shows the real footprint"""
    graph = profile.firefox_memory(PSS_TOTAL_PID)
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
    """The Firefox export contains the CPU time of all processes, even if they share tracks."""
    raw = sum(profile.cpu_seconds(samples) for samples in profile.processes.values())
    exported = sum(
        sum(t["samples"].get("threadCPUDelta") or []) / 1e6
        for t in profile.firefox_threads()
        if t["pid"] not in ("0", str(PSS_TOTAL_PID))
    )
    status = PASS if within(exported, raw, 0.5, 0.05) else FAIL
    return status, f"{raw:.2f} CPU-s in the profile", f"{exported:.2f} CPU-s exported"


def check_cpu_integral(profile, truth, phase, check):
    measured = profile.cpu_seconds(profile.processes.get(truth["pid"], []))
    expected = truth["total_cpu_seconds"]
    status = PASS if within(measured, expected, 0.25, 0.1) else FAIL
    return status, f"{expected:.2f} CPU-s", f"{measured:.2f} CPU-s"


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
    "global_cpu_delta": check_global_cpu_delta,
    "child_coverage": check_child_coverage,
    "firefox_lanes": check_firefox_lanes,
    "firefox_cpu_total": check_firefox_cpu_total,
    "cpu_integral": check_cpu_integral,
}


def run_scenario(name: str, args, cpus: int) -> tuple[str, list[Result]]:
    output = args.output / name
    shutil.rmtree(output, ignore_errors=True)
    output.mkdir(parents=True)
    profile_dir, truth_file = output / "profile", output / "truth.json"

    command = [
        args.binary, "profile", "--yes",
        "--interval", str(args.interval),
        "--output-dir", str(profile_dir),
        *PROFILER_ARGS.get(name, []),
        "--", sys.executable, str(SCENARIOS / f"{name}.py"),
    ]  # fmt: skip
    environment = {
        **os.environ,
        "STRESS_TRUTH": str(truth_file),
        "RUST_LOG": "py_crude_resource_monitor=warn",
    }
    run = subprocess.run(command, cwd=SCENARIOS, env=environment, capture_output=True, text=True)
    (output / "profiler.log").write_text(run.stdout + run.stderr)
    if run.returncode != 0 or not truth_file.exists():
        failure = Result("-", "run", FAIL, "exit code 0", f"exit code {run.returncode}")
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
            status, expected, measured = CHECKS[check["type"]](profile, truth, phase, check)
            results.append(Result(phase["name"], check["type"], status, expected, measured))
    for check in truth["checks"]:
        status, expected, measured = CHECKS[check["type"]](profile, truth, None, check)
        results.append(Result("whole run", check["type"], status, expected, measured))
    return truth["description"], results


def format_table(results: list[Result]) -> str:
    rows = [("status", "phase", "check", "ground truth", "profiler")]
    rows += [(r.status, r.phase, r.check, r.expected, r.measured) for r in results]
    widths = [max(len(row[i]) for row in rows) for i in range(len(rows[0]))]
    lines = ["| " + " | ".join(c.ljust(w) for c, w in zip(row, widths)) + " |" for row in rows]
    lines.insert(1, "|" + "|".join("-" * (w + 2) for w in widths) + "|")
    return "\n".join(lines)


def main():
    available = sorted(p.stem for p in SCENARIOS.glob("*.py") if not p.name.startswith("_"))
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("scenarios", nargs="*", help=f"default: all of {', '.join(available)}")
    parser.add_argument("--binary", default="py-crude-resource-monitor")
    parser.add_argument("--interval", type=int, default=250, help="sampling interval in ms")
    parser.add_argument("--output", type=Path, default=HERE / "results")
    args = parser.parse_args()
    if unknown := set(args.scenarios) - set(available):
        parser.error(f"unknown scenarios: {', '.join(sorted(unknown))}")

    cpus = cpu_count()
    summary = [f"# Stress-test results\n\n{cpus} CPUs, sampling every {args.interval} ms\n"]
    failed = False
    for name in args.scenarios or available:
        print(f"Running {name}...", file=sys.stderr, flush=True)
        description, results = run_scenario(name, args, cpus)
        failed |= any(r.status == FAIL for r in results)
        section = f"## {name}\n\n{description.strip()}\n\n{format_table(results)}\n"
        print(section, flush=True)
        summary.append(section)

    (args.output / "summary.md").write_text("\n".join(summary))
    print(f"Profiles, HTML reports and summary.md are in {args.output}", file=sys.stderr)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
