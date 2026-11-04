# Stress tests for the resource accounting

Scenarios with known CPU and memory behaviour, profiled with `py-crude-resource-monitor` and
compared against ground truth that each scenario measures from inside itself: CPU time from
`time.process_time()`/`time.thread_time()`, RSS and PSS from `/proc`.

```bash
./stress-tests/run.sh                          # all scenarios
./stress-tests/run.sh memory_steps pool_cpu    # a selection
./stress-tests/run.sh --interval 100           # a different sampling interval
```

`run.sh` builds the profiler in a Linux container and runs `suite.py` there, so it also works on
macOS without root. The results end up in `stress-tests/results/`: `summary.md`, and for every
scenario the raw profile, the ground truth, an HTML report and a Firefox Profiler export. View the
reports to see what each scenario looks like in the viewer.

Every check has one of these outcomes:

- `pass`/`FAIL`: the profiler should get this right. A failure is a bug or regression, and makes the
  suite exit with code 1.
- `limitation`: a known blind spot of sampling RSS and CPU, reproduced on purpose to document it.
- `info`: a limitation check whose effect did not show up in this run (some are probabilistic).

## Scenarios

| Scenario            | What it shows                                                                                                  |
|---------------------|----------------------------------------------------------------------------------------------------------------|
| `cpu_single_thread` | CPU follows a busy loop and samples point at the busy function. Also the CPU integral over the whole run.      |
| `gil_threads`       | Four GIL-bound threads share one core, four GIL-releasing threads use four. Per-thread CPU makes this visible. |
| `pool_cpu`          | Pool workers are discovered and accounted separately, the parent is idle in `Pool.map`.                        |
| `child_processes`   | Python grandchildren behind a shell are profiled, non-Python children only show up in the global CPU.          |
| `short_lived`       | *Limitation*: children living shorter than a few sampling intervals get no CPU attributed.                     |
| `memory_steps`      | RSS follows allocations and frees, memory growth is attributed to the function that allocates.                 |
| `memory_semantics`  | Reserved-but-untouched memory does not count, memory from native `malloc` does (tracemalloc misses it).        |
| `memory_spike`      | *Limitation*: spikes shorter than the sampling interval are missed.                                            |
| `fork_shared`       | *Limitation*: copy-on-write pages count for every forked process, so summing the graphs overcounts.            |

## Adding a scenario

Write a script in `scenarios/` that creates a `Truth`, wraps each part of its work in
`truth.phase(name, checks=[...])` and calls `truth.save()` at the end. The available checks are the
`check_*` functions in `suite.py`. Look at them to see which ground-truth fields they read from the
phase.
