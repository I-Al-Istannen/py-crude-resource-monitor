# Stress tests

The suite compares profiler results with CPU and memory measurements taken by each scenario. It runs in a Linux container, including on macOS.

```bash
./stress-tests/run.sh                         # all scenarios
./stress-tests/run.sh memory_steps pool_cpu   # selected scenarios
./stress-tests/run.sh --interval 100          # sampling interval in ms
```

Results go to `stress-tests/results/`: a summary, raw profiles, ground truth, HTML reports and Firefox Profiler exports. CI runs the default suite on pushes and pull requests; failures upload the results as an artifact.

| Result | Meaning |
| --- | --- |
| `pass` / `FAIL` | A failed check exits the suite with code 1. |
| `limitation` | A known sampling limitation was reproduced. |
| `info` | A limitation did not appear in this run. |

## Scenarios

| Scenario            | What it shows                                                                                                  |
|---------------------|----------------------------------------------------------------------------------------------------------------|
| `cpu_single_thread` | CPU follows a busy loop and samples point at the busy function. Also the CPU integral over the whole run.      |
| `gil_threads`       | Four GIL-bound threads share one core, four GIL-releasing threads use four. Per-thread CPU makes this visible. |
| `pool_cpu`          | Pool workers are discovered and accounted separately, the parent is idle in `Pool.map`.                        |
| `child_processes`   | Python grandchildren behind a shell are profiled, non-Python children get resources without stacks.           |
| `native_stacks`     | With `--native`, samples show the C functions (zlib's `deflate`) below the Python frame calling them.        |
| `polars_query`      | With `--native all`, polars' Rust worker threads, which never run Python code, are captured with their stacks. |
| `pool_churn`        | A pool recreated 30 times fills as many Firefox tracks as it has workers, without losing CPU time.            |
| `short_lived`       | *Limitation*: children living shorter than a sampling interval get only part of their CPU attributed.         |
| `memory_steps`      | RSS follows allocations and frees, memory growth is attributed to the function that allocates.                 |
| `memory_semantics`  | Reserved-but-untouched memory does not count, memory from native `malloc` does (tracemalloc misses it).        |
| `memory_spike`      | Spikes shorter than the sampling interval are missed by the samples, but caught by the memory sampler.         |
| `fork_shared`       | With `--pss`, the total PSS matches the real footprint. *Limitation*: summing the RSS graphs overcounts.        |
| `exit_race`         | Regression: exiting while being sampled neither hangs the profiler nor loses the exit code.                     |

## Findings

[`findings/`](findings/) contains examples of patterns a viewer could detect. These appear as `expected` in the summary until a detector exists; some also run regular profile checks.

```bash
./stress-tests/run.sh --findings
./stress-tests/run.sh --findings off_cpu_waits
DOCKER_RUN_ARGS="--cpus 2.5" ./stress-tests/run.sh --findings cpu_quota
DOCKER_RUN_ARGS="--memory 1g" ./stress-tests/run.sh --findings near_memory_limit
```

Results are written to `results/findings/`.

| Finding                   | Pattern                                                                                    |
|---------------------------|--------------------------------------------------------------------------------------------|
| `spike_between_stacks`    | A memory peak between two stack samples that show unrelated functions.                     |
| `freed_not_returned`      | Fragmentation: most objects freed, RSS stays, the process idles where it did before.       |
| `pool_results_pileup`     | `Pool.map` collects all results in the parent while its main thread waits.                 |
| `pickle_big_args`         | Pool workers spend their time unpickling large arguments, the parent pickling them.        |
| `temp_copy_peak`          | `deepcopy` briefly doubles the memory.                                                     |
| `slow_teardown`           | Freeing a huge dict is a CPU burst lined up with a memory drop.                            |
| `growth_per_iteration`    | Every iteration of the same loop leaves memory behind.                                     |
| `oom_killed`              | A worker is SIGKILLed at its memory peak (sent by the parent, as the OOM killer would).    |
| `near_memory_limit`       | Memory at 80% of the container limit. Needs `--memory`, records "no limit" otherwise.      |
| `thread_oversubscription` | 4 workers x one thread per core: every thread gets a quarter of a core.                    |
| `serialized_workers`      | Four workers share one lock and take turns, using one core together.                       |
| `undersized_pool`         | 8 workers, 3 chunks of work: five workers idle throughout.                                 |
| `off_cpu_waits`           | Waiting on the network, a lock, `sleep`, a subprocess and `select`, with almost no CPU.    |
| `busy_polling`            | A full core spent polling `get_nowait`, then the same wait done with a blocking `get`.     |
| `disk_bound`              | Writing and reading 1 GiB: low CPU, high disk throughput.                                  |
| `workers_reread_input`    | Every worker reads the whole input. Mostly page-cache hits, so `read_bytes` hides it.      |
| `cpu_quota`               | One thread per core under a CPU quota. Needs `--cpus`, records "no quota" otherwise.       |
| `import_cost`             | A module that computes at import time, re-imported by every `spawn` worker.                |
| `thread_leak`             | Every request starts a thread that never stops.                                            |
| `subprocess_storm`        | 1000 tiny shell commands, each far shorter than a sampling interval.                       |
| `lingering_children`      | A child outlives its job, a double-forked daemon is reparented out of the tree.            |
| `slow_shutdown`           | Exit waits for a non-daemon thread, then for a slow `atexit` handler.                      |
| `native_child_cpu`        | A busy non-Python child: CPU without stacks, by design rather than by failure.            |
| `sampler_overload`        | 400 threads with deep stacks make sampling slower than the interval (with `--interval 20`). |
| `sparse_stacks`           | CPU bursts shorter than a sampling interval.                                               |
| `slow_patterns`           | `re` cache misses, `deepcopy`, eager `__repr__` in logging, `inspect.stack`, `json`, polars `map_elements`. |

## Real projects

[`realworld/`](realworld/) profiles pinned projects and compares process-tree CPU and peak memory with kernel measurements. It also checks process discovery, stacks and the Firefox export.

```bash
./stress-tests/run.sh --realworld
./stress-tests/run.sh --realworld pytest_sympy
```

This builds `Dockerfile.realworld`, needs a few GiB and takes a few minutes. It is excluded from the default suite and CI. Results are written to `results/realworld/`.

| Scenario         | Project                                                                |
|------------------|------------------------------------------------------------------------|
| `black_django`   | black checks Django's source tree with a pool of four workers.         |
| `pytest_sympy`   | SymPy's polynomial tests: CPU-bound Python with deep stacks.           |
| `pytest_polars`  | polars' unit tests, with `--native all`.                               |
| `pytest_sklearn` | scikit-learn's tests: workers start joblib processes and BLAS threads. |
| `pytest_pandas`  | pandas' tests: memory use grows to over a GiB.                         |
| `pip_install`    | A virtual environment and `pip install`: spawns many short programs.   |

## Adding a scenario

Add a script to `scenarios/` using `Truth`, `truth.phase(name, checks=[...])` and `truth.save()`. See the `check_*` functions in `suite.py` for available checks and their ground-truth fields. Add any extra profiler arguments to `PROFILER_ARGS` there.
