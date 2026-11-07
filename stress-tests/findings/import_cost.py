"""A module that computes a table at import time, used by a pool with the `spawn` start method.

Finding: "Import cost". The parent spends its first seconds in `<module>` and importlib frames
(`_find_and_load`), and with `spawn` every worker pays the same cost again before it does any work,
since it imports the main module and everything it imports from scratch.
Rule: the first seconds of a process are dominated by `<module>`/`importlib._bootstrap` frames.
"""

import multiprocessing

from _truth import Truth

if __name__ == "__main__":
    truth = Truth(__doc__)
    with truth.phase(
        "parent imports _heavy_module",
        checks=[{"type": "stack", "function": "build_lookup_table", "min_fraction": 0.7}],
        finding="import_cost",
    ):
        import _heavy_module

    with multiprocessing.get_context("spawn").Pool(4) as pool:
        results = pool.map(_heavy_module.transform, range(4), chunksize=1)

    for result in results:
        truth.add_phase(
            {
                "name": f"spawned worker {result['pid']} imports it again",
                **result,
                # The profiler needs a moment to discover the new process
                "checks": [{"type": "stack", "function": "build_lookup_table", "min_fraction": 0.6}],
                "finding": "import_cost",
            }
        )
    truth.save()
