"""Every batch leaves 12 MiB behind in a module-level list.

Finding: "Growth per loop iteration". The same stack (`run → handle_batch`) repeats 25 times and
memory rises by the same step each time, although `handle_batch` is meant to be stateless. There
are no pauses between the batches, so there are no baselines between batches to compare either.
Rule: a stack that recurs regularly, with the memory at its occurrences on a rising line
(slope > 0, R² > 0.9).
"""

from _truth import MiB, Truth, burn_python, rss_bytes, touched_buffer

truth = Truth(__doc__)
_seen = []


def handle_batch():
    payload = touched_buffer(40 * MiB)
    burn_python(0.3)
    # The bug: meant as a small "seen" marker, but keeps a slice of the payload alive
    _seen.append(bytes(payload[: 12 * MiB]))


def run(batches: int) -> list[int]:
    rss = []
    for _ in range(batches):
        handle_batch()
        rss.append(rss_bytes())
    return rss


with truth.phase(
    "run: 25 batches",
    checks=[{"type": "growth_attribution", "function": "handle_batch"}],
    finding="growth_per_iteration",
) as phase:
    phase["rss_after_each_batch"] = run(25)

truth.save()
