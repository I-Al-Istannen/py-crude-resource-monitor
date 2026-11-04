"""Memory grows in steps while one function runs, is held while another one runs, then freed.

Shows: RSS follows the real allocation closely, and the stack traces of the samples where memory
grows point at the function responsible for the growth.
"""

import gc
import time

from _truth import MiB, Truth, touched_buffer

truth = Truth(__doc__)


def load_dataset(chunks: int, chunk_size: int) -> list:
    data = []
    for _ in range(chunks):
        data.append(touched_buffer(chunk_size))
        time.sleep(0.75)
    return data


def process_dataset(data: list):
    time.sleep(3)


with truth.phase("baseline", checks=[{"type": "memory"}]):
    time.sleep(2)

with truth.phase(
    "load_dataset: 4 x 150 MiB",
    checks=[{"type": "growth_attribution", "function": "load_dataset"}],
):
    dataset = load_dataset(4, 150 * MiB)

with truth.phase(
    "process_dataset holds 600 MiB",
    checks=[{"type": "memory"}, {"type": "stack", "function": "process_dataset"}],
):
    process_dataset(dataset)

with truth.phase("dataset freed", checks=[{"type": "memory"}]):
    del dataset
    gc.collect()
    time.sleep(2)

truth.save()
