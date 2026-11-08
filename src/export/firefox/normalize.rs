//! Prepare measurements independently of how Firefox renders them.

use super::MemoryMetric;
use crate::types::{JsonLine, MemorySample};
use std::collections::BTreeMap;

/// Retained memory points can arrive in a later sample than their timestamp suggests. Merge
/// the whole instance before computing counter deltas. Regular measurements win timestamp ties.
pub(super) fn memory_timeline(samples: &[JsonLine], metric: MemoryMetric) -> Vec<MemorySample> {
    let mut points = BTreeMap::new();
    if metric == MemoryMetric::Rss {
        for sample in samples.iter().flat_map(|line| &line.memory_samples) {
            points.insert(sample.time, sample.memory);
        }
    }
    for line in samples.iter().filter(|line| !line.exited) {
        let memory = match metric {
            MemoryMetric::Rss => line.resources.memory,
            MemoryMetric::Pss => line.resources.pss.unwrap_or(line.resources.memory),
        };
        points.insert(line.time, memory);
    }
    points
        .into_iter()
        .map(|(time, memory)| MemorySample { time, memory })
        .collect()
}
