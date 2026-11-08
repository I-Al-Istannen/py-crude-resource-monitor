use crate::types::JsonLine;
use std::collections::BTreeMap;

/// One profiled process. The samples of a pid can belong to several processes over time.
pub(super) struct Instance {
    pub(super) pid: u32,
    /// Never empty
    pub(super) samples: Vec<JsonLine>,
}

impl Instance {
    /// Splits the samples of one pid into the processes that used it.
    pub(super) fn split(pid: u32, samples: Vec<JsonLine>) -> Vec<Self> {
        let mut instances: Vec<Self> = Vec::new();
        for line in samples {
            match instances.last_mut() {
                Some(last)
                    if last.start_time() == line.process.as_ref().map(|it| it.start_time) =>
                {
                    last.samples.push(line)
                }
                _ => instances.push(Self {
                    pid,
                    samples: vec![line],
                }),
            }
        }
        instances
    }

    pub(super) fn start(&self) -> u128 {
        self.samples[0].time
    }

    pub(super) fn end(&self) -> u128 {
        self.samples[self.samples.len() - 1].time
    }

    fn start_time(&self) -> Option<u64> {
        self.samples[0].process.as_ref().map(|it| it.start_time)
    }

    pub(super) fn name(&self) -> &str {
        self.samples[0]
            .process
            .as_ref()
            .map_or("Process", |it| it.name.as_str())
    }

    pub(super) fn has_stacktraces(&self) -> bool {
        self.samples.iter().any(|it| !it.stacktraces.is_empty())
    }

    /// Only Tachyon knows whether threads wait for the GIL
    pub(super) fn waits_for_gil(&self) -> bool {
        self.samples
            .iter()
            .flat_map(|it| &it.stacktraces)
            .any(|it| it.waiting_for_gil)
    }
}

/// Packs processes into lanes, see [`super::ProcessLanes`]. Processes running for more than half
/// of the profile keep their own track.
pub(super) fn pack_processes(
    instances: Vec<Instance>,
    profile_duration: u128,
) -> Vec<Vec<Instance>> {
    let mut lanes = Vec::new();
    let mut groups: BTreeMap<(Option<u32>, String), Vec<Instance>> = BTreeMap::new();
    for instance in instances {
        let long_lived = (instance.end() - instance.start()) * 2 > profile_duration;
        match &instance.samples[0].process {
            Some(metadata) if !long_lived => groups
                .entry((metadata.parent_pid, metadata.name.clone()))
                .or_default()
                .push(instance),
            _ => lanes.push(vec![instance]),
        }
    }

    for group in groups.into_values() {
        let first_lane = lanes.len();
        let mut lane_ends = Vec::new();
        // The instances are sorted by start time
        for instance in group {
            let lane = first_lane + assign_lane(&mut lane_ends, instance.start(), instance.end());
            if lane == lanes.len() {
                lanes.push(Vec::new());
            }
            lanes[lane].push(instance);
        }
    }
    // Only the main threads of the first lanes are visible, see `set_visible_threads`
    lanes.sort_by_key(|lane| (lane[0].start(), lane[0].pid));

    lanes
}

/// Returns the first lane that is free at `start` and occupies it until `end`. Lanes are
/// identified by their index in `lane_ends`, which holds when each lane is free again.
pub(super) fn assign_lane(lane_ends: &mut Vec<u128>, start: u128, end: u128) -> usize {
    match lane_ends.iter().position(|lane_end| *lane_end < start) {
        Some(lane) => {
            lane_ends[lane] = end;
            lane
        }
        None => {
            lane_ends.push(end);
            lane_ends.len() - 1
        }
    }
}
