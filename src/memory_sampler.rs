//! Samples the memory of the tracked processes more often than the regular samples, which also
//! capture stacks and are much more expensive. Short allocation spikes would be missed otherwise.

use crate::types::MemorySample;
use std::collections::HashMap;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate};

/// Changes smaller than this are not recorded, so memory that stays flat takes up no space
const MIN_CHANGE_BYTES: u64 = 1024 * 1024;
/// Changes smaller than this fraction of the memory are not recorded either
const MIN_CHANGE_FRACTION: f64 = 0.01;

pub struct MemorySampler {
    state: Arc<Mutex<State>>,
    /// Dropping it stops the sampling thread, even while it waits for the next sample
    stop: Option<mpsc::Sender<()>>,
    thread: Option<thread::JoinHandle<()>>,
}

#[derive(Default)]
struct State {
    pids: Vec<Pid>,
    samples: HashMap<Pid, Recorder>,
}

impl MemorySampler {
    pub fn new(interval: Duration) -> Result<Self, sysinfo::Error> {
        let system = sysinfo::System::new()?;
        let state = Arc::new(Mutex::new(State::default()));
        let (stop, stopped) = mpsc::channel();
        let thread = {
            let state = state.clone();
            thread::spawn(move || sample(system, interval, &state, &stopped))
        };
        Ok(Self {
            state,
            stop: Some(stop),
            thread: Some(thread),
        })
    }

    /// Sets the processes to sample. Returns the samples of other processes that were not taken
    /// yet, e.g. the ones from right before a process exited.
    pub fn set_pids(&self, pids: impl IntoIterator<Item = Pid>) -> HashMap<Pid, Vec<MemorySample>> {
        let mut state = self.state.lock().unwrap();
        state.pids = pids.into_iter().collect();
        let State { pids, samples } = &mut *state;
        samples
            .extract_if(|pid, _| !pids.contains(pid))
            .map(|(pid, mut recorder)| (pid, recorder.take(u128::MAX)))
            .filter(|(_, samples)| !samples.is_empty())
            .collect()
    }

    /// Removes and returns the recorded samples of `pid` taken before `until`
    pub fn take(&self, pid: Pid, until: u128) -> Vec<MemorySample> {
        let mut state = self.state.lock().unwrap();
        match state.samples.get_mut(&pid) {
            Some(recorder) => recorder.take(until),
            None => vec![],
        }
    }
}

impl Drop for MemorySampler {
    fn drop(&mut self) {
        drop(self.stop.take());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn sample(
    mut system: sysinfo::System,
    interval: Duration,
    state: &Mutex<State>,
    stopped: &mpsc::Receiver<()>,
) {
    let mut next = Instant::now();
    loop {
        let pids = state.lock().unwrap().pids.clone();
        if !pids.is_empty() {
            system.refresh_processes_specifics(
                ProcessesToUpdate::Some(&pids),
                true,
                ProcessRefreshKind::nothing().with_memory(),
            );
            let mut state = state.lock().unwrap();
            // Taken while holding the lock, so samples added after `take` are not older than the
            // time it took samples until
            let time = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_millis();
            for pid in &pids {
                let Some(process) = system.process(*pid) else {
                    continue;
                };
                // The pid might have been removed while we were measuring
                if !state.pids.contains(pid) {
                    continue;
                }
                let sample = MemorySample {
                    time,
                    memory: process.memory(),
                };
                state.samples.entry(*pid).or_default().add(sample);
            }
        }

        next += interval;
        let now = Instant::now();
        if next < now {
            next = now;
        }
        if let Err(RecvTimeoutError::Disconnected) = stopped.recv_timeout(next - now) {
            return;
        }
    }
}

/// Keeps the samples of one process where its memory changed noticeably
#[derive(Default)]
struct Recorder {
    samples: Vec<MemorySample>,
    /// The last sample we recorded, even if it was already taken
    last_recorded: Option<MemorySample>,
    /// The latest sample, if it was not recorded
    pending: Option<MemorySample>,
    /// How many samples were not recorded since the last recorded one
    skipped: usize,
}

impl Recorder {
    fn add(&mut self, sample: MemorySample) {
        let Some(last) = self.last_recorded else {
            self.record(sample);
            return;
        };
        let change = sample.memory.abs_diff(last.memory);
        let threshold = MIN_CHANGE_BYTES.max((last.memory as f64 * MIN_CHANGE_FRACTION) as u64);
        if change < threshold {
            self.pending = Some(sample);
            self.skipped += 1;
            return;
        }
        // Graphs connect consecutive samples, so after a flat stretch, the memory would seem to
        // change slowly since the last recorded sample without the sample right before the change
        if let Some(pending) = self.pending.take()
            && self.skipped >= 2
        {
            self.record(pending);
        }
        self.record(sample);
    }

    fn record(&mut self, sample: MemorySample) {
        self.samples.push(sample);
        self.last_recorded = Some(sample);
        self.pending = None;
        self.skipped = 0;
    }

    fn take(&mut self, until: u128) -> Vec<MemorySample> {
        let split = self.samples.partition_point(|it| it.time < until);
        self.samples.drain(..split).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: u64 = 1024 * 1024;

    fn sample(time: u128, memory: u64) -> MemorySample {
        MemorySample { time, memory }
    }

    #[test]
    fn records_only_changes_with_the_sample_before_them() {
        let mut recorder = Recorder::default();
        for (time, memory) in [
            (0, 100),
            (10, 100),
            (20, 100),
            (30, 500),
            (40, 100),
            (50, 100),
        ] {
            recorder.add(sample(time, memory * MIB));
        }

        let times = recorder
            .take(u128::MAX)
            .iter()
            .map(|it| it.time)
            .collect::<Vec<_>>();

        assert_eq!(times, [0, 20, 30, 40]);
    }

    #[test]
    fn records_slow_growth_once_it_adds_up() {
        let mut recorder = Recorder::default();
        for time in 0..10 {
            recorder.add(sample(time, 10 * MIB + time as u64 * MIB / 2));
        }

        let memory = recorder
            .take(u128::MAX)
            .iter()
            .map(|it| it.memory)
            .collect::<Vec<_>>();

        assert_eq!(memory, [10 * MIB, 11 * MIB, 12 * MIB, 13 * MIB, 14 * MIB]);
    }

    #[test]
    fn returns_the_samples_of_removed_processes() {
        let sampler = MemorySampler::new(Duration::from_secs(3600)).unwrap();
        let (kept, removed) = (Pid::from_u32(1), Pid::from_u32(2));
        {
            let mut state = sampler.state.lock().unwrap();
            for pid in [kept, removed] {
                state.samples.entry(pid).or_default().add(sample(10, 0));
            }
        }

        let leftovers = sampler.set_pids([kept]);

        assert_eq!(leftovers, HashMap::from([(removed, vec![sample(10, 0)])]));
        assert_eq!(sampler.take(kept, u128::MAX), [sample(10, 0)]);
    }

    #[test]
    fn takes_samples_before_the_given_time() {
        let mut recorder = Recorder::default();
        recorder.add(sample(10, 0));
        recorder.add(sample(20, 100 * MIB));

        assert_eq!(recorder.take(20), [sample(10, 0)]);
        assert_eq!(recorder.take(30), [sample(20, 100 * MIB)]);
    }
}
