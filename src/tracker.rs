mod writer;

use self::writer::{WriteRequest, write_samples};
use crate::memory_sampler::MemorySampler;
use crate::resources::SystemMeasurements;
use crate::stacktraces::{SpyHelper, StackBackend, StackSampler};
use crate::tachyon::{TachyonError, TachyonHelper};
use crate::types::{MemorySample, ProcessMetadata, ProcessResources};
use log::info;
use snafu::{Location, ResultExt, Snafu};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, SystemTime};
use std::{sync, thread};
use sync::mpsc;

#[derive(Debug, Snafu)]
pub enum TrackerError {
    #[snafu(display("Could not find process {pid} at {location}"))]
    ProcessNotFound {
        pid: u32,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Error capturing stacks with tachyon at {location}"))]
    Tachyon {
        source: TachyonError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Error initializing system measurements at {location}"))]
    SystemMeasurements {
        source: sysinfo::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Error writing samples to `{}` at {location}", path.display()))]
    WriteSamples {
        source: std::io::Error,
        path: PathBuf,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Error serializing sample at {location}"))]
    SerializeSample {
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("The sample writer thread stopped unexpectedly at {location}"))]
    WriterGone {
        #[snafu(implicit)]
        location: Location,
    },
}

pub struct RecordingOptions {
    pub record_pss: bool,
    pub memory_interval: Option<Duration>,
    pub compress: bool,
}

pub struct Tracker {
    /// The root process and its descendants that were alive during the last tick
    processes: HashMap<sysinfo::Pid, ProcessMetadata>,
    /// The resources of each process in the last tick, without its threads
    last_resources: HashMap<sysinfo::Pid, ProcessResources>,
    spies: StackSampler,
    system: SystemMeasurements,
    memory_sampler: Option<MemorySampler>,
    writer_channel: mpsc::SyncSender<WriteRequest>,
    writer_thread: thread::JoinHandle<Result<(), TrackerError>>,
}

impl Tracker {
    pub fn new(
        pid: u32,
        output_dir: PathBuf,
        backend: &StackBackend,
        options: RecordingOptions,
        quit_requested: Arc<AtomicBool>,
    ) -> Result<Self, TrackerError> {
        let mut system =
            SystemMeasurements::new(options.record_pss).context(SystemMeasurementsSnafu)?;
        system.refresh();
        let processes = system.process_tree([(sysinfo::Pid::from_u32(pid), None)]);
        if processes.is_empty() {
            return ProcessNotFoundSnafu { pid }.fail();
        }

        let memory_sampler = options
            .memory_interval
            .map(MemorySampler::new)
            .transpose()
            .context(SystemMeasurementsSnafu)?;

        let spies = match backend {
            StackBackend::PySpy {
                native_capture,
                nonblocking,
            } => StackSampler::PySpy(SpyHelper::new(*native_capture, *nonblocking)),
            StackBackend::Tachyon { python, pause } => StackSampler::Tachyon(
                TachyonHelper::new(python, *pause, quit_requested).context(TachyonSnafu)?,
            ),
        };

        let (tx, rx) = mpsc::sync_channel::<WriteRequest>(100);

        let writer_thread = thread::spawn(move || write_samples(rx, output_dir, options.compress));

        Ok(Self {
            processes,
            last_resources: HashMap::new(),
            spies,
            system,
            memory_sampler,
            writer_channel: tx,
            writer_thread,
        })
    }

    pub fn is_still_tracking(&self) -> bool {
        !self.processes.is_empty()
    }

    pub fn tick(&mut self) -> Result<(), TrackerError> {
        self.system.refresh();
        let (new_processes, exited_processes) = self.update_processes();
        let exit_memory_samples = match &self.memory_sampler {
            Some(sampler) => sampler.set_processes(
                self.processes
                    .iter()
                    .map(|(pid, metadata)| (*pid, metadata.start_time)),
            ),
            None => HashMap::new(),
        };

        let query_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis();

        self.write_exit_memory_samples(exited_processes, exit_memory_samples)?;

        let mut traces = self
            .spies
            .get_stacktraces(self.processes.keys().map(|pid| pid.as_u32() as py_spy::Pid));
        for (pid, metadata) in &self.processes {
            let Some(info) = self
                .system
                .get_process_info(*pid, new_processes.contains(pid))
            else {
                continue;
            };
            let traces = traces
                .remove(&(pid.as_u32() as py_spy::Pid))
                .unwrap_or_else(|| Err("Not attached".to_string()));

            // Record the resources even if the stack capture failed, so the graph has no gaps
            let (stacktraces, stacktrace_error) = match traces {
                Ok(traces) => (traces, None),
                Err(e) => (vec![], Some(e)),
            };
            let memory_samples = match &self.memory_sampler {
                Some(sampler) => sampler.take(*pid, query_time),
                None => vec![],
            };
            self.last_resources.insert(
                *pid,
                ProcessResources {
                    thread_resources: HashMap::new(),
                    ..info.clone()
                },
            );
            self.send(WriteRequest {
                file_name: pid.to_string(),
                resources: info,
                process: Some(metadata.clone()),
                memory_samples,
                stacktraces,
                stacktrace_error,
                exited: false,
                time: query_time,
            })?;
        }

        let global_resources = self.system.get_global_info();
        self.send(WriteRequest {
            file_name: "global".to_string(),
            resources: global_resources,
            process: None,
            memory_samples: vec![],
            stacktraces: vec![],
            stacktrace_error: None,
            exited: false,
            time: query_time,
        })
    }

    /// Writes the memory measured between the previous tick and the exit of a process, which would
    /// be lost otherwise. See [`crate::types::JsonLine::exited`].
    fn write_exit_memory_samples(
        &mut self,
        exited_processes: HashMap<sysinfo::Pid, ProcessMetadata>,
        mut memory_samples: HashMap<sysinfo::Pid, Vec<MemorySample>>,
    ) -> Result<(), TrackerError> {
        for (pid, metadata) in exited_processes {
            let last_resources = self.last_resources.remove(&pid);
            let (Some(last_resources), Some(memory_samples)) =
                (last_resources, memory_samples.remove(&pid))
            else {
                continue;
            };
            let Some(&last_sample) = memory_samples.last() else {
                continue;
            };
            let resources = ProcessResources {
                memory: last_sample.memory,
                cpu: 0.0,
                disk_read_bytes: 0,
                disk_write_bytes: 0,
                ..last_resources
            };
            self.send(WriteRequest {
                file_name: pid.to_string(),
                resources,
                process: Some(metadata),
                memory_samples,
                stacktraces: vec![],
                stacktrace_error: None,
                exited: true,
                time: last_sample.time,
            })?;
        }
        Ok(())
    }

    /// Updates the tracked processes to the ones still alive and their descendants.
    /// Returns the processes that were not alive during the previous tick, and the ones that
    /// exited since.
    fn update_processes(
        &mut self,
    ) -> (
        HashSet<sysinfo::Pid>,
        HashMap<sysinfo::Pid, ProcessMetadata>,
    ) {
        let current = self.system.process_tree(
            self.processes
                .iter()
                .map(|(pid, metadata)| (*pid, Some(metadata.start_time))),
        );

        let (new_processes, exited_processes) = process_changes(&self.processes, &current);
        for pid in &new_processes {
            let name = &current[pid].name;
            if let Some(previous) = self.processes.get(pid) {
                info!(
                    "Tracked process {pid} ({}) exited, its pid now belongs to {name}",
                    previous.name
                );
                self.spies.forget(pid.as_u32() as py_spy::Pid);
                self.system.forget_process(*pid);
            } else {
                info!("Tracking new process {pid} ({name})");
            }
        }
        for pid in exited_processes.keys() {
            if !current.contains_key(pid) {
                info!("Tracked process {pid} exited");
            }
        }

        self.spies.sync(
            &current
                .keys()
                .map(|pid| pid.as_u32() as py_spy::Pid)
                .collect(),
        );
        self.processes = current;

        (new_processes, exited_processes)
    }

    /// Queues a sample for writing. If this fails, the writer thread has stopped and [`Self::finish`]
    /// returns the reason.
    fn send(&self, request: WriteRequest) -> Result<(), TrackerError> {
        self.writer_channel
            .send(request)
            .map_err(|_| WriterGoneSnafu.build())
    }

    /// Stops the writer thread, waiting until all queued samples are written to disk.
    pub fn finish(self) -> Result<(), TrackerError> {
        drop(self.writer_channel);
        match self.writer_thread.join() {
            Ok(res) => res,
            Err(panic) => std::panic::resume_unwind(panic),
        }
    }
}

/// A replacement is both the exit of the previous process and the start of the new one.
fn process_changes(
    previous: &HashMap<sysinfo::Pid, ProcessMetadata>,
    current: &HashMap<sysinfo::Pid, ProcessMetadata>,
) -> (
    HashSet<sysinfo::Pid>,
    HashMap<sysinfo::Pid, ProcessMetadata>,
) {
    let same_process = |pid: &sysinfo::Pid,
                        metadata: &ProcessMetadata,
                        other: &HashMap<sysinfo::Pid, ProcessMetadata>| {
        other
            .get(pid)
            .is_some_and(|other| other.start_time == metadata.start_time)
    };
    let started = current
        .iter()
        .filter(|(pid, metadata)| !same_process(pid, metadata, previous))
        .map(|(pid, _)| *pid)
        .collect();
    let exited = previous
        .iter()
        .filter(|(pid, metadata)| !same_process(pid, metadata, current))
        .map(|(pid, metadata)| (*pid, metadata.clone()))
        .collect();
    (started, exited)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pid_replacement_is_an_exit_and_a_start() {
        let pid = sysinfo::Pid::from_u32(42);
        let old = ProcessMetadata {
            name: "old".into(),
            parent_pid: None,
            start_time: 1,
        };
        let new = ProcessMetadata {
            name: "new".into(),
            parent_pid: None,
            start_time: 2,
        };
        let previous = HashMap::from([(pid, old.clone())]);
        assert_eq!(
            process_changes(&previous, &previous),
            (HashSet::new(), HashMap::new())
        );
        assert_eq!(
            process_changes(&previous, &HashMap::from([(pid, new)])),
            (HashSet::from([pid]), HashMap::from([(pid, old)]))
        );
    }
}
