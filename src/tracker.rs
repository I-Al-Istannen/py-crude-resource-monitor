use crate::memory_sampler::MemorySampler;
use crate::resources::SystemMeasurements;
use crate::stacktraces::SpyHelper;
use crate::types::{JsonLine, MemorySample, NativeCapture, ProcessMetadata, ProcessResources};
use log::{info, trace};
use py_spy::StackTrace;
use snafu::{Location, ResultExt, Snafu};
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::PathBuf;
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

#[derive(Clone, Debug)]
struct WriteRequest {
    output_path: PathBuf,
    resources: ProcessResources,
    process: Option<ProcessMetadata>,
    memory_samples: Vec<MemorySample>,
    stacktraces: Vec<StackTrace>,
    stacktrace_error: Option<String>,
    time: u128,
}

pub struct Tracker {
    /// The root process and its descendants that were alive during the last tick
    processes: HashMap<sysinfo::Pid, ProcessMetadata>,
    spies: SpyHelper,
    system: SystemMeasurements,
    memory_sampler: Option<MemorySampler>,
    output_dir: PathBuf,
    writer_channel: mpsc::SyncSender<WriteRequest>,
    writer_thread: thread::JoinHandle<Result<(), TrackerError>>,
}

impl Tracker {
    pub fn new(
        pid: u32,
        output_dir: PathBuf,
        native_capture: NativeCapture,
        record_pss: bool,
        memory_interval: Option<Duration>,
    ) -> Result<Self, TrackerError> {
        let mut system = SystemMeasurements::new(record_pss).context(SystemMeasurementsSnafu)?;
        system.refresh();
        let processes = system.process_tree([(sysinfo::Pid::from_u32(pid), None)]);
        if processes.is_empty() {
            return ProcessNotFoundSnafu { pid }.fail();
        }

        let memory_sampler = memory_interval
            .map(MemorySampler::new)
            .transpose()
            .context(SystemMeasurementsSnafu)?;

        let (tx, rx) = mpsc::sync_channel::<WriteRequest>(100);

        let writer_thread = thread::spawn(move || write_samples(rx));

        Ok(Self {
            processes,
            spies: SpyHelper::new(native_capture),
            system,
            memory_sampler,
            output_dir,
            writer_channel: tx,
            writer_thread,
        })
    }

    pub fn is_still_tracking(&self) -> bool {
        !self.processes.is_empty()
    }

    pub fn tick(&mut self) -> Result<(), TrackerError> {
        self.system.refresh();
        let new_processes = self.update_processes();
        if let Some(sampler) = &self.memory_sampler {
            sampler.set_pids(self.processes.keys().copied());
        }

        let query_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis();

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
            self.send(WriteRequest {
                output_path: self.output_dir.join(format!("{pid}.json")),
                resources: info,
                process: Some(metadata.clone()),
                memory_samples,
                stacktraces,
                stacktrace_error,
                time: query_time,
            })?;
        }

        let global_resources = self.system.get_global_info();
        self.send(WriteRequest {
            output_path: self.output_dir.join("global.json"),
            resources: global_resources,
            process: None,
            memory_samples: vec![],
            stacktraces: vec![],
            stacktrace_error: None,
            time: query_time,
        })
    }

    /// Updates the tracked processes to the ones still alive and their descendants.
    /// Returns the processes that were not alive during the previous tick.
    fn update_processes(&mut self) -> HashSet<sysinfo::Pid> {
        let current = self.system.process_tree(
            self.processes
                .iter()
                .map(|(pid, metadata)| (*pid, Some(metadata.start_time))),
        );

        let mut new_processes = HashSet::new();
        for (pid, metadata) in &current {
            match self.processes.get(pid) {
                Some(previous) if previous.start_time == metadata.start_time => {}
                previous => {
                    if previous.is_some() {
                        // The pid was reused, we must not keep using the old spy
                        self.spies.forget(pid.as_u32() as py_spy::Pid);
                    }
                    info!("Tracking new process {pid} ({})", metadata.name);
                    new_processes.insert(*pid);
                }
            }
        }
        for pid in self.processes.keys() {
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

        new_processes
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

/// Upper bound for cached file handles, so runs with many short-lived processes do not exhaust the
/// file descriptor limit
const MAX_OPEN_FILES: usize = 64;

fn write_samples(rx: mpsc::Receiver<WriteRequest>) -> Result<(), TrackerError> {
    let mut open_files: HashMap<PathBuf, BufWriter<File>> = HashMap::new();
    let mut line_indices: HashMap<PathBuf, usize> = HashMap::new();

    while let Ok(req) = rx.recv() {
        let path = req.output_path;
        trace!("Writing stacktraces to {path:?}");

        if !open_files.contains_key(&path) && open_files.len() >= MAX_OPEN_FILES {
            // Every line is flushed after writing, so we can just close all files. Files of
            // processes that are still alive will be reopened on their next sample.
            open_files.clear();
        }
        let file = match open_files.entry(path.clone()) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                let file = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&path)
                    .context(WriteSamplesSnafu { path: path.clone() })?;
                entry.insert(BufWriter::new(file))
            }
        };
        let line_index = line_indices.entry(path.clone()).or_insert(0);

        let line = JsonLine {
            stacktraces: req.stacktraces.into_iter().map(|s| s.into()).collect(),
            stacktrace_error: req.stacktrace_error,
            resources: req.resources,
            process: req.process,
            memory_samples: req.memory_samples,
            index: *line_index,
            time: req.time,
        };
        serde_json::to_writer(&mut *file, &line).context(SerializeSampleSnafu)?;
        file.write_all(b"\n")
            .and_then(|_| file.flush())
            .context(WriteSamplesSnafu { path })?;

        *line_index += 1;
    }

    Ok(())
}
