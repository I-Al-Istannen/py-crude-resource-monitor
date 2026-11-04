use crate::memory_sampler::MemorySampler;
use crate::resources::SystemMeasurements;
use crate::samples::{SampleFile, StackTable, write_line};
use crate::stacktraces::{SpyHelper, StackBackend, StackSampler};
use crate::tachyon::{TachyonError, TachyonHelper};
use crate::types::{JsonLine, MemorySample, ProcessMetadata, ProcessResources, StackTrace};
use log::{info, trace};
use snafu::{Location, ResultExt, Snafu};
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
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

#[derive(Clone, Debug)]
struct WriteRequest {
    /// The sample file, e.g. `42` or `global`
    file_name: String,
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
        record_pss: bool,
        memory_interval: Option<Duration>,
        compress: bool,
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

        let spies = match backend {
            StackBackend::PySpy {
                native_capture,
                nonblocking,
            } => StackSampler::PySpy(SpyHelper::new(*native_capture, *nonblocking)),
            StackBackend::Tachyon { python, pause } => {
                StackSampler::Tachyon(TachyonHelper::new(python, *pause).context(TachyonSnafu)?)
            }
        };

        let (tx, rx) = mpsc::sync_channel::<WriteRequest>(100);

        let writer_thread = thread::spawn(move || write_samples(rx, output_dir, compress));

        Ok(Self {
            processes,
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
            .get_stacktraces(self.processes.keys().map(|pid| pid.as_u32() as py_spy::Pid))
            .context(TachyonSnafu)?;
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
                file_name: pid.to_string(),
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
            file_name: "global".to_string(),
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

fn write_samples(
    rx: mpsc::Receiver<WriteRequest>,
    output_dir: PathBuf,
    compress: bool,
) -> Result<(), TrackerError> {
    let mut open_files: HashMap<String, SampleFile> = HashMap::new();
    let mut line_indices: HashMap<String, usize> = HashMap::new();
    // Kept when closing files, the frames and stacks in them stay valid
    let mut stack_tables: HashMap<String, StackTable> = HashMap::new();

    let result = (|| {
        while let Ok(req) = rx.recv() {
            let name = req.file_name;
            let path = output_dir.join(&name);
            trace!("Writing stacktraces to {path:?}");

            if !open_files.contains_key(&name) && open_files.len() >= MAX_OPEN_FILES {
                // Files of processes that are still alive will be reopened on their next sample
                close_all(&mut open_files, &output_dir)?;
            }
            let file = match open_files.entry(name.clone()) {
                Entry::Occupied(entry) => entry.into_mut(),
                Entry::Vacant(entry) => entry.insert(
                    SampleFile::open(&output_dir, &name, compress)
                        .context(WriteSamplesSnafu { path: path.clone() })?,
                ),
            };
            let line_index = line_indices.entry(name.clone()).or_insert(0);
            let stack_table = stack_tables.entry(name).or_default();

            let stacktraces = req
                .stacktraces
                .into_iter()
                .map(|trace| stack_table.store(trace, &mut *file))
                .collect::<Result<_, _>>()
                .context(SerializeSampleSnafu)?;
            let line = JsonLine {
                stacktraces,
                stacktrace_error: req.stacktrace_error,
                resources: req.resources,
                process: req.process,
                memory_samples: req.memory_samples,
                index: *line_index,
                time: req.time,
            };
            // The frames and stacks of the sample are flushed with it, so the file stays readable
            write_line(&mut *file, &line).context(SerializeSampleSnafu)?;
            file.flush_lines().context(WriteSamplesSnafu { path })?;

            *line_index += 1;
        }
        Ok(())
    })();

    // Also close the files if writing failed, so the samples written so far can be read
    let closed = close_all(&mut open_files, &output_dir);
    result.and(closed)
}

fn close_all(
    open_files: &mut HashMap<String, SampleFile>,
    output_dir: &Path,
) -> Result<(), TrackerError> {
    let mut result = Ok(());
    for (name, file) in open_files.drain() {
        let closed = file.close().context(WriteSamplesSnafu {
            path: output_dir.join(name),
        });
        result = result.and(closed);
    }
    result
}
