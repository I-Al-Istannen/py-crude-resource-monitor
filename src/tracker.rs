use crate::resources::SystemMeasurements;
use crate::stacktraces::{PySpyError, SpyHelper};
use crate::types::{JsonLine, NativeCapture, ProcessResources};
use log::{trace, warn};
use py_spy::StackTrace;
use snafu::{Location, ResultExt, Snafu};
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::time::SystemTime;
use std::{sync, thread};
use sync::mpsc;

#[derive(Debug, Snafu)]
pub enum TrackerError {
    #[snafu(display("Error coming from py-spy at {location}"))]
    PySpy {
        source: PySpyError,
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
    stacktraces: Vec<StackTrace>,
    stacktrace_error: Option<String>,
    time: u128,
}

pub struct Tracker {
    spies: SpyHelper,
    system: SystemMeasurements,
    output_dir: PathBuf,
    writer_channel: mpsc::SyncSender<WriteRequest>,
    writer_thread: thread::JoinHandle<Result<(), TrackerError>>,
}

impl Tracker {
    pub fn new_with_retry(
        pid: u32,
        output_dir: PathBuf,
        native_capture: NativeCapture,
    ) -> Result<Self, TrackerError> {
        let mut last_err = None;
        for _ in 0..5 {
            match Self::new(pid, output_dir.clone(), native_capture) {
                Ok(tracker) => return Ok(tracker),
                Err(e) => {
                    warn!("Got error during attach, will retry. ({e})");
                    last_err = Some(e);
                }
            }
            thread::sleep(std::time::Duration::from_secs(1));
        }
        Err(last_err.unwrap())
    }

    fn new(
        pid: u32,
        output_dir: PathBuf,
        native_capture: NativeCapture,
    ) -> Result<Self, TrackerError> {
        let system = SystemMeasurements::new().context(SystemMeasurementsSnafu)?;
        let spy_helper = SpyHelper::new(pid as py_spy::Pid, native_capture).context(PySpySnafu)?;

        let (tx, rx) = mpsc::sync_channel::<WriteRequest>(100);

        let writer_thread = thread::spawn(move || write_samples(rx));

        Ok(Self {
            spies: spy_helper,
            system,
            output_dir,
            writer_channel: tx,
            writer_thread,
        })
    }

    pub fn is_still_tracking(&self) -> bool {
        self.spies.any_live()
    }

    pub fn tick(&mut self) -> Result<(), TrackerError> {
        self.system.refresh();
        self.spies.refresh();

        let query_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis();

        for (pid, traces) in self.spies.get_stacktraces() {
            let Some(info) = self
                .system
                .get_process_info(sysinfo::Pid::from_u32(pid as u32))
            else {
                continue;
            };

            // Record the resources even if the stack capture failed, so the graph has no gaps
            let (stacktraces, stacktrace_error) = match traces {
                Ok(traces) => (traces, None),
                Err(e) => (vec![], Some(e)),
            };
            self.send(WriteRequest {
                output_path: self.output_dir.join(format!("{pid}.json")),
                resources: info,
                stacktraces,
                stacktrace_error,
                time: query_time,
            })?;
        }

        let global_resources = self.system.get_global_info();
        self.send(WriteRequest {
            output_path: self.output_dir.join("global.json"),
            resources: global_resources,
            stacktraces: vec![],
            stacktrace_error: None,
            time: query_time,
        })
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
