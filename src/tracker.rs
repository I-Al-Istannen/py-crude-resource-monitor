use crate::resources::SystemMeasurements;
use crate::stacktraces::{PySpyError, SpyHelper};
use crate::types::{JsonLine, NativeCapture, ProcessResources};
use log::{trace, warn};
use py_spy::StackTrace;
use snafu::{Location, ResultExt, Snafu};
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
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
}

#[derive(Clone, Debug)]
struct WriteRequest {
    output_path: PathBuf,
    resources: ProcessResources,
    stacktraces: Vec<StackTrace>,
    time: u128,
}

pub struct Tracker {
    spies: SpyHelper,
    system: SystemMeasurements,
    output_dir: PathBuf,
    writer_channel: mpsc::SyncSender<WriteRequest>,
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
        let system = SystemMeasurements::new();
        let spy_helper = SpyHelper::new(pid as py_spy::Pid, native_capture).context(PySpySnafu)?;

        let (tx, rx) = mpsc::sync_channel::<WriteRequest>(100);

        thread::spawn(move || {
            let mut file_lines = HashMap::new();

            while let Ok(req) = rx.recv() {
                let path = req.output_path;
                let line_index = file_lines.entry(path.clone()).or_insert(0);

                trace!("Writing stacktraces to {path:?}");
                let mut file = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&path)
                    .unwrap();
                let line = JsonLine {
                    stacktraces: req.stacktraces.into_iter().map(|s| s.into()).collect(),
                    resources: req.resources,
                    index: *line_index,
                    time: req.time,
                };
                file.write_all(serde_json::to_string(&line).unwrap().as_bytes())
                    .expect("Write succeeds");
                file.write_all(b"\n").expect("Write succeeds");

                *line_index += 1;
            }
        });

        Ok(Self {
            spies: spy_helper,
            system,
            output_dir,
            writer_channel: tx,
        })
    }

    pub fn is_still_tracking(&self) -> bool {
        self.spies.any_live()
    }

    pub fn tick(&mut self) {
        self.system.refresh();
        self.spies.refresh();

        let query_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis();

        for (pid, threads) in self.spies.get_stacktraces() {
            let Some(info) = self
                .system
                .get_process_info(sysinfo::Pid::from_u32(pid as u32))
            else {
                continue;
            };

            self.writer_channel
                .send(WriteRequest {
                    output_path: self.output_dir.join(format!("{pid}.json")),
                    resources: info,
                    stacktraces: threads.clone(),
                    time: query_time,
                })
                .expect("Send succeeds");
        }

        self.writer_channel
            .send(WriteRequest {
                output_path: self.output_dir.join("global.json"),
                resources: self.system.get_global_info(),
                stacktraces: vec![],
                time: query_time,
            })
            .expect("Send succeeds");
    }
}
