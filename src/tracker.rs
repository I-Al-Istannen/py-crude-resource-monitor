use crate::resources::{ProcessResources, SystemMeasurements};
use crate::stacktraces::SpyHelper;
use log::trace;
use py_spy::StackTrace;
use serde::Serialize;
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::{sync, thread};
use sync::mpsc;

#[derive(Serialize)]
struct JsonLine {
    stacktraces: Vec<StackTrace>,
    resources: ProcessResources,
    index: usize,
}

type WriteRequest = (PathBuf, ProcessResources, Vec<StackTrace>);

pub struct Tracker {
    spies: SpyHelper,
    system: SystemMeasurements,
    output_dir: PathBuf,
    writer_channel: mpsc::SyncSender<WriteRequest>,
}

impl Tracker {
    pub fn new(pid: u32, output_dir: PathBuf, capture_native: bool) -> anyhow::Result<Self> {
        let system = SystemMeasurements::new();
        let spy_helper = SpyHelper::new(pid as py_spy::Pid, capture_native)?;

        let (tx, rx) = mpsc::sync_channel::<WriteRequest>(100);

        thread::spawn(move || {
            let mut file_lines = HashMap::new();

            while let Ok((path, resources, stacktraces)) = rx.recv() {
                let line_index = file_lines.entry(path.clone()).or_insert(0);

                trace!("Writing stacktraces to {:?}", path);
                let mut file = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&path)
                    .unwrap();
                let line = JsonLine {
                    stacktraces,
                    resources,
                    index: *line_index,
                };
                file.write_all(serde_json::to_string(&line).unwrap().as_bytes())
                    .expect("Write succeeds");
                file.write_all(b"\n").expect("Write succeeds");

                *line_index += 1;
            }
        });

        Ok(Tracker {
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

        for (pid, threads) in self.spies.get_stacktraces() {
            let Some(info) = self
                .system
                .get_process_info(sysinfo::Pid::from_u32(pid as u32))
            else {
                continue;
            };

            self.writer_channel
                .send((
                    self.output_dir.join(format!("{}.json", pid)),
                    info,
                    threads.clone(),
                ))
                .expect("Send succeeds");
        }
    }
}