use crate::types::NativeCapture;
use log::{debug, info, warn};
use py_spy::{Config, PythonSpy, StackTrace};
use snafu::{Location, ResultExt, Snafu};
use std::collections::HashMap;

/// How often we try to attach to a child process before giving up on it. Freshly spawned Python
/// processes might not have initialized their interpreter yet, so the first attempts can fail.
const MAX_ATTACH_ATTEMPTS: u32 = 5;

#[derive(Debug, Snafu)]
pub enum PySpyError {
    #[snafu(display("Error creating py-spy at {location}"))]
    Create {
        source: anyhow::Error,
        #[snafu(implicit)]
        location: Location,
    },
}

pub struct SpyHelper {
    spies: HashMap<py_spy::Pid, PythonSpy>,
    /// Child processes we could not attach to, with the number of failed attempts
    failed_attaches: HashMap<py_spy::Pid, u32>,
    py_spy_config: Config,
}

impl SpyHelper {
    pub fn new(root: py_spy::Pid, native_capture: NativeCapture) -> Result<Self, PySpyError> {
        let mut helper = Self {
            spies: HashMap::new(),
            failed_attaches: HashMap::new(),
            py_spy_config: Config {
                native: native_capture.python_stacks(),
                native_all: native_capture.everything(),
                ..Default::default()
            },
        };
        helper.track_process(root)?;

        Ok(helper)
    }

    pub fn any_live(&self) -> bool {
        !self.spies.is_empty()
    }

    pub fn refresh(&mut self) {
        let mut to_remove = Vec::new();
        let mut new_processes = Vec::new();

        for spy in self.spies.values() {
            if let Ok(children) = spy.process.child_processes() {
                for (child, _) in children {
                    if self.spies.contains_key(&child) {
                        continue;
                    }
                    let attempts = self.failed_attaches.get(&child).copied().unwrap_or(0);
                    if attempts >= MAX_ATTACH_ATTEMPTS {
                        continue;
                    }
                    new_processes.push(child);
                }
            }
            if let Err(e) = spy.process.exe() {
                info!("Tracked process exited: {e}");
                to_remove.push(spy.pid);
            }
        }

        // Clean up exited processes
        for pid in to_remove {
            self.spies.remove(&pid);
        }

        // Add new processes
        new_processes.sort_unstable();
        new_processes.dedup();
        for pid in new_processes {
            match self.track_process(pid) {
                Ok(()) => {
                    self.failed_attaches.remove(&pid);
                    info!("Tracking new process {pid}");
                }
                Err(e) => {
                    let attempts = self.failed_attaches.entry(pid).or_insert(0);
                    *attempts += 1;
                    if *attempts >= MAX_ATTACH_ATTEMPTS {
                        warn!(
                            "Giving up on process {pid} after {attempts} attempts, \
                            it is probably not a Python process: {e}"
                        );
                    } else {
                        debug!("Error tracking process {pid} (attempt {attempts}): {e}");
                    }
                }
            }
        }

        debug!("Tracking {} processes", self.spies.len());
    }

    fn track_process(&mut self, pid: py_spy::Pid) -> Result<(), PySpyError> {
        let spy = PythonSpy::new(pid, &self.py_spy_config).context(CreateSnafu)?;

        self.spies.insert(pid, spy);

        Ok(())
    }

    /// Captures the stacktraces of all tracked processes. A failed capture is returned as an
    /// error message, so callers can still record the other data for that process.
    pub fn get_stacktraces(&mut self) -> HashMap<py_spy::Pid, Result<Vec<StackTrace>, String>> {
        let mut all_traces = HashMap::new();

        for spy in self.spies.values_mut() {
            let process_traces = spy.get_stack_traces().map_err(|e| {
                info!("Sample error {}: {:?}", spy.pid, e);
                format!("{e:#}")
            });
            all_traces.insert(spy.pid, process_traces);
        }

        all_traces
    }
}
