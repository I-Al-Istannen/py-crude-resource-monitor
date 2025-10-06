use crate::types::NativeCapture;
use log::{debug, info};
use py_spy::{Config, PythonSpy, StackTrace};
use snafu::{Location, ResultExt, Snafu};
use std::collections::HashMap;

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
    py_spy_config: Config,
}

impl SpyHelper {
    pub fn new(root: py_spy::Pid, native_capture: NativeCapture) -> Result<Self, PySpyError> {
        let mut helper = Self {
            spies: HashMap::new(),
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
        for pid in new_processes {
            if let Err(e) = self.track_process(pid) {
                info!("Error tracking process {pid}: {e}");
            }
            info!("Tracking new process {pid}");
        }

        debug!("Tracking {} processes", self.spies.len());
    }

    fn track_process(&mut self, pid: py_spy::Pid) -> Result<(), PySpyError> {
        let spy = PythonSpy::new(pid, &self.py_spy_config).context(CreateSnafu)?;

        self.spies.insert(pid, spy);

        Ok(())
    }

    pub fn get_stacktraces(&mut self) -> HashMap<py_spy::Pid, Vec<StackTrace>> {
        let mut all_traces = HashMap::new();

        for spy in self.spies.values_mut() {
            let process_traces = spy.get_stack_traces();
            if let Err(e) = process_traces {
                info!("Sample error {}: {:?}", spy.pid, e);
                // This might cause null values in the output (i.e. we miss a timestep)!
                // The viewer must account for that.
                continue;
            }
            all_traces.insert(spy.pid, process_traces.unwrap());
        }

        all_traces
    }
}
