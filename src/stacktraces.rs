use crate::tachyon::TachyonHelper;
use crate::types::{NativeCapture, StackTrace};
use log::{debug, info, warn};
use py_spy::config::LockingStrategy;
use py_spy::{Config, PythonSpy};
use snafu::{Location, ResultExt, Snafu};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

/// How often we try to attach to a process before giving up on it. Freshly spawned Python
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

/// How to capture the Python stacks
#[derive(Debug)]
pub enum StackBackend {
    PySpy {
        native_capture: NativeCapture,
        nonblocking: bool,
    },
    Tachyon {
        /// The interpreter the Tachyon helper runs on
        python: PathBuf,
        pause: bool,
    },
}

/// Captures Python stacks with py-spy or Tachyon
pub enum StackSampler {
    PySpy(SpyHelper),
    Tachyon(TachyonHelper),
}

impl StackSampler {
    /// Attaches to processes in `pids` we are not attached to yet and forgets all others.
    pub fn sync(&mut self, pids: &HashSet<py_spy::Pid>) {
        match self {
            Self::PySpy(spy) => spy.sync(pids),
            // The helper attaches when it is asked for the stacks
            Self::Tachyon(_) => {}
        }
    }

    /// Forgets a process, e.g. because its pid now belongs to a different process.
    pub fn forget(&mut self, pid: py_spy::Pid) {
        match self {
            Self::PySpy(spy) => spy.forget(pid),
            Self::Tachyon(tachyon) => tachyon.forget(pid),
        }
    }

    /// Captures the stacktraces of all given processes. A failed capture is returned as an error
    /// message, so callers can still record the other data for that process.
    pub fn get_stacktraces(
        &mut self,
        pids: impl Iterator<Item = py_spy::Pid>,
    ) -> HashMap<py_spy::Pid, Result<Vec<StackTrace>, String>> {
        match self {
            Self::PySpy(spy) => spy.get_stacktraces(pids),
            Self::Tachyon(tachyon) => tachyon.get_stacktraces(pids),
        }
    }
}

/// Captures the Python stacks of the processes it is told about. Finding the processes is up to
/// the caller, so processes we cannot attach to are still known.
pub struct SpyHelper {
    spies: HashMap<py_spy::Pid, PythonSpy>,
    /// Processes we could not attach to, with the number of failed attempts and the last error
    failed_attaches: HashMap<py_spy::Pid, (u32, String)>,
    py_spy_config: Config,
}

impl SpyHelper {
    pub fn new(native_capture: NativeCapture, nonblocking: bool) -> Self {
        Self {
            spies: HashMap::new(),
            failed_attaches: HashMap::new(),
            py_spy_config: Config {
                blocking: if nonblocking {
                    LockingStrategy::NonBlocking
                } else {
                    LockingStrategy::Lock
                },
                native: native_capture.python_stacks(),
                native_all: native_capture.everything(),
                ..Default::default()
            },
        }
    }

    /// Attaches to processes in `pids` we are not attached to yet and forgets all others.
    pub fn sync(&mut self, pids: &HashSet<py_spy::Pid>) {
        self.spies.retain(|pid, _| pids.contains(pid));
        self.failed_attaches.retain(|pid, _| pids.contains(pid));

        let mut new_processes = pids
            .iter()
            .filter(|pid| !self.spies.contains_key(pid))
            .filter(|pid| {
                self.failed_attaches
                    .get(pid)
                    .is_none_or(|(attempts, _)| *attempts < MAX_ATTACH_ATTEMPTS)
            })
            .copied()
            .collect::<Vec<_>>();
        new_processes.sort_unstable();

        for pid in new_processes {
            match self.track_process(pid) {
                Ok(()) => {
                    self.failed_attaches.remove(&pid);
                    info!("Attached to process {pid}");
                }
                Err(e) => {
                    let (attempts, error) = self
                        .failed_attaches
                        .entry(pid)
                        .or_insert((0, String::new()));
                    *attempts += 1;
                    *error = format!("{:#}", snafu::Report::from_error(&e));
                    if *attempts >= MAX_ATTACH_ATTEMPTS {
                        warn!(
                            "Giving up on capturing stacks of process {pid} after {attempts} \
                            attempts, it is probably not a Python process: {e}"
                        );
                    } else {
                        debug!("Error attaching to process {pid} (attempt {attempts}): {e}");
                    }
                }
            }
        }

        debug!("Attached to {} processes", self.spies.len());
    }

    /// Forgets a process, e.g. because its pid now belongs to a different process.
    pub fn forget(&mut self, pid: py_spy::Pid) {
        self.spies.remove(&pid);
        self.failed_attaches.remove(&pid);
    }

    fn track_process(&mut self, pid: py_spy::Pid) -> Result<(), PySpyError> {
        let spy = PythonSpy::new(pid, &self.py_spy_config).context(CreateSnafu)?;

        self.spies.insert(pid, spy);

        Ok(())
    }

    /// Captures the stacktraces of all given processes. A failed capture is returned as an error
    /// message, so callers can still record the other data for that process.
    pub fn get_stacktraces(
        &mut self,
        pids: impl Iterator<Item = py_spy::Pid>,
    ) -> HashMap<py_spy::Pid, Result<Vec<StackTrace>, String>> {
        let mut all_traces = HashMap::new();

        for pid in pids {
            let traces = match self.spies.get_mut(&pid) {
                Some(spy) => spy
                    .get_stack_traces()
                    .map(|traces| traces.into_iter().map(StackTrace::from).collect())
                    .map_err(|e| {
                        info!("Sample error {pid}: {e:?}");
                        format!("{e:#}")
                    }),
                None => Err(match self.failed_attaches.get(&pid) {
                    Some((attempts, error)) if *attempts >= MAX_ATTACH_ATTEMPTS => {
                        format!("Not a Python process: {error}")
                    }
                    Some((_, error)) => format!("Not attached yet: {error}"),
                    None => "Not attached".to_string(),
                }),
            };
            all_traces.insert(pid, traces);
        }

        all_traces
    }
}
