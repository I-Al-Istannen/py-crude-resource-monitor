use crate::types::StackTrace;
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use snafu::{Location, Report, ResultExt, Snafu};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};

const HELPER_TIMEOUT: Duration = Duration::from_secs(30);
const CANCELLATION_POLL_INTERVAL: Duration = Duration::from_millis(50);

const HELPER_SOURCE: &str = include_str!("tachyon_helper.py");

#[derive(Debug, Snafu)]
pub enum TachyonError {
    #[snafu(display("Error starting the tachyon helper with `{}` at {location}", python.display()))]
    Spawn {
        source: std::io::Error,
        python: PathBuf,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Error communicating with the tachyon helper at {location}"))]
    Io {
        source: std::io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display(
        "The tachyon helper exited unexpectedly, see its output above. It needs Python 3.15 or \
        newer. At {location}"
    ))]
    HelperExited {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Timed out waiting for the tachyon helper at {location}"))]
    Timeout {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Tachyon capture cancelled at {location}"))]
    Cancelled {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Error parsing the output of the tachyon helper at {location}"))]
    Parse {
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },
}

#[derive(Serialize)]
struct Request<'a> {
    pids: &'a [py_spy::Pid],
    forget: &'a [py_spy::Pid],
}

#[derive(Deserialize)]
struct Response {
    traces: HashMap<py_spy::Pid, TraceResult>,
    logs: Vec<LogMessage>,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum TraceResult {
    Ok(Vec<StackTrace>),
    Err(String),
}

#[derive(Deserialize)]
struct LogMessage {
    level: String,
    message: String,
}

/// Captures Python stacks with the `_remote_debugging` module behind CPython 3.15's sampling
/// profiler (Tachyon). It is only available from Python, so a helper script running on the given
/// interpreter does the sampling. That interpreter must have the same minor version as the
/// profiled processes.
pub struct TachyonHelper {
    python: PathBuf,
    pause: bool,
    /// Missing if the helper failed, it is restarted on the next capture
    process: Option<HelperProcess>,
    /// Processes whose pid now belongs to a different process, see [`Self::forget`]
    forgotten: Vec<py_spy::Pid>,
    quit_requested: Arc<AtomicBool>,
}

impl TachyonHelper {
    /// Starts the helper on `python`. If `pause` is set, it pauses the processes while capturing
    /// their stacks.
    pub fn new(
        python: &Path,
        pause: bool,
        quit_requested: Arc<AtomicBool>,
    ) -> Result<Self, TachyonError> {
        // Fails if the interpreter has no `_remote_debugging` module
        let process = HelperProcess::start(python, pause, &quit_requested)?;
        info!("Started the tachyon helper with `{}`", python.display());

        Ok(Self {
            python: python.to_path_buf(),
            pause,
            process: Some(process),
            forgotten: Vec::new(),
            quit_requested,
        })
    }

    /// Forgets a process, e.g. because its pid now belongs to a different process.
    pub fn forget(&mut self, pid: py_spy::Pid) {
        self.forgotten.push(pid);
    }

    /// Captures the stacktraces of the given processes and stops sampling all others. Processes we
    /// are not attached to yet are attached to first. A failed capture is returned as an error
    /// message, so callers can still record the other data for that process. If the helper fails,
    /// e.g. because it crashed while reading a process, all captures fail and it is restarted on
    /// the next call.
    pub fn get_stacktraces(
        &mut self,
        pids: impl Iterator<Item = py_spy::Pid>,
    ) -> HashMap<py_spy::Pid, Result<Vec<StackTrace>, String>> {
        let pids = pids.collect::<Vec<_>>();
        match self.capture(&pids) {
            Ok(traces) => traces,
            Err(e) => {
                let message = Report::from_error(e).to_string();
                warn!("Capturing stacks with the tachyon helper failed: {message}");
                self.process = None;
                pids.into_iter()
                    .map(|pid| (pid, Err(message.clone())))
                    .collect()
            }
        }
    }

    fn capture(
        &mut self,
        pids: &[py_spy::Pid],
    ) -> Result<HashMap<py_spy::Pid, Result<Vec<StackTrace>, String>>, TachyonError> {
        if self.quit_requested.load(Ordering::Acquire) {
            return CancelledSnafu.fail();
        }
        let process = match &mut self.process {
            Some(process) => process,
            None => {
                info!("Restarting the tachyon helper");
                // A new helper is not attached to any process yet
                self.forgotten.clear();
                self.process.insert(HelperProcess::start(
                    &self.python,
                    self.pause,
                    &self.quit_requested,
                )?)
            }
        };
        let request = Request {
            pids,
            forget: &self.forgotten,
        };
        let mut line = serde_json::to_vec(&request).expect("pids can be serialized");
        line.push(b'\n');
        process.send(line)?;
        self.forgotten.clear();

        let response: Response =
            serde_json::from_str(&process.read_line(&self.quit_requested, HELPER_TIMEOUT)?)
                .context(ParseSnafu)?;
        for LogMessage { level, message } in response.logs {
            match level.as_str() {
                "warn" => warn!("{message}"),
                "info" => info!("{message}"),
                _ => debug!("{message}"),
            }
        }

        Ok(response
            .traces
            .into_iter()
            .map(|(pid, result)| match result {
                TraceResult::Ok(traces) => (pid, Ok(traces)),
                TraceResult::Err(e) => (pid, Err(e)),
            })
            .collect())
    }
}

/// The running helper script. The worker owns both pipes so neither a blocked write nor a
/// blocked read prevents the monitor from observing cancellation. Killing and reaping the child
/// releases the worker's pipe operations before it is joined.
struct HelperProcess {
    child: Child,
    /// Only `None` while dropping: closing it ends an idle worker, which waits for requests and
    /// would not notice the killed child.
    requests: Option<mpsc::Sender<Vec<u8>>>,
    responses: mpsc::Receiver<std::io::Result<String>>,
    worker: Option<thread::JoinHandle<()>>,
}

impl HelperProcess {
    /// Starts the helper and waits until it is ready.
    fn start(
        python: &Path,
        pause: bool,
        quit_requested: &AtomicBool,
    ) -> Result<Self, TachyonError> {
        let child = Command::new(python)
            .arg("-I")
            .arg("-c")
            .arg(HELPER_SOURCE)
            .args(pause.then_some("--pause"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .context(SpawnSnafu { python })?;
        let mut process = Self::from_child(child);
        process.read_line(quit_requested, HELPER_TIMEOUT)?;
        Ok(process)
    }

    fn from_child(mut child: Child) -> Self {
        let mut stdin = child.stdin.take().expect("stdin is piped");
        let mut stdout = BufReader::new(child.stdout.take().expect("stdout is piped"));
        let (requests, incoming) = mpsc::channel::<Vec<u8>>();
        let (outgoing, responses) = mpsc::channel();
        let worker = thread::spawn(move || {
            let read_line = |stdout: &mut BufReader<_>| {
                let mut line = String::new();
                stdout.read_line(&mut line).map(|_| line)
            };
            if outgoing.send(read_line(&mut stdout)).is_err() {
                return;
            }
            while let Ok(request) = incoming.recv() {
                let response = stdin
                    .write_all(&request)
                    .and_then(|()| stdin.flush())
                    .and_then(|()| read_line(&mut stdout));
                let failed = response.as_ref().map_or(true, |line| line.is_empty());
                if outgoing.send(response).is_err() || failed {
                    break;
                }
            }
        });
        Self {
            child,
            requests: Some(requests),
            responses,
            worker: Some(worker),
        }
    }

    fn send(&self, request: Vec<u8>) -> Result<(), TachyonError> {
        let requests = self.requests.as_ref().expect("only taken when dropping");
        requests
            .send(request)
            .map_err(|_| HelperExitedSnafu.build())
    }

    fn read_line(
        &mut self,
        quit_requested: &AtomicBool,
        timeout: Duration,
    ) -> Result<String, TachyonError> {
        let deadline = Instant::now() + timeout;
        loop {
            if quit_requested.load(Ordering::Acquire) {
                return CancelledSnafu.fail();
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return TimeoutSnafu.fail();
            }
            match self
                .responses
                .recv_timeout(remaining.min(CANCELLATION_POLL_INTERVAL))
            {
                Ok(result) => {
                    let line = result.context(IoSnafu)?;
                    if line.is_empty() {
                        return HelperExitedSnafu.fail();
                    }
                    return Ok(line);
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => return HelperExitedSnafu.fail(),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
        }
    }
}

impl Drop for HelperProcess {
    fn drop(&mut self) {
        drop(self.requests.take());
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn helper(script: &str) -> HelperProcess {
        let child = Command::new("sh")
            .args(["-c", script])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        HelperProcess::from_child(child)
    }

    #[test]
    fn exchanges_ready_and_capture_messages() {
        let mut process =
            helper("printf 'ready\\n'; while IFS= read -r request; do printf 'response\\n'; done");
        let quit = AtomicBool::new(false);
        assert_eq!(
            process.read_line(&quit, Duration::from_secs(2)).unwrap(),
            "ready\n"
        );
        process.send(b"request\n".to_vec()).unwrap();
        assert_eq!(
            process.read_line(&quit, Duration::from_secs(2)).unwrap(),
            "response\n"
        );
    }

    #[test]
    fn times_out_during_startup_and_reaps_the_worker() {
        let start = Instant::now();
        let mut process = helper("exec sleep 30");
        assert!(matches!(
            process.read_line(&AtomicBool::new(false), Duration::from_millis(20)),
            Err(TachyonError::Timeout { .. })
        ));
        drop(process);
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn times_out_even_when_writing_a_request_blocks() {
        let start = Instant::now();
        let mut process = helper("printf 'ready\\n'; exec sleep 30");
        let quit = AtomicBool::new(false);
        process.read_line(&quit, Duration::from_secs(2)).unwrap();
        // Bigger than the pipe buffer, and the helper never reads its stdin.
        process.send(b"request\n".to_vec()).unwrap();
        assert!(matches!(
            process.read_line(&quit, Duration::from_millis(20)),
            Err(TachyonError::Timeout { .. })
        ));
        drop(process);
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn cancellation_interrupts_a_pending_reply() {
        let start = Instant::now();
        let mut process = helper("printf 'ready\\n'; exec sleep 30");
        let quit = Arc::new(AtomicBool::new(false));
        process.read_line(&quit, Duration::from_secs(2)).unwrap();
        process.send(b"request\n".to_vec()).unwrap();
        let cancel = quit.clone();
        let cancelling = thread::spawn(move || {
            thread::sleep(Duration::from_millis(20));
            cancel.store(true, Ordering::Release);
        });
        assert!(matches!(
            process.read_line(&quit, Duration::from_secs(30)),
            Err(TachyonError::Cancelled { .. })
        ));
        drop(process);
        cancelling.join().unwrap();
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn reports_eof_instead_of_waiting_for_the_deadline() {
        let mut process = helper("exit 0");
        assert!(matches!(
            process.read_line(&AtomicBool::new(false), Duration::from_secs(2)),
            Err(TachyonError::HelperExited { .. })
        ));
    }
}
