use crate::types::StackTrace;
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use snafu::{Location, ResultExt, Snafu};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

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
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    /// Processes whose pid now belongs to a different process, see [`Self::forget`]
    forgotten: Vec<py_spy::Pid>,
}

impl TachyonHelper {
    /// Starts the helper on `python`. If `pause` is set, it pauses the processes while capturing
    /// their stacks.
    pub fn new(python: &Path, pause: bool) -> Result<Self, TachyonError> {
        let mut child = Command::new(python)
            .arg("-I")
            .arg("-c")
            .arg(HELPER_SOURCE)
            .args(pause.then_some("--pause"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .context(SpawnSnafu { python })?;
        let stdin = child.stdin.take().expect("stdin is piped");
        let stdout = BufReader::new(child.stdout.take().expect("stdout is piped"));

        let mut helper = Self {
            child,
            stdin,
            stdout,
            forgotten: Vec::new(),
        };
        // Fails if the interpreter has no `_remote_debugging` module
        helper.read_line()?;
        info!("Started the tachyon helper with `{}`", python.display());

        Ok(helper)
    }

    /// Forgets a process, e.g. because its pid now belongs to a different process.
    pub fn forget(&mut self, pid: py_spy::Pid) {
        self.forgotten.push(pid);
    }

    /// Captures the stacktraces of the given processes and stops sampling all others. Processes we
    /// are not attached to yet are attached to first. A failed capture is returned as an error
    /// message, so callers can still record the other data for that process.
    pub fn get_stacktraces(
        &mut self,
        pids: impl Iterator<Item = py_spy::Pid>,
    ) -> Result<HashMap<py_spy::Pid, Result<Vec<StackTrace>, String>>, TachyonError> {
        let pids = pids.collect::<Vec<_>>();
        let request = Request {
            pids: &pids,
            forget: &self.forgotten,
        };
        let mut line = serde_json::to_vec(&request).expect("pids can be serialized");
        line.push(b'\n');
        self.stdin.write_all(&line).context(IoSnafu)?;
        self.stdin.flush().context(IoSnafu)?;
        self.forgotten.clear();

        let response: Response = serde_json::from_str(&self.read_line()?).context(ParseSnafu)?;
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

    fn read_line(&mut self) -> Result<String, TachyonError> {
        let mut line = String::new();
        let read = self.stdout.read_line(&mut line).context(IoSnafu)?;
        if read == 0 {
            return HelperExitedSnafu.fail();
        }
        Ok(line)
    }
}

impl Drop for TachyonHelper {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
