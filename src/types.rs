use clap::ValueEnum;
use clap::builder::PossibleValue;
use py_spy::Pid;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Display;

/// A sample of a process. In the files, the threads are [`StoredStackTrace`]s, see
/// [`crate::samples`].
#[derive(Serialize, Deserialize, Debug)]
pub struct JsonLine<S = StackTrace> {
    pub stacktraces: Vec<S>,
    /// Set if capturing the stacktraces failed for this sample. The resources are still valid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stacktrace_error: Option<String>,
    pub resources: ProcessResources,
    /// Missing in profiles written by older versions and in the global data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process: Option<ProcessMetadata>,
    /// Memory measured more often than the samples, between the previous sample and this one.
    /// Only contains changes, see [`crate::memory_sampler`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub memory_samples: Vec<MemorySample>,
    /// Set on the line written after the process exited. It only has the memory measured between
    /// the previous sample and the exit, `time` is the last of these measurements. Only memory
    /// is populated in its resources; other fields are empty placeholders.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub exited: bool,
    pub index: usize,
    pub time: u128,
}

impl<S> JsonLine<S> {
    /// The earliest measurement in this line, including its memory samples.
    pub fn earliest_time(&self) -> u128 {
        self.memory_samples
            .iter()
            .map(|sample| sample.time)
            .fold(self.time, u128::min)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemorySample {
    /// Milliseconds since the unix epoch
    pub time: u128,
    pub memory: u64,
}

/// Identifies a process. Pids can be reused, so a file might contain several processes with
/// different start times.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessMetadata {
    pub name: String,
    pub parent_pid: Option<u32>,
    /// Seconds since the unix epoch
    pub start_time: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadResources {
    pub cpu: f32,
    pub memory: u64,
    pub disk_read_bytes: u64,
    pub disk_write_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessResources {
    pub memory: u64,
    /// Proportional set size: like `memory`, but pages shared with other processes are split
    /// between them. Only recorded on Linux if requested.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pss: Option<u64>,
    /// Divided by the number of cores, so 100% means all cores are fully used
    pub cpu: f32,
    /// The number of cores `cpu` was divided by. Missing in the global data and in profiles
    /// written by older versions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpus: Option<u32>,
    pub disk_read_bytes: u64,
    pub disk_write_bytes: u64,
    /// The bytes the process requested with read calls since it started (`rchar`). Unlike
    /// `disk_read_bytes`, this includes reads served from the page cache, pipes and sockets. Only
    /// recorded on Linux, missing in the global data and in profiles written by older versions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_read_call_bytes: Option<u64>,
    pub thread_resources: HashMap<u64, ThreadResources>,
}

// the following structs are `Deserialize`-able wrappers for py-spy structs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackTrace {
    pub pid: Pid,
    pub thread_id: u64,
    pub thread_name: Option<String>,
    pub os_thread_id: Option<u64>,
    pub active: bool,
    pub owns_gil: bool,
    /// Whether the thread waits to take the GIL. Only Tachyon reports it.
    #[serde(default)]
    pub waiting_for_gil: bool,
    pub frames: Vec<Frame>,
    pub process_info: Option<ProcessInfo>,
}

impl From<py_spy::StackTrace> for StackTrace {
    fn from(trace: py_spy::StackTrace) -> Self {
        Self {
            pid: trace.pid,
            thread_id: trace.thread_id,
            thread_name: trace.thread_name,
            os_thread_id: trace.os_thread_id,
            active: trace.active,
            owns_gil: trace.owns_gil,
            waiting_for_gil: false,
            frames: trace.frames.into_iter().map(|f| f.into()).collect(),
            process_info: trace.process_info.map(|p| (*p).clone().into()),
        }
    }
}

/// A thread as stored in the sample files: its frames are written once and referenced by the id
/// of the innermost one, see [`crate::samples`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredStackTrace {
    pub pid: Pid,
    pub thread_id: u64,
    pub thread_name: Option<String>,
    pub os_thread_id: Option<u64>,
    pub active: bool,
    pub owns_gil: bool,
    /// Omitted if false, which it always is with py-spy
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub waiting_for_gil: bool,
    /// `None` if the thread has no frames
    #[serde(default)]
    pub stack: Option<u32>,
    /// Profiles written by older versions store the frames of every sample instead of `stack`
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub frames: Vec<Frame>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_info: Option<ProcessInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Frame {
    pub name: String,
    pub filename: String,
    pub module: Option<String>,
    pub short_filename: Option<String>,
    pub line: i32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locals: Option<Vec<LocalVariable>>,
    pub is_entry: bool,
}

impl From<py_spy::Frame> for Frame {
    fn from(frame: py_spy::Frame) -> Self {
        Self {
            name: frame.name,
            filename: frame.filename,
            module: frame.module,
            short_filename: frame.short_filename,
            line: frame.line,
            locals: frame
                .locals
                .map(|locals| locals.into_iter().map(|l| l.into()).collect()),
            is_entry: frame.is_entry,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LocalVariable {
    pub name: String,
    pub addr: usize,
    pub arg: bool,
    pub repr: Option<String>,
}

impl From<py_spy::stack_trace::LocalVariable> for LocalVariable {
    fn from(local: py_spy::stack_trace::LocalVariable) -> Self {
        Self {
            name: local.name,
            addr: local.addr,
            arg: local.arg,
            repr: local.repr,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: Pid,
    pub command_line: String,
    pub parent: Option<Box<Self>>,
}

impl From<py_spy::stack_trace::ProcessInfo> for ProcessInfo {
    fn from(info: py_spy::stack_trace::ProcessInfo) -> Self {
        Self {
            pid: info.pid,
            command_line: info.command_line,
            parent: info.parent.map(|p| Box::new((*p).into())),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum NativeCapture {
    NativeStacks,
    AllNative,
    None,
}

impl NativeCapture {
    pub fn python_stacks(&self) -> bool {
        matches!(self, Self::NativeStacks | Self::AllNative)
    }

    pub fn everything(&self) -> bool {
        matches!(self, Self::AllNative)
    }

    pub fn anything(&self) -> bool {
        !matches!(self, Self::None)
    }
}

impl Display for NativeCapture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            Self::NativeStacks => "native-stacks".to_string(),
            Self::AllNative => "all".to_string(),
            Self::None => "none".to_string(),
        };
        write!(f, "{}", str)
    }
}

impl ValueEnum for NativeCapture {
    fn value_variants<'a>() -> &'a [Self] {
        &[Self::NativeStacks, Self::AllNative, Self::None]
    }

    fn to_possible_value(&self) -> Option<PossibleValue> {
        match self {
            Self::NativeStacks => Some(
                PossibleValue::new("native-stacks")
                    .help("Capture native stacks only for threads with Python frames."),
            ),
            Self::AllNative => {
                Some(PossibleValue::new("all").help("Capture native stacks for all threads."))
            }
            Self::None => {
                Some(PossibleValue::new("none").help("Do not capture any native stacks."))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_lines_without_stacktrace_error() {
        // Written by versions before `stacktrace_error` existed
        let line = r#"{"stacktraces":[],"resources":{"memory":1,"cpu":2.0,"disk_read_bytes":0,"disk_write_bytes":0,"thread_resources":{}},"index":0,"time":1000}"#;

        let line: JsonLine<StoredStackTrace> = serde_json::from_str(line).unwrap();

        assert_eq!(line.stacktrace_error, None);
    }

    #[test]
    fn omits_missing_stacktrace_error() {
        let line: JsonLine = JsonLine {
            exited: false,
            stacktraces: vec![],
            stacktrace_error: None,
            process: None,
            memory_samples: vec![],
            resources: ProcessResources {
                memory: 1,
                pss: None,
                cpu: 2.0,
                cpus: None,
                disk_read_bytes: 0,
                disk_write_bytes: 0,
                total_read_call_bytes: None,
                thread_resources: HashMap::new(),
            },
            index: 0,
            time: 1000,
        };

        let json = serde_json::to_string(&line).unwrap();

        assert!(!json.contains("stacktrace_error"));
    }
}
