//! Serialize queued samples, keeping file handles bounded and stack IDs valid across reopens.

use super::{SerializeSampleSnafu, TrackerError, WriteSamplesSnafu};
use crate::samples::{SampleFile, StackTable, write_line};
use crate::types::{JsonLine, MemorySample, ProcessMetadata, ProcessResources, StackTrace};
use log::trace;
use snafu::ResultExt;
use std::collections::{HashMap, hash_map::Entry};
use std::path::{Path, PathBuf};
use std::sync::mpsc;

#[derive(Debug)]
pub(super) struct WriteRequest {
    /// The sample file, e.g. `42` or `global`
    pub(super) file_name: String,
    pub(super) resources: ProcessResources,
    pub(super) process: Option<ProcessMetadata>,
    pub(super) memory_samples: Vec<MemorySample>,
    pub(super) stacktraces: Vec<StackTrace>,
    pub(super) stacktrace_error: Option<String>,
    pub(super) exited: bool,
    pub(super) time: u128,
}

/// Upper bound for cached file handles, so runs with many short-lived processes do not exhaust the
/// file descriptor limit
const MAX_OPEN_FILES: usize = 64;

/// Persists across file-handle eviction so indices and interned stacks stay valid.
#[derive(Default)]
struct FileState {
    next_index: usize,
    stacks: StackTable,
}

pub(super) fn write_samples(
    rx: mpsc::Receiver<WriteRequest>,
    output_dir: PathBuf,
    compress: bool,
) -> Result<(), TrackerError> {
    let mut open_files: HashMap<String, SampleFile> = HashMap::new();
    let mut file_states: HashMap<String, FileState> = HashMap::new();

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
            let state = file_states.entry(name).or_default();

            let stacktraces = req
                .stacktraces
                .into_iter()
                .map(|trace| state.stacks.store(trace, &mut *file))
                .collect::<Result<_, _>>()
                .context(SerializeSampleSnafu)?;
            let line = JsonLine {
                stacktraces,
                stacktrace_error: req.stacktrace_error,
                resources: req.resources,
                process: req.process,
                memory_samples: req.memory_samples,
                exited: req.exited,
                index: state.next_index,
                time: req.time,
            };
            // The frames and stacks of the sample are flushed with it, so the file stays readable
            write_line(&mut *file, &line).context(SerializeSampleSnafu)?;
            file.flush_lines().context(WriteSamplesSnafu { path })?;

            state.next_index += 1;
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
