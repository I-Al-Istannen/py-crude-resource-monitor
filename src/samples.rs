//! The sample files contain one JSON object per line. Repeating every frame of every thread in
//! every sample makes them huge at short sampling intervals, so frames and stacks are written only
//! once, each as its own line before the first sample that uses it. Samples then reference the
//! stack of each thread by its id:
//!
//! ```text
//! {"frame":0,"name":"<module>","filename":"/w/main.py","module":null,"short_filename":"main.py","line":18,"is_entry":true}
//! {"stack":0,"parent":null,"frame":0}
//! {"frame":1,"name":"work","filename":"/w/main.py","module":null,"short_filename":"main.py","line":7,"is_entry":false}
//! {"stack":1,"parent":0,"frame":1}
//! {"stacktraces":[{"pid":42,"thread_id":1,"thread_name":"MainThread","os_thread_id":42,"active":true,"owns_gil":true,"stack":1}],"resources":{...},"index":0,"time":1000}
//! ```
//!
//! A stack is its innermost frame on top of the stack of its caller (`parent`), so stacks sharing
//! callers share lines. The ids of frames and stacks count up from 0 in every file. Profiles
//! written by older versions store the frames in the samples instead, and are read just the same.
//!
//! The files are compressed with zstd unless the user asks for plain ones. Both can be cut off
//! after any byte if the profiler is killed, so readers use all complete lines before that.

use crate::types::{Frame, JsonLine, StackTrace, StoredStackTrace};
use log::warn;
use serde::{Deserialize, Serialize};
use snafu::{OptionExt, ResultExt, Snafu};
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const COMPRESSED_SUFFIX: &str = ".json.zst";
const PLAIN_SUFFIX: &str = ".json";

/// How often compressed files are flushed. Every flush makes the compression worse, so we do not
/// flush every line, and lose at most this much data if the profiler is killed.
const FLUSH_INTERVAL: Duration = Duration::from_millis(500);
const COMPRESSION_LEVEL: i32 = 3;

/// A sample file open for appending
pub enum SampleFile {
    Plain(BufWriter<File>),
    Compressed {
        encoder: zstd::Encoder<'static, File>,
        last_flush: Instant,
    },
}

impl SampleFile {
    /// Opens the sample file `name` (e.g. `42` or `global`) in `dir`. A compressed file gets a new
    /// zstd frame, so a closed file can be opened again.
    pub fn open(dir: &Path, name: &str, compress: bool) -> io::Result<Self> {
        let suffix = if compress {
            COMPRESSED_SUFFIX
        } else {
            PLAIN_SUFFIX
        };
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join(format!("{name}{suffix}")))?;
        if !compress {
            return Ok(Self::Plain(BufWriter::new(file)));
        }
        let mut encoder = zstd::Encoder::new(file, COMPRESSION_LEVEL)?;
        encoder.include_checksum(true)?;
        Ok(Self::Compressed {
            encoder,
            last_flush: Instant::now(),
        })
    }

    /// Makes the lines written so far readable, see [`FLUSH_INTERVAL`] for compressed files.
    pub fn flush_lines(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(file) => file.flush(),
            Self::Compressed {
                encoder,
                last_flush,
            } => {
                if last_flush.elapsed() < FLUSH_INTERVAL {
                    return Ok(());
                }
                *last_flush = Instant::now();
                encoder.flush()
            }
        }
    }

    /// Writes everything and ends the zstd frame of compressed files
    pub fn close(self) -> io::Result<()> {
        match self {
            Self::Plain(mut file) => file.flush(),
            Self::Compressed { encoder, .. } => encoder.finish().map(|_| ()),
        }
    }
}

impl Write for SampleFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Plain(file) => file.write(buf),
            Self::Compressed { encoder, .. } => encoder.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(file) => file.flush(),
            Self::Compressed { encoder, .. } => encoder.flush(),
        }
    }
}

/// The sample files in `dir`, with their names without extension, e.g. `42` or `global`
pub fn sample_files(dir: &Path) -> io::Result<Vec<(String, PathBuf)>> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        let Some(file_name) = path.file_name().and_then(|it| it.to_str()) else {
            continue;
        };
        let name = file_name
            .strip_suffix(COMPRESSED_SUFFIX)
            .or_else(|| file_name.strip_suffix(PLAIN_SUFFIX));
        if let Some(name) = name
            && path.is_file()
        {
            files.push((name.to_string(), path));
        }
    }
    files.sort();
    Ok(files)
}

/// Reads a sample file, decompressing it if needed. Content after the last complete zstd block,
/// e.g. because the profiler is still running or was killed, is skipped.
pub fn read_sample_file(path: &Path) -> io::Result<String> {
    let bytes = std::fs::read(path)?;
    let mut content = if path.to_string_lossy().ends_with(COMPRESSED_SUFFIX) {
        let mut content = Vec::new();
        match zstd::Decoder::new(bytes.as_slice())?.read_to_end(&mut content) {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => warn!(
                "`{}` ends in an incomplete zstd frame. Reading the samples before it, the \
                profiler is probably still running or was killed",
                path.display()
            ),
            Err(e) => return Err(e),
        }
        content
    } else {
        bytes
    };

    match std::str::from_utf8(&content) {
        Ok(_) => {}
        // The file was cut off within a character, the line is incomplete anyway
        Err(e) if e.error_len().is_none() => content.truncate(e.valid_up_to()),
        Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidData, e)),
    }
    Ok(String::from_utf8(content).expect("checked above"))
}

#[derive(Debug, Snafu)]
pub enum ReadSamplesError {
    #[snafu(display("Could not parse line {line}"))]
    Parse {
        source: serde_json::Error,
        line: usize,
    },
    #[snafu(display("Line {line} defines {kind} {id}, but the next id is {expected}"))]
    UnexpectedId {
        kind: &'static str,
        id: u32,
        expected: usize,
        line: usize,
    },
    #[snafu(display("Line {line} references {kind} {id}, which is not defined before it"))]
    UnknownId {
        kind: &'static str,
        id: u32,
        line: usize,
    },
}

#[derive(Serialize, Deserialize)]
struct FrameLine<F> {
    frame: u32,
    #[serde(flatten)]
    data: F,
}

#[derive(Serialize, Deserialize)]
struct StackLine {
    stack: u32,
    parent: Option<u32>,
    frame: u32,
}

/// The frames and stacks already written to a sample file
#[derive(Debug, Default)]
pub struct StackTable {
    frames: HashMap<Frame, u32>,
    stacks: HashMap<(Option<u32>, u32), u32>,
}

impl StackTable {
    /// Converts a thread to the form stored in the file, first writing the frames and stacks it
    /// uses that are not in the file yet to `out`.
    pub fn store(
        &mut self,
        trace: StackTrace,
        out: &mut impl Write,
    ) -> serde_json::Result<StoredStackTrace> {
        Ok(StoredStackTrace {
            stack: self.intern(&trace.frames, out)?,
            pid: trace.pid,
            thread_id: trace.thread_id,
            thread_name: trace.thread_name,
            os_thread_id: trace.os_thread_id,
            active: trace.active,
            owns_gil: trace.owns_gil,
            waiting_for_gil: trace.waiting_for_gil,
            frames: vec![],
            process_info: trace.process_info,
        })
    }

    /// Returns the id of the stack of `frames` (innermost first).
    fn intern(
        &mut self,
        frames: &[Frame],
        out: &mut impl Write,
    ) -> serde_json::Result<Option<u32>> {
        let mut stack = None;
        for frame in frames.iter().rev() {
            let frame = match self.frames.get(frame) {
                Some(id) => *id,
                None => {
                    let id = self.frames.len() as u32;
                    write_line(
                        out,
                        &FrameLine {
                            frame: id,
                            data: frame,
                        },
                    )?;
                    self.frames.insert(frame.clone(), id);
                    id
                }
            };
            let next_id = self.stacks.len() as u32;
            stack = Some(match self.stacks.entry((stack, frame)) {
                Entry::Occupied(entry) => *entry.get(),
                Entry::Vacant(entry) => {
                    write_line(
                        out,
                        &StackLine {
                            stack: next_id,
                            parent: stack,
                            frame,
                        },
                    )?;
                    *entry.insert(next_id)
                }
            });
        }
        Ok(stack)
    }
}

/// Writes `value` as a line of JSON
pub fn write_line(out: &mut impl Write, value: &impl Serialize) -> serde_json::Result<()> {
    serde_json::to_writer(&mut *out, value)?;
    out.write_all(b"\n").map_err(serde_json::Error::io)
}

/// Reads the samples of a sample file, resolving the stacks of their threads. An incomplete last
/// line is skipped.
pub fn read_samples(content: &str) -> Result<Vec<JsonLine>, ReadSamplesError> {
    let mut reader = SampleReader::default();
    let mut lines = content.lines().enumerate().peekable();
    while let Some((index, text)) = lines.next() {
        if let Err(e) = reader.read_line(text, index + 1) {
            if lines.peek().is_none() && !content.ends_with('\n') {
                warn!("Skipping the incomplete last line: {e}");
                break;
            }
            return Err(e);
        }
    }
    Ok(reader.samples)
}

#[derive(Default)]
struct SampleReader {
    frames: Vec<Frame>,
    /// The parent and frame of every stack
    stacks: Vec<(Option<u32>, u32)>,
    samples: Vec<JsonLine>,
}

impl SampleReader {
    fn read_line(&mut self, text: &str, line: usize) -> Result<(), ReadSamplesError> {
        let Self {
            frames,
            stacks,
            samples,
        } = self;
        if text.is_empty() {
            return Ok(());
        }
        // The writer emits the fields in declaration order, so the first key tells the line type
        if text.starts_with(r#"{"frame":"#) {
            let parsed: FrameLine<Frame> =
                serde_json::from_str(text).context(ParseSnafu { line })?;
            check_next_id("frame", parsed.frame, frames.len(), line)?;
            frames.push(parsed.data);
        } else if text.starts_with(r#"{"stack":"#) {
            let parsed: StackLine = serde_json::from_str(text).context(ParseSnafu { line })?;
            check_next_id("stack", parsed.stack, stacks.len(), line)?;
            if let Some(parent) = parsed.parent {
                check_defined("stack", parent, stacks.len(), line)?;
            }
            check_defined("frame", parsed.frame, frames.len(), line)?;
            stacks.push((parsed.parent, parsed.frame));
        } else {
            let sample: JsonLine<StoredStackTrace> =
                serde_json::from_str(text).context(ParseSnafu { line })?;
            let stacktraces = sample
                .stacktraces
                .into_iter()
                .map(|trace| resolve(trace, frames, stacks, line))
                .collect::<Result<_, _>>()?;
            samples.push(JsonLine {
                stacktraces,
                stacktrace_error: sample.stacktrace_error,
                resources: sample.resources,
                process: sample.process,
                memory_samples: sample.memory_samples,
                exited: sample.exited,
                index: sample.index,
                time: sample.time,
            });
        }
        Ok(())
    }
}

fn resolve(
    trace: StoredStackTrace,
    frames: &[Frame],
    stacks: &[(Option<u32>, u32)],
    line: usize,
) -> Result<StackTrace, ReadSamplesError> {
    let mut resolved = trace.frames;
    let mut stack = trace.stack;
    while let Some(id) = stack {
        let (parent, frame) = stacks.get(id as usize).context(UnknownIdSnafu {
            kind: "stack",
            id,
            line,
        })?;
        resolved.push(frames[*frame as usize].clone());
        stack = *parent;
    }

    Ok(StackTrace {
        pid: trace.pid,
        thread_id: trace.thread_id,
        thread_name: trace.thread_name,
        os_thread_id: trace.os_thread_id,
        active: trace.active,
        owns_gil: trace.owns_gil,
        waiting_for_gil: trace.waiting_for_gil,
        frames: resolved,
        process_info: trace.process_info,
    })
}

fn check_next_id(
    kind: &'static str,
    id: u32,
    expected: usize,
    line: usize,
) -> Result<(), ReadSamplesError> {
    if id as usize != expected {
        return UnexpectedIdSnafu {
            kind,
            id,
            expected,
            line,
        }
        .fail();
    }
    Ok(())
}

fn check_defined(
    kind: &'static str,
    id: u32,
    defined: usize,
    line: usize,
) -> Result<(), ReadSamplesError> {
    if id as usize >= defined {
        return UnknownIdSnafu { kind, id, line }.fail();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ProcessResources;

    fn frame(name: &str, line: i32) -> Frame {
        Frame {
            name: name.to_string(),
            filename: "/w/main.py".to_string(),
            module: None,
            short_filename: Some("main.py".to_string()),
            line,
            locals: None,
            is_entry: false,
        }
    }

    fn trace(thread_id: u64, frames: Vec<Frame>) -> StackTrace {
        StackTrace {
            pid: 42,
            thread_id,
            thread_name: Some(format!("thread-{thread_id}")),
            os_thread_id: Some(thread_id),
            active: true,
            owns_gil: false,
            waiting_for_gil: false,
            frames,
            process_info: None,
        }
    }

    fn write(samples: Vec<Vec<StackTrace>>) -> String {
        let mut table = StackTable::default();
        let mut out = Vec::new();
        for (index, traces) in samples.into_iter().enumerate() {
            let stacktraces = traces
                .into_iter()
                .map(|trace| table.store(trace, &mut out).unwrap())
                .collect();
            write_line(&mut out, &sample(stacktraces, index)).unwrap();
        }
        String::from_utf8(out).unwrap()
    }

    fn sample<S>(stacktraces: Vec<S>, index: usize) -> JsonLine<S> {
        JsonLine {
            stacktraces,
            stacktrace_error: None,
            exited: false,
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
            process: None,
            memory_samples: vec![],
            index,
            time: 1000 + index as u128,
        }
    }

    fn frames_of(samples: &[JsonLine]) -> Vec<Vec<Vec<(String, i32)>>> {
        samples
            .iter()
            .map(|sample| {
                sample
                    .stacktraces
                    .iter()
                    .map(|trace| {
                        trace
                            .frames
                            .iter()
                            .map(|f| (f.name.clone(), f.line))
                            .collect()
                    })
                    .collect()
            })
            .collect()
    }

    #[test]
    fn reads_the_stacks_it_wrote() {
        let main = frame("main", 1);
        let samples = vec![
            vec![
                trace(1, vec![frame("work", 5), main.clone()]),
                trace(2, vec![]),
            ],
            vec![
                trace(1, vec![frame("work", 6), main.clone()]),
                trace(2, vec![frame("idle", 9), frame("run", 3)]),
            ],
            vec![trace(1, vec![frame("work", 5), main.clone()])],
        ];
        let expected = frames_of(
            &samples
                .iter()
                .cloned()
                .enumerate()
                .map(|(index, traces)| sample(traces, index))
                .collect::<Vec<_>>(),
        );

        let read = read_samples(&write(samples)).unwrap();

        assert_eq!(frames_of(&read), expected);
        assert_eq!(
            read[0].stacktraces[1].thread_name.as_deref(),
            Some("thread-2")
        );
        assert_eq!(read[2].index, 2);
    }

    #[test]
    fn stores_gil_waits_only_if_a_thread_waits() {
        let mut waiting = trace(2, vec![frame("work", 5)]);
        waiting.waiting_for_gil = true;

        let written = write(vec![vec![trace(1, vec![frame("work", 5)]), waiting]]);
        let read = read_samples(&written).unwrap();

        assert_eq!(written.matches("waiting_for_gil").count(), 1);
        let waits: Vec<bool> = read[0]
            .stacktraces
            .iter()
            .map(|it| it.waiting_for_gil)
            .collect();
        assert_eq!(waits, [false, true]);
    }

    #[test]
    fn writes_every_frame_and_stack_once() {
        let stack = vec![frame("work", 5), frame("main", 1)];
        let other = vec![frame("other", 7), frame("main", 1)];

        let written = write(vec![
            vec![trace(1, stack.clone()), trace(2, stack.clone())],
            vec![trace(1, stack), trace(2, other)],
        ]);

        let kinds: Vec<&str> = written
            .lines()
            .map(|line| line.split(':').next().unwrap())
            .collect();
        assert_eq!(
            kinds,
            [
                r#"{"frame""#,
                r#"{"stack""#,
                r#"{"frame""#,
                r#"{"stack""#,
                r#"{"stacktraces""#,
                // only "other" is new, "main" and its stack are reused
                r#"{"frame""#,
                r#"{"stack""#,
                r#"{"stacktraces""#,
            ]
        );
        assert!(!written.contains("\"frames\""));
    }

    #[test]
    fn reads_samples_with_inline_frames() {
        // Written by versions before frames and stacks were stored separately
        let line = r#"{"stacktraces":[{"pid":42,"thread_id":1,"thread_name":null,"os_thread_id":null,"active":true,"owns_gil":false,"frames":[{"name":"work","filename":"/w/main.py","module":null,"short_filename":null,"line":5,"locals":null,"is_entry":false}],"process_info":null}],"resources":{"memory":1,"cpu_core_percent":2.0,"disk_read_bytes":0,"disk_write_bytes":0,"thread_resources":{}},"index":0,"time":1000}"#;

        let read = read_samples(line).unwrap();

        assert_eq!(frames_of(&read), [[[("work".to_string(), 5)]]]);
    }

    #[test]
    fn rejects_references_to_undefined_stacks() {
        let line = "{\"stack\":0,\"parent\":3,\"frame\":0}\n";

        let error = read_samples(line).unwrap_err();

        assert!(matches!(
            error,
            ReadSamplesError::UnknownId {
                kind: "stack",
                id: 3,
                line: 1
            }
        ));
    }

    fn write_file(dir: &Path, compress: bool, samples: Vec<Vec<StackTrace>>) {
        let mut table = StackTable::default();
        for (index, traces) in samples.into_iter().enumerate() {
            // Reopen the file for every sample, as the writer does when too many files are open
            let mut file = SampleFile::open(dir, "42", compress).unwrap();
            let stacktraces = traces
                .into_iter()
                .map(|trace| table.store(trace, &mut file).unwrap())
                .collect();
            write_line(&mut file, &sample(stacktraces, index)).unwrap();
            file.close().unwrap();
        }
    }

    fn three_samples() -> Vec<Vec<StackTrace>> {
        (0..3)
            .map(|i| vec![trace(1, vec![frame("work", i), frame("main", 1)])])
            .collect()
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("prm-samples-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn read_dir(dir: &Path) -> Vec<JsonLine> {
        let files = sample_files(dir).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].0, "42");
        read_samples(&read_sample_file(&files[0].1).unwrap()).unwrap()
    }

    #[test]
    fn reads_compressed_and_plain_files() {
        for compress in [true, false] {
            let dir = temp_dir(&format!("{compress}"));

            write_file(&dir, compress, three_samples());

            let file_name = sample_files(&dir).unwrap()[0].1.clone();
            assert_eq!(file_name.to_string_lossy().ends_with(".zst"), compress);
            let names: Vec<_> = frames_of(&read_dir(&dir))
                .into_iter()
                .map(|sample| sample[0][0].1)
                .collect();
            assert_eq!(names, [0, 1, 2]);
            std::fs::remove_dir_all(dir).unwrap();
        }
    }

    #[test]
    fn reads_the_complete_lines_of_cut_off_files() {
        for compress in [true, false] {
            let dir = temp_dir(&format!("cut-{compress}"));
            write_file(&dir, compress, three_samples());
            let path = sample_files(&dir).unwrap()[0].1.clone();
            let full = std::fs::read(&path).unwrap();

            // Every possible end must be readable, and never yield more samples than were written
            let mut read_counts = Vec::new();
            for length in 0..full.len() {
                std::fs::write(&path, &full[..length]).unwrap();
                read_counts.push(read_dir(&dir).len());
            }

            assert!(read_counts.is_sorted(), "{read_counts:?}");
            assert_eq!(read_counts.first(), Some(&0));
            assert!(read_counts.contains(&2), "{read_counts:?}");
            assert!(read_counts.iter().all(|it| *it <= 3), "{read_counts:?}");
            std::fs::remove_dir_all(dir).unwrap();
        }
    }
}
