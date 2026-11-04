use crate::export::ReportIdentifier;
use crate::types::{JsonLine, ProcessResources};
use flate2::Compression;
use flate2::write::GzEncoder;
use fxprof_processed_profile::{
    CategoryColor, CategoryHandle, CounterHandle, CpuDelta, Frame, FrameFlags, FrameInfo,
    GraphColor, ProcessHandle, Profile, ReferenceTimestamp, SamplingInterval, ThreadHandle,
    Timestamp,
};
use log::info;
use snafu::{Location, OptionExt, ResultExt, Snafu, Whatever};
use std::borrow::Borrow;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};

const MAIN_THREAD_NAME: &str = "MainThread";
const CATEGORY_PYTHON_NAME: &str = "Python";
const CATEGORY_NATIVE_NAME: &str = "Native";

#[derive(Debug, Snafu)]
pub enum ExportError {
    #[snafu(display("Error reading report at {location}"))]
    ReadReport {
        source: Whatever,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Error serializing reports at {location}"))]
    SerializeReports {
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Error writing output file `{path}` at {location}"))]
    WriteOutput {
        source: std::io::Error,
        path: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Error writing gzipped output file `{path}` at {location}"))]
    WriteOutputGz {
        source: std::io::Error,
        path: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Error generating Firefox profile at {location}"))]
    FirefoxProfile {
        source: Whatever,
        #[snafu(implicit)]
        location: Location,
    },
}

struct ProfileBuilder {
    start_time_millis: u128,
    interval_millis: u64,
    profile: Profile,
    category_native: CategoryHandle,
    category_python: CategoryHandle,
    include_bandwidth: bool,
}

impl ProfileBuilder {
    pub fn from_samples<'a, T: Iterator<Item = &'a Vec<JsonLine>>>(
        samples: impl Fn() -> T,
        include_bandwidth: bool,
    ) -> Result<Self, Whatever> {
        let start_time_millis = Self::start_time(samples().flat_map(|lines| lines.iter()))?;
        let interval_millis = Self::sampling_interval(samples())?;

        Ok(Self::new(
            start_time_millis,
            interval_millis,
            include_bandwidth,
        ))
    }

    pub fn start_time(
        samples: impl Iterator<Item = impl Borrow<JsonLine>>,
    ) -> Result<u128, Whatever> {
        samples
            .map(|it| it.borrow().time)
            .min()
            .whatever_context("no samples found")
    }

    /// Estimates the sampling interval from the time between consecutive samples of each file.
    /// Deltas are only taken within a file, as different files cover different time ranges.
    pub fn sampling_interval<'a>(
        samples: impl Iterator<Item = &'a Vec<JsonLine>>,
    ) -> Result<u64, Whatever> {
        let mut deltas = samples
            .flat_map(|lines| {
                lines
                    .windows(2)
                    .map(|window| window[1].time.saturating_sub(window[0].time))
            })
            .collect::<Vec<_>>();
        deltas.sort_unstable();

        // take the median of the deltas as intended interval
        deltas
            .get(deltas.len() / 2)
            .copied()
            .map(|it| it as u64)
            .whatever_context("no samples found")
    }

    pub fn new(start_time_millis: u128, interval_millis: u64, include_bandwidth: bool) -> Self {
        let mut profile = Profile::new(
            // TODO: Add metadata to original data json files
            "python",
            ReferenceTimestamp::from_millis_since_unix_epoch(start_time_millis as f64),
            // TODO: Add metadata to original data json files
            SamplingInterval::from_millis(interval_millis),
        );
        let category_python = profile.add_category(CATEGORY_PYTHON_NAME, CategoryColor::Blue);
        let category_native = profile.add_category(CATEGORY_NATIVE_NAME, CategoryColor::Green);

        Self {
            interval_millis,
            profile,
            start_time_millis,
            category_native,
            category_python,
            include_bandwidth,
        }
    }

    fn time(&self, millis: u128) -> Timestamp {
        Timestamp::from_millis_since_reference((millis - self.start_time_millis) as f64)
    }

    fn cpu(&self, percent: f32) -> CpuDelta {
        CpuDelta::from_millis(percent as f64 / 100. * self.interval_millis as f64)
    }

    fn add_global(&mut self, samples: Vec<JsonLine>) -> Result<(), Whatever> {
        let Some(first_sample) = samples.first() else {
            return Ok(());
        };
        let (start, end) = (first_sample.time, samples.last().unwrap().time);

        let mut process = ProfileBuilderProcess::new(self, "Global", 0, start);
        // Global CPU is meant to be divided by the number of cores, 100% means all cores are busy
        process.add_label_samples("Global", samples, |line| line.resources.cpu);
        process.finish(end);

        Ok(())
    }

    /// Adds processes that ran one after another as a single process to the profile.
    fn add_lane(&mut self, lane: Vec<Instance>) -> Result<(), Whatever> {
        let (Some(first), Some(last)) = (lane.first(), lane.last()) else {
            return Ok(());
        };
        let (pid, start, end) = (first.pid, first.start(), last.end());
        let name = first.name().to_string();

        let mut process = ProfileBuilderProcess::new(self, &name, pid, start);
        for instance in lane {
            process.add_instance(instance)?;
        }
        process.finish(end);

        Ok(())
    }

    pub fn finish(self) -> Profile {
        self.profile
    }
}

/// One profiled process. The samples of a pid can belong to several processes over time.
struct Instance {
    pid: u32,
    /// Never empty
    samples: Vec<JsonLine>,
}

impl Instance {
    /// Splits the samples of one pid into the processes that used it.
    fn split(pid: u32, samples: Vec<JsonLine>) -> Vec<Self> {
        let mut instances: Vec<Self> = Vec::new();
        for line in samples {
            match instances.last_mut() {
                Some(last)
                    if last.start_time() == line.process.as_ref().map(|it| it.start_time) =>
                {
                    last.samples.push(line)
                }
                _ => instances.push(Self {
                    pid,
                    samples: vec![line],
                }),
            }
        }
        instances
    }

    fn start(&self) -> u128 {
        self.samples[0].time
    }

    fn end(&self) -> u128 {
        self.samples[self.samples.len() - 1].time
    }

    fn start_time(&self) -> Option<u64> {
        self.samples[0].process.as_ref().map(|it| it.start_time)
    }

    fn name(&self) -> &str {
        self.samples[0]
            .process
            .as_ref()
            .map_or("Process", |it| it.name.as_str())
    }

    fn has_stacktraces(&self) -> bool {
        self.samples.iter().any(|it| !it.stacktraces.is_empty())
    }
}

/// A process in the Firefox profile
struct ProfileBuilderProcess<'a> {
    parent: &'a mut ProfileBuilder,
    process: ProcessHandle,
    main_thread: ThreadHandle,
    /// All threads except the main thread, by their thread id
    threads: HashMap<u64, ThreadHandle>,
    thread_end_times: HashMap<ThreadHandle, Timestamp>,
    memory_counter: ProfileCounter<Initialized>,
    io_counter: Option<ProfileCounter<Initialized>>,
}

impl<'a> ProfileBuilderProcess<'a> {
    pub fn new(parent: &'a mut ProfileBuilder, name: &str, pid: u32, start_millis: u128) -> Self {
        assert!(start_millis >= parent.start_time_millis);

        let start_timestamp = parent.time(start_millis);
        let process = parent.profile.add_process(name, pid, start_timestamp);
        // Adding the main thread first makes the memory track belong to it
        let main_thread = parent
            .profile
            .add_thread(process, pid, start_timestamp, true);
        parent
            .profile
            .set_thread_name(main_thread, MAIN_THREAD_NAME);

        // See "renderTrack" for names:
        // https://github.com/firefox-devtools/profiler/blob/main/src/components/timeline/LocalTrack.js#L102
        // (at revision 5c7515aa243e8b21de77e0434d9cc0f761e8bafd if broken)
        let memory_counter = ProfileCounter::new(
            &mut parent.profile,
            process,
            "malloc",
            "Memory",
            "Amount of allocated memory",
            GraphColor::Orange,
        )
        .initialize(&mut parent.profile, start_timestamp, 0.);
        let io_counter = if parent.include_bandwidth {
            Some(
                ProfileCounter::new(
                    &mut parent.profile,
                    process,
                    "io",
                    "Bandwidth",
                    "I/O read/write in bytes",
                    GraphColor::Teal,
                )
                .initialize(&mut parent.profile, start_timestamp, 0.),
            )
        } else {
            None
        };

        Self {
            parent,
            process,
            main_thread,
            threads: HashMap::new(),
            thread_end_times: HashMap::new(),
            memory_counter,
            io_counter,
        }
    }

    fn time(&self, millis: u128) -> Timestamp {
        self.parent.time(millis)
    }

    fn cpu(&self, percent: f32) -> CpuDelta {
        self.parent.cpu(percent)
    }

    fn add_instance(&mut self, instance: Instance) -> Result<(), Whatever> {
        if instance.has_stacktraces() {
            let main_thread_id = main_thread_id(&instance.samples)?;
            self.add_stack_samples(instance.samples, main_thread_id);
        } else {
            info!(
                "No stacktraces for process {} ({}), exporting only its resources",
                instance.pid,
                instance.name()
            );
            let label = instance.name().to_string();
            // Without threads, all CPU usage belongs to the main thread. Undo the division by the
            // number of cores, as thread CPU is relative to one core.
            self.add_label_samples(&label, instance.samples, |line| {
                line.resources.cpu * line.resources.cpus.unwrap_or(1) as f32
            });
        }
        Ok(())
    }

    /// Adds samples without stacks, attributing them to a single frame named `label`.
    fn add_label_samples(
        &mut self,
        label: &str,
        samples: Vec<JsonLine>,
        cpu: impl Fn(&JsonLine) -> f32,
    ) {
        let frame_label = Frame::Label(self.parent.profile.intern_string(label));
        let stack = self.parent.profile.intern_stack_frames(
            self.main_thread,
            [FrameInfo {
                frame: frame_label,
                category_pair: self.parent.category_native.into(),
                flags: FrameFlags::empty(),
            }]
            .into_iter(),
        );
        for line in samples {
            let timestamp = self.time(line.time);
            let cpu_delta = self.cpu(cpu(&line));
            self.parent
                .profile
                .add_sample(self.main_thread, timestamp, stack, cpu_delta, 1);
            self.add_counter_values(timestamp, &line.resources);
        }
    }

    fn add_stack_samples(&mut self, samples: Vec<JsonLine>, main_thread_id: u64) {
        for line in samples {
            let timestamp = self.time(line.time);

            for stacktrace in line.stacktraces {
                let thread = if stacktrace.thread_id == main_thread_id {
                    self.main_thread
                } else {
                    let thread = *self.threads.entry(stacktrace.thread_id).or_insert_with(|| {
                        self.parent.profile.add_thread(
                            self.process,
                            stacktrace.thread_id as u32,
                            timestamp,
                            false,
                        )
                    });
                    // thread name might not be set in first line of the file, so we set it in
                    // every sample we find.
                    if let Some(thread_name) = stacktrace.thread_name {
                        self.parent
                            .profile
                            .set_thread_name(thread, thread_name.as_str());
                    }
                    thread
                };
                self.thread_end_times.insert(thread, timestamp);

                let mut stack_frames = Vec::with_capacity(stacktrace.frames.len());
                for frame in stacktrace.frames.iter().rev() {
                    stack_frames.push(FrameInfo {
                        frame: Frame::Label(
                            self.parent.profile.intern_string(
                                format!(
                                    "{} ({}:{})",
                                    frame.name,
                                    frame
                                        .short_filename
                                        .as_deref()
                                        .unwrap_or(frame.filename.as_str()),
                                    frame.line
                                )
                                .as_str(),
                            ),
                        ),
                        category_pair: if frame.is_entry {
                            self.parent.category_native.into()
                        } else {
                            self.parent.category_python.into()
                        },
                        flags: FrameFlags::empty(),
                    });
                }
                let stack = self
                    .parent
                    .profile
                    .intern_stack_frames(thread, stack_frames.into_iter());

                let thread_resources = stacktrace
                    .os_thread_id
                    .and_then(|id| line.resources.thread_resources.get(&id));
                let cpu_delta = match thread_resources {
                    Some(resources) => self.cpu(resources.cpu),
                    // Per-thread data is not available on all platforms, so we attribute the
                    // whole process to the main thread as a fallback. The process CPU is divided
                    // by the number of cores, thread CPU is not.
                    None if thread == self.main_thread
                        && line.resources.thread_resources.is_empty() =>
                    {
                        let cpus = line.resources.cpus.unwrap_or(1) as f32;
                        self.cpu(line.resources.cpu * cpus)
                    }
                    None => CpuDelta::ZERO,
                };
                self.parent
                    .profile
                    .add_sample(thread, timestamp, stack, cpu_delta, 1);
            }

            self.add_counter_values(timestamp, &line.resources);
        }
    }

    fn add_counter_values(&mut self, timestamp: Timestamp, resources: &ProcessResources) {
        self.memory_counter
            .add_value(&mut self.parent.profile, timestamp, resources.memory as f64);
        if let Some(io_counter) = self.io_counter.as_mut() {
            io_counter.add_value(
                &mut self.parent.profile,
                timestamp,
                (resources.disk_read_bytes + resources.disk_write_bytes) as f64,
            );
        }
    }

    /// Ends the process and all its threads. Threads that were last seen earlier end then.
    fn finish(self, end_millis: u128) {
        let end = self.time(end_millis);
        let profile = &mut self.parent.profile;
        profile.set_process_end_time(self.process, end);
        profile.set_thread_end_time(self.main_thread, end);
        for (thread, end) in self.thread_end_times {
            if thread != self.main_thread {
                profile.set_thread_end_time(thread, end);
            }
        }
    }
}

/// Picks the thread of the samples that is shown as the process's main thread
fn main_thread_id(samples: &[JsonLine]) -> Result<u64, Whatever> {
    let mut threads = samples
        .iter()
        .flat_map(|it| it.stacktraces.iter())
        .map(|it| (it.thread_id, it.thread_name.as_deref().unwrap_or("unnamed")))
        .collect::<HashSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    // Ensure the report is deterministic
    threads.sort_by_key(|(a_id, _)| *a_id);

    let main_thread = threads.iter().find(|(_, name)| *name == MAIN_THREAD_NAME);

    let main_thread_id = match main_thread {
        Some((thread_id, _)) => *thread_id,
        None => {
            let all_threads = threads.iter().map(|(_, name)| *name).collect::<Vec<_>>();
            info!(
                "No main thread found in samples, found threads `{}`.",
                all_threads.as_slice().join(", ")
            );
            let mut threads_with_py_frame = samples
                .iter()
                .flat_map(|it| it.stacktraces.iter())
                .filter(|it| it.frames.iter().any(|f| !f.is_entry))
                .map(|it| (it.thread_id, it.thread_name.as_deref().unwrap_or("unnamed")))
                .collect::<Vec<_>>();
            threads_with_py_frame.dedup();

            let chosen = if !threads_with_py_frame.is_empty() {
                info!(
                    "Choosing from threads with Python frames: `{}`.",
                    threads_with_py_frame
                        .iter()
                        .map(|(_, name)| *name)
                        .collect::<Vec<_>>()
                        .join(", ")
                );
                threads_with_py_frame
                    .first()
                    .whatever_context("no threads found")?
            } else {
                threads.first().whatever_context("no threads found")?
            };

            info!(
                "Using first thread `{}` with id `{}` as main thread.",
                chosen.1, chosen.0
            );
            chosen.0
        }
    };

    Ok(main_thread_id)
}

struct Initialized;
struct ProfileCounter<T> {
    handle: CounterHandle,
    last_value: f64,
    _marker: PhantomData<T>,
}

impl ProfileCounter<()> {
    pub fn new(
        profile: &mut Profile,
        process: ProcessHandle,
        name: &str,
        category: &str,
        description: &str,
        color: GraphColor,
    ) -> Self {
        let handle = profile.add_counter(process, name, category, description);
        profile.set_counter_color(handle, color);
        Self {
            handle,
            last_value: 0.0,
            _marker: PhantomData,
        }
    }

    /// Sets the initial value of the counter. All other values are relative to this value.
    /// Set this to zero if you want to start counting from zero.
    pub fn initialize(
        self,
        profile: &mut Profile,
        timestamp: Timestamp,
        value: f64,
    ) -> ProfileCounter<Initialized> {
        profile.add_counter_sample(self.handle, timestamp, value, 1);
        ProfileCounter {
            handle: self.handle,
            last_value: value,
            _marker: PhantomData,
        }
    }
}

impl ProfileCounter<Initialized> {
    pub fn add_value(&mut self, profile: &mut Profile, timestamp: Timestamp, value: f64) {
        let delta = value - self.last_value;
        self.last_value = value;
        profile.add_counter_sample(self.handle, timestamp, delta, 1);
    }
}

#[derive(clap::Args, Debug)]
pub struct FirefoxExportArguments {
    /// Whether to include bandwidth usage in the export
    #[arg(long, default_value_t = false)]
    bandwidth: bool,
    /// The directory containing the profile data
    data_dir: PathBuf,
    /// The output file to write the gz-compressed JSON to
    output_file: PathBuf,
}

pub(super) fn export_report(args: FirefoxExportArguments) -> Result<(), ExportError> {
    let process_to_profile = super::read_report(&args.data_dir).context(ReadReportSnafu)?;

    let profile = generate_fxprof(process_to_profile, &args).context(FirefoxProfileSnafu)?;

    write_profile(&args.output_file, profile)?;

    info!(
        "Wrote Firefox profile to {}. Open it in `https://profiler.firefox.com`.",
        args.output_file.display()
    );

    Ok(())
}

fn generate_fxprof(
    processes: HashMap<ReportIdentifier, Vec<JsonLine>>,
    args: &FirefoxExportArguments,
) -> Result<Profile, Whatever> {
    let mut builder = ProfileBuilder::from_samples(|| processes.values(), args.bandwidth)?;

    let mut instances = Vec::new();
    for (identifier, samples) in processes {
        match identifier {
            ReportIdentifier::Pid(pid) => instances.extend(Instance::split(pid, samples)),
            ReportIdentifier::Global => builder.add_global(samples)?,
        }
    }
    // Ensure the report is deterministic
    instances.sort_by_key(|it| (it.start(), it.pid));

    for instance in instances {
        builder.add_lane(vec![instance])?;
    }

    Ok(builder.finish())
}

fn write_profile(output_path: &Path, profile: Profile) -> Result<(), ExportError> {
    let output_file = File::create(output_path).context(WriteOutputSnafu {
        path: output_path.display().to_string(),
    })?;

    let mut gz = GzEncoder::new(output_file, Compression::default());

    // Serialize the data to JSON and write it to the gzipped file
    serde_json::to_writer(&mut gz, &profile).context(SerializeReportsSnafu)?;

    // Finish is required to finalize the compressed output and ensure all data is written,
    // without any corruption.
    gz.finish().context(WriteOutputGzSnafu {
        path: output_path.display().to_string(),
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ProcessMetadata, StackTrace, ThreadResources};

    fn stacktrace(thread_id: u64, name: &str) -> StackTrace {
        StackTrace {
            pid: 1,
            thread_id,
            thread_name: Some(name.to_string()),
            os_thread_id: Some(thread_id),
            active: true,
            owns_gil: false,
            frames: vec![crate::types::Frame {
                name: "work".to_string(),
                filename: "/app/main.py".to_string(),
                module: None,
                short_filename: Some("main.py".to_string()),
                line: 42,
                locals: None,
                is_entry: false,
            }],
            process_info: None,
        }
    }

    fn line(time: u128, stacktraces: Vec<StackTrace>, thread_cpu: &[(u64, f32)]) -> JsonLine {
        JsonLine {
            stacktraces,
            stacktrace_error: None,
            process: None,
            resources: ProcessResources {
                memory: 1024,
                cpu: 50.0,
                cpus: None,
                disk_read_bytes: 0,
                disk_write_bytes: 0,
                thread_resources: thread_cpu
                    .iter()
                    .map(|&(id, cpu)| {
                        (
                            id,
                            ThreadResources {
                                cpu,
                                memory: 0,
                                disk_read_bytes: 0,
                                disk_write_bytes: 0,
                            },
                        )
                    })
                    .collect(),
            },
            index: 0,
            time,
        }
    }

    fn args() -> FirefoxExportArguments {
        FirefoxExportArguments {
            bandwidth: true,
            data_dir: PathBuf::new(),
            output_file: PathBuf::new(),
        }
    }

    #[test]
    fn sampling_interval_ignores_deltas_across_files() {
        // Interleaved processes would produce many tiny deltas if all samples were mixed
        let first = (0..10).map(|i| line(1000 + i * 100, vec![], &[])).collect();
        let second = (0..10).map(|i| line(1050 + i * 100, vec![], &[])).collect();
        let files: Vec<Vec<JsonLine>> = vec![first, second];

        assert_eq!(
            ProfileBuilder::sampling_interval(files.iter()).unwrap(),
            100
        );
    }

    #[test]
    fn exports_threads_and_processes_without_stacktraces() {
        let threads = || vec![stacktrace(1, MAIN_THREAD_NAME), stacktrace(2, "worker")];
        let python = (0..3)
            .map(|i| line(1000 + i * 100, threads(), &[(1, 80.0), (2, 20.0)]))
            .collect();
        let mut failed_line = line(1000, vec![], &[]);
        failed_line.stacktrace_error = Some("not a python process".to_string());
        failed_line.process = Some(metadata("yes", 1));

        let processes = HashMap::from([
            (ReportIdentifier::Pid(1), python),
            (ReportIdentifier::Pid(2), vec![failed_line]),
            (
                ReportIdentifier::Global,
                (0..3).map(|i| line(1000 + i * 100, vec![], &[])).collect(),
            ),
        ]);

        let profile = generate_fxprof(processes, &args()).unwrap();
        let json = serde_json::to_value(&profile).unwrap();

        let mut thread_names = json["threads"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_string())
            .collect::<Vec<_>>();
        thread_names.sort();
        // Global has one thread, process 1 has two and process 2 one with its resources.
        // The main thread of each process is named after the process.
        assert_eq!(thread_names, ["Global", "Process", "worker", "yes"]);

        // Each thread gets its own CPU usage, not the one of the whole process (50%)
        let cpu_deltas = |name: &str| {
            let thread = json["threads"]
                .as_array()
                .unwrap()
                .iter()
                .find(|t| t["name"] == name)
                .unwrap();
            thread["samples"]["threadCPUDelta"].clone()
        };
        // 80% and 20% of a 100ms interval, in µs
        assert_eq!(
            cpu_deltas("Process"),
            serde_json::json!([80000, 80000, 80000])
        );
        assert_eq!(
            cpu_deltas("worker"),
            serde_json::json!([20000, 20000, 20000])
        );
    }

    fn metadata(name: &str, start_time: u64) -> ProcessMetadata {
        ProcessMetadata {
            name: name.to_string(),
            parent_pid: Some(1),
            start_time,
        }
    }

    fn processes_json(processes: HashMap<ReportIdentifier, Vec<JsonLine>>) -> serde_json::Value {
        serde_json::to_value(generate_fxprof(processes, &args()).unwrap()).unwrap()
    }

    #[test]
    fn splits_reused_pids_and_ends_processes_at_their_last_sample() {
        let samples = (0..6)
            .map(|i| {
                let mut line = line(1000 + i * 100, vec![], &[]);
                let (name, start_time) = if i < 3 { ("first", 1) } else { ("second", 2) };
                line.process = Some(metadata(name, start_time));
                line
            })
            .collect();
        let json = processes_json(HashMap::from([(ReportIdentifier::Pid(7), samples)]));

        let threads = json["threads"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| {
                (
                    t["name"].as_str().unwrap().to_string(),
                    t["registerTime"].as_f64().unwrap(),
                    t["unregisterTime"].as_f64().unwrap(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            threads,
            [
                ("first".to_string(), 0.0, 200.0),
                ("second".to_string(), 300.0, 500.0)
            ]
        );
    }

    fn thread_cpu_deltas(
        processes: HashMap<ReportIdentifier, Vec<JsonLine>>,
        name: &str,
    ) -> serde_json::Value {
        let profile = generate_fxprof(processes, &args()).unwrap();
        let json = serde_json::to_value(&profile).unwrap();
        let thread = json["threads"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["name"] == name)
            .unwrap();
        thread["samples"]["threadCPUDelta"].clone()
    }

    #[test]
    fn main_thread_falls_back_to_undivided_process_cpu() {
        // No per-thread data at all, like on macOS: 50% of 4 cores is two full cores
        let samples = (0..3)
            .map(|i| {
                let mut line = line(1000 + i * 100, vec![stacktrace(1, MAIN_THREAD_NAME)], &[]);
                line.resources.cpus = Some(4);
                line
            })
            .collect();
        let processes = HashMap::from([(ReportIdentifier::Pid(1), samples)]);

        assert_eq!(
            thread_cpu_deltas(processes, "Process"),
            serde_json::json!([200000, 200000, 200000])
        );
    }

    #[test]
    fn main_thread_without_own_data_is_idle_if_other_threads_have_data() {
        // Older profiles miss the main thread, the process CPU belongs to the worker
        let threads = || vec![stacktrace(1, MAIN_THREAD_NAME), stacktrace(2, "worker")];
        let samples = (0..3)
            .map(|i| line(1000 + i * 100, threads(), &[(2, 100.0)]))
            .collect();
        let processes = HashMap::from([(ReportIdentifier::Pid(1), samples)]);

        assert_eq!(
            thread_cpu_deltas(processes, "Process"),
            serde_json::json!([0, 0, 0])
        );
    }
}
