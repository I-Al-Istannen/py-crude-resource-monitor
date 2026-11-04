use crate::export::ReportIdentifier;
use crate::types::{JsonLine, MemorySample, ProcessResources};
use flate2::Compression;
use flate2::write::GzEncoder;
use fxprof_processed_profile::{
    CategoryColor, CategoryHandle, CounterHandle, CpuDelta, Frame, FrameFlags, FrameInfo,
    GraphColor, MarkerFieldFlags, MarkerFieldFormat, MarkerTiming, ProcessHandle, Profile,
    ReferenceTimestamp, SamplingInterval, StaticSchemaMarker, StaticSchemaMarkerField,
    StringHandle, ThreadHandle, Timestamp,
};
use log::info;
use snafu::{Location, OptionExt, ResultExt, Snafu, Whatever};
use std::borrow::Borrow;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::File;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};

const MAIN_THREAD_NAME: &str = "MainThread";
const CATEGORY_PYTHON_NAME: &str = "Python";
const CATEGORY_NATIVE_NAME: &str = "Native";
/// The pid of the track with the total PSS, which is not a real process. The Firefox Profiler
/// groups tracks by pid, so it must not be the pid of the global track.
const PSS_TOTAL_PID: u32 = u32::MAX;

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

/// The default interval of `profile`
const DEFAULT_INTERVAL_MILLIS: u64 = 1000;

impl ProfileBuilder {
    pub fn from_samples<'a, T: Iterator<Item = &'a Vec<JsonLine>>>(
        samples: impl Fn() -> T,
        include_bandwidth: bool,
    ) -> Result<Self, Whatever> {
        let start_time_millis = Self::start_time(samples().flat_map(|lines| lines.iter()))?;
        let interval_millis = Self::sampling_interval(samples());

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
    /// Deltas are only taken within a file, as different files cover different time ranges. If no
    /// file has two samples, e.g. because the profile ended after one tick, this is the default
    /// interval of `profile`.
    pub fn sampling_interval<'a>(samples: impl Iterator<Item = &'a Vec<JsonLine>>) -> u64 {
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
            .map_or(DEFAULT_INTERVAL_MILLIS, |it| *it as u64)
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

        let mut process = ProfileBuilderProcess::new(self, "Global", 0, start, false);
        // Global CPU is meant to be divided by the number of cores, 100% means all cores are busy
        process.add_label_samples("Global", samples, |line| line.resources.cpu);
        process.finish(end);

        Ok(())
    }

    /// Adds a track with the sum of the PSS of all processes over time. Unlike the sum of their
    /// memory, it counts memory shared between processes only once.
    fn add_pss_total(&mut self, totals: BTreeMap<u128, u64>) {
        let (Some((&start, _)), Some((&end, _))) =
            (totals.first_key_value(), totals.last_key_value())
        else {
            return;
        };

        let mut process = ProfileBuilderProcess::new(
            self,
            "All tracked processes (PSS)",
            PSS_TOTAL_PID,
            start,
            false,
        );
        for (time, total) in totals {
            let timestamp = process.time(time);
            process
                .memory_counter
                .add_value(&mut process.parent.profile, timestamp, total as f64);
        }
        process.finish(end);
    }

    /// Adds processes that ran one after another as a single process to the profile. With
    /// `pack_threads`, threads are packed into lanes too, see [`ProfileBuilderProcess`].
    fn add_lane(&mut self, lane: Vec<Instance>, pack_threads: bool) -> Result<(), Whatever> {
        let (Some(first), Some(last)) = (lane.first(), lane.last()) else {
            return Ok(());
        };
        let (pid, start, end) = (first.pid, first.start(), last.end());
        let name = match lane.len() {
            1 => first.name().to_string(),
            count => format!("{} ({count} processes)", first.name()),
        };
        let shared = lane.len() > 1;

        let mut process = ProfileBuilderProcess::new(self, &name, pid, start, pack_threads);
        let mut previous_end = None;
        for instance in lane {
            if shared {
                if let Some(previous_end) = previous_end {
                    // Don't let the memory of the previous process linger until the next starts
                    process.reset_counters((previous_end + instance.start()) / 2);
                }
                process.add_lifetime_marker(&instance);
            }
            previous_end = Some(instance.end());
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

/// A process in the Firefox profile. With `pack_threads`, threads whose names only differ in
/// numbers and that never ran at the same time share a Firefox thread, so recreated thread pools
/// don't add a thread per run.
struct ProfileBuilderProcess<'a> {
    parent: &'a mut ProfileBuilder,
    process: ProcessHandle,
    main_thread: ThreadHandle,
    /// All threads except the main thread
    threads: HashMap<ThreadKey, ThreadHandle>,
    pack_threads: bool,
    /// For packed threads, the end of each lane per normalized thread name
    thread_lane_ends: HashMap<String, Vec<u128>>,
    thread_end_times: HashMap<ThreadHandle, Timestamp>,
    memory_counter: ProfileCounter<Initialized>,
    io_counter: Option<ProfileCounter<Initialized>>,
}

impl<'a> ProfileBuilderProcess<'a> {
    pub fn new(
        parent: &'a mut ProfileBuilder,
        name: &str,
        pid: u32,
        start_millis: u128,
        pack_threads: bool,
    ) -> Self {
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
            pack_threads,
            thread_lane_ends: HashMap::new(),
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
            self.add_memory_samples(&line.memory_samples);
            let cpu_delta = self.cpu(cpu(&line));
            self.parent
                .profile
                .add_sample(self.main_thread, timestamp, stack, cpu_delta, 1);
            self.add_counter_values(timestamp, &line.resources);
        }
    }

    /// Decides which Firefox thread each thread of one process goes to
    fn thread_keys(
        &mut self,
        samples: &[JsonLine],
        main_thread_id: u64,
    ) -> HashMap<u64, ThreadKey> {
        if !self.pack_threads {
            return HashMap::new();
        }
        // The name and lifetime of each thread
        let mut threads: HashMap<u64, (String, u128, u128)> = HashMap::new();
        for line in samples {
            for stacktrace in &line.stacktraces {
                if stacktrace.thread_id == main_thread_id {
                    continue;
                }
                let name = normalize_thread_name(stacktrace.thread_name.as_deref());
                threads
                    .entry(stacktrace.thread_id)
                    .and_modify(|(_, _, end)| *end = line.time)
                    .or_insert((name, line.time, line.time));
            }
        }
        let mut threads = threads.into_iter().collect::<Vec<_>>();
        threads.sort_by_key(|(id, (_, start, _))| (*start, *id));

        threads
            .into_iter()
            .map(|(id, (name, start, end))| {
                let lane_ends = self.thread_lane_ends.entry(name.clone()).or_default();
                let lane = assign_lane(lane_ends, start, end);
                (id, ThreadKey::Lane(name, lane))
            })
            .collect()
    }

    fn add_stack_samples(&mut self, samples: Vec<JsonLine>, main_thread_id: u64) {
        let thread_keys = self.thread_keys(&samples, main_thread_id);
        for line in samples {
            let timestamp = self.time(line.time);
            self.add_memory_samples(&line.memory_samples);

            for stacktrace in line.stacktraces {
                let thread = if stacktrace.thread_id == main_thread_id {
                    self.main_thread
                } else {
                    let key = thread_keys
                        .get(&stacktrace.thread_id)
                        .cloned()
                        .unwrap_or(ThreadKey::Id(stacktrace.thread_id));
                    let thread = match self.threads.get(&key) {
                        Some(thread) => *thread,
                        None => {
                            let thread = self.parent.profile.add_thread(
                                self.process,
                                stacktrace.thread_id as u32,
                                timestamp,
                                false,
                            );
                            if let ThreadKey::Lane(name, _) = &key {
                                self.parent.profile.set_thread_name(thread, name);
                            }
                            self.threads.insert(key.clone(), thread);
                            thread
                        }
                    };
                    // thread name might not be set in first line of the file, so we set it in
                    // every sample we find.
                    if let (ThreadKey::Id(_), Some(thread_name)) = (&key, stacktrace.thread_name) {
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

    /// Adds the memory measured between two samples
    fn add_memory_samples(&mut self, samples: &[MemorySample]) {
        for sample in samples {
            let timestamp = self.time(sample.time);
            self.memory_counter.add_value(
                &mut self.parent.profile,
                timestamp,
                sample.memory as f64,
            );
        }
    }

    fn reset_counters(&mut self, millis: u128) {
        let timestamp = self.time(millis);
        self.add_counter_values(
            timestamp,
            &ProcessResources {
                memory: 0,
                pss: None,
                cpu: 0.0,
                cpus: None,
                disk_read_bytes: 0,
                disk_write_bytes: 0,
                thread_resources: HashMap::new(),
            },
        );
    }

    /// Marks when a process sharing this Firefox process was alive
    fn add_lifetime_marker(&mut self, instance: &Instance) {
        let timing = MarkerTiming::Interval(self.time(instance.start()), self.time(instance.end()));
        let name = self.parent.profile.intern_string(instance.name());
        self.parent.profile.add_marker(
            self.main_thread,
            timing,
            ProcessLifetimeMarker {
                name,
                pid: instance.pid,
            },
        );
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
    /// Whether processes with the same parent and name that never run at the same time share a
    /// track. Recreated worker pools otherwise get a track per process.
    #[arg(long, value_enum, default_value_t = ProcessLanes::Auto)]
    lanes: ProcessLanes,
    /// The directory containing the profile data
    data_dir: PathBuf,
    /// The output file to write the gz-compressed JSON to
    output_file: PathBuf,
}

/// More processes than this are packed into lanes by default
const AUTO_LANES_THRESHOLD: usize = 50;

/// Long-running programs that recreate worker pools spawn thousands of short-lived processes. With
/// a track per process, the Firefox Profiler becomes unusable. Lanes pack processes with the same
/// parent and name that never run at the same time into one track, so the number of tracks is
/// the number of processes running at the same time.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessLanes {
    /// Share tracks if there are more than 50 processes
    Auto,
    /// Always share tracks
    Always,
    /// Give every process its own track
    Never,
}

/// Packs processes into lanes, see [`ProcessLanes`]. Processes running for more than half of the
/// profile keep their own track.
fn pack_processes(instances: Vec<Instance>, profile_duration: u128) -> Vec<Vec<Instance>> {
    let mut lanes = Vec::new();
    let mut groups: BTreeMap<(Option<u32>, String), Vec<Instance>> = BTreeMap::new();
    for instance in instances {
        let long_lived = (instance.end() - instance.start()) * 2 > profile_duration;
        match &instance.samples[0].process {
            Some(metadata) if !long_lived => groups
                .entry((metadata.parent_pid, metadata.name.clone()))
                .or_default()
                .push(instance),
            _ => lanes.push(vec![instance]),
        }
    }

    for group in groups.into_values() {
        let first_lane = lanes.len();
        let mut lane_ends = Vec::new();
        // The instances are sorted by start time
        for instance in group {
            let lane = first_lane + assign_lane(&mut lane_ends, instance.start(), instance.end());
            if lane == lanes.len() {
                lanes.push(Vec::new());
            }
            lanes[lane].push(instance);
        }
    }

    lanes
}

/// Returns the first lane that is free at `start` and occupies it until `end`. Lanes are
/// identified by their index in `lane_ends`, which holds when each lane is free again.
fn assign_lane(lane_ends: &mut Vec<u128>, start: u128, end: u128) -> usize {
    match lane_ends.iter().position(|lane_end| *lane_end < start) {
        Some(lane) => {
            lane_ends[lane] = end;
            lane
        }
        None => {
            lane_ends.push(end);
            lane_ends.len() - 1
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum ThreadKey {
    Id(u64),
    /// A normalized thread name and the lane among threads with that name
    Lane(String, usize),
}

/// Replaces numbers in a thread name, so `ThreadPoolExecutor-17_3` becomes `ThreadPoolExecutor-#_#`
fn normalize_thread_name(name: Option<&str>) -> String {
    let mut normalized = String::new();
    for c in name.unwrap_or("unnamed").chars() {
        if !c.is_ascii_digit() {
            normalized.push(c);
        } else if !normalized.ends_with('#') {
            normalized.push('#');
        }
    }
    normalized
}

/// Marks when a process that shares a track with others was alive
struct ProcessLifetimeMarker {
    name: StringHandle,
    pid: u32,
}

impl StaticSchemaMarker for ProcessLifetimeMarker {
    const UNIQUE_MARKER_TYPE_NAME: &'static str = "ProcessLifetime";
    // Only the pid fits into the boxes of short-lived processes
    const CHART_LABEL: Option<&'static str> = Some("{marker.data.pid}");
    const TOOLTIP_LABEL: Option<&'static str> = Some("{marker.name} {marker.data.pid}");
    const TABLE_LABEL: Option<&'static str> = Some("{marker.name} {marker.data.pid}");
    const FIELDS: &'static [StaticSchemaMarkerField] = &[StaticSchemaMarkerField {
        key: "pid",
        label: "PID",
        format: MarkerFieldFormat::Integer,
        flags: MarkerFieldFlags::empty(),
    }];

    fn name(&self, _profile: &mut Profile) -> StringHandle {
        self.name
    }

    fn category(&self, _profile: &mut Profile) -> CategoryHandle {
        CategoryHandle::OTHER
    }

    fn string_field_value(&self, _field_index: u32) -> StringHandle {
        unreachable!("the marker has no string fields")
    }

    fn number_field_value(&self, _field_index: u32) -> f64 {
        self.pid as f64
    }
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
    let end_millis = processes.values().flatten().map(|it| it.time).max();
    let duration_millis = end_millis.unwrap_or_default() - builder.start_time_millis;

    // Samples of the same tick share their time, so we can add them up by time
    let mut pss_totals = BTreeMap::<u128, u64>::new();
    for (identifier, samples) in &processes {
        if let ReportIdentifier::Pid(_) = identifier {
            for line in samples {
                if let Some(pss) = line.resources.pss {
                    *pss_totals.entry(line.time).or_default() += pss;
                }
            }
        }
    }

    let mut instances = Vec::new();
    for (identifier, samples) in processes {
        match identifier {
            ReportIdentifier::Pid(pid) => instances.extend(Instance::split(pid, samples)),
            ReportIdentifier::Global => builder.add_global(samples)?,
        }
    }
    builder.add_pss_total(pss_totals);
    // Ensure the report is deterministic
    instances.sort_by_key(|it| (it.start(), it.pid));

    let pack = match args.lanes {
        ProcessLanes::Auto => instances.len() > AUTO_LANES_THRESHOLD,
        ProcessLanes::Always => true,
        ProcessLanes::Never => false,
    };
    let lanes = if pack {
        let count = instances.len();
        let lanes = pack_processes(instances, duration_millis);
        info!("Packed {count} processes into {} lanes", lanes.len());
        lanes
    } else {
        instances.into_iter().map(|it| vec![it]).collect()
    };
    for lane in lanes {
        builder.add_lane(lane, pack)?;
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
            memory_samples: vec![],
            resources: ProcessResources {
                memory: 1024,
                pss: None,
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
            lanes: ProcessLanes::Never,
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

        assert_eq!(ProfileBuilder::sampling_interval(files.iter()), 100);
    }

    #[test]
    fn sampling_interval_falls_back_to_the_default_with_one_sample_per_file() {
        let files: Vec<Vec<JsonLine>> =
            vec![vec![line(1000, vec![], &[])], vec![line(1000, vec![], &[])]];

        assert_eq!(
            ProfileBuilder::sampling_interval(files.iter()),
            DEFAULT_INTERVAL_MILLIS
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

    /// The memory graph of the process with `pid` as (milliseconds since the start, bytes)
    fn memory_graph(json: &serde_json::Value, pid: u32) -> Vec<(f64, f64)> {
        let pid = pid.to_string();
        let counter = json["counters"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["category"] == "Memory" && c["pid"] == pid)
            .unwrap();
        let samples = &counter["samples"];
        let (mut time, mut value) = (0.0, 0.0);
        let deltas = samples["timeDeltas"].as_array().unwrap();
        let counts = samples["count"].as_array().unwrap();
        deltas
            .iter()
            .zip(counts)
            .map(|(delta, count)| {
                time += delta.as_f64().unwrap();
                value += count.as_f64().unwrap();
                (time, value)
            })
            .collect()
    }

    #[test]
    fn adds_memory_samples_between_two_samples_to_the_memory_graph() {
        let mut second = line(1100, vec![], &[]);
        second.memory_samples = vec![
            MemorySample {
                time: 1040,
                memory: 1024,
            },
            MemorySample {
                time: 1050,
                memory: 4096,
            },
        ];
        let samples = vec![line(1000, vec![], &[]), second];

        let json = processes_json(HashMap::from([(ReportIdentifier::Pid(7), samples)]));

        // Starts at zero, then the memory of the first sample, the spike, and the second sample
        assert_eq!(
            memory_graph(&json, 7),
            [
                (0.0, 0.0),
                (0.0, 1024.0),
                (40.0, 1024.0),
                (50.0, 4096.0),
                (100.0, 1024.0)
            ]
        );
    }

    #[test]
    fn adds_a_track_with_the_total_pss() {
        let process = |pss: &[u64]| {
            pss.iter()
                .enumerate()
                .map(|(i, pss)| {
                    let mut line = line(1000 + i as u128 * 100, vec![], &[]);
                    line.resources.pss = Some(*pss);
                    line
                })
                .collect::<Vec<_>>()
        };
        let json = processes_json(HashMap::from([
            (ReportIdentifier::Pid(1), process(&[100, 300])),
            (ReportIdentifier::Pid(2), process(&[50])),
        ]));

        assert_eq!(
            memory_graph(&json, PSS_TOTAL_PID),
            [(0.0, 0.0), (0.0, 150.0), (100.0, 300.0)]
        );
    }

    #[test]
    fn adds_no_pss_track_without_pss() {
        let json = processes_json(HashMap::from([(
            ReportIdentifier::Pid(1),
            vec![line(1000, vec![], &[]), line(1100, vec![], &[])],
        )]));
        let pss_total_pid = PSS_TOTAL_PID.to_string();

        assert!(
            json["counters"]
                .as_array()
                .unwrap()
                .iter()
                .all(|c| c["pid"] != pss_total_pid)
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

    /// Samples of a process with the given threads, one every 100ms from `start` to `end`
    fn process(name: &str, start: u128, end: u128, threads: &[(u64, &str)]) -> Vec<JsonLine> {
        (start..=end)
            .step_by(100)
            .map(|time| {
                let stacktraces = threads
                    .iter()
                    .map(|(id, thread)| stacktrace(*id, thread))
                    .collect();
                let mut line = line(time, stacktraces, &[]);
                line.process = Some(metadata(name, start as u64));
                line
            })
            .collect()
    }

    fn thread_names(json: &serde_json::Value) -> Vec<String> {
        let mut names = json["threads"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_string())
            .collect::<Vec<_>>();
        names.sort();
        names
    }

    #[test]
    fn packs_processes_that_never_overlap_into_lanes() {
        let main = [(1, MAIN_THREAD_NAME)];
        let mut processes =
            HashMap::from([(ReportIdentifier::Pid(1), process("root", 1000, 3000, &main))]);
        // A pool of two workers, recreated three times
        for run in 0..3 {
            for worker in 0..2 {
                let start = 1100 + run * 600;
                let pid = 10 + (run * 2 + worker) as u32;
                processes.insert(
                    ReportIdentifier::Pid(pid),
                    process("worker", start, start + 400, &main),
                );
            }
        }
        let mut args = args();
        args.lanes = ProcessLanes::Always;

        let profile = generate_fxprof(processes, &args).unwrap();
        let json = serde_json::to_value(&profile).unwrap();

        // The long-lived root keeps its own track, the workers share two
        assert_eq!(
            thread_names(&json),
            ["root", "worker (3 processes)", "worker (3 processes)"]
        );
        let markers = json["threads"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["markers"]["length"].as_u64().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(markers.iter().sum::<u64>(), 6);
    }

    #[test]
    fn packs_threads_with_the_same_name_that_never_overlap() {
        let mut samples = process(
            "python",
            1000,
            1200,
            &[(1, MAIN_THREAD_NAME), (2, "Pool-1_0")],
        );
        samples.extend(process(
            "python",
            1300,
            1500,
            &[(1, MAIN_THREAD_NAME), (3, "Pool-2_0"), (4, "Pool-2_1")],
        ));
        for line in &mut samples {
            line.process = Some(metadata("python", 1));
        }
        let mut args = args();
        args.lanes = ProcessLanes::Always;

        let profile =
            generate_fxprof(HashMap::from([(ReportIdentifier::Pid(1), samples)]), &args).unwrap();
        let json = serde_json::to_value(&profile).unwrap();

        // Pool-1_0 and Pool-2_0 share a thread, Pool-2_1 runs at the same time as Pool-2_0
        assert_eq!(thread_names(&json), ["Pool-#_#", "Pool-#_#", "python"]);
    }

    #[test]
    fn normalizes_numbers_in_thread_names() {
        assert_eq!(
            normalize_thread_name(Some("ThreadPoolExecutor-17_3")),
            "ThreadPoolExecutor-#_#"
        );
        assert_eq!(normalize_thread_name(None), "unnamed");
    }
}
