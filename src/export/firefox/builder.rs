use super::MemoryMetric;
use super::lanes::{Instance, assign_lane};
use super::markers::{ProcessLifetimeMarker, SkippedTicksMarker, StackCaptureFailedMarker};
use super::normalize::memory_timeline;
use crate::types::{JsonLine, StackTrace};
use fxprof_processed_profile::{
    CategoryColor, CategoryHandle, CounterHandle, CpuDelta, Frame, FrameFlags, FrameInfo,
    GraphColor, MarkerTiming, ProcessHandle, Profile, ReferenceTimestamp, SamplingInterval,
    ThreadHandle, Timestamp,
};
use log::info;
use snafu::{OptionExt, Whatever};
use std::borrow::Borrow;
use std::collections::{BTreeMap, HashMap};

pub(super) const MAIN_THREAD_NAME: &str = "MainThread";
pub(super) const CATEGORY_PYTHON_NAME: &str = "Python";
const CATEGORY_NATIVE_NAME: &str = "Native";
pub(super) const CATEGORY_GIL_WAIT_NAME: &str = "Waiting for GIL";
/// The frame added on top of the stacks of threads waiting for the GIL
pub(super) const GIL_WAIT_FRAME_NAME: &str = "<waiting for GIL>";
/// The pid of the track with the total PSS, which is not a real process. The Firefox Profiler
/// groups tracks by pid, so it must not be the pid of the global track.
pub(super) const PSS_TOTAL_PID: u32 = u32::MAX;

pub(super) struct ProfileBuilder {
    pub(super) start_time_millis: u128,
    interval_millis: u64,
    profile: Profile,
    category_native: CategoryHandle,
    category_python: CategoryHandle,
    category_gil_wait: CategoryHandle,
    include_bandwidth: bool,
    include_gil_waiters: bool,
    memory: MemoryMetric,
    /// The main thread of every process in the order they were added, i.e. the global tracks
    /// first and then by start time
    main_threads: Vec<ThreadHandle>,
    /// The summed CPU usage of every other thread, in percent of one core per sample
    thread_cpu: HashMap<ThreadHandle, f64>,
}

/// The default interval of `profile`
pub(super) const DEFAULT_INTERVAL_MILLIS: u64 = 1000;

/// At most this many main threads are shown by default. Without lanes, every short-lived process
/// has its own main thread.
pub(super) const VISIBLE_MAIN_THREADS: usize = 15;
/// At most this many threads besides the main threads are shown by default
const VISIBLE_THREADS: usize = 10;

impl ProfileBuilder {
    pub(super) fn from_samples<'a, T: Iterator<Item = &'a Vec<JsonLine>>>(
        samples: impl Fn() -> T,
        include_bandwidth: bool,
        include_gil_waiters: bool,
        memory: MemoryMetric,
    ) -> Result<Self, Whatever> {
        let start_time_millis = Self::start_time(samples().flat_map(|lines| lines.iter()))?;
        let interval_millis = Self::sampling_interval(samples());

        Ok(Self::new(
            start_time_millis,
            interval_millis,
            include_bandwidth,
            include_gil_waiters,
            memory,
        ))
    }

    fn start_time(samples: impl Iterator<Item = impl Borrow<JsonLine>>) -> Result<u128, Whatever> {
        samples
            .map(|it| it.borrow().earliest_time())
            .min()
            .whatever_context("no samples found")
    }

    /// Estimates the sampling interval from the time between consecutive samples of each file.
    /// Deltas are only taken within a file, as different files cover different time ranges. If no
    /// file has two samples, e.g. because the profile ended after one tick, this is the default
    /// interval of `profile`.
    pub(super) fn sampling_interval<'a>(samples: impl Iterator<Item = &'a Vec<JsonLine>>) -> u64 {
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

    fn new(
        start_time_millis: u128,
        interval_millis: u64,
        include_bandwidth: bool,
        include_gil_waiters: bool,
        memory: MemoryMetric,
    ) -> Self {
        let mut profile = Profile::new(
            // TODO: Add metadata to original data json files
            "python",
            ReferenceTimestamp::from_millis_since_unix_epoch(start_time_millis as f64),
            // TODO: Add metadata to original data json files
            SamplingInterval::from_millis(interval_millis),
        );
        let category_python = profile.add_category(CATEGORY_PYTHON_NAME, CategoryColor::Blue);
        let category_native = profile.add_category(CATEGORY_NATIVE_NAME, CategoryColor::Green);
        let category_gil_wait = profile.add_category(CATEGORY_GIL_WAIT_NAME, CategoryColor::Red);

        Self {
            interval_millis,
            profile,
            start_time_millis,
            category_native,
            category_python,
            category_gil_wait,
            include_bandwidth,
            include_gil_waiters,
            memory,
            main_threads: Vec::new(),
            thread_cpu: HashMap::new(),
        }
    }

    fn time(&self, millis: u128) -> Timestamp {
        Timestamp::from_millis_since_reference((millis - self.start_time_millis) as f64)
    }

    /// The CPU time used at `percent` of one core for `window_millis`
    fn cpu(&self, percent: f32, window_millis: u64) -> CpuDelta {
        CpuDelta::from_millis(percent as f64 / 100. * window_millis as f64)
    }

    /// The time each sample's CPU usage was measured over, which is the time since the previous
    /// sample of the same process. Ticks can be skipped, so it is not always the interval. The
    /// first sample is assumed to cover one interval.
    fn cpu_windows(&self, samples: &[JsonLine]) -> Vec<u64> {
        std::iter::once(self.interval_millis)
            .chain(
                samples
                    .windows(2)
                    .map(|window| window[1].time.saturating_sub(window[0].time) as u64),
            )
            .take(samples.len())
            .collect()
    }

    pub(super) fn add_global(&mut self, samples: Vec<JsonLine>) {
        let Some(first_sample) = samples.first() else {
            return;
        };
        let (start, end) = (first_sample.time, samples.last().unwrap().time);

        let mut process = ProfileBuilderProcess::new(self, "Global", 0, start, false);
        // Every tick writes a global sample, so gaps in them are ticks the profiler skipped
        process.add_skipped_ticks_markers(&samples);
        // Global CPU is meant to be divided by the number of cores, 100% means all cores are busy
        process.add_label_samples("Global", samples, |line| {
            line.resources.cpu / line.resources.cpus.unwrap_or(1) as f32
        });
        process.finish(end);
    }

    /// Adds a track with the sum of the PSS of all processes over time. Unlike the sum of their
    /// memory, it counts memory shared between processes only once.
    pub(super) fn add_pss_total(&mut self, totals: BTreeMap<u128, u64>) {
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
    pub(super) fn add_lane(&mut self, lane: Vec<Instance>, pack_threads: bool) {
        let (Some(first), Some(last)) = (lane.first(), lane.last()) else {
            return;
        };
        let (pid, start, end) = (first.pid, first.start(), last.end());
        let name = match lane.len() {
            1 => first.name().to_string(),
            count => format!("{} ({count} processes)", first.name()),
        };
        let gil_waiters = self.include_gil_waiters && lane.iter().any(Instance::waits_for_gil);
        let mut process = ProfileBuilderProcess::new(self, &name, pid, start, pack_threads);
        if gil_waiters {
            process.add_gil_wait_counter();
        }
        let mut previous_end = None;
        for instance in lane {
            if let Some(previous_end) = previous_end {
                // Don't let the memory of the previous process linger until the next starts
                process.reset_counters((previous_end + instance.start()) / 2);
            }
            process.add_lifetime_marker(&instance);
            process.add_stack_error_markers(&instance.samples);
            previous_end = Some(instance.end());
            process.add_instance(instance);
        }
        process.finish(end);
    }

    /// Without this, the Firefox Profiler shows the 15 busiest threads. Pools with many busy
    /// threads, like polars', fill all of them and hide the main threads. We show the main threads
    /// of the processes that started first, which includes the profiled one, and the busiest
    /// threads.
    fn set_visible_threads(&mut self) {
        let mut threads = self.thread_cpu.iter().collect::<Vec<_>>();
        // Sort by CPU, then by handle so the report is deterministic
        threads.sort_by(|(a, a_cpu), (b, b_cpu)| b_cpu.total_cmp(a_cpu).then(a.cmp(b)));
        // Like the Firefox Profiler, hide threads that are idle compared to the busiest one
        let threshold = threads.first().map_or(0.0, |(_, cpu)| **cpu * 0.05);
        let busiest = threads
            .into_iter()
            .take(VISIBLE_THREADS)
            .filter(|(_, cpu)| **cpu > threshold)
            .map(|(thread, _)| *thread)
            .collect::<Vec<_>>();

        let main_threads = self.main_threads.iter().take(VISIBLE_MAIN_THREADS);
        for thread in main_threads.chain(&busiest) {
            self.profile.add_initial_visible_thread(*thread);
        }
    }

    pub(super) fn finish(mut self) -> Profile {
        self.set_visible_threads();
        self.profile
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
    memory_counter: ProfileCounter,
    /// Unlike the memory, the I/O is recorded as the bytes since the previous sample, so its
    /// samples are the values themselves
    io_counter: Option<CounterHandle>,
    /// The number of threads waiting for the GIL, see [`Self::add_gil_wait_counter`]
    gil_wait_counter: Option<CounterHandle>,
}

impl<'a> ProfileBuilderProcess<'a> {
    fn new(
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
        parent.main_threads.push(main_thread);
        // Otherwise, the Firefox Profiler only shows markers in the tracks of known Firefox threads
        parent
            .profile
            .set_thread_show_markers_in_timeline(main_thread, true);

        // See "renderTrack" for names:
        // https://github.com/firefox-devtools/profiler/blob/main/src/components/timeline/LocalTrack.js#L102
        // (at revision 5c7515aa243e8b21de77e0434d9cc0f761e8bafd if broken)
        let memory_counter = ProfileCounter::new(
            &mut parent.profile,
            process,
            "malloc",
            "Memory",
            match parent.memory {
                MemoryMetric::Rss => "Resident set size (RSS)",
                MemoryMetric::Pss => "Proportional set size (PSS)",
            },
            GraphColor::Orange,
            start_timestamp,
        );
        let io_counter = if parent.include_bandwidth {
            Some(
                ProfileCounter::new(
                    &mut parent.profile,
                    process,
                    "io",
                    "Bandwidth",
                    "I/O read/write in bytes",
                    GraphColor::Teal,
                    start_timestamp,
                )
                .handle,
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
            gil_wait_counter: None,
        }
    }

    /// Adds a track with the number of threads waiting for the GIL. Unlike the other counters, its
    /// samples are the values themselves, not changes, as the Firefox Profiler plots each sample
    /// divided by the time since the previous one for counters it does not know.
    fn add_gil_wait_counter(&mut self) {
        let profile = &mut self.parent.profile;
        let handle = profile.add_counter(
            self.process,
            "Threads waiting for GIL",
            "GIL",
            "The number of threads waiting to take the GIL",
        );
        profile.set_counter_color(handle, GraphColor::Red);
        self.gil_wait_counter = Some(handle);
    }

    fn time(&self, millis: u128) -> Timestamp {
        self.parent.time(millis)
    }

    fn cpu(&self, percent: f32, window_millis: u64) -> CpuDelta {
        self.parent.cpu(percent, window_millis)
    }

    fn add_instance(&mut self, instance: Instance) {
        if let Some(main_thread_id) = main_thread_id(&instance.samples) {
            self.add_stack_samples(instance.samples, main_thread_id);
        } else {
            info!(
                "No stacktraces for process {} ({}), exporting only its resources",
                instance.pid,
                instance.name()
            );
            let label = instance.name().to_string();
            // Without threads, all CPU usage belongs to the main thread.
            self.add_label_samples(&label, instance.samples, |line| line.resources.cpu);
        }
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
        self.add_resource_samples(&samples);
        let windows = self.parent.cpu_windows(&samples);
        for (line, window) in samples.into_iter().zip(windows) {
            if line.exited {
                continue;
            }
            let timestamp = self.time(line.time);
            let cpu_delta = self.cpu(cpu(&line), window);
            self.parent
                .profile
                .add_sample(self.main_thread, timestamp, stack, cpu_delta, 1);
        }
    }

    /// Decides which Firefox thread each thread of one process goes to
    fn thread_keys(
        &mut self,
        samples: &[JsonLine],
        main_thread_id: u64,
    ) -> HashMap<ThreadIdentity, ThreadKey> {
        if !self.pack_threads {
            return HashMap::new();
        }
        // The name and lifetime of each thread
        let mut threads: HashMap<ThreadIdentity, (String, u128, u128)> = HashMap::new();
        for line in samples {
            for stacktrace in &line.stacktraces {
                if stacktrace.thread_id == main_thread_id {
                    continue;
                }
                let name = normalize_thread_name(stacktrace.thread_name.as_deref());
                threads
                    .entry(ThreadIdentity::of(stacktrace))
                    .and_modify(|(known_name, _, end)| {
                        // The first sample of a thread that reuses an id can still have the name of
                        // the previous one
                        if stacktrace.thread_name.is_some() {
                            *known_name = name.clone();
                        }
                        *end = line.time;
                    })
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
        self.add_resource_samples(&samples);
        let windows = self.parent.cpu_windows(&samples);
        for (line, window) in samples.into_iter().zip(windows) {
            if line.exited {
                continue;
            }
            let timestamp = self.time(line.time);
            let gil_waiters = line.stacktraces.iter().filter(|it| it.waiting_for_gil);
            self.add_gil_wait_value(timestamp, gil_waiters.count());

            for stacktrace in line.stacktraces {
                let thread = if stacktrace.thread_id == main_thread_id {
                    self.main_thread
                } else {
                    let identity = ThreadIdentity::of(&stacktrace);
                    let key = thread_keys
                        .get(&identity)
                        .cloned()
                        .unwrap_or(ThreadKey::Id(identity));
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
                // Shows the wait in the call tree and colors it in the activity graph
                if stacktrace.waiting_for_gil {
                    stack_frames.push(FrameInfo {
                        frame: Frame::Label(self.parent.profile.intern_string(GIL_WAIT_FRAME_NAME)),
                        category_pair: self.parent.category_gil_wait.into(),
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
                let cpu = match thread_resources {
                    Some(resources) => resources.cpu,
                    // Per-thread data is not available on all platforms, so we attribute the
                    // whole process to the main thread as a fallback.
                    None if thread == self.main_thread
                        && line.resources.thread_resources.is_empty() =>
                    {
                        line.resources.cpu
                    }
                    None => 0.0,
                };
                if thread != self.main_thread {
                    *self.parent.thread_cpu.entry(thread).or_default() += cpu as f64;
                }
                let cpu_delta = self.cpu(cpu, window);
                self.parent
                    .profile
                    .add_sample(thread, timestamp, stack, cpu_delta, 1);
            }
        }
    }

    /// Process resources are independent of whether stack capture succeeded.
    fn add_resource_samples(&mut self, samples: &[JsonLine]) {
        self.add_memory_timeline(samples);
        for line in samples.iter().filter(|line| !line.exited) {
            self.add_bandwidth_value(
                self.time(line.time),
                line.resources.disk_read_bytes + line.resources.disk_write_bytes,
            );
        }
    }

    fn add_bandwidth_value(&mut self, timestamp: Timestamp, bytes: u64) {
        if let Some(io_counter) = self.io_counter {
            self.parent
                .profile
                .add_counter_sample(io_counter, timestamp, bytes as f64, 1);
        }
    }

    /// Convert absolute memory measurements to deltas only after ordering the full timeline.
    fn add_memory_timeline(&mut self, samples: &[JsonLine]) {
        for sample in memory_timeline(samples, self.parent.memory) {
            let timestamp = self.time(sample.time);
            self.memory_counter.add_value(
                &mut self.parent.profile,
                timestamp,
                sample.memory as f64,
            );
        }
    }

    fn add_gil_wait_value(&mut self, timestamp: Timestamp, waiters: usize) {
        if let Some(counter) = self.gil_wait_counter {
            self.parent
                .profile
                .add_counter_sample(counter, timestamp, waiters as f64, 1);
        }
    }

    fn reset_counters(&mut self, millis: u128) {
        let timestamp = self.time(millis);
        self.add_gil_wait_value(timestamp, 0);
        self.memory_counter
            .add_value(&mut self.parent.profile, timestamp, 0.0);
        self.add_bandwidth_value(timestamp, 0);
    }

    /// Marks when a process was alive. This tells processes sharing a track apart, and lists all
    /// processes with their start and exit in the marker table.
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

    /// Marks consecutive samples whose stacks could not be captured for the same reason
    fn add_stack_error_markers(&mut self, samples: &[JsonLine]) {
        fn reason(line: &JsonLine) -> Option<&str> {
            line.stacktrace_error.as_deref().map(error_reason)
        }
        for run in samples.chunk_by(|a, b| reason(a) == reason(b)) {
            let (Some(reason), Some(details)) =
                (reason(&run[0]), &run[run.len() - 1].stacktrace_error)
            else {
                continue;
            };
            let (start, end) = (run[0].time, run[run.len() - 1].time);
            let timing = if start == end {
                MarkerTiming::Instant(self.time(start))
            } else {
                MarkerTiming::Interval(self.time(start), self.time(end))
            };
            let marker = StackCaptureFailedMarker {
                reason: self.parent.profile.intern_string(reason),
                details: self.parent.profile.intern_string(details),
            };
            self.parent
                .profile
                .add_marker(self.main_thread, timing, marker);
        }
    }

    /// Marks gaps of more than one and a half intervals between samples
    fn add_skipped_ticks_markers(&mut self, samples: &[JsonLine]) {
        let interval = self.parent.interval_millis.max(1) as u128;
        for window in samples.windows(2) {
            let (previous, next) = (window[0].time, window[1].time);
            let gap = next.saturating_sub(previous);
            if gap * 2 <= interval * 3 {
                continue;
            }
            let timing = MarkerTiming::Interval(self.time(previous), self.time(next));
            let skipped = ((gap + interval / 2) / interval).saturating_sub(1).max(1);
            self.parent.profile.add_marker(
                self.main_thread,
                timing,
                SkippedTicksMarker {
                    skipped: skipped as u64,
                },
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

/// The root cause of a stack capture error, the last line of its cause chain. Errors change while
/// attaching is retried, e.g. from "Not attached yet: ..." to "Not a Python process: ...", but keep
/// their root cause.
fn error_reason(error: &str) -> &str {
    let last_line = error
        .lines()
        .rev()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or(error);
    // Causes are numbered, like `1: Failed to find python version`
    match last_line.split_once(": ") {
        Some((number, cause)) if number.parse::<u32>().is_ok() => cause,
        _ => last_line,
    }
}

/// Picks the thread of the samples that is shown as the process's main thread
fn main_thread_id(samples: &[JsonLine]) -> Option<u64> {
    samples
        .iter()
        .flat_map(|line| &line.stacktraces)
        .min_by_key(|trace| {
            // Prefer a named main thread, then the first observed Python thread,
            // then the lowest thread ID. No stacks means a resource-only track.
            if trace.thread_name.as_deref() == Some(MAIN_THREAD_NAME) {
                (0, trace.thread_id)
            } else if trace.frames.iter().any(|frame| !frame.is_entry) {
                (1, 0)
            } else {
                (2, trace.thread_id)
            }
        })
        .map(|trace| trace.thread_id)
}

/// Adapts absolute measurements to the deltas Firefox counters store.
struct ProfileCounter {
    handle: CounterHandle,
    last_value: f64,
}

impl ProfileCounter {
    fn new(
        profile: &mut Profile,
        process: ProcessHandle,
        name: &str,
        category: &str,
        description: &str,
        color: GraphColor,
        start: Timestamp,
    ) -> Self {
        let handle = profile.add_counter(process, name, category, description);
        profile.set_counter_color(handle, color);
        profile.add_counter_sample(handle, start, 0.0, 1);
        Self {
            handle,
            last_value: 0.0,
        }
    }

    fn add_value(&mut self, profile: &mut Profile, timestamp: Timestamp, value: f64) {
        let delta = value - self.last_value;
        self.last_value = value;
        profile.add_counter_sample(self.handle, timestamp, delta, 1);
    }
}

/// Identifies a thread of a process. The `thread_id` is the address of the pthread, which a new
/// thread reuses once the previous one exited, so the OS thread id has to tell them apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct ThreadIdentity {
    thread_id: u64,
    os_thread_id: Option<u64>,
}

impl ThreadIdentity {
    fn of(stacktrace: &StackTrace) -> Self {
        Self {
            thread_id: stacktrace.thread_id,
            os_thread_id: stacktrace.os_thread_id,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum ThreadKey {
    Id(ThreadIdentity),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_numbers_in_thread_names() {
        assert_eq!(
            normalize_thread_name(Some("ThreadPoolExecutor-17_3")),
            "ThreadPoolExecutor-#_#"
        );
        assert_eq!(normalize_thread_name(None), "unnamed");
    }
}
