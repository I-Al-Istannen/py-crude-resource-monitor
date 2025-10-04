use crate::export::ReportIdentifier;
use crate::types::JsonLine;
use flate2::write::GzEncoder;
use flate2::Compression;
use fxprof_processed_profile::{
    CategoryColor, CategoryHandle, CounterHandle, CpuDelta, Frame, FrameFlags, FrameInfo,
    GraphColor, ProcessHandle, Profile, ReferenceTimestamp, SamplingInterval, StackHandle,
    ThreadHandle, Timestamp,
};
use log::info;
use snafu::{Location, OptionExt, ResultExt, Snafu, Whatever};
use std::borrow::Borrow;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::marker::PhantomData;
use std::path::Path;

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
}

impl ProfileBuilder {
    pub fn from_samples<'a, T: Iterator<Item = &'a Vec<JsonLine>>>(
        samples: impl Fn() -> T,
    ) -> Result<Self, Whatever> {
        let start_time_millis = Self::start_time(samples().flat_map(|lines| lines.iter()))?;
        let interval_millis = Self::sampling_interval(samples().flat_map(|lines| lines.iter()))?;

        Ok(Self::new(start_time_millis, interval_millis))
    }

    pub fn start_time(
        samples: impl Iterator<Item = impl Borrow<JsonLine>>,
    ) -> Result<u128, Whatever> {
        samples
            .map(|it| it.borrow().time)
            .min()
            .whatever_context("no samples found")
    }

    pub fn sampling_interval(
        samples: impl Iterator<Item = impl Borrow<JsonLine>>,
    ) -> Result<u64, Whatever> {
        let deltas = samples.collect::<Vec<_>>();
        let mut deltas = deltas
            .windows(2)
            .map(|window| {
                window[1]
                    .borrow()
                    .time
                    .saturating_sub(window[0].borrow().time)
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

    pub fn new(start_time_millis: u128, interval_millis: u64) -> Self {
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
        assert!(first_sample.time >= self.start_time_millis);

        ProfileBuilderProcess::new(self, first_sample.time, ReportIdentifier::Global)
            .add_global(samples)?;

        Ok(())
    }

    fn add_process(&mut self, pid: u32, samples: Vec<JsonLine>) -> Result<(), Whatever> {
        let Some(first_sample) = samples.first() else {
            return Ok(());
        };
        assert!(first_sample.time >= self.start_time_millis);

        ProfileBuilderProcess::new(self, first_sample.time, ReportIdentifier::Pid(pid))
            .add_main_thread(samples.iter())?
            .add_samples(samples)?;

        Ok(())
    }

    pub fn finish(self) -> Profile {
        self.profile
    }
}

struct MainThreadAdded {
    main_thread_handle: ThreadHandle,
}
struct GlobalAdded;

struct ProfileBuilderProcess<'a, T> {
    parent: &'a mut ProfileBuilder,
    process: ProcessHandle,
    pid: u32,
    start_time_millis: u128,
    threads: HashMap<u32, ThreadHandle>,
    memory_counter: ProfileCounter<Initialized>,
    io_counter: ProfileCounter<Initialized>,
    data: T,
}

impl<'a> ProfileBuilderProcess<'a, ()> {
    pub fn new(
        parent: &'a mut ProfileBuilder,
        start_time_millis: u128,
        identifier: ReportIdentifier,
    ) -> Self {
        assert!(start_time_millis >= parent.start_time_millis);

        let start_timestamp = parent.time(start_time_millis);
        let (pid, process) = match identifier {
            ReportIdentifier::Global => {
                (0, parent.profile.add_process("Global", 0, start_timestamp))
            }
            ReportIdentifier::Pid(pid) => (
                pid,
                parent.profile.add_process("Process", pid, start_timestamp),
            ),
        };

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
        let io_counter = ProfileCounter::new(
            &mut parent.profile,
            process,
            "io",
            "Bandwidth",
            "I/O read/write in bytes",
            GraphColor::Teal,
        )
        .initialize(&mut parent.profile, start_timestamp, 0.);

        Self {
            parent,
            process,
            pid,
            start_time_millis,
            threads: HashMap::new(),
            memory_counter,
            io_counter,
            data: (),
        }
    }

    fn add_main_thread(
        mut self,
        samples: impl Iterator<Item = impl Borrow<JsonLine>>,
    ) -> Result<ProfileBuilderProcess<'a, MainThreadAdded>, Whatever> {
        // adding the main thread first leads to the RAM display corresponding to mainThreadIndex 0 working
        let mut threads = samples
            .flat_map(|line| line.borrow().stacktraces.clone())
            .map(|it| {
                (
                    it.thread_id,
                    it.thread_name.clone().unwrap_or("unnamed".to_string()),
                )
            })
            .collect::<HashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        // Ensure the report is deterministic
        threads.sort_by(|(a_id, _), (b_id, _)| a_id.cmp(b_id));

        let main_thread = threads.iter().find(|(_, name)| name == MAIN_THREAD_NAME);

        let (main_thread_id, _) = match main_thread {
            Some(thread) => thread,
            None => {
                let all_threads = threads
                    .iter()
                    .map(|(_, name)| name.as_str())
                    .collect::<Vec<_>>();
                info!(
                    "No main thread found in samples, found threads `{}`.",
                    all_threads.as_slice().join(", ")
                );
                let chosen = threads.first().whatever_context("no threads found")?;
                info!(
                    "Using first thread `{}` with id `{}` as main thread.",
                    chosen.1, chosen.0
                );
                chosen
            }
        };
        let main_thread_handle = self.parent.profile.add_thread(
            self.process,
            *main_thread_id as u32,
            self.time(self.start_time_millis),
            true,
        );
        self.parent
            .profile
            .set_thread_name(main_thread_handle, MAIN_THREAD_NAME);
        self.threads
            .insert(*main_thread_id as u32, main_thread_handle);

        Ok(ProfileBuilderProcess {
            parent: self.parent,
            process: self.process,
            pid: self.pid,
            start_time_millis: self.start_time_millis,
            threads: self.threads,
            memory_counter: self.memory_counter,
            io_counter: self.io_counter,
            data: MainThreadAdded { main_thread_handle },
        })
    }

    pub fn add_global(
        mut self,
        samples: Vec<JsonLine>,
    ) -> Result<ProfileBuilderProcess<'a, GlobalAdded>, Whatever> {
        let main_thread = self.parent.profile.add_thread(
            self.process,
            0,
            self.time(self.start_time_millis),
            true,
        );
        for line in samples {
            assert!(line.time >= self.start_time_millis);
            let timestamp = self.time(line.time);

            self.memory_counter.add_value(
                &mut self.parent.profile,
                timestamp,
                line.resources.memory as f64,
            );
            self.io_counter.add_value(
                &mut self.parent.profile,
                timestamp,
                (line.resources.disk_read_bytes + line.resources.disk_write_bytes) as f64,
            );

            let cpu_delta = self.cpu(line.resources.cpu);
            let frame_label = Frame::Label(self.parent.profile.intern_string("Global"));
            let stack = self.parent.profile.intern_stack_frames(
                main_thread,
                vec![FrameInfo {
                    frame: frame_label,
                    category_pair: self.parent.category_native.into(),
                    flags: FrameFlags::empty(),
                }]
                .into_iter(),
            );
            self.parent
                .profile
                .add_sample(main_thread, timestamp, stack, cpu_delta, 1);
        }

        Ok(ProfileBuilderProcess {
            parent: self.parent,
            process: self.process,
            pid: self.pid,
            start_time_millis: self.start_time_millis,
            threads: HashMap::new(),
            memory_counter: self.memory_counter,
            io_counter: self.io_counter,
            data: GlobalAdded,
        })
    }
}

impl<T> ProfileBuilderProcess<'_, T> {
    fn time(&self, millis: u128) -> Timestamp {
        self.parent.time(millis)
    }

    fn cpu(&self, percent: f32) -> CpuDelta {
        self.parent.cpu(percent)
    }
}

impl ProfileBuilderProcess<'_, MainThreadAdded> {
    pub fn add_samples(mut self, samples: Vec<JsonLine>) -> Result<Self, Whatever> {
        let mut all_frames = HashMap::new();

        for line in samples {
            assert!(line.time >= self.start_time_millis);
            let timestamp = self.time(line.time);

            for stacktrace in line.stacktraces {
                let thread_id = stacktrace.thread_id as u32;

                let &mut thread = self.threads.entry(thread_id).or_insert_with(|| {
                    self.parent
                        .profile
                        .add_thread(self.process, thread_id, timestamp, false)
                });

                // thread name might not be set in first line of the file, so we set it in every
                // sample we find.
                if let Some(thread_name) = stacktrace.thread_name {
                    self.parent
                        .profile
                        .set_thread_name(thread, thread_name.as_str());
                }

                let mut stack_frames = Vec::with_capacity(stacktrace.frames.len());
                for frame in stacktrace.frames.iter().rev() {
                    let frame_info = all_frames
                        .entry((frame.filename.clone(), frame.line))
                        .or_insert_with(|| FrameInfo {
                            frame: Frame::Label(
                                self.parent.profile.intern_string(
                                    format!(
                                        "{} ({}:{})",
                                        frame.name,
                                        frame.short_filename.as_ref().unwrap(),
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
                    stack_frames.push(frame_info.clone());
                }
                let stack = self
                    .parent
                    .profile
                    .intern_stack_frames(thread, stack_frames.into_iter());

                let cpu_delta = if thread == self.data.main_thread_handle {
                    self.cpu(line.resources.cpu)
                } else if let Some(os_thread_id) = stacktrace.os_thread_id {
                    if let Some(resources) = line.resources.thread_resources.get(&os_thread_id) {
                        self.cpu(resources.cpu)
                    } else {
                        CpuDelta::ZERO
                    }
                } else {
                    CpuDelta::ZERO
                };
                self.parent
                    .profile
                    .add_sample(thread, timestamp, stack, cpu_delta, 1);
            }

            self.memory_counter.add_value(
                &mut self.parent.profile,
                timestamp,
                line.resources.memory as f64,
            );
            self.io_counter.add_value(
                &mut self.parent.profile,
                timestamp,
                (line.resources.disk_read_bytes + line.resources.disk_write_bytes) as f64,
            );
        }

        Ok(self)
    }
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

pub(super) fn export_report(data_dir: &Path, output_path: &Path) -> Result<(), ExportError> {
    let process_to_profile = super::read_report(data_dir).context(ReadReportSnafu)?;

    let profile = generate_fxprof(process_to_profile).context(FirefoxProfileSnafu)?;

    write_profile(output_path, profile)?;

    info!(
        "Wrote Firefox profile to {}. Open it in `https://profiler.firefox.com`.",
        output_path.display()
    );

    Ok(())
}

fn generate_fxprof(
    processes: HashMap<ReportIdentifier, Vec<JsonLine>>,
) -> Result<Profile, Whatever> {
    let mut builder = ProfileBuilder::from_samples(|| processes.values())?;

    for (pid, samples) in processes {
        match pid {
            ReportIdentifier::Pid(pid) => builder.add_process(pid, samples)?,
            ReportIdentifier::Global => builder.add_global(samples)?,
        }
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
