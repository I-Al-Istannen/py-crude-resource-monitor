use crate::export::ReportIdentifier;
use crate::types::JsonLine;
use flate2::write::GzEncoder;
use flate2::Compression;
use fxprof_processed_profile::{
    CategoryColor, CategoryHandle, CounterHandle, CpuDelta, Frame, FrameFlags, FrameInfo,
    GraphColor, ProcessHandle, Profile, ReferenceTimestamp, SamplingInterval, ThreadHandle,
    Timestamp,
};
use snafu::{Location, OptionExt, ResultExt, Snafu, Whatever};
use std::borrow::Borrow;
use std::collections::HashMap;
use std::fs::File;
use std::marker::PhantomData;
use std::path::Path;

const MAIN_THREAD_NAME: &str = "MainThread";
const PROCESS_CPU_COUNTER_NAME: &str = "processCPU";
const PROCESS_CPU_CATEGORY_NAME: &str = "CPU";
const PROCESS_CPU_DESCRIPTION: &str = "Process CPU utilization";
const MALLOC_COUNTER_NAME: &str = "malloc";
const MALLOC_CATEGORY_NAME: &str = "Memory";
const MALLOC_DESCRIPTION: &str = "Amount of allocated memory";
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

    fn add_process(&mut self, pid: u32, samples: Vec<JsonLine>) -> Result<(), Whatever> {
        let Some(first_sample) = samples.first() else {
            return Ok(());
        };
        assert!(first_sample.time >= self.start_time_millis);

        ProfileBuilderProcess::new(self, first_sample.time, pid)
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

struct ProfileBuilderProcess<'a, T> {
    parent: &'a mut ProfileBuilder,
    process: ProcessHandle,
    pid: u32,
    start_time_millis: u128,
    threads: HashMap<u32, ThreadHandle>,
    cpu_counter: ProfileCounter<Initialized>,
    memory_counter: ProfileCounter<Initialized>,
    data: T,
}

impl<'a> ProfileBuilderProcess<'a, ()> {
    pub fn new(parent: &'a mut ProfileBuilder, start_time_millis: u128, pid: u32) -> Self {
        assert!(start_time_millis >= parent.start_time_millis);

        let start_timestamp = parent.time(start_time_millis);
        let process = parent.profile.add_process("Process", pid, start_timestamp);

        let cpu_counter = ProfileCounter::new(
            &mut parent.profile,
            process,
            PROCESS_CPU_COUNTER_NAME,
            PROCESS_CPU_CATEGORY_NAME,
            PROCESS_CPU_DESCRIPTION,
            GraphColor::Red,
        )
        .initialize(&mut parent.profile, start_timestamp, 0.);
        let memory_counter = ProfileCounter::new(
            &mut parent.profile,
            process,
            MALLOC_COUNTER_NAME,
            MALLOC_CATEGORY_NAME,
            MALLOC_DESCRIPTION,
            GraphColor::Purple,
        )
        .initialize(&mut parent.profile, start_timestamp, 0.);

        Self {
            parent,
            process,
            pid,
            start_time_millis,
            threads: HashMap::new(),
            cpu_counter,
            memory_counter,
            data: (),
        }
    }

    fn add_main_thread(
        mut self,
        samples: impl Iterator<Item = impl Borrow<JsonLine>>,
    ) -> Result<ProfileBuilderProcess<'a, MainThreadAdded>, Whatever> {
        // adding the main thread first leads to the RAM display corresponding to mainThreadIndex 0 working
        let main_thread = samples
            .flat_map(|line| line.borrow().stacktraces.clone())
            .find(|stack_trace| stack_trace.thread_name == Some(MAIN_THREAD_NAME.into()))
            .with_whatever_context(|| format!("no main thread found in process {}", self.pid))?;
        let main_thread_handle = self.parent.profile.add_thread(
            self.process,
            main_thread.thread_id as u32,
            self.time(self.start_time_millis),
            true,
        );
        self.parent
            .profile
            .set_thread_name(main_thread_handle, MAIN_THREAD_NAME);
        self.threads
            .insert(main_thread.thread_id as u32, main_thread_handle);

        Ok(ProfileBuilderProcess {
            parent: self.parent,
            process: self.process,
            pid: self.pid,
            start_time_millis: self.start_time_millis,
            threads: self.threads,
            cpu_counter: self.cpu_counter,
            memory_counter: self.memory_counter,
            data: MainThreadAdded { main_thread_handle },
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

            self.cpu_counter.add_value(
                &mut self.parent.profile,
                timestamp,
                line.resources.cpu as f64,
            );

            self.memory_counter.add_value(
                &mut self.parent.profile,
                timestamp,
                line.resources.memory as f64,
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

    eprintln!(
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
        if let ReportIdentifier::Pid(pid) = pid {
            builder.add_process(pid, samples)?;
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
