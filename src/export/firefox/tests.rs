use super::builder::{
    CATEGORY_GIL_WAIT_NAME, CATEGORY_PYTHON_NAME, DEFAULT_INTERVAL_MILLIS, GIL_WAIT_FRAME_NAME,
    MAIN_THREAD_NAME, PSS_TOTAL_PID, VISIBLE_MAIN_THREADS,
};
use super::*;
use crate::types::{MemorySample, ProcessMetadata, ProcessResources, StackTrace, ThreadResources};

fn stacktrace(thread_id: u64, name: &str) -> StackTrace {
    StackTrace {
        pid: 1,
        thread_id,
        thread_name: Some(name.to_string()),
        os_thread_id: Some(thread_id),
        active: true,
        owns_gil: false,
        waiting_for_gil: false,
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
        exited: false,
        process: None,
        memory_samples: vec![],
        resources: ProcessResources {
            memory: 1024,
            pss: None,
            cpu: 50.0,
            cpus: None,
            disk_read_bytes: 0,
            disk_write_bytes: 0,
            total_read_call_bytes: None,
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
        gil_waiters: true,
        lanes: ProcessLanes::Never,
        memory: MemoryMetric::Rss,
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
    let processes = HashMap::from([
        (ReportIdentifier::Pid(1), process(&[100, 300])),
        (ReportIdentifier::Pid(2), process(&[50])),
    ]);
    let args = FirefoxExportArguments {
        memory: MemoryMetric::Pss,
        ..args()
    };
    let json = serde_json::to_value(generate_fxprof(processes, &args).unwrap()).unwrap();

    assert_eq!(
        memory_graph(&json, 1),
        [(0.0, 0.0), (0.0, 100.0), (100.0, 300.0)]
    );
    assert_eq!(
        memory_graph(&json, PSS_TOTAL_PID),
        [(0.0, 0.0), (0.0, 150.0), (100.0, 300.0)]
    );
}

#[test]
fn shows_rss_and_no_pss_track_by_default() {
    let samples = (0..2)
        .map(|i| {
            let mut line = line(1000 + i * 100, vec![], &[]);
            line.resources.pss = Some(1);
            line
        })
        .collect();
    let json = processes_json(HashMap::from([(ReportIdentifier::Pid(1), samples)]));
    let pss_total_pid = PSS_TOTAL_PID.to_string();

    assert_eq!(
        memory_graph(&json, 1),
        [(0.0, 0.0), (0.0, 1024.0), (100.0, 1024.0)]
    );

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

#[test]
fn cpu_covers_the_time_since_the_previous_sample() {
    // The profiler skipped two ticks before the last sample, its CPU covers all three
    let threads = || vec![stacktrace(1, MAIN_THREAD_NAME), stacktrace(2, "worker")];
    let samples = [1000, 1100, 1200, 1500]
        .into_iter()
        .map(|time| line(time, threads(), &[(2, 100.0)]))
        .collect();
    let processes = HashMap::from([(ReportIdentifier::Pid(1), samples)]);

    assert_eq!(
        thread_cpu_deltas(processes, "worker"),
        serde_json::json!([100000, 100000, 100000, 300000])
    );
}

#[test]
fn exit_lines_only_add_their_memory_samples() {
    let mut samples = (0..3)
        .map(|i| line(1000 + i * 100, vec![stacktrace(1, MAIN_THREAD_NAME)], &[]))
        .collect::<Vec<_>>();
    let mut exit = line(1250, vec![], &[]);
    exit.exited = true;
    exit.memory_samples = vec![
        MemorySample {
            time: 1230,
            memory: 4096,
        },
        MemorySample {
            time: 1250,
            memory: 2048,
        },
    ];
    samples.push(exit);
    let processes = HashMap::from([(ReportIdentifier::Pid(1), samples)]);

    let profile = generate_fxprof(processes, &args()).unwrap();
    let json = serde_json::to_value(&profile).unwrap();

    let thread = &json["threads"][0];
    assert_eq!(thread["samples"]["length"], 3);
    let memory = json["counters"]
        .as_array()
        .unwrap()
        .iter()
        .find(|it| it["category"] == "Memory")
        .unwrap();
    // The initial zero, three samples and the two measurements before the exit
    let counts = memory["samples"]["count"].as_array().unwrap();
    let total = counts.iter().map(|it| it.as_f64().unwrap()).sum::<f64>();
    assert_eq!(counts.len(), 6);
    assert_eq!(total, 2048.0);
}

#[test]
fn bandwidth_is_the_bytes_since_the_previous_sample() {
    // Constant I/O must not look like none at all
    let samples = (0..3)
        .map(|i| {
            let mut line = line(1000 + i * 100, vec![stacktrace(1, MAIN_THREAD_NAME)], &[]);
            line.resources.disk_read_bytes = 100;
            line.resources.disk_write_bytes = 50;
            line
        })
        .collect();
    let processes = HashMap::from([(ReportIdentifier::Pid(1), samples)]);

    let profile = generate_fxprof(processes, &args()).unwrap();
    let json = serde_json::to_value(&profile).unwrap();
    let counter = json["counters"]
        .as_array()
        .unwrap()
        .iter()
        .find(|it| it["name"] == "io")
        .unwrap();
    assert_eq!(
        counter["samples"]["count"],
        serde_json::json!([0.0, 150.0, 150.0, 150.0])
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
    // One per worker, and one for the root
    assert_eq!(markers.iter().sum::<u64>(), 7);
}

#[test]
fn shows_the_main_threads_of_the_processes_that_started_first() {
    let main = [(1, MAIN_THREAD_NAME)];
    let mut processes =
        HashMap::from([(ReportIdentifier::Pid(1), process("root", 1000, 3000, &main))]);
    // Enough processes running at the same time to fill all visible main threads
    for pid in 10..10 + VISIBLE_MAIN_THREADS as u32 {
        processes.insert(
            ReportIdentifier::Pid(pid),
            process("early", 1100, 1500, &main),
        );
    }
    // Sorts before the others by name
    processes.insert(ReportIdentifier::Pid(2), process("a", 2400, 2800, &main));
    let mut args = args();
    args.lanes = ProcessLanes::Always;

    let profile = generate_fxprof(processes, &args).unwrap();
    let json = serde_json::to_value(&profile).unwrap();

    let threads = json["threads"].as_array().unwrap();
    let visible = json["meta"]["initialVisibleThreads"]
        .as_array()
        .unwrap()
        .iter()
        .map(|index| {
            threads[index.as_u64().unwrap() as usize]["name"]
                .as_str()
                .unwrap()
        })
        .collect::<Vec<_>>();
    assert_eq!(visible.len(), VISIBLE_MAIN_THREADS);
    assert!(visible.contains(&"root"));
    assert!(!visible.contains(&"a"));
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

/// The markers of the thread named `thread` as (name, start, end, data). Instant markers have
/// no end, string fields are resolved.
fn markers(
    json: &serde_json::Value,
    thread: &str,
) -> Vec<(String, f64, Option<f64>, serde_json::Value)> {
    let thread = json["threads"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == thread)
        .unwrap();
    let strings = thread["stringArray"].as_array().unwrap();
    let markers = &thread["markers"];
    (0..markers["length"].as_u64().unwrap() as usize)
        .map(|i| {
            let name = strings[markers["name"][i].as_u64().unwrap() as usize]
                .as_str()
                .unwrap()
                .to_string();
            let instant = markers["phase"][i] == 0;
            let mut data = markers["data"][i].clone();
            for field in ["reason", "details"] {
                if let Some(value) = data.get_mut(field) {
                    *value = strings[value.as_u64().unwrap() as usize].clone();
                }
            }
            (
                name,
                markers["startTime"][i].as_f64().unwrap(),
                markers["endTime"][i].as_f64().filter(|_| !instant),
                data,
            )
        })
        .collect()
}

const NOT_PYTHON: &str = "Error creating py-spy at src/stacktraces.rs:95:60\n\nCaused by this error:\n  1: Failed to find python version from target process\n";

#[test]
fn marks_failed_stack_captures() {
    let samples = (0..5)
        .map(|i| {
            let mut line = line(1000 + i * 100, vec![], &[]);
            line.process = Some(metadata("python", 1));
            line.stacktrace_error = match i {
                0 => Some("Timed out".to_string()),
                1 => None,
                // Retrying changes the message, but not the cause
                2 => Some(format!("Not attached yet: {NOT_PYTHON}")),
                _ => Some(format!("Not a Python process: {NOT_PYTHON}")),
            };
            line
        })
        .collect();
    let json = processes_json(HashMap::from([(ReportIdentifier::Pid(1), samples)]));

    let failed = markers(&json, "python")
        .into_iter()
        .filter(|(name, ..)| name == "Stack capture failed")
        .map(|(_, start, end, data)| (start, end, data["reason"].clone()))
        .collect::<Vec<_>>();
    assert_eq!(
        failed,
        [
            (0.0, None, serde_json::json!("Timed out")),
            (
                200.0,
                Some(400.0),
                serde_json::json!("Failed to find python version from target process")
            ),
        ]
    );
}

#[test]
fn marks_skipped_ticks_in_the_global_track() {
    let samples = [1000, 1100, 1200, 1500, 1600, 1700]
        .into_iter()
        .map(|time| line(time, vec![], &[]))
        .collect();
    let json = processes_json(HashMap::from([(ReportIdentifier::Global, samples)]));

    let skipped = markers(&json, "Global")
        .into_iter()
        .map(|(name, start, end, data)| (name, start, end, data["skipped"].clone()))
        .collect::<Vec<_>>();
    assert_eq!(
        skipped,
        [(
            "Skipped samples".to_string(),
            200.0,
            Some(500.0),
            serde_json::json!(2.0)
        )]
    );
}

#[test]
fn shows_main_threads_and_the_busiest_threads_by_default() {
    // A main thread that waits for 12 busy workers and an idle one
    let mut threads = vec![stacktrace(1, MAIN_THREAD_NAME), stacktrace(99, "idle")];
    let mut cpu = vec![(1, 0.0), (99, 0.0)];
    for id in 2..14 {
        threads.push(stacktrace(id, &format!("worker-{id}")));
        cpu.push((id, 50.0 + id as f32));
    }
    let samples = (0..3)
        .map(|i| line(1000 + i * 100, threads.clone(), &cpu))
        .collect();
    let json = processes_json(HashMap::from([(ReportIdentifier::Pid(1), samples)]));

    let mut visible = json["meta"]["initialVisibleThreads"]
        .as_array()
        .unwrap()
        .iter()
        .map(|index| {
            json["threads"][index.as_u64().unwrap() as usize]["name"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect::<Vec<_>>();
    visible.sort();
    let mut expected = (4..14).map(|id| format!("worker-{id}")).collect::<Vec<_>>();
    expected.push("Process".to_string());
    expected.sort();
    assert_eq!(visible, expected);
}

/// The name and category of the innermost frame of every sample of `thread`
fn leaf_frames(json: &serde_json::Value, thread: &str) -> Vec<(String, String)> {
    let thread = json["threads"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == thread)
        .unwrap();
    let strings = thread["stringArray"].as_array().unwrap();
    let index = |value: &serde_json::Value| value.as_u64().unwrap() as usize;
    thread["samples"]["stack"]
        .as_array()
        .unwrap()
        .iter()
        .map(|stack| {
            let frame = index(&thread["stackTable"]["frame"][index(stack)]);
            let func = index(&thread["frameTable"]["func"][frame]);
            let category = index(&thread["frameTable"]["category"][frame]);
            (
                strings[index(&thread["funcTable"]["name"][func])]
                    .as_str()
                    .unwrap()
                    .to_string(),
                json["meta"]["categories"][category]["name"]
                    .as_str()
                    .unwrap()
                    .to_string(),
            )
        })
        .collect()
}

/// The values of the GIL wait counter of the process with `pid`, if it has one
fn gil_wait_counts(json: &serde_json::Value, pid: u32) -> Option<Vec<f64>> {
    let pid = pid.to_string();
    let counter = json["counters"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["category"] == "GIL" && c["pid"] == pid)?;
    let counts = counter["samples"]["count"].as_array().unwrap();
    Some(counts.iter().map(|it| it.as_f64().unwrap()).collect())
}

#[test]
fn marks_threads_waiting_for_the_gil() {
    let samples = (0..3)
        .map(|i| {
            let mut worker = stacktrace(2, "worker");
            worker.waiting_for_gil = i == 1;
            let mut other = stacktrace(3, "other");
            other.waiting_for_gil = i >= 1;
            line(
                1000 + i * 100,
                vec![stacktrace(1, MAIN_THREAD_NAME), worker, other],
                &[],
            )
        })
        .collect();
    let json = processes_json(HashMap::from([(ReportIdentifier::Pid(1), samples)]));

    let work = (
        "work (main.py:42)".to_string(),
        CATEGORY_PYTHON_NAME.to_string(),
    );
    let wait = (
        GIL_WAIT_FRAME_NAME.to_string(),
        CATEGORY_GIL_WAIT_NAME.to_string(),
    );
    assert_eq!(leaf_frames(&json, "worker"), [work.clone(), wait, work]);
    assert_eq!(gil_wait_counts(&json, 1), Some(vec![0.0, 2.0, 1.0]));
}

#[test]
fn adds_the_gil_wait_track_only_if_asked_to() {
    let samples = (0..2)
        .map(|i| {
            let mut waiting = stacktrace(2, "worker");
            waiting.waiting_for_gil = true;
            line(
                1000 + i * 100,
                vec![stacktrace(1, MAIN_THREAD_NAME), waiting],
                &[],
            )
        })
        .collect();
    let args = FirefoxExportArguments {
        gil_waiters: false,
        ..args()
    };
    let profile = generate_fxprof(HashMap::from([(ReportIdentifier::Pid(1), samples)]), &args);
    let json = serde_json::to_value(profile.unwrap()).unwrap();

    assert_eq!(gil_wait_counts(&json, 1), None);
}

#[test]
fn adds_no_gil_wait_track_without_waiting_threads() {
    let samples = (0..3)
        .map(|i| line(1000 + i * 100, vec![stacktrace(1, MAIN_THREAD_NAME)], &[]))
        .collect();
    let json = processes_json(HashMap::from([(ReportIdentifier::Pid(1), samples)]));

    assert_eq!(gil_wait_counts(&json, 1), None);
}

#[test]
fn orders_retained_memory_before_computing_deltas() {
    // A flat point retained across a tick is emitted only when memory changes afterwards.
    for with_stacks in [false, true] {
        let mut samples = Vec::new();
        for (time, memory, retained) in [
            (1000, 100, vec![]),
            (2000, 150, vec![(1010, 100)]),
            (3000, 150, vec![(1990, 100), (2010, 150)]),
        ] {
            let threads = if with_stacks {
                vec![stacktrace(1, MAIN_THREAD_NAME)]
            } else {
                vec![]
            };
            let mut sample = line(time, threads, &[]);
            sample.resources.memory = memory;
            sample.memory_samples = retained
                .into_iter()
                .map(|(time, memory)| MemorySample { time, memory })
                .collect();
            samples.push(sample);
        }
        let json = processes_json(HashMap::from([(ReportIdentifier::Pid(7), samples)]));
        assert_eq!(
            memory_graph(&json, 7),
            [
                (0.0, 0.0),
                (0.0, 100.0),
                (10.0, 100.0),
                (990.0, 100.0),
                (1000.0, 150.0),
                (1010.0, 150.0),
                (2000.0, 150.0),
            ]
        );
    }
}

#[test]
fn memory_can_precede_the_first_regular_sample() {
    let mut sample = line(1000, vec![], &[]);
    sample.memory_samples = vec![MemorySample {
        time: 990,
        memory: 512,
    }];
    let json = processes_json(HashMap::from([(ReportIdentifier::Pid(7), vec![sample])]));
    assert_eq!(
        memory_graph(&json, 7),
        [(0.0, 0.0), (0.0, 512.0), (10.0, 1024.0)]
    );
}
