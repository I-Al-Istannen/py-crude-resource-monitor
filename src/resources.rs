use crate::types::{ProcessMetadata, ProcessResources, ThreadResources};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use sysinfo::{
    CpuRefreshKind, DiskRefreshKind, MemoryRefreshKind, Pid, ProcessRefreshKind, ProcessStatus,
    RefreshKind, UpdateKind,
};

#[derive(Debug)]
pub struct SystemMeasurements {
    system: sysinfo::System,
    disk: sysinfo::Disks,
    last_refresh: Option<Instant>,
    /// Time between the last two refreshes
    refresh_interval: Option<Duration>,
    /// The CPU time in milliseconds each process used until the previous refresh
    previous_cpu_times: HashMap<Pid, u64>,
    /// Measures the CPU time of threads, which sysinfo does not do for all threads
    thread_cpu_times: ThreadCpuTimes,
    /// The busy and total time of all cores until this and the previous refresh, see
    /// [`read_cpu_ticks`]
    cpu_ticks: Option<CpuTicks>,
    previous_cpu_ticks: Option<CpuTicks>,
    record_pss: bool,
}

impl SystemMeasurements {
    pub fn new(record_pss: bool) -> Result<Self, sysinfo::Error> {
        Ok(Self {
            system: sysinfo::System::new()?,
            disk: sysinfo::Disks::new()?,
            last_refresh: None,
            refresh_interval: None,
            previous_cpu_times: HashMap::new(),
            thread_cpu_times: ThreadCpuTimes::default(),
            cpu_ticks: None,
            previous_cpu_ticks: None,
            record_pss,
        })
    }

    /// Returns the given processes and all their descendants that are still alive. Processes are
    /// not descendants of each other once their parent exited, so callers pass all processes they
    /// already track to keep them. A root with a start time is skipped if its pid now belongs to a
    /// process that started at a different time.
    pub fn process_tree(
        &self,
        roots: impl IntoIterator<Item = (Pid, Option<u64>)>,
    ) -> HashMap<Pid, ProcessMetadata> {
        let mut children: HashMap<Pid, Vec<Pid>> = HashMap::new();
        for (pid, process) in self.system.processes() {
            // On Linux, threads are listed as processes too
            if process.thread_kind().is_some() {
                continue;
            }
            if let Some(parent) = process.parent() {
                children.entry(parent).or_default().push(*pid);
            }
        }

        let mut tree = HashMap::new();
        let mut queue = roots.into_iter().collect::<Vec<_>>();
        while let Some((pid, start_time)) = queue.pop() {
            if tree.contains_key(&pid) {
                continue;
            }
            let Some(process) = self.system.process(pid) else {
                continue;
            };
            if start_time.is_some_and(|it| it != process.start_time()) {
                continue;
            }
            // Exited processes stay around as zombies until their parent waits for them. For the
            // process we spawned ourselves, that only happens after tracking stopped.
            if process.status() == ProcessStatus::Zombie {
                continue;
            }
            tree.insert(
                pid,
                ProcessMetadata {
                    name: process.name().to_string_lossy().into_owned(),
                    parent_pid: process.parent().map(|it| it.as_u32()),
                    start_time: process.start_time(),
                },
            );
            queue.extend(
                children
                    .get(&pid)
                    .into_iter()
                    .flatten()
                    .map(|child| (*child, None)),
            );
        }

        tree
    }

    pub fn refresh(&mut self) {
        let now = Instant::now();
        self.refresh_interval = self.last_refresh.map(|last| now - last);
        self.last_refresh = Some(now);
        self.previous_cpu_times = self
            .system
            .processes()
            .iter()
            .map(|(pid, process)| (*pid, process.accumulated_cpu_time()))
            .collect();
        self.previous_cpu_ticks = self.cpu_ticks.take();
        self.cpu_ticks = read_cpu_ticks();

        self.system.refresh_specifics(
            RefreshKind::default()
                .with_cpu(CpuRefreshKind::default().with_usage())
                .with_processes(
                    ProcessRefreshKind::default()
                        .with_cpu()
                        .with_memory()
                        .with_disk_usage()
                        .with_cmd(UpdateKind::Always),
                )
                .with_memory(MemoryRefreshKind::default().with_ram().with_swap()),
        );
        self.disk
            .refresh_specifics(true, DiskRefreshKind::nothing().with_io_usage());
        self.thread_cpu_times
            .next_refresh(|pid| self.system.process(pid).is_some());
    }

    /// The CPU usage of a process since the previous refresh, where 100% is one core.
    ///
    /// sysinfo's `cpu_usage` divides the CPU time a process used since the last refresh by the time
    /// all cores ran since the last time sysinfo measured them. It measures the cores at most every
    /// 200ms on Linux, so with shorter intervals, processes seem to use a fraction of their CPU.
    /// We divide by the time between our refreshes instead.
    ///
    /// `started_since_last_refresh` marks processes that did not exist during the previous refresh,
    /// so all the CPU time they used so far counts.
    fn cpu_usage(&self, process: &sysinfo::Process, started_since_last_refresh: bool) -> f32 {
        let previous = match self.previous_cpu_times.get(&process.pid()) {
            Some(previous) if !started_since_last_refresh => *previous,
            _ => 0,
        };
        self.cpu_percent(Duration::from_millis(
            process.accumulated_cpu_time().saturating_sub(previous),
        ))
    }

    /// The CPU usage of `used` CPU time since the previous refresh
    fn cpu_percent(&self, used: Duration) -> f32 {
        match self.refresh_interval.filter(|it| !it.is_zero()) {
            Some(interval) => used.as_secs_f32() / interval.as_secs_f32() * 100.0,
            None => 0.0,
        }
    }

    pub fn get_process_info(
        &mut self,
        pid: Pid,
        started_since_last_refresh: bool,
    ) -> Option<ProcessResources> {
        let thread_cpu_times = self
            .thread_cpu_times
            .since_previous_refresh(pid, started_since_last_refresh);
        let process = self.system.process(pid)?;
        let process_cpu = self.cpu_usage(process, started_since_last_refresh);
        let cpus = self.system.cpus().len().max(1) as u32;
        let memory = process.memory();
        let disk_usage = process.disk_usage();

        // We only measure the CPU usage of threads, they share the memory of their process
        let thread_resources = thread_cpu_times
            .into_iter()
            .map(|(tid, used)| {
                let resources = ThreadResources {
                    cpu: self.cpu_percent(used),
                };
                (tid, resources)
            })
            .collect();

        Some(ProcessResources {
            memory,
            pss: self.record_pss.then(|| read_pss(pid)).flatten(),
            cpu: process_cpu,
            cpus: Some(cpus),
            disk_read_bytes: disk_usage.read_bytes,
            disk_write_bytes: disk_usage.written_bytes,
            total_read_call_bytes: read_rchar(pid),
            thread_resources,
        })
    }

    /// Discard cached handles and CPU baselines when a PID belongs to a new process.
    pub fn forget_process(&mut self, pid: Pid) {
        self.previous_cpu_times.remove(&pid);
        self.thread_cpu_times.forget(pid);
    }

    pub fn get_global_info(&mut self) -> ProcessResources {
        let memory = self.system.used_memory() + self.system.used_swap();
        // sysinfo updates global CPU at most every 200ms, so measure it ourselves where possible.
        // Convert its machine-wide percentage to the same one-core units as process/thread CPU.
        let cpu = match (self.previous_cpu_ticks, self.cpu_ticks) {
            (Some(previous), Some(current)) if current.total > previous.total => {
                let busy = current.busy.saturating_sub(previous.busy);
                busy as f32 / (current.total - previous.total) as f32 * 100.0
            }
            _ => self.system.global_cpu_usage(),
        };
        let (disk_read_bytes, disk_write_bytes) = self
            .disk
            .iter()
            .map(|it| it.usage())
            .fold((0, 0), |(read, written), usage| {
                (read + usage.read_bytes, written + usage.written_bytes)
            });

        let cpus = self.system.cpus().len().max(1) as u32;
        ProcessResources {
            memory,
            pss: None,
            cpu: cpu * cpus as f32,
            cpus: Some(cpus),
            disk_read_bytes,
            disk_write_bytes,
            total_read_call_bytes: None,
            thread_resources: HashMap::new(),
        }
    }
}

/// How long all cores were busy, and how long they ran in total, in clock ticks
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CpuTicks {
    busy: u64,
    total: u64,
}

/// Reads the time all cores spent so far from `/proc/stat`, like sysinfo does. Elsewhere we would
/// need unsafe calls, so the global CPU usage is only updated every 200ms there.
#[cfg(target_os = "linux")]
fn read_cpu_ticks() -> Option<CpuTicks> {
    let stat = std::fs::read_to_string("/proc/stat").ok()?;
    parse_cpu_ticks(&stat)
}

#[cfg(not(target_os = "linux"))]
fn read_cpu_ticks() -> Option<CpuTicks> {
    None
}

/// Parses the `cpu` line of `/proc/stat`, the sum of all cores
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_cpu_ticks(stat: &str) -> Option<CpuTicks> {
    let line = stat.lines().find(|it| it.starts_with("cpu "))?;
    // user nice system idle iowait irq softirq steal guest guest_nice. The guest times are already
    // part of user and nice.
    let ticks = line
        .split_whitespace()
        .skip(1)
        .take(8)
        .map(|it| it.parse::<u64>().ok())
        .collect::<Option<Vec<_>>>()?;
    let total: u64 = ticks.iter().sum();
    let idle = ticks.get(3)? + ticks.get(4).unwrap_or(&0);
    Some(CpuTicks {
        busy: total - idle,
        total,
    })
}

/// Measures how much CPU time the threads of processes used since the previous refresh. sysinfo
/// does not measure the main thread on Linux and does not list threads at all on macOS. On Linux,
/// it also only updates the time all cores ran at most every 200ms, which its thread CPU usage is
/// relative to.
#[derive(Debug, Default)]
struct ThreadCpuTimes {
    /// The handle of each process, if we could open it. On macOS, that needs root, like py-spy.
    processes: HashMap<Pid, Option<RemoteProcess>>,
    /// The CPU time each thread of a process used until this and the previous refresh
    current: HashMap<Pid, HashMap<u64, Duration>>,
    previous: HashMap<Pid, HashMap<u64, Duration>>,
}

impl ThreadCpuTimes {
    fn forget(&mut self, pid: Pid) {
        self.processes.remove(&pid);
        self.current.remove(&pid);
        self.previous.remove(&pid);
    }

    /// Starts a new refresh and forgets about processes that are not alive anymore
    fn next_refresh(&mut self, alive: impl Fn(Pid) -> bool) {
        self.processes.retain(|pid, _| alive(*pid));
        self.previous = std::mem::take(&mut self.current);
    }

    /// The CPU time each thread of a process used since the previous refresh, by thread id.
    /// `started_since_last_refresh` marks processes that did not exist during the previous
    /// refresh, so all the CPU time their threads used so far counts.
    ///
    /// If we measured the process in the previous refresh, threads we did not see then started
    /// since. If we did not, e.g. because we just attached to it, they might have run for a long
    /// time, so they are left out.
    fn since_previous_refresh(
        &mut self,
        pid: Pid,
        started_since_last_refresh: bool,
    ) -> HashMap<u64, Duration> {
        let threads = self.read(pid);
        let previous = self.previous.get(&pid);
        let used = threads
            .iter()
            .filter_map(|(tid, cpu_time)| {
                let previous = match previous {
                    _ if started_since_last_refresh => Duration::ZERO,
                    Some(previous) => previous.get(tid).copied().unwrap_or_default(),
                    None => return None,
                };
                Some((*tid, cpu_time.saturating_sub(previous)))
            })
            .collect();
        if !threads.is_empty() {
            self.current.insert(pid, threads);
        }
        used
    }

    /// The CPU time each thread of a process used so far, by thread id. Platforms where
    /// remoteprocess can not measure it return nothing.
    fn read(&mut self, pid: Pid) -> HashMap<u64, Duration> {
        let process = self.processes.entry(pid).or_insert_with(|| {
            remoteprocess::Process::new(pid.as_u32() as remoteprocess::Pid)
                .inspect_err(|e| log::debug!("Could not open process {pid}: {e}"))
                .ok()
                .map(RemoteProcess)
        });
        let Some(RemoteProcess(process)) = process else {
            return HashMap::new();
        };
        let Ok(threads) = process.threads() else {
            // The process exited, try again if its pid is reused
            self.processes.remove(&pid);
            return HashMap::new();
        };
        threads
            .iter()
            .filter_map(|thread| Some((thread_id(thread)?, thread.cpu_time().ok()??)))
            .collect()
    }
}

/// The id py-spy reports for a thread. On macOS, it reads the system-wide id
/// (`pthread_threadid_np`) from Python's thread states, not the mach port name of the thread.
#[cfg(target_os = "macos")]
fn thread_id(thread: &remoteprocess::Thread) -> Option<u64> {
    Some(thread.get_thread_identifier_info().ok()?.thread_id)
}

#[cfg(not(target_os = "macos"))]
fn thread_id(thread: &remoteprocess::Thread) -> Option<u64> {
    Some(thread.id().ok()? as u64)
}

struct RemoteProcess(remoteprocess::Process);

impl std::fmt::Debug for RemoteProcess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("RemoteProcess").field(&self.0.pid).finish()
    }
}

/// Reads the proportional set size of a process. This walks all its pages, so it gets slow for
/// processes with a lot of memory.
#[cfg(target_os = "linux")]
fn read_pss(pid: Pid) -> Option<u64> {
    let rollup = std::fs::read_to_string(format!("/proc/{pid}/smaps_rollup")).ok()?;
    parse_pss(&rollup)
}

#[cfg(not(target_os = "linux"))]
fn read_pss(_pid: Pid) -> Option<u64> {
    None
}

/// Reads the bytes a process requested with read calls so far, including page cache hits
#[cfg(target_os = "linux")]
fn read_rchar(pid: Pid) -> Option<u64> {
    let io = std::fs::read_to_string(format!("/proc/{pid}/io")).ok()?;
    parse_rchar(&io)
}

#[cfg(not(target_os = "linux"))]
fn read_rchar(_pid: Pid) -> Option<u64> {
    None
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_rchar(io: &str) -> Option<u64> {
    let line = io.lines().find(|it| it.starts_with("rchar:"))?;
    line.split_whitespace().nth(1)?.parse::<u64>().ok()
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_pss(rollup: &str) -> Option<u64> {
    let line = rollup.lines().find(|it| it.starts_with("Pss:"))?;
    let kib = line.split_whitespace().nth(1)?.parse::<u64>().ok()?;
    Some(kib * 1024)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forgets_all_thread_state_when_a_pid_is_reused() {
        let pid = Pid::from_u32(42);
        let mut reader = ThreadCpuTimes::default();
        reader.processes.insert(pid, None);
        reader
            .current
            .insert(pid, HashMap::from([(1, Duration::from_secs(1))]));
        reader
            .previous
            .insert(pid, HashMap::from([(1, Duration::from_secs(1))]));

        reader.forget(pid);

        assert!(!reader.processes.contains_key(&pid));
        assert!(!reader.current.contains_key(&pid));
        assert!(!reader.previous.contains_key(&pid));
    }

    #[test]
    fn parses_the_cpu_ticks_of_all_cores() {
        let stat = "cpu  100 5 50 800 40 3 2 0 7 0\ncpu0 50 2 25 400 20 1 1 0 3 0\nintr 1234\n";

        let ticks = parse_cpu_ticks(stat).unwrap();

        assert_eq!(
            ticks,
            CpuTicks {
                busy: 160,
                total: 1000
            }
        );
    }

    #[test]
    fn parses_pss_from_smaps_rollup() {
        let rollup = "\
55d0c8a4e000-7ffd4b5f1000 ---p 00000000 00:00 0                          [rollup]
Rss:              630352 kB
Pss:              157776 kB
Pss_Dirty:        154004 kB
";

        assert_eq!(parse_pss(rollup), Some(157776 * 1024));
    }

    #[test]
    fn parses_rchar_from_proc_io() {
        let io = "\
rchar: 268437913
wchar: 1024
syscr: 70
syscw: 2
read_bytes: 57671680
write_bytes: 0
cancelled_write_bytes: 0
";

        assert_eq!(parse_rchar(io), Some(268437913));
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn reads_the_cpu_time_of_threads() {
        let pid = Pid::from_u32(std::process::id());
        let mut reader = ThreadCpuTimes::default();
        let total = |reader: &mut ThreadCpuTimes| -> Duration { reader.read(pid).values().sum() };
        let before = total(&mut reader);
        let start = Instant::now();
        while start.elapsed() < Duration::from_millis(100) {
            std::hint::black_box(());
        }

        assert!(total(&mut reader) - before >= Duration::from_millis(50));
    }
}
