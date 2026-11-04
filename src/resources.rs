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
    /// The CPU time in milliseconds each process and thread used until the previous refresh
    previous_cpu_times: HashMap<Pid, u64>,
    /// The CPU time in milliseconds the main thread of each tracked process used until this and
    /// the previous refresh. sysinfo does not measure main threads.
    main_thread_cpu_times: HashMap<Pid, u64>,
    previous_main_thread_cpu_times: HashMap<Pid, u64>,
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
            main_thread_cpu_times: HashMap::new(),
            previous_main_thread_cpu_times: HashMap::new(),
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
        self.previous_main_thread_cpu_times = std::mem::take(&mut self.main_thread_cpu_times);
        self.previous_cpu_ticks = self.cpu_ticks.take();
        self.cpu_ticks = read_cpu_ticks();

        self.system.refresh_specifics(
            RefreshKind::default()
                .with_cpu(CpuRefreshKind::default().with_usage())
                .with_processes(
                    ProcessRefreshKind::default()
                        .with_cpu()
                        .with_memory()
                        .with_tasks()
                        .with_disk_usage()
                        .with_cmd(UpdateKind::Always),
                )
                .with_memory(MemoryRefreshKind::default().with_ram().with_swap()),
        );
        self.disk
            .refresh_specifics(true, DiskRefreshKind::nothing().with_io_usage());
    }

    /// The CPU usage of a process or thread since the previous refresh, where 100% is one core.
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
        self.cpu_percent(process.accumulated_cpu_time().saturating_sub(previous))
    }

    /// Like [`Self::cpu_usage`], for the main thread of a process
    fn main_thread_cpu_usage(&mut self, pid: Pid, started_since_last_refresh: bool) -> Option<f32> {
        let cpu_time = read_main_thread_cpu_time(pid)?;
        self.main_thread_cpu_times.insert(pid, cpu_time);
        let previous = match self.previous_main_thread_cpu_times.get(&pid) {
            Some(previous) if !started_since_last_refresh => *previous,
            _ => 0,
        };
        Some(self.cpu_percent(cpu_time.saturating_sub(previous)))
    }

    /// The CPU usage of `used` milliseconds of CPU time since the previous refresh
    fn cpu_percent(&self, used: u64) -> f32 {
        match self.refresh_interval.filter(|it| !it.is_zero()) {
            Some(interval) => used as f32 / interval.as_secs_f32() / 1000.0 * 100.0,
            None => 0.0,
        }
    }

    pub fn get_process_info(
        &mut self,
        pid: Pid,
        started_since_last_refresh: bool,
    ) -> Option<ProcessResources> {
        let process = self.system.process(pid)?;

        let process_cpu = self.cpu_usage(process, started_since_last_refresh);
        let main_thread_cpu = self.main_thread_cpu_usage(pid, started_since_last_refresh);
        let process = self.system.process(pid)?;
        // Normalize cpu usage to number of cores, as firefox profiler can only render up to 100%
        let cpus = self.system.cpus().len().max(1) as u32;
        let cpu_usage = process_cpu / cpus as f32;
        let memory = process.memory();
        let disk_usage = process.disk_usage();

        let mut thread_resources = process
            .tasks()
            .into_iter()
            .flatten()
            .flat_map(|tid| self.system.process(*tid))
            .map(|task| {
                (
                    task.pid().as_u32() as u64,
                    ThreadResources {
                        // Threads we have not seen in the previous refresh started since then
                        cpu: self.cpu_usage(task, false),
                        memory: task.memory(),
                        disk_read_bytes: task.disk_usage().read_bytes,
                        disk_write_bytes: task.disk_usage().written_bytes,
                    },
                )
            })
            .collect::<HashMap<u64, _>>();

        // sysinfo leaves the main thread (tid == pid) out of the tasks. If we cannot measure it
        // ourselves, we attribute everything the other threads did not use to it. That is noisy for
        // short intervals, and flooring it at zero makes idle main threads seem busy.
        if process.tasks().is_some() {
            let others = thread_resources.values();
            let cpu = main_thread_cpu.unwrap_or_else(|| {
                (process_cpu - others.clone().map(|it| it.cpu).sum::<f32>()).max(0.0)
            });
            let main_thread = ThreadResources {
                cpu,
                memory,
                disk_read_bytes: disk_usage
                    .read_bytes
                    .saturating_sub(others.clone().map(|it| it.disk_read_bytes).sum()),
                disk_write_bytes: disk_usage
                    .written_bytes
                    .saturating_sub(others.map(|it| it.disk_write_bytes).sum()),
            };
            thread_resources.insert(pid.as_u32() as u64, main_thread);
        }

        Some(ProcessResources {
            memory,
            pss: self.record_pss.then(|| read_pss(pid)).flatten(),
            cpu: cpu_usage,
            cpus: Some(cpus),
            disk_read_bytes: disk_usage.read_bytes,
            disk_write_bytes: disk_usage.written_bytes,
            thread_resources,
        })
    }

    pub fn get_global_info(&mut self) -> ProcessResources {
        let memory = self.system.used_memory() + self.system.used_swap();
        // We do not want to normalize global cpu usage, 100% means all cores are fully loaded.
        // sysinfo updates it at most every 200ms, so we measure it ourselves where we can.
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

        ProcessResources {
            memory,
            pss: None,
            cpu,
            cpus: None,
            disk_read_bytes,
            disk_write_bytes,
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

/// Reads the CPU time in milliseconds the main thread of a process used
#[cfg(target_os = "linux")]
fn read_main_thread_cpu_time(pid: Pid) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/task/{pid}/stat")).ok()?;
    parse_cpu_time(&stat)
}

#[cfg(not(target_os = "linux"))]
fn read_main_thread_cpu_time(_pid: Pid) -> Option<u64> {
    None
}

/// Clock ticks per second of the times in `/proc`. Fixed by the kernel ABI, reading it would need
/// `sysconf` and with it unsafe code.
const USER_HZ: u64 = 100;

/// Parses the CPU time in milliseconds from a `/proc/<pid>/stat` file
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_cpu_time(stat: &str) -> Option<u64> {
    // The name in the second field may contain spaces and parentheses, so we split after it. The
    // first field after it is the third one.
    let fields = stat
        .rsplit_once(')')?
        .1
        .split_whitespace()
        .collect::<Vec<_>>();
    let utime = fields.get(14 - 3)?.parse::<u64>().ok()?;
    let stime = fields.get(15 - 3)?.parse::<u64>().ok()?;
    Some((utime + stime) * 1000 / USER_HZ)
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
    fn parses_cpu_time_from_stat() {
        let stat = "42 (a) b) S 1 42 42 0 -1 4194560 3000 0 0 0 250 30 0 0 20 0 4 0 100 0 0";

        // 250 + 30 clock ticks of 10ms
        assert_eq!(parse_cpu_time(stat), Some(2800));
    }
}
