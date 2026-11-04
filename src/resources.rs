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
}

impl SystemMeasurements {
    pub fn new() -> Result<Self, sysinfo::Error> {
        Ok(Self {
            system: sysinfo::System::new()?,
            disk: sysinfo::Disks::new()?,
            last_refresh: None,
            refresh_interval: None,
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

    /// `started_since_last_refresh` marks processes that did not exist during the previous refresh.
    /// sysinfo reports no CPU usage for them, as it needs two measurements, so we use all the CPU
    /// time they used so far instead.
    pub fn get_process_info(
        &mut self,
        pid: Pid,
        started_since_last_refresh: bool,
    ) -> Option<ProcessResources> {
        let process = self.system.process(pid)?;

        let process_cpu = match self.refresh_interval {
            Some(interval) if started_since_last_refresh && !interval.is_zero() => {
                process.accumulated_cpu_time() as f32 / interval.as_millis() as f32 * 100.0
            }
            _ => process.cpu_usage(),
        };
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
                        cpu: task.cpu_usage(),
                        memory: task.memory(),
                        disk_read_bytes: task.disk_usage().read_bytes,
                        disk_write_bytes: task.disk_usage().written_bytes,
                    },
                )
            })
            .collect::<HashMap<u64, _>>();

        // sysinfo leaves the main thread (tid == pid) out of the tasks, so we attribute
        // everything the other threads did not use to it.
        if process.tasks().is_some() {
            let others = thread_resources.values();
            let main_thread = ThreadResources {
                cpu: (process_cpu - others.clone().map(|it| it.cpu).sum::<f32>()).max(0.0),
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
            cpu: cpu_usage,
            cpus: Some(cpus),
            disk_read_bytes: disk_usage.read_bytes,
            disk_write_bytes: disk_usage.written_bytes,
            thread_resources,
        })
    }

    pub fn get_global_info(&mut self) -> ProcessResources {
        let memory = self.system.used_memory() + self.system.used_swap();
        // We do not want to normalize global cpu usage, 100% means all cores are fully loaded
        let cpu = self.system.global_cpu_usage();
        let (disk_read_bytes, disk_write_bytes) = self
            .disk
            .iter()
            .map(|it| it.usage())
            .fold((0, 0), |(read, written), usage| {
                (read + usage.read_bytes, written + usage.written_bytes)
            });

        ProcessResources {
            memory,
            cpu,
            cpus: None,
            disk_read_bytes,
            disk_write_bytes,
            thread_resources: HashMap::new(),
        }
    }
}
