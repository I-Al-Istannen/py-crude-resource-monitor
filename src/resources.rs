use crate::types::{ProcessResources, ThreadResources};
use std::collections::HashMap;
use sysinfo::{
    CpuRefreshKind, DiskRefreshKind, MemoryRefreshKind, ProcessRefreshKind, RefreshKind, UpdateKind,
};

#[derive(Debug)]
pub struct SystemMeasurements {
    system: sysinfo::System,
    disk: sysinfo::Disks,
}

impl SystemMeasurements {
    pub fn new() -> Self {
        Self {
            system: sysinfo::System::new(),
            disk: sysinfo::Disks::new(),
        }
    }

    pub fn refresh(&mut self) {
        self.system.refresh_specifics(
            RefreshKind::default()
                .with_cpu(CpuRefreshKind::default().with_cpu_usage())
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

    pub fn get_process_info(&mut self, pid: sysinfo::Pid) -> Option<ProcessResources> {
        let process = self.system.process(pid)?;

        let cpu_usage = process.cpu_usage();
        let memory = process.memory();

        let thread_resources = process
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

        Some(ProcessResources {
            memory,
            cpu: cpu_usage,
            disk_read_bytes: process.disk_usage().read_bytes,
            disk_write_bytes: process.disk_usage().written_bytes,
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
            disk_read_bytes,
            disk_write_bytes,
            thread_resources: HashMap::new(),
        }
    }
}
