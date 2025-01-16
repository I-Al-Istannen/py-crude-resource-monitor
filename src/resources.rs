use serde::{Deserialize, Serialize};
use sysinfo::{CpuRefreshKind, MemoryRefreshKind, ProcessRefreshKind, RefreshKind, UpdateKind};

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct ProcessResources {
    pub memory: u64,
    pub cpu: f32,
}

#[derive(Debug)]
pub struct SystemMeasurements {
    system: sysinfo::System,
}

impl SystemMeasurements {
    pub fn new() -> Self {
        SystemMeasurements {
            system: sysinfo::System::new(),
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
                        .with_cmd(UpdateKind::Always),
                )
                .with_memory(MemoryRefreshKind::default().with_ram()),
        );
    }

    pub fn get_process_info(&mut self, pid: sysinfo::Pid) -> Option<ProcessResources> {
        let process = self.system.process(pid)?;

        let cpu_usage = process.cpu_usage();
        let memory = process.memory();

        Some(ProcessResources {
            memory,
            cpu: cpu_usage,
        })
    }

    pub fn get_global_info(&mut self) -> ProcessResources {
        let memory = self.system.used_memory();
        // We want to normalize the cpu usage so that 100% is only one core
        let cpu = self.system.global_cpu_usage() * self.system.cpus().len() as f32;

        ProcessResources { memory, cpu }
    }
}
