mod builder;
mod lanes;
mod markers;
#[cfg(test)]
mod tests;

use self::builder::ProfileBuilder;
use self::lanes::{Instance, pack_processes};
use crate::export::ReportIdentifier;
use crate::types::JsonLine;
use flate2::Compression;
use flate2::write::GzEncoder;
use fxprof_processed_profile::Profile;
use log::{info, warn};
use snafu::{Location, ResultExt, Snafu, Whatever};
use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::path::{Path, PathBuf};

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

#[derive(clap::Args, Debug)]
pub struct FirefoxExportArguments {
    /// Whether to include bandwidth usage in the export
    #[arg(long, default_value_t = false)]
    bandwidth: bool,
    /// Whether processes whose threads waited for the GIL get a track with the number of waiting
    /// threads. Only Tachyon records the waits.
    #[arg(long, default_value_t = false)]
    gil_waiters: bool,
    /// Whether processes with the same parent and name that never run at the same time share a
    /// track. Recreated worker pools otherwise get a track per process.
    #[arg(long, value_enum, default_value_t = ProcessLanes::Auto)]
    lanes: ProcessLanes,
    /// Which memory the memory graphs show
    #[arg(long, value_enum, default_value_t = MemoryMetric::Rss)]
    memory: MemoryMetric,
    /// The directory containing the profile data
    data_dir: PathBuf,
    /// The output file to write the gz-compressed JSON to
    output_file: PathBuf,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryMetric {
    /// Resident set size, including the memory measured in between samples
    Rss,
    /// Proportional set size, if recorded with `profile --pss`. Memory shared between processes is
    /// split between them, so the graphs add up. Also adds a track with the total of all processes.
    Pss,
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
    let mut builder = ProfileBuilder::from_samples(
        || processes.values(),
        args.bandwidth,
        args.gil_waiters,
        args.memory,
    )?;
    let end_millis = processes.values().flatten().map(|it| it.time).max();
    let duration_millis = end_millis.unwrap_or_default() - builder.start_time_millis;

    // Samples of the same tick share their time, so we can add them up by time
    let mut pss_totals = BTreeMap::<u128, u64>::new();
    for (identifier, samples) in &processes {
        if let ReportIdentifier::Pid(_) = identifier {
            for line in samples {
                if let Some(pss) = line.resources.pss
                    && !line.exited
                {
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
    if args.memory == MemoryMetric::Pss {
        if pss_totals.is_empty() {
            warn!(
                "The profile contains no PSS, showing RSS instead. Record it with `profile --pss`"
            );
        }
        builder.add_pss_total(pss_totals);
    }
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
