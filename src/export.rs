use crate::types::JsonLine;
use snafu::{Location, ResultExt, Snafu, Whatever};
use std::collections::HashMap;
use std::path::Path;

pub use firefox::FirefoxExportArguments;

mod firefox;
mod html;

#[derive(Debug, Snafu)]
pub enum ExportError {
    #[snafu(display("Error generating html report at {location}"))]
    Html {
        source: html::ExportError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Error generating firefox report at {location}"))]
    Firefox {
        source: firefox::ExportError,
        #[snafu(implicit)]
        location: Location,
    },
}

/// Exports the profile data to a self-contained single-file HTML report.
pub fn export_html(data_dir: &Path, output_file: &Path) -> Result<(), ExportError> {
    html::export_report(data_dir, output_file).context(HtmlSnafu)
}

/// Exports the profile data to a Firefox-compatible JSON report.
pub fn export_firefox(args: FirefoxExportArguments) -> Result<(), ExportError> {
    firefox::export_report(args).context(FirefoxSnafu)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReportIdentifier {
    Pid(u32),
    Global,
}

/// Reads the report data from the specified directory and returns a mapping of process identifiers
/// to their respective JSON lines.
/// This method is not very memory efficient, as it effectively reads all files in the directory
/// in memory.
fn read_report(data_dir: &Path) -> Result<HashMap<ReportIdentifier, Vec<JsonLine>>, Whatever> {
    let mut all_processes = HashMap::new();
    for entry in std::fs::read_dir(data_dir).whatever_context("could not open data dir")? {
        let entry = entry.whatever_context("could not read data dir entry")?;
        let name = entry
            .path()
            .file_stem()
            .unwrap()
            .to_string_lossy()
            .to_string();

        let content = std::fs::read_to_string(entry.path()).with_whatever_context(|_| {
            format!("could not read file `{}`", entry.path().display())
        })?;

        let lines: Vec<JsonLine> = content
            .lines()
            .map(|line| {
                serde_json::from_str(line).with_whatever_context(|_| {
                    format!("could not deserialize line in `{}`", entry.path().display())
                })
            })
            .collect::<Result<_, _>>()?;

        let pid = if name == "global" {
            // Pid 1 is the init process, pid 0 is not real and used as a global placeholder.
            ReportIdentifier::Global
        } else {
            ReportIdentifier::Pid(
                name.parse::<u32>()
                    .with_whatever_context(|_| format!("could not parse pid from `{name}`"))?,
            )
        };

        all_processes.insert(pid, lines);
    }

    Ok(all_processes)
}
