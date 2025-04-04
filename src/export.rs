use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use flate2::Compression;
use rust_embed::Embed;
use serde_json::json;
use snafu::{IntoError, Location, NoneError, ResultExt, Snafu};
use std::io::Write;
use std::path::Path;

#[derive(Debug, Snafu)]
pub enum ExportError {
    #[snafu(display("Error reading output directory at {location}"))]
    OutputDirRead {
        source: std::io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Error reading report `{name}` at {location}"))]
    ReadReport {
        source: std::io::Error,
        name: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Error serializing reports at {location}"))]
    SerializeReports {
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Error compressing report at {location}"))]
    CompressReport {
        source: std::io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("index.html not found in binary at {location}"))]
    IndexNotFound {
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
    #[snafu(display(
        "Profile data insertion point not found in bundled index.html at {location}"
    ))]
    InsertionPointMissing {
        #[snafu(implicit)]
        location: Location,
    },
}

#[derive(Embed)]
#[folder = "frontend/dist/"]
struct Asset;

pub fn export_report(data_dir: &Path, output_file: &Path) -> Result<(), ExportError> {
    let mut reports = Vec::new();

    for entry in std::fs::read_dir(data_dir).context(OutputDirReadSnafu)? {
        let entry = entry.context(OutputDirReadSnafu)?;

        let name = entry.file_name().to_string_lossy().to_string();
        let content =
            std::fs::read(entry.path()).context(ReadReportSnafu { name: name.clone() })?;

        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(&content).context(CompressReportSnafu)?;
        let data = BASE64_STANDARD.encode(encoder.finish().context(CompressReportSnafu)?);

        reports.push(json!({
            "name": name,
            "data": data,
        }));
    }

    let report_json = serde_json::to_string(&reports).context(SerializeReportsSnafu)?;

    let index_html = Asset::get("index.html").ok_or(IndexNotFoundSnafu.into_error(NoneError))?;
    let original_html = String::from_utf8_lossy(&index_html.data);
    let index_html = original_html.replace(
        "const BUNDLED_REPORTS = []",
        &format!("const BUNDLED_REPORTS = {};", report_json),
    );

    if original_html == index_html {
        return Err(InsertionPointMissingSnafu.into_error(NoneError));
    }

    std::fs::write(output_file, index_html).context(WriteOutputSnafu {
        path: output_file.display().to_string(),
    })?;

    Ok(())
}
