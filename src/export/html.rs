use crate::view::Asset;
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use flate2::Compression;
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
    #[snafu(display("Profile data insertion point not found in bundled index.html at {location}"))]
    InsertionPointMissing {
        #[snafu(implicit)]
        location: Location,
    },
}

pub(super) fn export_report(data_dir: &Path, output_file: &Path) -> Result<(), ExportError> {
    let mut reports = Vec::new();

    for entry in std::fs::read_dir(data_dir).context(OutputDirReadSnafu)? {
        let entry = entry.context(OutputDirReadSnafu)?;
        if !super::is_report_file(&entry.path()) {
            continue;
        }

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
    let index_html = inject_reports(&String::from_utf8_lossy(&index_html.data), &report_json)
        .ok_or(InsertionPointMissingSnafu.into_error(NoneError))?;

    std::fs::write(output_file, index_html).context(WriteOutputSnafu {
        path: output_file.display().to_string(),
    })?;

    Ok(())
}

/// Replaces the empty `BUNDLED_REPORTS` array in the frontend with the given reports.
/// We do not match the `const` keyword, as the bundler might turn it into a `var`.
fn inject_reports(html: &str, report_json: &str) -> Option<String> {
    const INSERTION_POINT: &str = "BUNDLED_REPORTS = []";
    if !html.contains(INSERTION_POINT) {
        return None;
    }
    // Ensure no report content can close the surrounding script tag
    let report_json = report_json.replace("</", "<\\/");
    Some(html.replacen(
        INSERTION_POINT,
        &format!("BUNDLED_REPORTS = {report_json}"),
        1,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_frontend_has_insertion_point() {
        let index_html = Asset::get("index.html").expect("frontend is embedded");
        let html = String::from_utf8_lossy(&index_html.data);

        let injected = inject_reports(&html, r#"[{"name":"1.json","data":""}]"#).unwrap();

        assert!(injected.contains(r#"BUNDLED_REPORTS = [{"name":"1.json","data":""}]"#));
    }

    #[test]
    fn injected_reports_can_not_close_script_tag() {
        let injected = inject_reports("BUNDLED_REPORTS = []", r#"["</script>"]"#).unwrap();

        assert_eq!(injected, r#"BUNDLED_REPORTS = ["<\/script>"]"#);
    }
}
