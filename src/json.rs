//! JSON output for `reachmap scan --json`, built from the same [`ScanReport`]
//! as the table. The shape is a promise to scripts: `docs/json.md` documents
//! it, and `tests/json_output.rs` pins it.

use std::error::Error;

use serde::Serialize;

use crate::errors::render_chain;
use crate::scan::{ScanReport, ScannedPort};
use crate::warning::ScanWarning;

/// Raised when a change to the output would break existing scripts.
pub const SCHEMA_VERSION: u32 = 1;

/// The document on standard output. It borrows from the report, so nothing
/// is copied but the errors, which have no JSON form of their own.
#[derive(Serialize)]
struct JsonReport<'a> {
    schema_version: u32,
    ports: &'a [ScannedPort],
    warnings: &'a [ScanWarning],
    collector_errors: Vec<CollectorError>,
}

/// An optional collector that failed, so scripts need not read standard
/// error to learn that facts are missing.
#[derive(Serialize)]
struct CollectorError {
    collector: Collector,
    message: String,
    hint: Option<String>,
}

/// The optional collectors a scan can finish without.
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum Collector {
    Interfaces,
    Docker,
    SocketOptions,
}

impl CollectorError {
    fn new(collector: Collector, error: &(dyn Error + 'static), hint: Option<String>) -> Self {
        CollectorError {
            collector,
            message: render_chain(error),
            hint,
        }
    }
}

/// The scan as pretty-printed JSON, ending in a newline.
pub fn render(report: &ScanReport) -> Result<String, serde_json::Error> {
    let interfaces = report
        .interfaces_error
        .as_ref()
        .map(|error| CollectorError::new(Collector::Interfaces, error, error.hint()));
    let docker = report
        .docker_error
        .as_ref()
        .map(|error| CollectorError::new(Collector::Docker, error, error.hint()));
    let socket_options = report
        .socket_options_error
        .as_ref()
        .map(|error| CollectorError::new(Collector::SocketOptions, error, error.hint()));
    let document = JsonReport {
        schema_version: SCHEMA_VERSION,
        ports: &report.ports,
        warnings: &report.warnings,
        collector_errors: interfaces
            .into_iter()
            .chain(docker)
            .chain(socket_options)
            .collect(),
    };
    serde_json::to_string_pretty(&document).map(|text| text + "\n")
}

#[cfg(test)]
mod tests;
