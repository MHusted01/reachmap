//! Output of `reachmap probe`: a table for people and JSON for scripts.

use std::fmt;

use serde::Serialize;

use super::{Outcome, ProbeReport, ProbedPort};
use crate::table::write_table;

/// Raised when a change to the output would break existing scripts.
pub const SCHEMA_VERSION: u32 = 1;

/// Column titles, in order.
const HEADERS: [&str; 3] = ["PORT", "ADDRESS", "RESULT"];

/// Printed under a table with a port that gave no answer, because that row
/// is the one most easily read as more than the probe knows.
const NO_ANSWER_NOTE: &str = "no answer means the connection timed out; a firewall and a host that is down look the same from here";

/// The document on standard output.
#[derive(Serialize)]
struct JsonReport<'a> {
    schema_version: u32,
    host: &'a str,
    results: &'a [ProbedPort],
}

/// The report as pretty-printed JSON, ending in a newline.
pub fn render_json(report: &ProbeReport) -> Result<String, serde_json::Error> {
    let document = JsonReport {
        schema_version: SCHEMA_VERSION,
        host: &report.host,
        results: &report.results,
    };
    serde_json::to_string_pretty(&document).map(|text| text + "\n")
}

/// Displays a probe as the user sees it on standard output: the table, then a
/// note if a port gave no answer.
#[derive(Debug, Clone, Copy)]
pub struct Report<'a>(pub &'a ProbeReport);

impl fmt::Display for Report<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let results = &self.0.results;
        let rows: Vec<_> = results.iter().map(cells).collect();
        write_table(f, &HEADERS, &rows)?;
        if results
            .iter()
            .any(|probed| probed.result == Outcome::NoAnswer)
        {
            writeln!(f, "\nnote: {NO_ANSWER_NOTE}")?;
        }
        Ok(())
    }
}

/// The text of each column for one result.
fn cells(probed: &ProbedPort) -> [String; HEADERS.len()] {
    [
        probed.port.to_string(),
        probed.address.to_string(),
        probed.result.to_string(),
    ]
}
