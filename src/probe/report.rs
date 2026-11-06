//! Output of `reachmap probe`: a table for people and JSON for scripts.

use std::collections::BTreeSet;
use std::fmt;

use serde::Serialize;

use super::compare::{Comparison, Difference, Disagreement};
use super::{Outcome, ProbeReport, ProbedPort};
use crate::network::Network;
use crate::table::write_table;

/// Raised when a change to the output would break existing scripts.
pub const SCHEMA_VERSION: u32 = 1;

/// Column titles, in order.
const HEADERS: [&str; 3] = ["PORT", "ADDRESS", "RESULT"];

/// Column titles of the differences, in order.
const DIFFERENCE_HEADERS: [&str; 3] = ["PORT", "FROM", "DIFFERENCE"];

/// Said of a network that was worked out, because it is only a guess.
const GUESSED: &str = " (worked out from the address; --from overrides it)";

/// Printed under a table with a port that gave no answer, because that row
/// is the one most easily read as more than the probe knows.
const NO_ANSWER_NOTE: &str = "no answer means the connection timed out; a firewall and a host that is down look the same from here";

/// The document on standard output.
#[derive(Serialize)]
struct JsonReport<'a> {
    schema_version: u32,
    host: &'a str,
    results: &'a [ProbedPort],
    #[serde(skip_serializing_if = "Option::is_none")]
    comparison: Option<&'a Comparison>,
}

/// The report as pretty-printed JSON, ending in a newline.
pub fn render_json(report: &ProbeReport) -> Result<String, serde_json::Error> {
    let document = JsonReport {
        schema_version: SCHEMA_VERSION,
        host: &report.host,
        results: &report.results,
        comparison: report.comparison.as_ref(),
    };
    serde_json::to_string_pretty(&document).map(|text| text + "\n")
}

/// Displays a probe as the user sees it on standard output: the table, the
/// comparison with a saved scan if there is one, then the notes.
#[derive(Debug, Clone, Copy)]
pub struct Report<'a>(pub &'a ProbeReport);

impl fmt::Display for Report<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let report = self.0;
        let rows: Vec<_> = report.results.iter().map(cells).collect();
        write_table(f, &HEADERS, &rows)?;
        if let Some(comparison) = &report.comparison {
            writeln!(f)?;
            write_comparison(f, comparison)?;
        }
        let notes = notes(report);
        if !notes.is_empty() {
            writeln!(f)?;
        }
        notes
            .iter()
            .try_for_each(|note| writeln!(f, "note: {note}"))
    }
}

/// The heading of a comparison, then its differences or that there are none.
fn write_comparison(f: &mut fmt::Formatter<'_>, comparison: &Comparison) -> fmt::Result {
    let from = joined(comparison.from.iter().map(|&network| source_name(network)));
    let guessed = if comparison.guessed { GUESSED } else { "" };
    write!(f, "compared with the scan from {from}{guessed}")?;
    if comparison.differences.is_empty() {
        return writeln!(f, ": no differences");
    }
    writeln!(f)?;
    let rows: Vec<_> = comparison
        .differences
        .iter()
        .map(difference_cells)
        .collect();
    write_table(f, &DIFFERENCE_HEADERS, &rows)
}

/// What needs saying under the tables.
fn notes(report: &ProbeReport) -> Vec<String> {
    let no_answer = report
        .results
        .iter()
        .any(|probed| probed.result == Outcome::NoAnswer)
        .then(|| NO_ANSWER_NOTE.to_string());
    let comparison = report.comparison.iter().flat_map(comparison_notes);
    no_answer.into_iter().chain(comparison).collect()
}

/// What a comparison leaves open.
fn comparison_notes(comparison: &Comparison) -> impl Iterator<Item = String> {
    let ports = |ports: &BTreeSet<u16>| joined(ports.iter().map(u16::to_string));
    let unknown = (!comparison.unknown_ports.is_empty()).then(|| {
        format!(
            "the scan has no verdict for these ports from at least one network, so only the probe result counts there: {}",
            ports(&comparison.unknown_ports)
        )
    });
    let skipped = (!comparison.skipped_ports.is_empty()).then(|| {
        format!(
            "rows that are not TCP are left out, because a connect probe cannot confirm them: {}",
            ports(&comparison.skipped_ports)
        )
    });
    unknown.into_iter().chain(skipped)
}

/// `items`, separated by commas.
fn joined(items: impl Iterator<Item = String>) -> String {
    items.collect::<Vec<_>>().join(", ")
}

/// A network as the place a probe came from. The caveat in the scan's name for
/// the internet is about a host's reach, not about this machine.
fn source_name(network: Network) -> String {
    match network {
        Network::Internet => "internet".to_string(),
        other => other.to_string(),
    }
}

/// The text of each column for one difference.
fn difference_cells(difference: &Difference) -> [String; DIFFERENCE_HEADERS.len()] {
    let text = match difference.kind {
        Disagreement::UnexpectedConnection => {
            "connected, but the scan says this network cannot reach it"
        }
        Disagreement::MissingConnection => {
            "did not connect, but the scan says this network can reach it; a firewall can cause that"
        }
    };
    [
        difference.port.to_string(),
        source_name(difference.from),
        text.to_string(),
    ]
}

/// The text of each column for one result.
fn cells(probed: &ProbedPort) -> [String; HEADERS.len()] {
    [
        probed.port.to_string(),
        probed.address.to_string(),
        probed.result.to_string(),
    ]
}
