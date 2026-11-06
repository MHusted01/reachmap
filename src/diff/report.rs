//! Output of `reachmap diff`: a table for people and JSON for scripts.

use std::collections::BTreeSet;
use std::fmt;

use serde::Serialize;

use super::{Change, Diff, Difference};
use crate::baseline::{Exposure, Tolerant};
use crate::json::Collector;
use crate::reach::Reach;
use crate::scan::Listener;
use crate::socket::Protocol;
use crate::table::write_table;
use crate::warning::Warning;

/// Raised when a change to the output would break existing scripts.
pub const SCHEMA_VERSION: u32 = 1;

/// Printed instead of an empty table when nothing needs attention.
const NO_DIFFERENCES: &str = "No differences.";

/// Printed instead of an empty table when the rows match but the current scan
/// lacks facts the baseline has, so a match proves nothing.
const NO_DIFFERENCES_IN_ROWS: &str = "No differences in the rows.";

/// Column titles, in order.
const HEADERS: [&str; 5] = ["CHANGE", "PORT", "PROTO", "ADDRESS", "DETAIL"];

/// Between the facts of a row. A comma would blend with the list of networks.
const SEPARATOR: &str = "; ";

const UNVERIFIED_NOTE: &str = "an unverified row is missing now, but this scan could not have seen it, so it may still be there";

const PRIVILEGES_NOTE: &str = "only one of the two scans could inspect every process, so owners can differ for that reason alone; run both with sudo";

const UDP_NOTE: &str = "a UDP client that sent without connecting looks like a server, so UDP rows on high ports can come and go";

/// The document on standard output.
#[derive(Serialize)]
struct JsonReport<'a> {
    schema_version: u32,
    differences: &'a [Difference],
    baseline_collector_errors: &'a BTreeSet<Tolerant<Collector>>,
    current_collector_errors: &'a BTreeSet<Tolerant<Collector>>,
    privileges_differ: bool,
}

/// The report as pretty-printed JSON, ending in a newline.
pub fn render_json(diff: &Diff) -> Result<String, serde_json::Error> {
    let document = JsonReport {
        schema_version: SCHEMA_VERSION,
        differences: &diff.differences,
        baseline_collector_errors: &diff.baseline_missing,
        current_collector_errors: &diff.current_missing,
        privileges_differ: diff.privileges_differ,
    };
    serde_json::to_string_pretty(&document).map(|text| text + "\n")
}

/// Displays a diff as the user sees it on standard output: the table, or a
/// line saying there is none, then the notes that qualify it.
#[derive(Debug, Clone, Copy)]
pub struct Report<'a>(pub &'a Diff);

impl fmt::Display for Report<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let diff = self.0;
        if !diff.differences.is_empty() {
            let rows: Vec<_> = diff.differences.iter().map(cells).collect();
            write_table(f, &HEADERS, &rows)?;
        } else if diff.is_clean() {
            writeln!(f, "{NO_DIFFERENCES}")?;
        } else {
            writeln!(f, "{NO_DIFFERENCES_IN_ROWS}")?;
        }
        let notes = notes(diff);
        if !notes.is_empty() {
            writeln!(f)?;
        }
        notes
            .iter()
            .try_for_each(|note| writeln!(f, "note: {note}"))
    }
}

/// The notes under the table, in the order they are printed.
fn notes(diff: &Diff) -> Vec<String> {
    let has = |wanted: fn(&Difference) -> bool| diff.differences.iter().any(wanted);
    let unverified = has(|difference| matches!(difference.change, Change::Unverified { .. }));
    let udp = has(|difference| difference.key.protocol == Tolerant::Known(Protocol::Udp));
    [
        unverified.then(|| UNVERIFIED_NOTE.to_string()),
        missing_note("the baseline", &diff.baseline_missing),
        missing_note("the current scan", &diff.current_missing),
        diff.privileges_differ.then(|| PRIVILEGES_NOTE.to_string()),
        udp.then(|| UDP_NOTE.to_string()),
    ]
    .into_iter()
    .flatten()
    .collect()
}

/// The note for facts one side lacks, if it lacks any.
fn missing_note(side: &str, missing: &BTreeSet<Tolerant<Collector>>) -> Option<String> {
    (!missing.is_empty()).then(|| {
        let names: Vec<String> = missing.iter().map(ToString::to_string).collect();
        format!(
            "{side} has no facts from {}, so the rows those facts affect cannot be trusted",
            names.join(", ")
        )
    })
}

/// The text of each column for one difference.
fn cells(difference: &Difference) -> [String; HEADERS.len()] {
    let key = &difference.key;
    let (name, detail) = match &difference.change {
        Change::New { now } => ("new", summary(now)),
        Change::Removed { was } => ("removed", summary(was)),
        Change::Unverified { was } => ("unverified", summary(was)),
        Change::Changed { was, now } => ("changed", what_changed(was, now)),
    };
    [
        name.to_string(),
        key.port.to_string(),
        key.protocol_name(),
        key.address.to_string(),
        detail,
    ]
}

/// What a row says. A host socket is the normal case, so it goes unsaid.
fn summary(exposure: &Exposure) -> String {
    let reach = match &exposure.reach {
        Reach::From { .. } => format!("reachable from {}", exposure.reach),
        Reach::Unknown => "reach unknown".to_string(),
    };
    let listener = (exposure.listener != Tolerant::Known(Listener::HostSocket))
        .then(|| format!("listener: {}", exposure.listener));
    let warning = exposure.warning.map(|warning| warning.to_string());
    [
        Some(exposure.service.to_string()),
        Some(reach),
        listener,
        warning,
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>()
    .join(SEPARATOR)
}

/// Each fact that differs between two versions of a row.
fn what_changed(was: &Exposure, now: &Exposure) -> String {
    [
        change("reachable from", &was.reach, &now.reach),
        change("service", &was.service, &now.service),
        change("listener", &was.listener, &now.listener),
        change(
            "warning",
            &warning_text(was.warning),
            &warning_text(now.warning),
        ),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>()
    .join(SEPARATOR)
}

/// `label: was -> now`, when they differ.
fn change<T: PartialEq + fmt::Display>(label: &str, was: &T, now: &T) -> Option<String> {
    (was != now).then(|| format!("{label}: {was} -> {now}"))
}

/// The warning of a row, which may have none.
fn warning_text(warning: Option<Tolerant<Warning>>) -> String {
    warning.map_or_else(|| "none".to_string(), |warning| warning.to_string())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;
    use crate::baseline::{Owner, RowKey};
    use crate::network::Network;

    fn exposure() -> Exposure {
        Exposure {
            listener: Tolerant::Known(Listener::HostSocket),
            service: Owner::Process {
                name: "sshd".to_string(),
            },
            reach: Reach::From {
                networks: BTreeSet::from([Network::Lan]),
            },
            warning: None,
        }
    }

    fn diff(change: Change) -> Diff {
        Diff {
            differences: vec![Difference {
                key: RowKey {
                    port: 22,
                    protocol: Tolerant::Known(Protocol::Tcp),
                    address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                },
                change,
            }],
            ..clean()
        }
    }

    fn clean() -> Diff {
        Diff {
            differences: Vec::new(),
            baseline_missing: BTreeSet::new(),
            current_missing: BTreeSet::new(),
            privileges_differ: false,
        }
    }

    #[test]
    fn a_changed_row_lists_each_fact_that_differs() {
        let now = Exposure {
            listener: Tolerant::Known(Listener::DockerForward),
            service: Owner::Unknown,
            reach: Reach::Unknown,
            warning: Some(Tolerant::Known(Warning::UfwBypassed)),
        };

        assert_eq!(
            what_changed(&exposure(), &now),
            "reachable from: LAN -> unknown; service: sshd -> unknown; \
             listener: host socket -> Docker forward; \
             warning: none -> Docker port: UFW does not apply"
        );
    }

    #[test]
    fn a_changed_row_leaves_out_what_stayed_the_same() {
        let now = Exposure {
            service: Owner::Unknown,
            ..exposure()
        };

        assert_eq!(what_changed(&exposure(), &now), "service: sshd -> unknown");
    }

    #[test]
    fn a_row_names_a_listener_this_version_cannot_read() {
        let row = Exposure {
            listener: Tolerant::Unknown,
            ..exposure()
        };

        assert_eq!(summary(&row), "sshd; reachable from LAN; listener: unknown");
    }

    #[test]
    fn matching_rows_with_lost_facts_do_not_say_no_differences() {
        let lost = Diff {
            current_missing: BTreeSet::from([
                Tolerant::Known(Collector::Docker),
                Tolerant::Known(Collector::Interfaces),
            ]),
            ..clean()
        };

        assert_eq!(
            Report(&lost).to_string(),
            "No differences in the rows.\n\n\
             note: the current scan has no facts from interfaces, Docker, so the rows those \
             facts affect cannot be trusted\n"
        );
    }

    #[test]
    fn facts_missing_from_both_sides_keep_the_clean_line_and_the_notes() {
        let missing = BTreeSet::from([Tolerant::Known(Collector::Docker)]);
        let both = Diff {
            baseline_missing: missing.clone(),
            current_missing: missing,
            ..clean()
        };

        assert_eq!(
            Report(&both).to_string(),
            "No differences.\n\n\
             note: the baseline has no facts from Docker, so the rows those facts affect cannot \
             be trusted\n\
             note: the current scan has no facts from Docker, so the rows those facts affect \
             cannot be trusted\n"
        );
    }

    #[test]
    fn only_rows_that_need_a_note_get_one() {
        let removed = diff(Change::Removed { was: exposure() });

        assert_eq!(notes(&removed), Vec::<String>::new());
    }
}
