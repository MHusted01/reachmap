//! Print the opt-in Caddy route report.

use std::{fmt, process::ExitCode};

use reachmap::caddy::routes::{self, ConfigSource, snapshot};
use reachmap::errors::render_chain;
use reachmap::host_input_snapshot::HostRef;

use super::write_stdout;

/// Exits 0 when the report is complete, 1 when it is partial, uncertain or
/// could not be collected.
pub(super) fn run(source: &ConfigSource, host_ref: Option<HostRef>) -> ExitCode {
    if let Some(host_ref) = host_ref {
        return match snapshot::capture(host_ref, source) {
            Ok((json, complete)) => write_report(&json, complete),
            Err(error) => fail(&error),
        };
    }
    match routes::scan(source) {
        Ok(report) => write_report(&report, report.is_complete()),
        Err(error) => fail(&error),
    }
}

pub(super) fn write_report(report: &impl fmt::Display, complete: bool) -> ExitCode {
    let status = if complete {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    };
    write_stdout(report, status)
}

fn fail(error: &(dyn std::error::Error + 'static)) -> ExitCode {
    eprintln!("error: {}", render_chain(error));
    ExitCode::FAILURE
}
