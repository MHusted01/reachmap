//! Print the opt-in Nginx route report.

use std::{fmt, process::ExitCode};

use reachmap::errors::render_chain;
use reachmap::host_input_snapshot::HostRef;
use reachmap::nginx::routes::{self, snapshot};

use super::write_stdout;

pub(super) fn run(host_ref: Option<HostRef>) -> ExitCode {
    if let Some(host_ref) = host_ref {
        return match snapshot::capture(host_ref) {
            Ok((json, complete)) => write_report(&json, complete),
            Err(error) => fail(&error),
        };
    }
    match routes::scan() {
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
