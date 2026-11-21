//! Print the opt-in Tailscale route report.

use std::process::ExitCode;

use reachmap::errors::render_chain;
use reachmap::tailscale::routes;

use super::write_stdout;

pub(super) fn run() -> ExitCode {
    match routes::scan() {
        Ok(report) => {
            let status = if report.is_complete() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            };
            write_stdout(&report, status)
        }
        Err(error) => {
            eprintln!("error: {}", render_chain(&error));
            ExitCode::FAILURE
        }
    }
}
