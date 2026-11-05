//! Command-line entry point. Kept thin: parse arguments, call the library,
//! print, set the exit code.

use std::fmt;
use std::io::{self, Write};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use reachmap::errors::render_chain;
use reachmap::scan::ScanReport;
use reachmap::table::Report;

/// Shows which services on a host can be reached, from where, and why.
#[derive(Parser)]
#[command(name = "reachmap", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// List the TCP and UDP sockets listening on this host (Linux only for now)
    Scan {
        /// Print the findings as JSON instead of a table
        #[arg(long)]
        json: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Scan { json } => run_scan(json),
    }
}

fn run_scan(json: bool) -> ExitCode {
    match reachmap::scan::scan() {
        Ok(report) => {
            if let Some(error) = &report.interfaces_error {
                eprintln!("warning: {}", render_chain(error));
                print_hint(error.hint());
            }
            if let Some(error) = &report.docker_error {
                eprintln!("note: {}", render_chain(error));
                print_hint(error.hint());
            }
            if let Some(error) = &report.socket_options_error {
                eprintln!("note: {}", render_chain(error));
                print_hint(error.hint());
            }
            let status = if report.warnings.is_empty() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            };
            print_report(&report, json, status)
        }
        Err(error) => {
            eprintln!("error: {}", render_chain(&error));
            print_hint(error.hint());
            ExitCode::FAILURE
        }
    }
}

/// Prints the finished scan in the chosen format and returns `status`.
fn print_report(report: &ScanReport, json: bool, status: ExitCode) -> ExitCode {
    if !json {
        return write_stdout(&Report(report), status);
    }
    match reachmap::json::render(report) {
        Ok(text) => write_stdout(&text, status),
        Err(error) => {
            eprintln!("error: could not format the scan as JSON: {error}");
            ExitCode::FAILURE
        }
    }
}

fn print_hint(hint: Option<String>) {
    if let Some(hint) = hint {
        eprintln!("hint: {hint}");
    }
}

/// Writes to stdout and flushes, without `print!`, which panics when the
/// reader has gone away (`reachmap scan | head -1`), and returns `status`. A
/// closed pipe is a normal way to stop, so it does not change `status`; any
/// other write error is reported.
fn write_stdout(content: &impl fmt::Display, status: ExitCode) -> ExitCode {
    let mut out = io::stdout().lock();
    match write!(out, "{content}").and_then(|()| out.flush()) {
        Ok(()) => status,
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => status,
        Err(error) => {
            eprintln!("error: could not write output: {error}");
            ExitCode::FAILURE
        }
    }
}
