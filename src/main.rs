//! Command-line entry point. Kept thin: parse arguments, call the library,
//! print, set the exit code.

use std::fmt;
use std::io::{self, Write};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use reachmap::errors::render_chain;
use reachmap::table::Table;

/// Shows which services on a host can be reached, from where, and why.
#[derive(Parser)]
#[command(name = "reachmap", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// List the TCP sockets listening on this host (Linux only for now)
    Scan,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Scan => run_scan(),
    }
}

fn run_scan() -> ExitCode {
    match reachmap::scan::scan() {
        Ok(report) => {
            if let Some(error) = &report.interfaces_error {
                eprintln!("warning: {}", render_chain(error));
                if let Some(hint) = error.hint() {
                    eprintln!("hint: {hint}");
                }
            }
            write_stdout(&Table(&report.sockets))
        }
        Err(error) => {
            eprintln!("error: {}", render_chain(&error));
            if let Some(hint) = error.hint() {
                eprintln!("hint: {hint}");
            }
            ExitCode::FAILURE
        }
    }
}

/// Writes to stdout and flushes, without `print!`, which panics when the
/// reader has gone away (`reachmap scan | head -1`). A closed pipe is a
/// normal way to stop; any other write error is reported.
fn write_stdout(content: &impl fmt::Display) -> ExitCode {
    let mut out = io::stdout().lock();
    match write!(out, "{content}").and_then(|()| out.flush()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: could not write output: {error}");
            ExitCode::FAILURE
        }
    }
}
