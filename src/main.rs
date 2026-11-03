//! Command-line entry point. Kept thin: parse arguments, call the library,
//! print, set the exit code.

use std::io::{self, Write};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use reachmap::errors::render_chain;

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
    let sockets = match reachmap::scan::scan() {
        Ok(sockets) => sockets,
        Err(error) => {
            eprintln!("error: {}", render_chain(&error));
            return ExitCode::FAILURE;
        }
    };
    write_stdout(&reachmap::table::render_table(&sockets))
}

/// Writes to stdout without `print!`, which panics when the reader has gone
/// away (`reachmap scan | head -1`). A closed pipe is a normal way to stop.
fn write_stdout(text: &str) -> ExitCode {
    match io::stdout().lock().write_all(text.as_bytes()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: could not write output: {error}");
            ExitCode::FAILURE
        }
    }
}
