//! Command-line entry point. Kept thin: parse arguments, call the library,
//! print, set the exit code.

use std::fmt;
use std::io::{self, Write};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand};
use reachmap::baseline::{self, Snapshot};
use reachmap::diff::report::{Report as DiffTable, render_json as render_diff_json};
use reachmap::diff::{Diff, DiffError, compare};
use reachmap::errors::render_chain;
use reachmap::parse::probe_args::{PortList, parse_timeout};
use reachmap::probe::report::{Report as ProbeTable, render_json};
use reachmap::probe::{DEFAULT_CONCURRENCY, DEFAULT_TIMEOUT, ProbeOptions};
use reachmap::scan::ScanReport;
use reachmap::table::Report;

/// `reachmap diff`'s status when nothing could be compared, as for `diff(1)`.
/// Status 1 means differences, so a failure must not look like one.
const COULD_NOT_COMPARE: u8 = 2;

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
    /// Try to connect to TCP ports of a host from this machine
    Probe {
        /// The host to connect to: a name or an IP address
        host: String,
        /// The ports to try, for example 22,80,8000-8100
        #[arg(long)]
        ports: PortList,
        /// Seconds to wait for each connection
        #[arg(long, default_value = DEFAULT_TIMEOUT, value_parser = parse_timeout)]
        timeout: Duration,
        /// How many connections may be in progress at once
        #[arg(long, default_value = DEFAULT_CONCURRENCY)]
        concurrency: NonZeroUsize,
        /// Print the results as JSON instead of a table
        #[arg(long)]
        json: bool,
    },
    /// Compare a saved `reachmap scan --json` with this host, or with a second file
    Diff {
        /// The saved scan to compare against
        baseline: PathBuf,
        /// A saved scan to use instead of scanning this host
        current: Option<PathBuf>,
        /// Print the differences as JSON instead of a table
        #[arg(long)]
        json: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Scan { json } => run_scan(json),
        Command::Probe {
            host,
            ports,
            timeout,
            concurrency,
            json,
        } => {
            let options = ProbeOptions {
                timeout,
                concurrency,
            };
            run_probe(&host, &ports, options, json)
        }
        Command::Diff {
            baseline,
            current,
            json,
        } => run_diff(&baseline, current.as_deref(), json),
    }
}

/// Compares two scans: 0 when nothing needs attention, 1 when something does,
/// [`COULD_NOT_COMPARE`] when that cannot be told.
fn run_diff(baseline: &Path, current: Option<&Path>, json: bool) -> ExitCode {
    match diff_with(baseline, current) {
        Ok(diff) => print_diff(&diff, json),
        Err(error) => {
            eprintln!("error: {}", render_chain(&error));
            print_hint(error.hint());
            COULD_NOT_COMPARE.into()
        }
    }
}

/// Reads the baseline first, so a bad file fails before a scan runs.
fn diff_with(baseline: &Path, current: Option<&Path>) -> Result<Diff, DiffError> {
    let baseline = baseline::load(baseline)?;
    let current = match current {
        Some(path) => baseline::load(path)?,
        None => live_snapshot()?,
    };
    Ok(compare(&baseline, &current))
}

/// Scans this host, with the same notes on standard error as `reachmap scan`.
fn live_snapshot() -> Result<Snapshot, DiffError> {
    let report = reachmap::scan::scan()?;
    print_collector_errors(&report);
    Ok(Snapshot::from(&report))
}

/// Prints the finished diff in the chosen format.
fn print_diff(diff: &Diff, json: bool) -> ExitCode {
    let status = if diff.is_clean() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    };
    if !json {
        return write_or(&DiffTable(diff), status, COULD_NOT_COMPARE.into());
    }
    match render_diff_json(diff) {
        Ok(text) => write_or(&text, status, COULD_NOT_COMPARE.into()),
        Err(error) => {
            eprintln!("error: could not format the diff as JSON: {error}");
            COULD_NOT_COMPARE.into()
        }
    }
}

/// Probes `host`. A closed port is a result, not a failure, so the status only
/// reports ports that could not be tested.
fn run_probe(host: &str, ports: &PortList, options: ProbeOptions, json: bool) -> ExitCode {
    let report = match reachmap::probe::probe(host, ports, options) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("error: {}", render_chain(&error));
            return ExitCode::FAILURE;
        }
    };
    let status = if report.all_tested() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    };
    if !json {
        return write_stdout(&ProbeTable(&report), status);
    }
    match render_json(&report) {
        Ok(text) => write_stdout(&text, status),
        Err(error) => {
            eprintln!("error: could not format the probe as JSON: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_scan(json: bool) -> ExitCode {
    match reachmap::scan::scan() {
        Ok(report) => {
            print_collector_errors(&report);
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

/// Says on standard error which optional facts the scan could not collect.
fn print_collector_errors(report: &ScanReport) {
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
    if let Some(error) = &report.tailscale_error {
        eprintln!("note: {}", render_chain(error));
        print_hint(error.hint());
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
    write_or(content, status, ExitCode::FAILURE)
}

/// [`write_stdout`] with the status to return when the write fails.
fn write_or(content: &impl fmt::Display, status: ExitCode, failed: ExitCode) -> ExitCode {
    let mut out = io::stdout().lock();
    match write!(out, "{content}").and_then(|()| out.flush()) {
        Ok(()) => status,
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => status,
        Err(error) => {
            eprintln!("error: could not write output: {error}");
            failed
        }
    }
}
