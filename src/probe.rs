//! `reachmap probe`: tries to connect to TCP ports of a host the user names,
//! from this machine, and reports what happened to each.
//!
//! This is the only part of reachmap that sends traffic. A probe connects and
//! closes straight away, without sending data. [`Outcome`], the formatting in
//! [`report`] and the comparison with a saved scan in [`claims`] and [`compare`]
//! are pure; `connect` holds the code that touches the network.

mod address;
pub mod claims;
pub mod compare;
mod connect;
pub mod report;

use std::fmt;
use std::io::{self, ErrorKind};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Serialize;
use thiserror::Error;
use tokio::net::TcpStream;
use tokio::runtime::Builder;
use tokio::task::JoinError;

pub use address::ProbedAddress;

use crate::baseline::LoadError;
use crate::network::Network;
use crate::parse::probe_args::PortList;
use crate::probe::compare::Comparison;
use crate::sanitize::sanitize;

/// The default of `--timeout`, in seconds.
pub const DEFAULT_TIMEOUT: &str = "2";

/// The default of `--concurrency`. It stays below the 256 open files macOS
/// allows a shell's programs by default.
pub const DEFAULT_CONCURRENCY: &str = "100";

/// How long a host name may take to resolve, in seconds.
const RESOLVE_TIMEOUT_SECONDS: u64 = 10;

/// What happened to one connection attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Outcome {
    /// The connection succeeded.
    Open,
    /// A refusal came back, from the host or from a firewall in front of it.
    Closed,
    /// Nothing came back in time. A firewall that drops packets and a host
    /// that is down look the same, so this claims neither.
    NoAnswer,
    /// This machine or a router reports that the host cannot be reached. A
    /// missing route, a firewall and a host that is down can all cause that.
    Unreachable,
    /// The attempt failed in a way that says nothing about the port, for
    /// example because this machine ran out of open files.
    Failed {
        /// The system's error message.
        message: String,
    },
}

impl Outcome {
    /// The outcome of a connection attempt that ended in `error`.
    pub fn from_error(error: &io::Error) -> Self {
        match error.kind() {
            ErrorKind::ConnectionRefused => Outcome::Closed,
            ErrorKind::TimedOut => Outcome::NoAnswer,
            ErrorKind::HostUnreachable | ErrorKind::NetworkUnreachable | ErrorKind::NetworkDown => {
                Outcome::Unreachable
            }
            _ => Outcome::Failed {
                message: sanitize(&error.to_string()),
            },
        }
    }
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Outcome::Open => f.write_str("open"),
            Outcome::Closed => f.write_str("closed"),
            Outcome::NoAnswer => f.write_str("no answer"),
            Outcome::Unreachable => f.write_str("unreachable"),
            Outcome::Failed { message } => write!(f, "failed: {message}"),
        }
    }
}

/// One port of one address, and what happened when connecting to it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProbedPort {
    /// The TCP port.
    pub port: u16,
    /// The address connected to.
    pub address: ProbedAddress,
    /// What happened.
    pub result: Outcome,
}

/// Everything `reachmap probe` found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeReport {
    /// The host as the user named it, safe to print.
    pub host: String,
    /// One entry per address and port, by port, then address.
    pub results: Vec<ProbedPort>,
    /// How the results compare with a saved scan, if one was given.
    pub comparison: Option<Comparison>,
}

impl ProbeReport {
    /// Whether every attempt says something about its port. A failed attempt
    /// says nothing, so that port is unknown rather than fine.
    pub fn all_tested(&self) -> bool {
        !self
            .results
            .iter()
            .any(|probed| matches!(probed.result, Outcome::Failed { .. }))
    }

    /// Whether nothing needs attention: every port was tested, and the results
    /// agree with the saved scan, if there is one.
    pub fn is_clean(&self) -> bool {
        self.all_tested()
            && self
                .comparison
                .as_ref()
                .is_none_or(|comparison| comparison.differences.is_empty())
    }
}

/// How to run a probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeOptions {
    /// How long to wait for each connection.
    pub timeout: Duration,
    /// How many connections may be in progress at once.
    pub concurrency: NonZeroUsize,
}

/// Why a probe could not run. A port that cannot be reached is a result, not
/// an error.
#[derive(Debug, Error)]
pub enum ProbeError {
    /// The async runtime did not start.
    #[error("could not start the probe")]
    Runtime(#[source] io::Error),
    /// The name lookup failed.
    #[error("could not resolve {host}")]
    Resolve {
        /// The host as the user named it, safe to print.
        host: String,
        /// The lookup's error.
        #[source]
        source: io::Error,
    },
    /// The name lookup took too long.
    #[error("could not resolve {host}: no answer after {RESOLVE_TIMEOUT_SECONDS} seconds")]
    ResolveTimeout {
        /// The host as the user named it, safe to print.
        host: String,
    },
    /// The lookup succeeded without an address.
    #[error("could not resolve {host}: it has no addresses")]
    NoAddresses {
        /// The host as the user named it, safe to print.
        host: String,
    },
    /// A connection task stopped without a result.
    #[error("a connection attempt stopped unexpectedly")]
    Task(#[source] JoinError),
    /// The saved scan could not be used.
    #[error(transparent)]
    Scan(#[from] LoadError),
    /// The saved scan lists no port a connection could test.
    #[error("{} has no TCP ports to probe", path.display())]
    NoTcpPorts {
        /// The file.
        path: PathBuf,
    },
}

/// Connects to `ports` on every address of `host`.
///
/// The attempts wait on the network, not the processor, so one thread runs
/// them all. Only this function starts the runtime: the rest of reachmap is
/// ordinary blocking code.
pub fn probe(
    host: &str,
    ports: &PortList,
    options: ProbeOptions,
) -> Result<ProbeReport, ProbeError> {
    let runtime = Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(ProbeError::Runtime)?;
    let report = runtime.block_on(run(host, ports, options));
    // A lookup that timed out still holds a thread that cannot be cancelled.
    runtime.shutdown_background();
    report
}

/// Connects to the TCP ports of the saved scan at `scan` and compares the
/// results with it. `from` is the network this machine is on; without it, the
/// addresses of `host` suggest one. The file is read first, so a bad one sends
/// no traffic.
pub fn probe_against_scan(
    host: &str,
    scan: &Path,
    from: Option<Network>,
    options: ProbeOptions,
) -> Result<ProbeReport, ProbeError> {
    let claims = claims::load(scan)?;
    let ports = claims.ports().ok_or_else(|| ProbeError::NoTcpPorts {
        path: scan.to_path_buf(),
    })?;
    let report = probe(host, &ports, options)?;
    let comparison = compare::compare(&claims, &report.results, from);
    Ok(ProbeReport {
        comparison: Some(comparison),
        ..report
    })
}

/// Resolves `host` and connects to every target.
async fn run(
    host: &str,
    ports: &PortList,
    options: ProbeOptions,
) -> Result<ProbeReport, ProbeError> {
    let addresses = connect::resolve(host).await?;
    let targets = connect::targets(&addresses, ports);
    let results = connect::probe_all(targets, options.concurrency, |target| {
        connect::attempt(TcpStream::connect(target), options.timeout)
    })
    .await
    .map_err(ProbeError::Task)?;
    Ok(ProbeReport {
        host: sanitize(host),
        results,
        comparison: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::compare::{Difference, Disagreement};
    use std::collections::BTreeSet;
    use std::net::{IpAddr, Ipv4Addr, TcpListener};

    fn outcome_of(kind: ErrorKind) -> Outcome {
        Outcome::from_error(&io::Error::from(kind))
    }

    fn options() -> ProbeOptions {
        ProbeOptions {
            timeout: Duration::from_secs(2),
            concurrency: NonZeroUsize::MIN,
        }
    }

    /// A port nothing listens on: bound by the system, then released.
    fn closed_port() -> u16 {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.local_addr().unwrap().port()
    }

    #[test]
    fn a_refused_connection_is_closed() {
        assert_eq!(outcome_of(ErrorKind::ConnectionRefused), Outcome::Closed);
    }

    #[test]
    fn a_timeout_from_the_system_is_no_answer() {
        assert_eq!(outcome_of(ErrorKind::TimedOut), Outcome::NoAnswer);
    }

    #[test]
    fn a_missing_route_is_unreachable() {
        for kind in [
            ErrorKind::HostUnreachable,
            ErrorKind::NetworkUnreachable,
            ErrorKind::NetworkDown,
        ] {
            assert_eq!(outcome_of(kind), Outcome::Unreachable, "{kind:?}");
        }
    }

    #[test]
    fn any_other_error_is_failed_and_keeps_its_message() {
        let error = io::Error::other("too many open files");
        assert_eq!(
            Outcome::from_error(&error),
            Outcome::Failed {
                message: "too many open files".to_string()
            }
        );
    }

    #[test]
    fn a_failed_outcome_cannot_carry_terminal_escapes() {
        let error = io::Error::other("bad\u{1b}[2J");
        assert_eq!(
            Outcome::from_error(&error),
            Outcome::Failed {
                message: "bad\\u{1b}[2J".to_string()
            }
        );
    }

    #[test]
    fn outcomes_read_as_plain_words() {
        assert_eq!(Outcome::Open.to_string(), "open");
        assert_eq!(Outcome::Closed.to_string(), "closed");
        assert_eq!(Outcome::NoAnswer.to_string(), "no answer");
        assert_eq!(Outcome::Unreachable.to_string(), "unreachable");
        let failed = Outcome::Failed {
            message: "too many open files".to_string(),
        };
        assert_eq!(failed.to_string(), "failed: too many open files");
    }

    fn report_of(result: Outcome) -> ProbeReport {
        ProbeReport {
            host: "server.example".to_string(),
            results: vec![ProbedPort {
                port: 80,
                address: IpAddr::from(Ipv4Addr::LOCALHOST).into(),
                result,
            }],
            comparison: None,
        }
    }

    #[test]
    fn every_real_answer_counts_as_tested() {
        for result in [
            Outcome::Open,
            Outcome::Closed,
            Outcome::NoAnswer,
            Outcome::Unreachable,
        ] {
            assert!(report_of(result.clone()).all_tested(), "{result}");
        }
    }

    #[test]
    fn a_failed_attempt_means_a_port_was_not_tested() {
        let failed = Outcome::Failed {
            message: "too many open files".to_string(),
        };
        assert!(!report_of(failed).all_tested());
    }

    #[test]
    fn a_probe_without_a_comparison_is_clean_when_every_port_was_tested() {
        assert!(report_of(Outcome::Closed).is_clean());
        let failed = Outcome::Failed {
            message: "too many open files".to_string(),
        };
        assert!(!report_of(failed).is_clean());
    }

    fn comparison_of(differences: Vec<Difference>) -> Comparison {
        Comparison {
            from: BTreeSet::from([Network::Lan]),
            guessed: true,
            differences,
            unknown_ports: BTreeSet::new(),
            skipped_ports: BTreeSet::new(),
        }
    }

    #[test]
    fn a_comparison_without_differences_is_clean() {
        let report = ProbeReport {
            comparison: Some(comparison_of(vec![])),
            ..report_of(Outcome::Open)
        };
        assert!(report.is_clean());
    }

    #[test]
    fn a_difference_is_not_clean() {
        for kind in [
            Disagreement::UnexpectedConnection,
            Disagreement::MissingConnection,
        ] {
            let difference = Difference {
                kind,
                port: 80,
                from: Network::Lan,
            };
            let report = ProbeReport {
                comparison: Some(comparison_of(vec![difference])),
                ..report_of(Outcome::Open)
            };
            assert!(!report.is_clean(), "{kind:?}");
        }
    }

    #[test]
    fn a_scan_without_tcp_ports_is_an_error_naming_the_file() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/probe_scan_udp.json");
        let error = probe_against_scan("127.0.0.1", &path, None, options()).unwrap_err();
        assert!(matches!(error, ProbeError::NoTcpPorts { .. }), "{error}");
        assert!(error.to_string().contains("probe_scan_udp.json"), "{error}");
    }

    #[test]
    fn probes_the_ports_of_a_scan_and_compares() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/diff_baseline.json");
        let report = probe_against_scan("127.0.0.1", &path, None, options()).unwrap();
        let comparison = report.comparison.unwrap();
        assert_eq!(comparison.from, BTreeSet::from([Network::ThisHost]));
        assert!(comparison.guessed);
    }

    #[test]
    fn probes_real_ports_of_an_address() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let open = listener.local_addr().unwrap().port();
        let closed = closed_port();
        let list = format!("{open},{closed}").parse().unwrap();

        let report = probe("127.0.0.1", &list, options()).unwrap();

        assert_eq!(report.host, "127.0.0.1");
        let found: Vec<_> = report
            .results
            .iter()
            .map(|probed| (probed.port, probed.result.clone()))
            .collect();
        let mut expected = vec![(open, Outcome::Open), (closed, Outcome::Closed)];
        expected.sort_by_key(|(port, _)| *port);
        assert_eq!(found, expected);
    }

    #[test]
    fn a_host_that_cannot_be_resolved_is_an_error_naming_it() {
        let list = "80".parse().unwrap();
        let error = probe("no-such-host.invalid", &list, options()).unwrap_err();
        assert!(
            error
                .to_string()
                .starts_with("could not resolve no-such-host.invalid"),
            "{error}"
        );
    }

    #[test]
    fn a_host_name_cannot_carry_terminal_escapes_into_the_error() {
        let list = "80".parse().unwrap();
        let error = probe("bad\u{1b}[2J.invalid", &list, options()).unwrap_err();
        assert!(!error.to_string().contains('\u{1b}'), "{error}");
    }
}
