//! Shared local TCP listener matching and diagnostic helpers for host-side proxies.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{self, ErrorKind};
use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use crate::collect::{self, CollectError};
use crate::parse::sock_diag::SockDiagError;
use crate::scan::{ScanError, parse_tables};
use crate::socket::{ListeningSocket, Protocol};
use crate::socket_options::{OptionsReport, SocketOptionsError, read_socket_options};

/// Whether local TCP socket evidence was needed and collected.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub(crate) enum TcpEvidence {
    NotNeeded,
    Unavailable,
    Collected { listeners: Vec<Listener> },
}

/// One local TCP listening socket and its relevant kernel socket options.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub(crate) struct Listener {
    pub(crate) address: SocketAddr,
    pub(crate) options: Option<ListenerOptions>,
}

/// Kernel socket options that determine whether a listener can accept a target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub(crate) struct ListenerOptions {
    pub(crate) bound_to_device: bool,
    pub(crate) ipv6_only: bool,
}

/// Target addresses grouped by TCP port for fast listener filtering.
pub(crate) type TargetsByPort = BTreeMap<u16, BTreeSet<SocketAddr>>;

impl Listener {
    pub(crate) fn could_match(&self, by_port: &TargetsByPort) -> bool {
        by_port.get(&self.address.port()).is_some_and(|targets| {
            targets
                .iter()
                .any(|&target| candidate(self, target).is_some())
        })
    }
}

/// Local Linux socket tables paired with `sock_diag` socket options.
#[derive(Debug)]
pub(crate) struct Inventory {
    pub(crate) sockets: Vec<ListeningSocket>,
    pub(crate) options: OptionsReport,
}

impl Inventory {
    pub(crate) fn relevant_listeners(self, predicate: impl Fn(&Listener) -> bool) -> Vec<Listener> {
        self.sockets
            .into_iter()
            .filter(|socket| socket.protocol == Protocol::Tcp)
            .filter_map(|socket| {
                let listener = Listener {
                    address: SocketAddr::new(socket.address, socket.port),
                    options: self.options.by_inode.get(&socket.inode).map(|options| {
                        ListenerOptions {
                            bound_to_device: options.bound_device.is_some(),
                            ipv6_only: options.ipv6_only,
                        }
                    }),
                };
                predicate(&listener).then_some(listener)
            })
            .collect()
    }
}

/// Read the Linux TCP/UDP socket tables and `sock_diag` socket options.
pub(crate) fn read_inventory() -> Result<Inventory, ScanError> {
    let sockets = parse_tables(&collect::read_socket_tables()?)?;
    Ok(Inventory {
        sockets,
        options: read_socket_options(),
    })
}

/// Group socket addresses by port.
pub(crate) fn index_targets(targets: impl Iterator<Item = SocketAddr>) -> TargetsByPort {
    let mut by_port = TargetsByPort::new();
    for target in targets {
        by_port.entry(target.port()).or_default().insert(target);
    }
    by_port
}

/// Outcome of correlating a target against collected local TCP listeners.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TargetMatch {
    Matched(SocketAddr),
    Ambiguous,
    UncertainOptions,
    Missing,
}

/// Evaluate `match_fn` across `listeners` and summarize whether a single
/// listener matched conclusively, with uncertain options, ambiguously, or not at all.
pub(crate) fn match_listeners<'a>(
    listeners: &'a [Listener],
    mut match_fn: impl FnMut(&'a Listener) -> Option<bool>,
) -> TargetMatch {
    let mut matches = listeners
        .iter()
        .filter_map(|listener| match_fn(listener).map(|confirmed| (listener, confirmed)));
    match (matches.next(), matches.next()) {
        (_, Some(_)) => TargetMatch::Ambiguous,
        (Some((listener, true)), None) => TargetMatch::Matched(listener.address),
        (Some((_, false)), None) => TargetMatch::UncertainOptions,
        (None, None) => TargetMatch::Missing,
    }
}

/// Returns whether a listener can accept `target` (matching exact address or
/// wildcard listeners, including dual-stack `[::]`). Unknown socket options
/// leave device binding and IPv6 wildcard behavior uncertain (`Some(false)`).
pub(crate) fn candidate(listener: &Listener, target: SocketAddr) -> Option<bool> {
    if listener.address.port() != target.port() {
        return None;
    }
    let bound = listener.address.ip().to_canonical();
    let target = target.ip().to_canonical();
    let options = listener.options.as_ref();
    let unbound = options.is_some_and(|options| !options.bound_to_device);
    if bound == target || (bound.is_unspecified() && bound.is_ipv4() == target.is_ipv4()) {
        return Some(unbound);
    }
    if bound.is_unspecified() && bound.is_ipv6() && target.is_ipv4() {
        return match options {
            Some(options) if options.ipv6_only => None,
            _ => Some(unbound),
        };
    }
    None
}

/// Returns whether a listener is bound to the exact canonical IP and port of `target`,
/// without treating wildcard `0.0.0.0` or `[::]` sockets as matches.
pub(crate) fn exact_candidate(listener: &Listener, target: SocketAddr) -> Option<bool> {
    if listener.address.port() != target.port() {
        return None;
    }
    let bound = listener.address.ip().to_canonical();
    let target = target.ip().to_canonical();
    if bound == target {
        let unbound = listener
            .options
            .as_ref()
            .is_some_and(|options| !options.bound_to_device);
        Some(unbound)
    } else {
        None
    }
}

/// Secret-safe classification of Linux socket-inventory or socket-option failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SocketFailure {
    PermissionDenied,
    Unsupported,
    MissingLinuxData,
    InvalidKernelData,
    ReadFailed,
}

impl From<&ScanError> for SocketFailure {
    fn from(error: &ScanError) -> Self {
        match error {
            ScanError::Collect(source) => source.into(),
            ScanError::UnsupportedOs { .. } => Self::Unsupported,
            ScanError::Parse { .. } | ScanError::SocketInventory { .. } => Self::InvalidKernelData,
        }
    }
}

impl From<&SocketOptionsError> for SocketFailure {
    fn from(error: &SocketOptionsError) -> Self {
        match error {
            SocketOptionsError::Open(source) | SocketOptionsError::Collect { source, .. } => {
                source.into()
            }
            SocketOptionsError::Reply {
                source: SockDiagError::Refused(source),
                ..
            } => source.into(),
            SocketOptionsError::Reply {
                source: SockDiagError::Malformed,
                ..
            } => Self::InvalidKernelData,
        }
    }
}

impl From<&CollectError> for SocketFailure {
    fn from(error: &CollectError) -> Self {
        match error {
            CollectError::Read { source, .. } | CollectError::SockDiag { source, .. } => {
                source.into()
            }
            CollectError::UnsupportedOs { .. } => Self::Unsupported,
            _ => Self::ReadFailed,
        }
    }
}

impl From<&io::Error> for SocketFailure {
    fn from(error: &io::Error) -> Self {
        match error.kind() {
            ErrorKind::PermissionDenied => Self::PermissionDenied,
            ErrorKind::NotFound => Self::MissingLinuxData,
            ErrorKind::Unsupported => Self::Unsupported,
            ErrorKind::InvalidData => Self::InvalidKernelData,
            _ => Self::ReadFailed,
        }
    }
}

impl fmt::Display for SocketFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::PermissionDenied => "permission denied; check access to the Linux socket data",
            Self::Unsupported => "the required Linux collector is unavailable",
            Self::MissingLinuxData => {
                "required Linux socket data is missing; check the procfs mount and kernel support"
            }
            Self::InvalidKernelData => "unrecognized Linux socket data; report the kernel version",
            Self::ReadFailed => "Linux socket data could not be read; retry the scan on the host",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn listener(address: SocketAddr, options: Option<ListenerOptions>) -> Listener {
        Listener { address, options }
    }

    fn clean_opts(ipv6_only: bool) -> Option<ListenerOptions> {
        Some(ListenerOptions {
            bound_to_device: false,
            ipv6_only,
        })
    }

    #[test]
    fn exact_candidate_does_not_match_wildcard_sockets() {
        let target = SocketAddr::new("192.0.2.10".parse().unwrap(), 8080);
        let wildcard4 = listener(
            SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 8080),
            clean_opts(false),
        );
        let wildcard6 = listener(
            SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 8080),
            clean_opts(false),
        );
        let exact = listener(target, clean_opts(false));

        assert_eq!(exact_candidate(&wildcard4, target), None);
        assert_eq!(exact_candidate(&wildcard6, target), None);
        assert_eq!(exact_candidate(&exact, target), Some(true));
    }

    #[test]
    fn match_listeners_classifies_single_uncertain_ambiguous_and_missing() {
        let target = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 8080);
        let exact = listener(target, clean_opts(false));
        let wildcard = listener(
            SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 8080),
            clean_opts(false),
        );
        let uncertain = listener(target, None);

        assert_eq!(
            match_listeners(std::slice::from_ref(&exact), |l| candidate(l, target)),
            TargetMatch::Matched(target)
        );
        assert_eq!(
            match_listeners(&[uncertain], |l| candidate(l, target)),
            TargetMatch::UncertainOptions
        );
        assert_eq!(
            match_listeners(&[exact, wildcard], |l| candidate(l, target)),
            TargetMatch::Ambiguous
        );
        assert_eq!(
            match_listeners(&[], |l| candidate(l, target)),
            TargetMatch::Missing
        );
    }
}
