//! Local TCP listener evidence for the matched Caddy listen address and the
//! `reverse_proxy` upstreams, kept apart from HTTP gateway errors.

use std::net::SocketAddr;

use serde::Serialize;

use crate::caddy::{DialTarget, ListenAddress, ReverseProxy};
use crate::local_tcp::{TargetMatch, TcpEvidence};
use crate::proxy_audit::{BackendState, ListenerEvidence};

use super::super::link::{frontend_match, linked_ports, upstream_addrs, upstream_match};

/// Reason local TCP upstream correlation remained uncertain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendUncertainty {
    /// Multiple local TCP listeners could accept an upstream.
    Ambiguous,
    /// Socket options (`SO_BINDTODEVICE` or `IPV6_V6ONLY`) were unavailable.
    UncertainOptions,
    /// Local TCP socket inventory was unavailable during capture.
    InventoryUnavailable,
    /// Some upstreams have a local listener and others do not, or are remote.
    MixedUpstreamAvailability,
    /// An upstream address is unspecified (`0.0.0.0`, `::`).
    UnsupportedScope,
}

/// Local TCP listener evidence for the `reverse_proxy` the request reaches.
///
/// Kept strictly independent from observed HTTP `502`/`503`/`504` status codes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum BackendEvidence {
    /// The route ends at a responder or at no handler, without proxying.
    NoProxyTarget {},
    /// Local TCP listeners accept every upstream.
    LocalTcpPresent {
        /// Matching local TCP listener socket address(es).
        addresses: Vec<SocketAddr>,
    },
    /// No local TCP listener accepts the loopback upstream(s).
    LocalTcpAbsent {},
    /// Local TCP upstream presence could not be established cleanly.
    LocalTcpUncertain {
        /// Why local upstream correlation was inconclusive.
        reason: BackendUncertainty,
    },
    /// Upstreams use non-loopback IPs with no exact local TCP listener (may be remote).
    NonLocalOrRemote {},
    /// An upstream uses a host name that needs DNS resolution.
    UnresolvedHostname {},
    /// The proxy's transport, upstreams or `dynamic_upstreams` were not fully
    /// understood, so requests may go elsewhere.
    IncompleteProxy {},
}

impl BackendEvidence {
    /// The backend layer reduced to what the shared decision table needs.
    pub(super) fn state(&self) -> BackendState {
        match self {
            Self::NoProxyTarget {} => BackendState::NoTarget,
            Self::LocalTcpPresent { .. } => BackendState::Present,
            Self::LocalTcpAbsent {} => BackendState::Absent,
            Self::LocalTcpUncertain { .. }
            | Self::NonLocalOrRemote {}
            | Self::UnresolvedHostname {}
            | Self::IncompleteProxy {} => BackendState::Unverified,
        }
    }
}

pub(super) fn evaluate_frontend(
    listen: &ListenAddress,
    port: u16,
    inventory: &TcpEvidence,
) -> ListenerEvidence {
    let TcpEvidence::Collected { listeners } = inventory else {
        return ListenerEvidence::InventoryUnavailable {};
    };
    if linked_ports(listen.ports()).is_none() {
        return ListenerEvidence::InventoryUnavailable {};
    }
    match frontend_match(listeners, listen, port) {
        TargetMatch::Matched(address) => ListenerEvidence::Matched { address },
        TargetMatch::Missing => ListenerEvidence::Missing {},
        TargetMatch::Ambiguous => ListenerEvidence::Ambiguous {},
        TargetMatch::UncertainOptions => ListenerEvidence::UncertainOptions {},
    }
}

pub(super) fn evaluate_backend(
    proxy: Option<&ReverseProxy>,
    inventory: &TcpEvidence,
) -> BackendEvidence {
    let Some(proxy) = proxy else {
        return BackendEvidence::NoProxyTarget {};
    };
    if proxy
        .upstreams
        .iter()
        .any(|target| matches!(target, DialTarget::Hostname { .. }))
    {
        return BackendEvidence::UnresolvedHostname {};
    }
    if !proxy.complete || proxy.upstreams.is_empty() {
        return BackendEvidence::IncompleteProxy {};
    }
    let TcpEvidence::Collected { listeners } = inventory else {
        return uncertain(BackendUncertainty::InventoryUnavailable);
    };

    let mut present = Vec::new();
    let (mut absent, mut remote) = (false, false);
    for target in &proxy.upstreams {
        if upstream_addrs(target).is_empty() {
            return uncertain(BackendUncertainty::UnsupportedScope);
        }
        match upstream_match(listeners, target) {
            TargetMatch::Matched(address) => {
                if !present.contains(&address) {
                    present.push(address);
                }
            }
            TargetMatch::Ambiguous => return uncertain(BackendUncertainty::Ambiguous),
            TargetMatch::UncertainOptions => {
                return uncertain(BackendUncertainty::UncertainOptions);
            }
            TargetMatch::Missing if stays_on_host(target) => absent = true,
            TargetMatch::Missing => remote = true,
        }
    }
    match (!present.is_empty(), absent, remote) {
        (true, false, false) => BackendEvidence::LocalTcpPresent { addresses: present },
        (false, true, false) => BackendEvidence::LocalTcpAbsent {},
        (false, false, true) => BackendEvidence::NonLocalOrRemote {},
        _ => uncertain(BackendUncertainty::MixedUpstreamAvailability),
    }
}

fn uncertain(reason: BackendUncertainty) -> BackendEvidence {
    BackendEvidence::LocalTcpUncertain { reason }
}

/// Whether a dial of `target` stays on this host, counting IPv4-mapped
/// loopback addresses.
fn stays_on_host(target: &DialTarget) -> bool {
    match target {
        DialTarget::Socket { address } => address.ip().to_canonical().is_loopback(),
        DialTarget::Localhost { .. } => true,
        DialTarget::Hostname { .. } => false,
    }
}
