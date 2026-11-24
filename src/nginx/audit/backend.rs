//! Local TCP listener evidence evaluation for Nginx frontend and backend endpoints.

use std::net::SocketAddr;

use serde::Serialize;

use crate::local_tcp::{TargetMatch, TcpEvidence, match_listeners};
use crate::nginx::routes::{backend_candidate, listen_candidate};
use crate::nginx::{ListenEndpoint, NginxConfig, ProxyTarget, UnsupportedProxyReason};
use crate::proxy_audit::{BackendState, ListenerEvidence};

/// Reason local TCP backend listener correlation remained uncertain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendUncertainty {
    /// Multiple local TCP listeners could accept a backend target.
    Ambiguous,
    /// Socket options (`SO_BINDTODEVICE` or `IPV6_V6ONLY`) were unavailable.
    UncertainOptions,
    /// Local TCP socket inventory was unavailable during capture.
    InventoryUnavailable,
    /// The referenced `upstream` group contains unresolved or dynamic servers.
    IncompleteUpstreamGroup,
    /// An `upstream` group has a mix of present and absent/non-local server listeners.
    MixedUpstreamAvailability,
    /// The referenced `upstream` group has no active (`!down`) servers.
    NoActiveUpstreamServers,
    /// Target address is unspecified or outside the supported local TCP scope.
    UnsupportedScope,
}

/// Local TCP listener evidence for the matched location's `proxy_pass` backend.
///
/// Kept strictly independent from observed HTTP `502`/`503`/`504` status codes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum BackendEvidence {
    /// The matched location (or missing location) has no `proxy_pass` target.
    NoProxyTarget {},
    /// Local TCP listener evidence matched the configured backend target(s).
    LocalTcpPresent {
        /// Matching local TCP listener socket address(es).
        addresses: Vec<SocketAddr>,
    },
    /// No local TCP listener matched the configured loopback backend target(s).
    LocalTcpAbsent {},
    /// Local TCP backend presence could not be established cleanly.
    LocalTcpUncertain {
        /// Why local backend correlation was inconclusive.
        reason: BackendUncertainty,
    },
    /// Backend uses non-loopback IP(s) with no exact local TCP listener (may be remote).
    NonLocalOrRemote {},
    /// Backend uses a hostname requiring DNS resolution.
    UnresolvedHostname {},
    /// Backend uses an unsupported transport, variable, or invalid `proxy_pass` target.
    UnsupportedTarget {
        /// Why the `proxy_pass` target could not be statically resolved.
        reason: UnsupportedProxyReason,
    },
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
            | Self::UnsupportedTarget { .. } => BackendState::Unverified,
        }
    }
}

pub(super) fn evaluate_frontend_listener(
    listen: &ListenEndpoint,
    inventory: &TcpEvidence,
) -> ListenerEvidence {
    let TcpEvidence::Collected { listeners } = inventory else {
        return ListenerEvidence::InventoryUnavailable {};
    };
    match match_listeners(listeners, |listener| listen_candidate(listener, listen)) {
        TargetMatch::Matched(address) => ListenerEvidence::Matched { address },
        TargetMatch::Missing => ListenerEvidence::Missing {},
        TargetMatch::Ambiguous => ListenerEvidence::Ambiguous {},
        TargetMatch::UncertainOptions => ListenerEvidence::UncertainOptions {},
    }
}

pub(super) fn evaluate_backend(
    target: Option<&ProxyTarget>,
    config: &NginxConfig,
    inventory: &TcpEvidence,
) -> BackendEvidence {
    let Some(target) = target else {
        return BackendEvidence::NoProxyTarget {};
    };
    match target {
        ProxyTarget::StaticHttp { targets, .. } => evaluate_target_group(targets, inventory),
        ProxyTarget::Upstream {
            name,
            targets,
            complete,
            ..
        } => evaluate_upstream(name, targets, *complete, config, inventory),
        ProxyTarget::UnresolvedHost { .. } => BackendEvidence::UnresolvedHostname {},
        ProxyTarget::Unsupported { reason } => {
            BackendEvidence::UnsupportedTarget { reason: *reason }
        }
    }
}

fn evaluate_upstream(
    name: &str,
    fallback_targets: &[SocketAddr],
    target_complete: bool,
    config: &NginxConfig,
    inventory: &TcpEvidence,
) -> BackendEvidence {
    let group = config.upstreams.iter().find(|group| group.name == name);
    let complete = target_complete && group.is_none_or(|g| g.complete);
    if !complete {
        return BackendEvidence::LocalTcpUncertain {
            reason: BackendUncertainty::IncompleteUpstreamGroup,
        };
    }

    let server_slices: Vec<&[SocketAddr]> = if let Some(group) = group {
        group
            .servers
            .iter()
            .filter(|server| !server.down)
            .map(|server| server.targets.as_slice())
            .collect()
    } else if fallback_targets.is_empty() {
        Vec::new()
    } else {
        fallback_targets.chunks(1).collect()
    };

    if server_slices.is_empty() {
        return BackendEvidence::LocalTcpUncertain {
            reason: BackendUncertainty::NoActiveUpstreamServers,
        };
    }

    let mut present_addrs = Vec::new();
    let mut absent_count = 0usize;
    let mut remote_count = 0usize;

    for slice in server_slices {
        match evaluate_target_group(slice, inventory) {
            BackendEvidence::LocalTcpPresent { addresses } => {
                for addr in addresses {
                    if !present_addrs.contains(&addr) {
                        present_addrs.push(addr);
                    }
                }
            }
            BackendEvidence::LocalTcpAbsent {} => absent_count += 1,
            BackendEvidence::NonLocalOrRemote {} => remote_count += 1,
            uncertain @ BackendEvidence::LocalTcpUncertain { .. } => return uncertain,
            BackendEvidence::NoProxyTarget {}
            | BackendEvidence::UnresolvedHostname {}
            | BackendEvidence::UnsupportedTarget { .. } => {}
        }
    }

    match (
        !present_addrs.is_empty(),
        absent_count > 0,
        remote_count > 0,
    ) {
        (true, false, false) => BackendEvidence::LocalTcpPresent {
            addresses: present_addrs,
        },
        (false, true, false) => BackendEvidence::LocalTcpAbsent {},
        (false, false, true) => BackendEvidence::NonLocalOrRemote {},
        _ => BackendEvidence::LocalTcpUncertain {
            reason: BackendUncertainty::MixedUpstreamAvailability,
        },
    }
}

fn evaluate_target_group(targets: &[SocketAddr], inventory: &TcpEvidence) -> BackendEvidence {
    let valid: Vec<SocketAddr> = targets
        .iter()
        .copied()
        .filter(|target| !target.ip().to_canonical().is_unspecified())
        .collect();
    if valid.is_empty() {
        return BackendEvidence::LocalTcpUncertain {
            reason: BackendUncertainty::UnsupportedScope,
        };
    }
    let TcpEvidence::Collected { listeners } = inventory else {
        return BackendEvidence::LocalTcpUncertain {
            reason: BackendUncertainty::InventoryUnavailable,
        };
    };

    let mut matched_addrs = Vec::new();
    let mut uncertain = None;
    for &target in &valid {
        match match_listeners(listeners, |listener| backend_candidate(listener, target)) {
            TargetMatch::Matched(addr) => {
                if !matched_addrs.contains(&addr) {
                    matched_addrs.push(addr);
                }
            }
            TargetMatch::Ambiguous => {
                return BackendEvidence::LocalTcpUncertain {
                    reason: BackendUncertainty::Ambiguous,
                };
            }
            TargetMatch::UncertainOptions => {
                uncertain = Some(BackendUncertainty::UncertainOptions);
            }
            TargetMatch::Missing => {}
        }
    }

    if let Some(reason) = uncertain {
        return BackendEvidence::LocalTcpUncertain { reason };
    }
    if !matched_addrs.is_empty() {
        return BackendEvidence::LocalTcpPresent {
            addresses: matched_addrs,
        };
    }
    if valid
        .iter()
        .all(|target| target.ip().to_canonical().is_loopback())
    {
        BackendEvidence::LocalTcpAbsent {}
    } else {
        BackendEvidence::NonLocalOrRemote {}
    }
}
