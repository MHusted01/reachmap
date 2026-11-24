//! Proxy-neutral pieces of the scoped reverse proxy correlation shared by the
//! Nginx and Caddy audits.
//!
//! A reverse proxy audit compares five independent evidence layers: the
//! configured route, frontend TCP connectivity, one client HTTP observation,
//! local backend listener presence, and proxy-layer authentication. The types
//! here hold what every proxy shares (scopes, observations, layer states and
//! the comparison result); each proxy keeps its own route resolution, route
//! evidence and gap explanations.
//!
//! Nothing here performs network or filesystem I/O.

mod layers;
mod types;

#[cfg(test)]
mod tests;

pub(crate) use self::layers::{
    BackendState, CommonGap, ProxyAuth, check_provenance, correlate_layers, tcp_layer,
};
pub use self::types::{
    ApplicationAuthStatus, Comparison, HttpObservation, HttpOutcome, InboundTcpVerdict,
    ListenerEvidence, ProxyAuthIndicator, Scope, TcpLayerEvidence, TcpLayerState, TcpObservation,
    TlsStatus,
};
