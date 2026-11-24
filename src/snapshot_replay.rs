//! Dispatch saved scan evidence to its offline evaluator.

use std::path::Path;

use serde::Deserialize;
use thiserror::Error;

use crate::caddy::routes::snapshot as caddy_snapshot;
use crate::host_input_snapshot::{self, SnapshotError};
use crate::nftables::NftablesReport;
use crate::nginx::routes::snapshot as nginx_snapshot;
use crate::tailscale::routes::snapshot as tailscale_snapshot;

/// The report for the scope recorded in a saved scan snapshot.
pub enum Report {
    /// Linux host-input firewall evidence.
    HostInput(NftablesReport),
    /// Configured Tailscale routes and local TCP listener evidence.
    TailscaleRoutes(tailscale_snapshot::Snapshot),
    /// Configured Nginx routes and local TCP listener evidence.
    NginxRoutes(nginx_snapshot::Snapshot),
    /// Configured Caddy routes and local TCP listener evidence.
    CaddyRoutes(caddy_snapshot::Snapshot),
}

/// Why a saved scan snapshot could not be replayed.
#[derive(Debug, Error)]
pub enum Error {
    /// The file could not be loaded, or the host-input evidence was invalid.
    #[error(transparent)]
    HostInput(#[from] SnapshotError),
    /// The Tailscale route evidence was invalid.
    #[error(transparent)]
    TailscaleRoutes(#[from] tailscale_snapshot::ReplayError),
    /// The Nginx route evidence was invalid.
    #[error(transparent)]
    NginxRoutes(#[from] nginx_snapshot::ReplayError),
    /// The Caddy route evidence was invalid.
    #[error(transparent)]
    CaddyRoutes(#[from] caddy_snapshot::ReplayError),
}

#[derive(Deserialize)]
struct Header {
    scope: String,
}

/// Read a bounded snapshot and choose its evaluator from the saved scope.
pub fn replay(path: &Path) -> Result<Report, Error> {
    let document = host_input_snapshot::read_document(path)?;
    match serde_json::from_str::<Header>(&document)
        .ok()
        .as_ref()
        .map(|header| header.scope.as_str())
    {
        Some(tailscale_snapshot::SCOPE) => Ok(Report::TailscaleRoutes(tailscale_snapshot::decode(
            &document,
        )?)),
        Some(nginx_snapshot::SCOPE) => Ok(Report::NginxRoutes(nginx_snapshot::decode(&document)?)),
        Some(caddy_snapshot::SCOPE) => Ok(Report::CaddyRoutes(caddy_snapshot::decode(&document)?)),
        _ => Ok(Report::HostInput(host_input_snapshot::replay_document(
            &document,
        )?)),
    }
}
