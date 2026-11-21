//! Dispatch saved scan evidence to its offline evaluator.

use std::path::Path;

use serde::Deserialize;
use thiserror::Error;

use crate::host_input_snapshot::{self, SnapshotError};
use crate::nftables::NftablesReport;
use crate::tailscale::routes::snapshot;

/// The report for the scope recorded in a saved scan snapshot.
pub enum Report {
    /// Linux host-input firewall evidence.
    HostInput(NftablesReport),
    /// Configured Tailscale routes and local TCP listener evidence.
    TailscaleRoutes(snapshot::Snapshot),
}

/// Why a saved scan snapshot could not be replayed.
#[derive(Debug, Error)]
pub enum Error {
    /// The file could not be loaded, or the host-input evidence was invalid.
    #[error(transparent)]
    HostInput(#[from] SnapshotError),
    /// The Tailscale route evidence was invalid.
    #[error(transparent)]
    TailscaleRoutes(#[from] snapshot::ReplayError),
}

#[derive(Deserialize)]
struct Header {
    scope: String,
}

/// Read a bounded snapshot and choose its evaluator from the saved scope.
pub fn replay(path: &Path) -> Result<Report, Error> {
    let document = host_input_snapshot::read_document(path)?;
    if serde_json::from_str::<Header>(&document).is_ok_and(|header| header.scope == snapshot::SCOPE)
    {
        Ok(Report::TailscaleRoutes(snapshot::decode(&document)?))
    } else {
        Ok(Report::HostInput(host_input_snapshot::replay_document(
            &document,
        )?))
    }
}
