//! reachmap shows which services on a host can be reached, from where, and why.
//!
//! Layout: [`collect`] reads from the running system, [`parse`] holds pure
//! parsers (text in, values out), [`scan`] joins the two into [`socket`] and
//! [`service`] values with the help of [`docker`], [`firewall`], [`tailscale`] and
//! [`socket_options`], [`warning`]
//! decides what deserves attention, and [`table`], [`json`] and [`errors`] format
//! results for the terminal and for scripts. [`sanitize`] cleans text from other programs before it can
//! reach the terminal. [`baseline`] reads saved scans and [`diff`] compares them.
//! Network checks, including SSH audits, only run when the user starts them.
//!
//! The library exists for reachmap's own binary and tests. It is not a
//! stable API and may change in any release.

#![warn(missing_docs)]

mod artifact;
pub mod baseline;
pub mod caddy;
pub mod collect;
pub mod diff;
pub mod docker;
pub mod egress;
pub mod errors;
pub mod firewall;
pub mod host_input_snapshot;
pub mod inbound_path;
pub mod json;
mod local_tcp;
pub mod network;
pub mod nftables;
pub mod nginx;
pub mod parse;
pub mod pf;
pub mod probe;
pub mod proxy_audit;
pub mod reach;
pub mod sanitize;
pub mod scan;
pub mod service;
pub mod snapshot_replay;
pub mod socket;
pub mod socket_options;
pub mod table;
pub mod tailscale;
pub mod warning;
