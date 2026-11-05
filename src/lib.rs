//! reachmap shows which services on a host can be reached, from where, and why.
//!
//! Layout: [`collect`] reads from the running system, [`parse`] holds pure
//! parsers (text in, values out), [`scan`] joins the two into [`socket`] and
//! [`service`] values with the help of [`docker`], [`firewall`] and
//! [`socket_options`], [`warning`]
//! decides what deserves attention, and [`table`], [`json`] and [`errors`] format
//! results for the terminal and for scripts. [`sanitize`] cleans text from other programs before it can
//! reach the terminal. [`probe`] is the only part that sends traffic: it
//! connects to ports of a host the user names.
//!
//! The library exists for reachmap's own binary and tests. It is not a
//! stable API and may change in any release.

#![warn(missing_docs)]

pub mod collect;
pub mod docker;
pub mod errors;
pub mod firewall;
pub mod json;
pub mod network;
pub mod parse;
pub mod probe;
pub mod reach;
pub mod sanitize;
pub mod scan;
pub mod service;
pub mod socket;
pub mod socket_options;
pub mod table;
pub mod warning;
