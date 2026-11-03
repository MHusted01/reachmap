//! reachmap shows which services on a host can be reached, from where, and why.
//!
//! Layout: [`collect`] reads from the running system, [`parse`] holds pure
//! parsers (text in, values out), [`scan`] joins the two into [`socket`] and
//! [`service`] values, and [`table`] and [`errors`] format results for the
//! terminal.
//!
//! The library exists for reachmap's own binary and tests. It is not a
//! stable API and may change in any release.

#![warn(missing_docs)]

pub mod collect;
pub mod errors;
pub mod network;
pub mod parse;
pub mod reach;
pub mod scan;
pub mod service;
pub mod socket;
pub mod table;
