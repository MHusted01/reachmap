//! Whether macOS `pf` input rules pass or block traffic to a listening socket.
//!
//! Pure and cross-platform: [`Ruleset::parse`] reads the text `pfctl -sr`
//! prints, and [`Ruleset::evaluate`] answers for one inbound packet, as pf
//! does: the last matching rule wins unless a matching `quick` rule ends the
//! walk, and traffic that matches no rule passes. Nothing here runs `pfctl` or
//! knows whether pf is enabled.
//!
//! Whatever is not modeled makes the answer `unknown` and names the
//! construct and the rule: tables, anchors whose rules were not supplied,
//! `user`, `group`, `os`, translation (`rdr`, `nat`, `binat`), `route-to`,
//! `reply-to`, `tagged`, `received-on`, interface groups, dynamic addresses
//! such as `(en0)`, and lines that cannot be read. A rule that restricts the
//! source address or port makes the answer depend on the peer, so it is
//! unknown unless [`Traffic::source`] names one.

use std::collections::BTreeMap;
use std::net::IpAddr;

use serde::Serialize;

use crate::socket::Protocol;

mod eval;
mod fields;
mod lex;
mod matching;
mod model;
mod parse;

pub use model::Ruleset;

#[cfg(test)]
mod tests;

/// The rules of anchors, keyed by anchor path.
///
/// Nested relative anchors use slash-separated paths (such as `site/rules`),
/// leading `/` resolves from the root, and leading `../` segments move up one
/// level. For a
/// wildcard anchor such as `com.apple/*`, supply its direct children under
/// keys like `com.apple/250.ApplicationFirewall` and include the wildcard key
/// (`com.apple/*`) as a completeness marker; its own rules are not evaluated,
/// and omitting the wildcard key leaves the child list incomplete and yields
/// `unknown`.
pub type AnchorRulesets = BTreeMap<String, Ruleset>;

/// A new inbound TCP connection or UDP datagram to a local address.
#[derive(Debug, Clone, Copy)]
pub struct Traffic<'a> {
    /// The interface the packet arrives on, such as `en0`.
    pub interface: &'a str,
    /// Transport protocol of the listening socket.
    pub protocol: Protocol,
    /// The local address the packet is sent to. For a dual-stack socket
    /// receiving IPv4 traffic, pass the IPv4 address rather than an
    /// IPv4-mapped IPv6 address.
    pub destination: IpAddr,
    /// The local port the packet is sent to.
    pub port: u16,
    /// Where the packet comes from, when the question is about one peer.
    pub source: Option<IpAddr>,
}

/// What pf does with the traffic, and why.
#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum Verdict {
    /// pf lets the traffic in.
    Pass {
        /// The deciding rule, or the default.
        reason: String,
    },
    /// pf stops the traffic.
    Block {
        /// The deciding rule.
        reason: String,
    },
    /// The rules do not settle it.
    Unknown {
        /// The unmodeled construct and where it is.
        reason: String,
    },
}

impl Ruleset {
    /// Reads `pfctl -sr` output, with optional `set skip on` lines. Never
    /// fails: a line that cannot be read makes verdicts that reach it unknown.
    #[must_use]
    pub fn parse(text: &str) -> Self {
        parse::parse(text)
    }

    /// Evaluates the rules for `traffic`. An `anchor` line is replaced by the
    /// rules supplied under its name in `anchors`.
    #[must_use]
    pub fn evaluate(&self, anchors: &AnchorRulesets, traffic: &Traffic<'_>) -> Verdict {
        eval::evaluate(self, anchors, traffic)
    }
}
