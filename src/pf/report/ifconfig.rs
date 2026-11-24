//! Parsing `/sbin/ifconfig -a` output into interface-to-IP address mappings.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::sanitize::sanitize;

/// Interface-to-IP address map parsed from `/sbin/ifconfig -a`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MacosInterfaces {
    pub(super) addresses: BTreeMap<String, BTreeSet<IpAddr>>,
}

/// Parses `ifconfig -a` output into interface addresses.
#[must_use]
pub fn parse_ifconfig(text: &str) -> MacosInterfaces {
    let mut addresses: BTreeMap<String, BTreeSet<IpAddr>> = BTreeMap::new();
    let mut current: Option<String> = None;
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        if !line.starts_with(|ch: char| ch.is_ascii_whitespace()) {
            current = line
                .split_once(':')
                .map(|(name, _)| sanitize(name.trim()))
                .filter(|name| !name.is_empty());
            if let Some(name) = &current {
                addresses.entry(name.clone()).or_default();
            }
            continue;
        }
        let Some(iface) = current.as_ref() else {
            continue;
        };
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("inet ") {
            if let Some(token) = rest.split_whitespace().next()
                && let Ok(ip) = token.parse::<Ipv4Addr>()
                && let Some(set) = addresses.get_mut(iface)
            {
                set.insert(IpAddr::V4(ip));
            }
        } else if let Some(rest) = trimmed.strip_prefix("inet6 ")
            && let Some(token) = rest.split_whitespace().next()
        {
            let ip_part = token.split('%').next().unwrap_or(token);
            if let Ok(ip) = ip_part.parse::<Ipv6Addr>()
                && let Some(set) = addresses.get_mut(iface)
            {
                set.insert(IpAddr::V6(ip));
            }
        }
    }
    MacosInterfaces { addresses }
}
