//! Detect hooks whose effects the local input evaluator cannot reproduce.

use std::collections::HashSet;

use serde_json::Value;

use crate::sanitize::sanitize;
use crate::socket::AddressFamily;

use super::{Entry, Ruleset, TableFlags};

impl Ruleset {
    pub(crate) fn pre_input_gap(&self, family: AddressFamily, interface: &str) -> Option<String> {
        self.early_hook_gap(family, interface, false)
    }

    pub(super) fn early_hook_gap(
        &self,
        family: AddressFamily,
        interface: &str,
        docker: bool,
    ) -> Option<String> {
        let family = match family {
            AddressFamily::Ipv4 => "ip",
            AddressFamily::Ipv6 => "ip6",
        };
        let dormant: HashSet<_> = self
            .nftables
            .iter()
            .filter_map(|entry| match entry {
                Entry::Table(table) if table.flags.as_ref().is_some_and(TableFlags::dormant) => {
                    Some((table.family.as_str(), table.name.as_str()))
                }
                _ => None,
            })
            .collect();
        self.nftables.iter().find_map(|entry| {
            let Entry::Chain(chain) = entry else {
                return None;
            };
            let hook = chain.hook.as_deref()?;
            let ip_family = chain.family == family || chain.family == "inet";
            let relevant = match hook {
                "egress" | "forward" | "prerouting" | "input" | "postrouting"
                    if docker && chain.family == "bridge" =>
                {
                    true
                }
                "prerouting" => ip_family && !docker,
                "egress" if docker && chain.family == "netdev" => true,
                "ingress" if docker && matches!(chain.family.as_str(), "bridge" | "netdev") => true,
                "ingress" if ip_family || chain.family == "netdev" => match &chain.dev {
                    Some(Value::String(device)) if !device.is_empty() && !device.contains('*') => {
                        device == interface
                    }
                    _ => true,
                },
                _ => false,
            };
            let table = (chain.family.as_str(), chain.table.as_str());
            (relevant && !dormant.contains(&table)).then(|| {
                sanitize(&format!(
                    "unsupported nftables {hook} hook in {} {} {}",
                    chain.family, chain.table, chain.name
                ))
            })
        })
    }
}
