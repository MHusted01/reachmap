//! Extra nftables evidence used for the scoped IPv4 Docker forwarding path.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4};

use serde::Deserialize;
use serde::de::IgnoredAny;

use crate::socket::{AddressFamily, Protocol};

use super::matches::{Packet, PathPacket as MatchPath};
use super::{Chain, ChainTarget, Entry, Ruleset, TableFlags};

const DOCKER_TABLE: &str = "docker-bridges";

pub(crate) struct PathPacket<'a> {
    pub(crate) source: Ipv4Addr,
    pub(crate) destination: SocketAddrV4,
    pub(crate) ingress: &'a str,
    pub(crate) egress: Option<&'a str>,
    pub(crate) local_source: Option<bool>,
}

pub(crate) enum PathHookResult {
    Accept {
        reason: String,
    },
    Drop {
        reason: String,
    },
    Unknown {
        reason: String,
    },
    Dnat {
        endpoint: SocketAddrV4,
        reason: String,
    },
}

impl Ruleset {
    pub(crate) fn docker_prerouting(&self) -> bool {
        self.active_ip_hook("prerouting").any(|chain| {
            chain.family == "ip" && chain.table == DOCKER_TABLE && chain.name == "nat-PREROUTING"
        })
    }

    pub(crate) fn docker_ingress_gap(&self, ingress: &str) -> Option<String> {
        self.early_hook_gap(AddressFamily::Ipv4, ingress, true)
    }

    pub(crate) fn docker_hook(&self, hook: &str, flow: &PathPacket<'_>) -> PathHookResult {
        let supported = match hook {
            "prerouting" => self.active_ip_hook(hook).all(|chain| {
                chain.family == "ip"
                    && chain.table == DOCKER_TABLE
                    && matches!(
                        (chain.name.as_str(), chain.kind.as_deref(), chain.prio),
                        ("raw-PREROUTING", Some("filter"), Some(-300))
                            | ("nat-PREROUTING", Some("nat"), Some(-100))
                    )
            }),
            "forward" => self.active_ip_hook(hook).any(|chain| {
                chain.family == "ip"
                    && chain.table == DOCKER_TABLE
                    && chain.name == "filter-FORWARD"
            }),
            "postrouting" => self.active_ip_hook(hook).all(|chain| {
                chain.family == "ip"
                    && chain.table == DOCKER_TABLE
                    && chain.name == "nat-POSTROUTING"
                    && chain.kind.as_deref() == Some("nat")
                    && chain.prio == Some(100)
            }),
            _ => false,
        };
        if !supported {
            return PathHookResult::Unknown {
                reason: format!("missing or unsupported nftables {hook} chains for Docker bridge"),
            };
        }
        let packet = Packet {
            protocol: Protocol::Tcp,
            port: flow.destination.port(),
            ingress: flow.ingress,
            path: Some(MatchPath {
                source: flow.source,
                destination: *flow.destination.ip(),
                egress: flow.egress,
                local_destination: hook == "prerouting",
                local_source: flow.local_source,
                new_connection: hook != "prerouting",
                allow_dnat: hook == "prerouting",
            }),
        };
        self.hook(AddressFamily::Ipv4, hook).map_or_else(
            || PathHookResult::Accept {
                reason: format!("no applicable nftables {hook} chains"),
            },
            |base| base.evaluate_packet(packet),
        )
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn has_container_ipv4_hooks(&self, ingress: &str) -> bool {
        self.early_hook_gap(AddressFamily::Ipv4, ingress, false)
            .is_some()
            || self.active_ip_hook("input").next().is_some()
    }

    fn active_ip_hook<'a>(&'a self, hook: &'a str) -> impl Iterator<Item = &'a Chain> {
        self.nftables.iter().filter_map(move |entry| match entry {
            Entry::Chain(chain)
                if chain.hook.as_deref() == Some(hook)
                    && matches!(chain.family.as_str(), "ip" | "inet")
                    && !self.nftables.iter().any(|entry| {
                        matches!(entry, Entry::Table(table)
                    if table.family == chain.family && table.name == chain.table
                        && table.flags.as_ref().is_some_and(TableFlags::dormant))
                    }) =>
            {
                Some(chain)
            }
            _ => None,
        })
    }
}

pub(super) type MapIndex<'a> = HashMap<(&'a str, &'a str, &'a str), &'a InterfaceMap>;

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub(super) enum VerdictMapEntry {
    Supported(InterfaceMap),
    Other(IgnoredAny),
}

#[derive(Debug, Deserialize)]
pub(super) struct InterfaceMap {
    family: String,
    table: String,
    name: String,
    #[serde(rename = "type")]
    kind: String,
    map: String,
    #[serde(default)]
    flags: Vec<String>,
    elem: Vec<(String, MapVerdict)>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum MapVerdict {
    Jump(ChainTarget),
}

impl InterfaceMap {
    pub(super) fn key(&self) -> (&str, &str, &str) {
        (&self.family, &self.table, &self.name)
    }

    pub(super) fn target(&self, interface: &str) -> Result<Option<&str>, &'static str> {
        if self.kind != "ifname"
            || self.map != "verdict"
            || !self.flags.is_empty()
            || self
                .elem
                .iter()
                .any(|(key, _)| key.is_empty() || key.contains(['*', '\\', '\0']))
        {
            return Err("unsupported interface verdict map");
        }
        let mut targets = self
            .elem
            .iter()
            .filter_map(|(key, MapVerdict::Jump(target))| {
                (key == interface).then_some(target.target.as_str())
            });
        let target = targets.next();
        if targets.next().is_some() {
            return Err("ambiguous interface verdict map target");
        }
        Ok(target)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct VerdictMap {
    key: MapKey,
    data: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum MapKey {
    Meta { key: String },
}

impl VerdictMap {
    pub(super) fn lookup<'a>(
        &self,
        packet: Packet<'_>,
        map: impl Fn(&str, &str) -> Result<Option<&'a str>, &'static str>,
    ) -> Result<Option<&'a str>, &'static str> {
        let MapKey::Meta { key } = &self.key;
        let interface = match key.as_str() {
            "iifname" => Some(packet.ingress),
            "oifname" => packet.path.and_then(|path| path.egress),
            _ => None,
        }
        .ok_or("unsupported interface verdict map key")?;
        let name = self
            .data
            .strip_prefix('@')
            .ok_or("unsupported verdict map reference")?;
        map(name, interface)
    }
}
