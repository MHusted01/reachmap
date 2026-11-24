//! Socket-to-interface expansion and pf evaluation helpers for [`super::PfReport`].

use std::collections::BTreeSet;
use std::net::IpAddr;

use crate::sanitize::sanitize;
use crate::socket::{AddressFamily, Protocol};

use super::super::{AnchorRulesets, Ruleset, Traffic, Verdict};
use super::{MacosInterfaces, PfInterfaceVerdict, SocketTarget};

pub(super) struct EvalContext<'a> {
    pub(super) rules: &'a Ruleset,
    pub(super) anchors: &'a AnchorRulesets,
    pub(super) listed_interfaces: &'a BTreeSet<String>,
    pub(super) skipped_groups: &'a BTreeSet<String>,
    pub(super) interfaces: Result<&'a MacosInterfaces, &'a str>,
}

impl EvalContext<'_> {
    pub(super) fn evaluate_socket(
        &self,
        socket: &SocketTarget,
    ) -> Vec<(AddressFamily, Vec<PfInterfaceVerdict>)> {
        let endpoint = socket.endpoint;
        let canonical = endpoint.address.to_canonical();
        if canonical.is_multicast() {
            return vec![(
                family_of(canonical),
                vec![PfInterfaceVerdict {
                    interface: None,
                    outcome: Verdict::Unknown {
                        reason: "multicast destination is not evaluated by pf".to_owned(),
                    },
                }],
            )];
        }
        if canonical.is_unspecified() {
            return match canonical {
                IpAddr::V4(_) => vec![(
                    AddressFamily::Ipv4,
                    self.evaluate_wildcard(AddressFamily::Ipv4, endpoint.protocol, endpoint.port),
                )],
                IpAddr::V6(_) => vec![
                    (
                        AddressFamily::Ipv4,
                        self.evaluate_wildcard(
                            AddressFamily::Ipv4,
                            endpoint.protocol,
                            endpoint.port,
                        ),
                    ),
                    (
                        AddressFamily::Ipv6,
                        self.evaluate_wildcard(
                            AddressFamily::Ipv6,
                            endpoint.protocol,
                            endpoint.port,
                        ),
                    ),
                ],
            };
        }
        let family = family_of(canonical);
        let verdicts = if canonical.is_loopback() {
            self.evaluate_loopback(endpoint.protocol, canonical, endpoint.port)
        } else if let Some(zone) = socket.zone.as_deref().filter(|zone| !zone.is_empty()) {
            let iface = sanitize(zone);
            vec![PfInterfaceVerdict {
                interface: Some(iface.clone()),
                outcome: self.eval_one(&iface, endpoint.protocol, canonical, endpoint.port),
            }]
        } else {
            self.evaluate_specific(endpoint.protocol, canonical, endpoint.port)
        };
        vec![(family, verdicts)]
    }

    fn evaluate_loopback(
        &self,
        protocol: Protocol,
        destination: IpAddr,
        port: u16,
    ) -> Vec<PfInterfaceVerdict> {
        let ifaces = match self.interfaces {
            Ok(map) => {
                let mut exact: Vec<String> = map
                    .addresses
                    .iter()
                    .filter(|(_, ips)| ips.contains(&destination))
                    .map(|(name, _)| name.clone())
                    .collect();
                if exact.is_empty() {
                    exact = map
                        .addresses
                        .iter()
                        .filter(|(_, ips)| ips.iter().any(IpAddr::is_loopback))
                        .map(|(name, _)| name.clone())
                        .collect();
                }
                if exact.is_empty() {
                    vec!["lo0".to_owned()]
                } else {
                    exact
                }
            }
            Err(_) => vec!["lo0".to_owned()],
        };
        ifaces
            .into_iter()
            .map(|iface| PfInterfaceVerdict {
                outcome: self.eval_one(&iface, protocol, destination, port),
                interface: Some(iface),
            })
            .collect()
    }

    fn evaluate_specific(
        &self,
        protocol: Protocol,
        destination: IpAddr,
        port: u16,
    ) -> Vec<PfInterfaceVerdict> {
        let map = match self.interfaces {
            Ok(map) => map,
            Err(reason) => {
                return vec![PfInterfaceVerdict {
                    interface: None,
                    outcome: Verdict::Unknown {
                        reason: format!("could not list interfaces: {}", sanitize(reason)),
                    },
                }];
            }
        };
        let matching: Vec<&String> = map
            .addresses
            .iter()
            .filter(|(_, ips)| ips.contains(&destination))
            .map(|(name, _)| name)
            .collect();
        if matching.is_empty() {
            return vec![PfInterfaceVerdict {
                interface: None,
                outcome: Verdict::Unknown {
                    reason: "no interface has this address".to_owned(),
                },
            }];
        }
        matching
            .into_iter()
            .map(|iface| PfInterfaceVerdict {
                interface: Some(iface.clone()),
                outcome: self.eval_one(iface, protocol, destination, port),
            })
            .collect()
    }

    fn evaluate_wildcard(
        &self,
        family: AddressFamily,
        protocol: Protocol,
        port: u16,
    ) -> Vec<PfInterfaceVerdict> {
        let map = match self.interfaces {
            Ok(map) => map,
            Err(reason) => {
                return vec![PfInterfaceVerdict {
                    interface: None,
                    outcome: Verdict::Unknown {
                        reason: format!("could not list interfaces: {}", sanitize(reason)),
                    },
                }];
            }
        };
        let matching: Vec<(&String, Vec<IpAddr>)> = map
            .addresses
            .iter()
            .filter_map(|(name, ips)| {
                let family_ips: Vec<IpAddr> = ips
                    .iter()
                    .copied()
                    .filter(|ip| family_of(*ip) == family)
                    .collect();
                (!family_ips.is_empty()).then_some((name, family_ips))
            })
            .collect();
        if matching.is_empty() {
            let label = match family {
                AddressFamily::Ipv4 => "IPv4",
                AddressFamily::Ipv6 => "IPv6",
            };
            return vec![PfInterfaceVerdict {
                interface: None,
                outcome: Verdict::Unknown {
                    reason: format!("no interface has an {label} address"),
                },
            }];
        }
        matching
            .into_iter()
            .map(|(iface, ips)| {
                let verdicts: Vec<Verdict> = ips
                    .into_iter()
                    .map(|ip| self.eval_one(iface, protocol, ip, port))
                    .collect();
                PfInterfaceVerdict {
                    interface: Some(iface.clone()),
                    outcome: combine_address_verdicts(iface, verdicts),
                }
            })
            .collect()
    }

    fn eval_one(
        &self,
        interface: &str,
        protocol: Protocol,
        destination: IpAddr,
        port: u16,
    ) -> Verdict {
        let traffic = Traffic {
            interface,
            protocol,
            destination,
            port,
            source: None,
        };
        let verdict = self.rules.evaluate(self.anchors, &traffic);
        match verdict {
            Verdict::Block { .. } if !self.skipped_groups.is_empty() => {
                // Only concrete interface skips were added to `rules.skip`; an
                // active interface group in `set skip` may include `interface`.
                let groups = self
                    .skipped_groups
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ");
                let scope_note = if self.listed_interfaces.contains(interface) {
                    format!("interface group in set skip ({groups}) may exclude {interface}")
                } else {
                    format!(
                        "interface group in set skip ({groups}) may exclude unlisted interface {interface}"
                    )
                };
                Verdict::Unknown { reason: scope_note }
            }
            other => other,
        }
    }
}

fn combine_address_verdicts(interface: &str, verdicts: Vec<Verdict>) -> Verdict {
    let mut iter = verdicts.into_iter();
    let Some(first) = iter.next() else {
        return Verdict::Unknown {
            reason: format!("no address available on {interface}"),
        };
    };
    let mut current = first;
    for next in iter {
        current = match (&current, &next) {
            (Verdict::Unknown { .. }, _) => current,
            (_, Verdict::Unknown { .. }) => next,
            (Verdict::Pass { .. }, Verdict::Pass { .. })
            | (Verdict::Block { .. }, Verdict::Block { .. }) => current,
            (Verdict::Pass { .. }, Verdict::Block { .. })
            | (Verdict::Block { .. }, Verdict::Pass { .. }) => Verdict::Unknown {
                reason: format!("pf rules differ across addresses on {interface}"),
            },
        };
    }
    current
}

fn family_of(ip: IpAddr) -> AddressFamily {
    if ip.to_canonical().is_ipv6() {
        AddressFamily::Ipv6
    } else {
        AddressFamily::Ipv4
    }
}
