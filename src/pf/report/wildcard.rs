//! Wildcard (`0.0.0.0` / `::`) socket expansion across active interfaces.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};

use crate::sanitize::sanitize;
use crate::socket::{AddressFamily, Protocol};

use super::super::Verdict;
use super::PfInterfaceVerdict;
use super::eval::{EvalContext, family_of, is_link_local};

impl EvalContext<'_> {
    pub(super) fn evaluate_wildcard(
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
        let label = match family {
            AddressFamily::Ipv4 => "IPv4",
            AddressFamily::Ipv6 => "IPv6",
        };
        let all_family_ips: BTreeSet<IpAddr> = map
            .interfaces
            .values()
            .flat_map(|info| info.addresses.iter().copied())
            .filter(|ip| family_of(*ip) == family)
            .collect();
        if all_family_ips.is_empty() {
            return vec![PfInterfaceVerdict {
                interface: None,
                outcome: Verdict::Unknown {
                    reason: format!("no interface has an {label} address"),
                },
            }];
        }
        let routable_family_ips: BTreeSet<IpAddr> = all_family_ips
            .iter()
            .copied()
            .filter(|ip| !ip.is_loopback() && !is_link_local(*ip))
            .collect();
        let mut results = Vec::new();
        for (iface, info) in map.active_interfaces() {
            let mut candidates: BTreeSet<IpAddr> = if info.is_loopback {
                all_family_ips
                    .iter()
                    .copied()
                    .filter(|ip| !is_link_local(*ip))
                    .collect()
            } else {
                routable_family_ips.clone()
            };
            candidates.extend(
                info.addresses
                    .iter()
                    .copied()
                    .filter(|ip| family_of(*ip) == family && is_link_local(*ip)),
            );
            if family == AddressFamily::Ipv4 && protocol == Protocol::Udp && !info.is_loopback {
                // macOS accepts limited broadcast (255.255.255.255) on all active
                // non-loopback interfaces (including point-to-point), while
                // directed broadcasts apply only when BROADCAST/broadcast is set.
                candidates.insert(IpAddr::V4(Ipv4Addr::BROADCAST));
                if info.is_broadcast || !info.broadcasts.is_empty() {
                    candidates.extend(info.broadcasts.iter().copied());
                }
            }
            if candidates.is_empty() {
                continue;
            }
            let verdicts: Vec<Verdict> = candidates
                .into_iter()
                .map(|ip| self.eval_one(iface, protocol, ip, port))
                .collect();
            results.push(PfInterfaceVerdict {
                interface: Some(iface.clone()),
                outcome: combine_address_verdicts(iface, verdicts),
            });
        }
        if results.is_empty() {
            return vec![PfInterfaceVerdict {
                interface: None,
                outcome: Verdict::Unknown {
                    reason: format!("no active interface has an {label} address"),
                },
            }];
        }
        results
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
