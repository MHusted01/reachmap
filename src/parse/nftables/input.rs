//! Evaluation of the active base chains at the local IP input hook.

use crate::nftables::InputVerdict;
use crate::sanitize::sanitize;
use crate::socket::{AddressFamily, Protocol};

use super::{Action, Chain, ChainDecision, Entry, Policy, Rule, Ruleset, TableFlags};

impl Ruleset {
    pub(crate) fn input(&self, family: AddressFamily) -> Option<InputHook<'_>> {
        let family_name = match family {
            AddressFamily::Ipv4 => "ip",
            AddressFamily::Ipv6 => "ip6",
        };
        let mut chains = Vec::new();
        for chain in self.nftables.iter().filter_map(|entry| match entry {
            Entry::Chain(chain)
                if chain.hook.as_deref() == Some("input")
                    && (chain.family == family_name || chain.family == "inet") =>
            {
                Some(chain)
            }
            _ => None,
        }) {
            let table = self.nftables.iter().find_map(|entry| match entry {
                Entry::Table(table)
                    if table.family == chain.family && table.name == chain.table =>
                {
                    Some(table)
                }
                _ => None,
            });
            if table
                .and_then(|table| table.flags.as_ref())
                .is_some_and(TableFlags::dormant)
            {
                continue;
            }
            let filter = table
                .ok_or("input chain's table is missing")
                .and_then(|_| self.filter_chain(chain));
            chains.push(InputChain { chain, filter });
        }
        // A missing priority could precede every known priority.
        chains.sort_by_key(|input| input.chain.prio);
        (!chains.is_empty()).then_some(InputHook { family, chains })
    }

    fn filter_chain(&self, chain: &Chain) -> Result<FilterChain<'_>, &'static str> {
        if chain.kind.as_deref() != Some("filter") {
            return Err("unsupported input chain type");
        }
        if chain.prio.is_none() {
            return Err("input chain priority is missing");
        }
        let policy = match chain.policy {
            Some(Policy::Known(action)) => action,
            Some(Policy::Unsupported(_)) => return Err("unsupported input chain policy"),
            None => return Err("input chain policy is missing"),
        };
        let rules = self
            .nftables
            .iter()
            .filter_map(|entry| match entry {
                Entry::Rule(rule)
                    if rule.family == chain.family
                        && rule.table == chain.table
                        && rule.chain == chain.name =>
                {
                    Some(rule)
                }
                _ => None,
            })
            .collect();
        Ok(FilterChain { policy, rules })
    }
}

#[derive(Debug)]
pub(crate) struct InputHook<'a> {
    family: AddressFamily,
    chains: Vec<InputChain<'a>>,
}

impl InputHook<'_> {
    pub(crate) fn evaluate(&self, protocol: Protocol, port: u16, interface: &str) -> InputVerdict {
        let mut accept_reason = "all applicable input chains accept";
        for group in self
            .chains
            .chunk_by(|left, right| left.chain.prio == right.chain.prio)
        {
            let mut drop = None;
            for input in group {
                let decision = input
                    .filter
                    .as_ref()
                    .map_err(|&reason| reason)
                    .and_then(|filter| filter.evaluate(self.family, protocol, port, interface));
                match decision {
                    Ok((Action::Accept, reason)) if self.chains.len() == 1 => {
                        accept_reason = reason;
                    }
                    Ok((Action::Accept, _)) => {}
                    Ok((Action::Drop, reason)) => {
                        drop.get_or_insert((input, reason));
                    }
                    // Netfilter does not guarantee an order within a priority.
                    Err(reason) => {
                        return InputVerdict::Unknown {
                            reason: input.reason(reason),
                        };
                    }
                }
            }
            if let Some((input, reason)) = drop {
                return InputVerdict::Drop {
                    reason: input.reason(reason),
                };
            }
        }
        InputVerdict::Accept {
            reason: accept_reason.to_string(),
        }
    }
}

#[derive(Debug)]
struct InputChain<'a> {
    chain: &'a Chain,
    filter: Result<FilterChain<'a>, &'static str>,
}

impl InputChain<'_> {
    fn reason(&self, reason: &str) -> String {
        sanitize(&format!(
            "{reason} in {} {} {}",
            self.chain.family, self.chain.table, self.chain.name
        ))
    }
}

#[derive(Debug)]
struct FilterChain<'a> {
    policy: Action,
    rules: Vec<&'a Rule>,
}

impl FilterChain<'_> {
    fn evaluate(
        &self,
        family: AddressFamily,
        protocol: Protocol,
        port: u16,
        interface: &str,
    ) -> ChainDecision {
        self.rules
            .iter()
            .find_map(|rule| rule.evaluate(family, protocol, port, interface))
            .unwrap_or(Ok((self.policy, "chain policy")))
    }
}
