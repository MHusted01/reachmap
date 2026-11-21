//! Pure evaluation of the captured facts in packet-path order.

use std::fmt;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use super::{Flow, Listener, PathEvidence};
use crate::nftables::InputVerdict;
use crate::parse::nftables::{Ruleset, parse_ruleset};
use crate::sanitize::sanitize;
use crate::socket::{AddressFamily, Protocol};

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum Stage {
    Ingress,
    Routing,
    Input,
    Socket,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum Decision {
    Continue,
    Ends,
    Unknown,
}

#[derive(Debug, Serialize)]
pub(super) struct Step<'a> {
    stage: Stage,
    decision: Decision,
    reason: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    listeners: Vec<&'a Listener>,
}

impl fmt::Display for Step<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let stage = match self.stage {
            Stage::Ingress => "Ingress",
            Stage::Routing => "Routing",
            Stage::Input => "nftables input",
            Stage::Socket => "Socket",
        };
        write!(f, "{stage}: {}", self.reason)?;
        for listener in &self.listeners {
            write!(f, " [bind {}, inode {}]", listener.address, listener.inode)?;
        }
        Ok(())
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Verdict {
    ListenerReachable,
    Blocked,
    NotLocal,
    NoListener,
    Unknown,
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ListenerReachable => "listener reachable within scope",
            Self::Blocked => "blocked at nftables input",
            Self::NotLocal => "route leaves the local socket path",
            Self::NoListener => "no matching TCP listener",
            Self::Unknown => "unknown",
        })
    }
}

pub(super) fn evaluate<'a>(flow: &Flow, evidence: &'a PathEvidence) -> (Vec<Step<'a>>, Verdict) {
    let mut steps = Vec::with_capacity(4);
    let verdict = walk(flow, evidence, &mut steps).unwrap_or_else(|(stage, reason)| {
        steps.push(step(stage, Decision::Unknown, reason));
        Verdict::Unknown
    });
    (steps, verdict)
}

fn step(stage: Stage, decision: Decision, reason: impl Into<String>) -> Step<'static> {
    Step {
        stage,
        decision,
        reason: reason.into(),
        listeners: Vec::new(),
    }
}

fn walk<'a>(
    flow: &Flow,
    evidence: &'a PathEvidence,
    steps: &mut Vec<Step<'a>>,
) -> Result<Verdict, (Stage, String)> {
    let (link, rules) = ingress(flow, evidence).map_err(|reason| (Stage::Ingress, reason))?;
    steps.push(step(
        Stage::Ingress,
        Decision::Continue,
        format!(
            "{} (index {}); no applicable earlier nftables hooks, legacy tables or XFRM policies",
            flow.ingress, link.ifindex
        ),
    ));

    let route = route(flow, evidence).map_err(|reason| (Stage::Routing, reason))?;
    if route.kind.as_deref() != Some("local") {
        steps.push(step(
            Stage::Routing,
            Decision::Ends,
            format!(
                "kernel lookup returned a unicast route through {}",
                sanitize(&route.dev)
            ),
        ));
        return Ok(Verdict::NotLocal);
    }
    steps.push(step(
        Stage::Routing,
        Decision::Continue,
        format!(
            "kernel lookup returned a local route on {}",
            sanitize(&route.dev)
        ),
    ));

    let input = rules.input(flow.family()).map_or_else(
        || InputVerdict::Accept {
            reason: "no applicable nftables input base chain".to_owned(),
        },
        |input| input.evaluate(Protocol::Tcp, flow.port.get(), &flow.ingress),
    );
    match input {
        InputVerdict::Accept { reason } => {
            steps.push(step(Stage::Input, Decision::Continue, reason));
        }
        InputVerdict::Drop { reason } => {
            steps.push(step(Stage::Input, Decision::Ends, reason));
            return Ok(Verdict::Blocked);
        }
        InputVerdict::Unknown { reason } => return Err((Stage::Input, reason)),
    }

    let listeners = evidence
        .listeners
        .as_result()
        .map_err(|reason| (Stage::Socket, reason))?;
    let (socket, verdict) = match_listeners(flow.destination, link.ifindex, listeners);
    steps.push(socket);
    Ok(verdict)
}

#[derive(Deserialize)]
struct Link {
    ifindex: u32,
    ifname: String,
    link_type: String,
    master: Option<String>,
    linkinfo: Option<LinkInfo>,
}

#[derive(Deserialize)]
struct LinkInfo {
    info_kind: Option<String>,
}

fn ingress(flow: &Flow, evidence: &PathEvidence) -> Result<(Link, Ruleset), String> {
    let [link]: [Link; 1] = serde_json::from_str(evidence.link.as_result()?)
        .map_err(|_| "expected one ingress interface from ip link")?;
    if link.ifindex == 0 || link.ifname != flow.ingress {
        return Err("interface lookup does not match the stated ingress".to_owned());
    }
    let kind = link
        .linkinfo
        .as_ref()
        .and_then(|info| info.info_kind.as_deref());
    if link.master.is_some()
        || !matches!(link.link_type.as_str(), "ether" | "loopback")
        || !matches!(kind, None | Some("veth"))
    {
        return Err("unsupported ingress link type or master device".to_owned());
    }
    if flow.family() == AddressFamily::Ipv6 {
        let disabled = evidence
            .ipv6_disabled
            .as_ref()
            .ok_or("IPv6 ingress configuration was not captured")?
            .as_result()?;
        if *disabled {
            return Err("IPv6 is disabled on the ingress interface".to_owned());
        }
    }
    let legacy = evidence.legacy_tables.as_result()?;
    if !legacy.trim().is_empty() {
        return Err(format!(
            "unsupported legacy Netfilter tables: {}",
            sanitize(legacy.trim())
        ));
    }
    if !evidence.xfrm_policies.as_result()?.trim().is_empty() {
        return Err("unsupported XFRM policies in this network namespace".to_owned());
    }
    let inbound_default = evidence
        .xfrm_defaults
        .as_result()?
        .lines()
        .find_map(|line| line.trim().strip_prefix("in:").map(str::trim));
    if inbound_default != Some("accept") {
        return Err("could not establish an accepting inbound XFRM default".to_owned());
    }
    let rules = parse_ruleset(evidence.nftables.as_result()?).map_err(|error| error.to_string())?;
    if let Some(reason) = rules.pre_input_gap(flow.family(), &flow.ingress) {
        return Err(reason);
    }
    Ok((link, rules))
}

#[derive(Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct RoutingRule<'a> {
    priority: u32,
    src: &'a str,
    table: &'a str,
}

#[derive(Deserialize)]
struct Route {
    #[serde(rename = "type")]
    kind: Option<String>,
    dst: IpAddr,
    from: Option<IpAddr>,
    iif: String,
    dev: String,
    encap: Option<serde::de::IgnoredAny>,
}

fn route(flow: &Flow, evidence: &PathEvidence) -> Result<Route, String> {
    let rules: Vec<RoutingRule<'_>> = serde_json::from_str(evidence.routing_rules.as_result()?)
        .map_err(|_| "unsupported routing policy rules")?;
    let expected = |priority, table| RoutingRule {
        priority,
        table,
        src: "all",
    };
    let mut standard = vec![expected(0, "local"), expected(32766, "main")];
    if flow.family() == AddressFamily::Ipv4 {
        standard.push(expected(32767, "default"));
    }
    if rules != standard {
        return Err("routing policy differs from the default rules".to_owned());
    }

    let [route]: [Route; 1] = serde_json::from_str(evidence.route.as_result()?)
        .map_err(|_| "expected one usable kernel route for the stated flow")?;
    if route.dst != flow.destination
        || route.from.is_some_and(|from| from != flow.source)
        || route.iif != flow.ingress
    {
        return Err("kernel route evidence does not match the stated flow".to_owned());
    }
    if route.dev.is_empty()
        || route.encap.is_some()
        || !matches!(route.kind.as_deref(), None | Some("local" | "unicast"))
    {
        return Err("unsupported route type or encapsulation".to_owned());
    }
    Ok(route)
}

fn match_listeners(
    destination: IpAddr,
    ingress: u32,
    listeners: &[Listener],
) -> (Step<'_>, Verdict) {
    let mut matches = Vec::new();
    let mut unchecked = Vec::new();
    for listener in listeners {
        let address = listener.address;
        let mapped = match (destination, address) {
            (IpAddr::V4(_), IpAddr::V6(address)) => {
                address.is_unspecified()
                    || address.to_ipv4_mapped().map(IpAddr::V4) == Some(destination)
            }
            _ => false,
        };
        let native = address == destination
            || (address.is_ipv4() == destination.is_ipv4() && address.is_unspecified());
        if !native && !mapped {
            continue;
        }
        let Some(options) = &listener.options else {
            unchecked.push(listener);
            continue;
        };
        if options.bound_device.is_none_or(|index| index == ingress)
            && !(mapped && options.ipv6_only)
        {
            matches.push(listener);
        }
    }
    if !unchecked.is_empty() {
        let mut socket = step(
            Stage::Socket,
            Decision::Unknown,
            "socket options are missing for a candidate listener",
        );
        socket.listeners = unchecked;
        return (socket, Verdict::Unknown);
    }
    if matches.is_empty() {
        return (
            step(
                Stage::Socket,
                Decision::Ends,
                "no TCP listener matches the address, port and ingress device",
            ),
            Verdict::NoListener,
        );
    }
    let mut socket = step(
        Stage::Socket,
        Decision::Continue,
        "matching TCP listener candidates",
    );
    socket.listeners = matches;
    (socket, Verdict::ListenerReachable)
}
