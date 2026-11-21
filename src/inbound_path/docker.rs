//! Evidence and ordered decisions for one IPv4 Docker bridge publish.

use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};

use serde::{Deserialize, Serialize};

use super::evaluate::{Decision, Route, Stage, Step, Verdict, match_listeners, route_for, step};
use super::{Flow, Listener, PathEvidence};
use crate::host_input_snapshot::Evidence;
use crate::parse::nftables::{PathHookResult, PathPacket, Ruleset};
use crate::sanitize::sanitize;

pub(crate) const BRIDGE: &str = "docker0";

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct DockerEvidence {
    pub(crate) publish: Evidence<Option<Publish>>,
    pub(crate) route: Evidence<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) local_source: Option<Evidence<bool>>,
    #[serde(default = "missing_forwarding")]
    pub(crate) forwarding: Evidence<bool>,
    pub(crate) container: Evidence<ContainerSocketEvidence>,
}

fn missing_forwarding() -> Evidence<bool> {
    Evidence::Unavailable {
        reason: "IPv4 forwarding evidence was not captured".to_owned(),
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Publish {
    pub(crate) host: SocketAddrV4,
    pub(crate) target: SocketAddrV4,
    pub(crate) name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ContainerSocketEvidence {
    pub(crate) ingress: u32,
    pub(crate) listeners: Vec<Listener>,
}

#[derive(Debug, Serialize)]
pub(super) struct Translation {
    original: SocketAddrV4,
    translated: SocketAddrV4,
}

pub(crate) fn original_packet(flow: &Flow) -> Option<PathPacket<'_>> {
    let (IpAddr::V4(source), IpAddr::V4(destination)) = (flow.source, flow.destination) else {
        return None;
    };
    Some(PathPacket {
        source,
        destination: SocketAddrV4::new(destination, flow.port.get()),
        ingress: &flow.ingress,
        egress: None,
        local_source: None,
    })
}

pub(super) fn walk<'a>(
    flow: &Flow,
    evidence: &'a PathEvidence,
    rules: &Ruleset,
    original_route: &Route,
    steps: &mut Vec<Step<'a>>,
) -> Result<Option<Verdict>, (Stage, String)> {
    let mut packet = original_packet(flow)
        .ok_or_else(|| (Stage::DestinationNat, "expected an IPv4 flow".to_owned()))?;
    let docker = evidence.docker.as_ref();
    if original_route.kind.as_deref() != Some("local") {
        // Docker's native dstnat base chain is scoped to fib daddr type local.
        // Other forms of prerouting may still affect this packet.
        return Err((
            Stage::DestinationNat,
            "Docker path requires an original local IPv4 route".to_owned(),
        ));
    }
    if flow.ingress == BRIDGE
        || packet.source.is_loopback()
        || packet.destination.ip().is_loopback()
    {
        return Err((
            Stage::DestinationNat,
            "Docker path requires external ingress to a local IPv4 address".to_owned(),
        ));
    }
    let original = packet.destination;
    let (translated, nat_reason) = match rules.docker_hook("prerouting", &packet) {
        PathHookResult::Accept { .. } => {
            if docker.is_some_and(|docker| matches!(docker.publish.as_result(), Ok(Some(_)))) {
                return Err((
                    Stage::DestinationNat,
                    "Docker lists a publish without a matching kernel DNAT rule".to_owned(),
                ));
            }
            return Ok(None);
        }
        PathHookResult::Drop { reason } => {
            steps.push(step(Stage::DestinationNat, Decision::Ends, reason));
            return Ok(Some(Verdict::Blocked));
        }
        PathHookResult::Unknown { reason } => return Err((Stage::DestinationNat, reason)),
        PathHookResult::Dnat { endpoint, reason } => (endpoint, reason),
    };
    let docker = docker.ok_or_else(|| {
        (
            Stage::DestinationNat,
            "Docker bridge evidence was not captured".to_owned(),
        )
    })?;
    let publish = docker
        .publish
        .as_result()
        .map_err(|reason| (Stage::DestinationNat, reason))?
        .as_ref()
        .filter(|publish| matches_publish(publish, original, translated))
        .ok_or_else(|| {
            (
                Stage::DestinationNat,
                "Docker did not corroborate the matching IPv4 DNAT rule".to_owned(),
            )
        })?;
    let mut nat = step(
        Stage::DestinationNat,
        Decision::Continue,
        format!("{original} -> {translated}: {nat_reason}"),
    );
    nat.translation = Some(Translation {
        original,
        translated,
    });
    steps.push(nat);

    let translated_route = docker
        .route
        .as_result()
        .and_then(|raw| route_for(flow, IpAddr::V4(*translated.ip()), raw))
        .map_err(|reason| (Stage::Routing, reason))?;
    if !matches!(translated_route.kind.as_deref(), None | Some("unicast"))
        || translated_route.dev != BRIDGE
        || translated_route.gateway.is_some()
    {
        return Err((
            Stage::Routing,
            "translated endpoint has no direct unicast route through docker0".to_owned(),
        ));
    }
    steps.push(step(
        Stage::Routing,
        Decision::Continue,
        format!("kernel route to {translated} through {BRIDGE}"),
    ));

    check_xfrm_forwarding(evidence)?;
    if !*docker
        .forwarding
        .as_result()
        .map_err(|reason| (Stage::Forward, reason))?
    {
        steps.push(step(
            Stage::Forward,
            Decision::Ends,
            "IPv4 forwarding is disabled on the ingress interface",
        ));
        return Ok(Some(Verdict::Blocked));
    }
    packet.destination = translated;
    packet.egress = Some(BRIDGE);
    packet.local_source = docker
        .local_source
        .as_ref()
        .and_then(|source| source.as_result().ok())
        .copied();
    for (hook, stage) in [
        ("forward", Stage::Forward),
        ("postrouting", Stage::Postrouting),
    ] {
        match rules.docker_hook(hook, &packet) {
            PathHookResult::Accept { reason } => {
                steps.push(step(stage, Decision::Continue, reason))
            }
            PathHookResult::Drop { reason } => {
                steps.push(step(stage, Decision::Ends, reason));
                return Ok(Some(Verdict::Blocked));
            }
            PathHookResult::Unknown { reason } => return Err((stage, reason)),
            PathHookResult::Dnat { .. } => {
                return Err((stage, "unexpected destination translation".to_owned()));
            }
        }
    }

    let container = docker
        .container
        .as_result()
        .map_err(|reason| (Stage::Container, reason))?;
    if container.ingress == 0 {
        return Err((
            Stage::Container,
            "invalid container ingress device index".to_owned(),
        ));
    }
    steps.push(step(
        Stage::Container,
        Decision::Continue,
        format!(
            "{translated} belongs to Docker container {}",
            sanitize(&publish.name)
        ),
    ));
    let (socket, verdict) = match_listeners(
        IpAddr::V4(*translated.ip()),
        container.ingress,
        &container.listeners,
    );
    steps.push(socket);
    Ok(Some(verdict))
}

fn check_xfrm_forwarding(evidence: &PathEvidence) -> Result<(), (Stage, String)> {
    let defaults = evidence
        .xfrm_defaults
        .as_result()
        .map_err(|reason| (Stage::Forward, reason))?;
    if defaults
        .lines()
        .find_map(|line| line.trim().strip_prefix("fwd:").map(str::trim))
        != Some("accept")
    {
        return Err((
            Stage::Forward,
            "could not establish an accepting forwarding XFRM default".to_owned(),
        ));
    }
    Ok(())
}

fn matches_publish(publish: &Publish, original: SocketAddrV4, translated: SocketAddrV4) -> bool {
    let target = translated.ip();
    publish.host.port() == original.port()
        && (publish.host.ip().is_unspecified() || publish.host.ip() == original.ip())
        && publish.target == translated
        && !publish.name.is_empty()
        && !matches!(*target, Ipv4Addr::UNSPECIFIED | Ipv4Addr::BROADCAST)
        && !target.is_loopback()
        && !target.is_multicast()
}
