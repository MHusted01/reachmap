//! Collect route, interface and listener evidence for a Docker bridge publish.

use std::fs::File;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::os::fd::AsFd;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::thread;

use rustix::thread::{LinkNameSpaceType, move_into_link_name_space};
use serde::Deserialize;

use super::{ip, legacy_tables, linux, listeners, read_proc, route, run};
use crate::docker::engine::bridge::{Attachment, LocalEngine};
use crate::host_input_snapshot::Evidence;
use crate::inbound_path::docker::{
    BRIDGE, ContainerSocketEvidence, DockerEvidence, original_packet,
};
use crate::inbound_path::{Flow, PathEvidence};
use crate::parse::nftables::{PathHookResult, parse_ruleset};
use crate::socket::AddressFamily;

pub(super) fn capture(flow: &Flow, evidence: &PathEvidence) -> Option<DockerEvidence> {
    let packet = original_packet(flow)?;
    let rules = parse_ruleset(evidence.nftables.as_result().ok()?).ok()?;
    if !rules.docker_prerouting() {
        return None;
    }
    let mut result = DockerEvidence {
        publish: Evidence::Collected { data: None },
        route: unavailable(),
        local_source: None,
        forwarding: unavailable(),
        container: unavailable(),
    };
    let (engine, attachment) = match LocalEngine::connect().and_then(|engine| {
        let attachment = engine.find(packet.destination)?;
        Ok((engine, attachment))
    }) {
        Ok((engine, Some(attachment))) => (engine, attachment),
        Ok((_, None)) => return Some(result),
        Err(reason) => {
            result.publish = Evidence::Failed { reason };
            return Some(result);
        }
    };

    if matches!(rules.docker_hook("prerouting", &packet), PathHookResult::Dnat { endpoint, .. }
        if endpoint == attachment.publish.target)
    {
        let translated = attachment.publish.target;
        result.route = route(flow, IpAddr::V4(*translated.ip()), translated.port());
        result.local_source = Some(observe(source_is_local(packet.source)));
        result.forwarding = observe(forwarding(&flow.ingress));
        result.container = observe(container(&engine, &attachment, packet.destination));
    }
    result.publish = Evidence::Collected {
        data: Some(attachment.publish),
    };
    Some(result)
}

fn unavailable<T>() -> Evidence<T> {
    Evidence::Unavailable {
        reason: "no matching Docker bridge DNAT evidence".to_owned(),
    }
}

fn observe<T>(result: Result<T, String>) -> Evidence<T> {
    match result {
        Ok(data) => Evidence::Collected { data },
        Err(reason) => Evidence::Failed { reason },
    }
}

fn forwarding(ingress: &str) -> Result<bool, String> {
    let path = Path::new("/proc/sys/net/ipv4/conf")
        .join(ingress)
        .join("forwarding");
    let value =
        read_proc(&path).map_err(|error| format!("could not read {}: {error}", path.display()))?;
    match value.trim() {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err("unsupported IPv4 forwarding setting".to_owned()),
    }
}

fn source_is_local(source: Ipv4Addr) -> Result<bool, String> {
    #[derive(Deserialize)]
    struct SourceRoute {
        dst: Ipv4Addr,
        #[serde(rename = "type")]
        kind: Option<String>,
    }
    let evidence = ip(&["-4", "-j", "route", "get", &source.to_string()]);
    let [route]: [SourceRoute; 1] = serde_json::from_str(evidence.as_result()?)
        .map_err(|_| "could not establish the IPv4 route type for the packet source")?;
    match (route.dst == source, route.kind.as_deref()) {
        (true, Some("local")) => Ok(true),
        (true, None | Some("unicast")) => Ok(false),
        _ => Err("unsupported IPv4 route to the packet source".to_owned()),
    }
}

fn container(
    engine: &LocalEngine,
    attachment: &Attachment,
    original: SocketAddrV4,
) -> Result<ContainerSocketEvidence, String> {
    let ns_path = format!("/proc/{}/ns/net", attachment.pid);
    let namespace = File::open(&ns_path)
        .map_err(|error| format!("could not open container network namespace: {error}"))?;
    let identity = |file: &File| {
        file.metadata()
            .map(|metadata| (metadata.dev(), metadata.ino()))
    };
    let namespace_id = identity(&namespace).map_err(|error| error.to_string())?;
    let host = File::open("/proc/thread-self/ns/net")
        .and_then(|file| identity(&file))
        .map_err(|error| format!("could not identify host network namespace: {error}"))?;
    if namespace_id == host {
        return Err("Docker container uses the host network namespace".to_owned());
    }
    let target = attachment.publish.target;
    let sample = thread::Builder::new()
        .spawn(move || {
            move_into_link_name_space(namespace.as_fd(), Some(LinkNameSpaceType::Network))
                .map_err(|error| format!("could not enter container network namespace: {error}"))?;
            container_sample(target)
        })
        .map_err(|error| format!("could not start the namespace collector: {error}"))?
        .join()
        .map_err(|_| "container namespace collector stopped unexpectedly")??;
    let (link, data) = sample;
    verify_bridge_peer(&link)?;
    engine.verify(attachment, original)?;
    let current = File::open(ns_path)
        .and_then(|file| identity(&file))
        .map_err(|error| format!("could not recheck container network namespace: {error}"))?;
    if current != namespace_id {
        return Err("Docker container network namespace changed during capture".to_owned());
    }
    Ok(data)
}

#[derive(Deserialize)]
struct Link {
    ifindex: u32,
    ifname: String,
    link_index: Option<u32>,
    flags: Vec<String>,
    linkinfo: Option<LinkInfo>,
    #[serde(default)]
    addr_info: Vec<Address>,
}

#[derive(Deserialize)]
struct LinkInfo {
    info_kind: Option<String>,
    info_slave_data: Option<BridgePort>,
}

#[derive(Deserialize)]
struct BridgePort {
    state: String,
}

#[derive(Deserialize)]
struct Address {
    local: IpAddr,
}

impl Link {
    fn up_veth(&self) -> bool {
        self.ifindex > 0
            && self.flags.iter().any(|flag| flag == "LOWER_UP")
            && self.flags.iter().any(|flag| flag == "UP")
            && self
                .linkinfo
                .as_ref()
                .and_then(|info| info.info_kind.as_deref())
                == Some("veth")
    }
}

fn container_sample(target: SocketAddrV4) -> Result<(Link, ContainerSocketEvidence), String> {
    let evidence = ip(&["-j", "-details", "address", "show"]);
    let links: Vec<Link> = serde_json::from_str(evidence.as_result()?)
        .map_err(|_| "could not parse container interfaces")?;
    let mut matching = links.into_iter().filter(|link| {
        link.addr_info
            .iter()
            .any(|address| address.local == IpAddr::V4(*target.ip()))
    });
    let link = matching
        .next()
        .filter(Link::up_veth)
        .ok_or("container IPv4 endpoint is missing from an active veth interface")?;
    if matching.next().is_some() {
        return Err("container IPv4 endpoint appears on multiple interfaces".to_owned());
    }
    let legacy = legacy_tables(AddressFamily::Ipv4);
    if !legacy.as_result()?.trim().is_empty() {
        return Err("unsupported legacy IPv4 firewall tables in the container".to_owned());
    }
    let policies = ip(&["xfrm", "policy", "list"]);
    let defaults = ip(&["xfrm", "policy", "getdefault"]);
    if !policies.as_result()?.trim().is_empty()
        || !defaults.as_result()?.lines().any(|line| {
            line.trim()
                .strip_prefix("in:")
                .is_some_and(|policy| policy.trim() == "accept")
        })
    {
        return Err("unsupported container inbound XFRM policy".to_owned());
    }
    let evidence = run(linux::NFT_PATHS, linux::NFT_ARGS, "nft");
    let rules = parse_ruleset(evidence.as_result()?).map_err(|error| error.to_string())?;
    if rules.has_container_ipv4_hooks(&link.ifname) {
        return Err("unsupported IPv4 firewall hooks in the container namespace".to_owned());
    }
    let listeners = listeners(
        AddressFamily::Ipv4,
        target.port(),
        Path::new("/proc/thread-self/net"),
    )?;
    let data = ContainerSocketEvidence {
        ingress: link.ifindex,
        listeners,
    };
    Ok((link, data))
}

fn verify_bridge_peer(link: &Link) -> Result<(), String> {
    let evidence = ip(&["-j", "-details", "link", "show", "master", BRIDGE]);
    let ports: Vec<Link> = serde_json::from_str(evidence.as_result()?)
        .map_err(|_| "could not parse docker0 bridge ports")?;
    if !ports.iter().any(|port| {
        link.link_index == Some(port.ifindex)
            && port.link_index == Some(link.ifindex)
            && port.up_veth()
            && port
                .linkinfo
                .as_ref()
                .and_then(|info| info.info_slave_data.as_ref())
                .is_some_and(|data| data.state == "forwarding")
    }) {
        return Err("container veth peer is not forwarding on docker0".to_owned());
    }
    Ok(())
}
