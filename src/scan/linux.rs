//! Assemble the Linux inventory from /proc, netlink and optional collectors.

use super::{
    HostCollector, HostInterfaces, InterfacesError, ScanError, ScanReport, join, parse_tables,
};
use crate::docker::{DockerError, PublishedPort};
use crate::firewall::{DockerUserChain, Firewall, UfwState};
use crate::warning::docker_ufw_bypass;
use crate::{
    collect, docker, nftables::check_scan, parse::ip_addr::parse_ip_addr,
    socket_options::read_socket_options, tailscale,
};

pub(super) struct Linux;

impl HostCollector for Linux {
    fn scan(&self) -> Result<ScanReport, ScanError> {
        let tables = collect::read_socket_tables()?;
        let sockets = parse_tables(&tables)?;
        let options = read_socket_options();
        let open_files = collect::read_open_files()?;
        let published = docker::read_published_ports();
        let firewall = firewall_facts(
            &published,
            crate::firewall::read_ufw_state(),
            crate::firewall::read_docker_user_chain,
        );
        let host = read_host_interfaces();
        let host_facts = host.as_ref().ok().cloned();
        let mut report = join(
            sockets,
            &open_files,
            host,
            published,
            tailscale::read_shared_ports(),
            options,
            &firewall,
        );
        check_scan(
            collect::read_nftables_rules(),
            host_facts.as_ref(),
            &mut report,
        );
        Ok(report)
    }
}

/// Only look up the DOCKER-USER chain if a publish makes it relevant.
pub(super) fn firewall_facts(
    published: &Result<Vec<PublishedPort>, DockerError>,
    ufw: UfwState,
    read_chain: impl FnOnce() -> DockerUserChain,
) -> Firewall {
    let chain_matters = published.as_ref().is_ok_and(|ports| {
        ports
            .iter()
            .any(|port| docker_ufw_bypass(port, &ufw).is_some())
    });
    Firewall {
        ufw,
        docker_user: chain_matters.then(read_chain),
    }
}

fn read_host_interfaces() -> Result<HostInterfaces, InterfacesError> {
    let json = collect::read_interfaces().map_err(InterfacesError::Collect)?;
    parse_ip_addr(&json).map_err(InterfacesError::Parse)
}
