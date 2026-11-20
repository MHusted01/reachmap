//! Docker's binding inventory and the nftables host-input evidence for IPv6.

use std::collections::BTreeSet;
use std::fmt;

use serde::Serialize;

use crate::docker::PublishedPort;
use crate::network::HostInterfaces;
use crate::service::Container;
use crate::socket::Endpoint;
use crate::warning::ScanWarning;

use super::{InputChains, InputVerdict, NO_INPUT_CHAINS, NO_INTERFACES};

/// One observed host binding from the Docker Engine API.
#[derive(Debug, Serialize)]
pub struct DockerPublish {
    /// The observed address, port and transport protocol.
    #[serde(flatten)]
    pub endpoint: Endpoint,
    /// The container that publishes the binding.
    pub container: Container,
    #[serde(skip_serializing_if = "Option::is_none")]
    host_input: Option<HostInput>,
}

/// A finding about local nftables input only.
#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum HostInput {
    Ipv4Only {},
    Ipv6Evidence {},
    Unknown { reason: String },
}

impl From<PublishedPort> for DockerPublish {
    fn from(publish: PublishedPort) -> Self {
        Self {
            endpoint: publish.endpoint(),
            container: publish.container,
            host_input: None,
        }
    }
}

pub(super) fn check(
    publishes: &mut [DockerPublish],
    chains: Result<&InputChains<'_>, &str>,
    host: Option<&HostInterfaces>,
) -> Option<ScanWarning> {
    let mut bindings = BTreeSet::new();
    for publish in publishes
        .iter_mut()
        .filter(|publish| publish.endpoint.address.to_canonical().is_ipv6())
    {
        let evidence = chains
            .map_err(str::to_string)
            .and_then(|chains| host_input(publish.endpoint, chains, host))
            .unwrap_or_else(|reason| HostInput::Unknown { reason });
        if matches!(evidence, HostInput::Ipv4Only {}) && !publish.endpoint.address.is_loopback() {
            bindings.insert(publish.endpoint);
        }
        publish.host_input = Some(evidence);
    }
    (!bindings.is_empty()).then_some(ScanWarning::DockerIpv6InputGap { bindings })
}

fn host_input(
    endpoint: Endpoint,
    chains: &InputChains<'_>,
    host: Option<&HostInterfaces>,
) -> Result<HostInput, String> {
    let host = host.ok_or_else(|| NO_INTERFACES.to_string())?;
    let address = endpoint.address;
    let mut interfaces = host
        .addresses
        .iter()
        .filter(|entry| {
            let ip = entry.ip.to_canonical();
            ip == address || (address.is_unspecified() && ip.is_ipv6())
        })
        .peekable();
    if interfaces.peek().is_none() {
        return Err("no matching IPv6 interface addresses".to_string());
    }
    let (input, status) = match &chains.ipv6 {
        Some(input) => (input, HostInput::Ipv6Evidence {}),
        // Confirmed absence of applicable IPv6 chains is needed for this gap.
        None => (
            chains
                .ipv4
                .as_ref()
                .ok_or_else(|| NO_INPUT_CHAINS.to_string())?,
            HostInput::Ipv4Only {},
        ),
    };
    for entry in interfaces {
        if let InputVerdict::Unknown { reason } =
            input.evaluate(endpoint.protocol, endpoint.port, &entry.interface)
        {
            return Err(reason);
        }
    }
    Ok(status)
}

impl fmt::Display for DockerPublish {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Endpoint {
            port,
            protocol,
            address,
        } = self.endpoint;
        write!(f, "{port}/{protocol} {address} ({})", self.container)?;
        match &self.host_input {
            Some(HostInput::Ipv4Only {}) => f.write_str(" | nftables host input: IPv4 only"),
            Some(HostInput::Ipv6Evidence {}) => {
                f.write_str(" | nftables host input: IPv6 evidence")
            }
            Some(HostInput::Unknown { reason }) => {
                write!(f, " | nftables host input: unknown ({reason})")
            }
            None => Ok(()),
        }
    }
}
