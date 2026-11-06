//! Parser for what `tailscale serve status --json` prints: Tailscale's serve
//! config, or `null` when there is none. Only the facts about exposure are
//! kept. Host names stay out of the result, so a saved scan does not name the
//! tailnet.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use serde::{Deserialize, Deserializer};
use thiserror::Error;

use crate::sanitize::sanitize;
use crate::tailscale::{SharedPort, Sharing};

/// The host name Tailscale accepts as a target without a scheme. It can mean
/// either loopback address, so a target with this name counts as both.
const LOCALHOST: &str = "localhost";

/// Why Tailscale's output could not be understood.
#[derive(Debug, Error)]
pub enum TailscaleParseError {
    /// `tailscale serve status --json` printed something other than a config.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// A key that should be a host and port has no port.
    #[error("{0:?} is not a host and port")]
    HostPort(String),
}

/// A serve config, or the part of one that a Tailscale Service has. Tailscale
/// leaves out what is empty, and fields reachmap does not need are ignored.
#[derive(Debug, Default, Deserialize)]
struct RawConfig {
    #[serde(rename = "TCP", default)]
    tcp: BTreeMap<u16, RawTcpHandler>,
    /// Keyed by host and port, e.g. `host.example.ts.net:443`.
    #[serde(rename = "Web", default)]
    web: BTreeMap<String, RawWebServer>,
    #[serde(rename = "Services", default)]
    services: BTreeMap<String, RawConfig>,
    /// Keyed by host and port, like `web`.
    #[serde(rename = "AllowFunnel", default)]
    allow_funnel: BTreeMap<String, bool>,
    /// What `tailscale serve` and `tailscale funnel` share without `--bg`, for
    /// as long as they run. Keyed by session.
    #[serde(rename = "Foreground", default)]
    foreground: BTreeMap<String, RawConfig>,
}

#[derive(Debug, Deserialize)]
struct RawTcpHandler {
    /// Where the connection goes, e.g. `127.0.0.1:5432`.
    #[serde(rename = "TCPForward")]
    tcp_forward: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawWebServer {
    /// Keyed by the path of the URL. Unlike the maps above, this one has no
    /// `omitempty`, so Go prints an unset one as `null`.
    #[serde(rename = "Handlers", default, deserialize_with = "null_as_empty")]
    handlers: BTreeMap<String, RawHttpHandler>,
}

#[derive(Debug, Deserialize)]
struct RawHttpHandler {
    /// Where requests go, e.g. `http://127.0.0.1:3000`. Other handlers answer
    /// from Tailscale itself, with a file, a text or a redirect.
    #[serde(rename = "Proxy")]
    proxy: Option<String>,
}

fn null_as_empty<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

impl RawConfig {
    /// Adds the ports of this config and the configs inside it to `shared`.
    ///
    /// Funnel counts per port, not per host name. A port shared under two names
    /// with Funnel on one of them therefore counts as Funnel, which reports
    /// more reach rather than less.
    fn add_to(&self, shared: &mut BTreeMap<u16, SharedPort>) -> Result<(), TailscaleParseError> {
        for (port, handler) in &self.tcp {
            let forwards = handler.tcp_forward.as_deref().map(socket_addresses);
            share(shared, *port)
                .targets
                .extend(forwards.into_iter().flatten());
        }
        for (host_port, server) in &self.web {
            let proxies = server.handlers.values().filter_map(|h| h.proxy.as_deref());
            share(shared, port_of(host_port)?)
                .targets
                .extend(proxies.flat_map(proxy_addresses));
        }
        let funnels = self.allow_funnel.iter().filter(|(_, allowed)| **allowed);
        for (host_port, _) in funnels {
            share(shared, port_of(host_port)?).sharing = Sharing::Funnel;
        }
        self.services
            .values()
            .chain(self.foreground.values())
            .try_for_each(|config| config.add_to(shared))
    }
}

/// The entry for `port`, created as shared with the tailnet alone.
fn share(shared: &mut BTreeMap<u16, SharedPort>, port: u16) -> &mut SharedPort {
    shared.entry(port).or_insert_with(|| SharedPort {
        port,
        sharing: Sharing::Tailnet,
        targets: BTreeSet::new(),
    })
}

/// The port in a key such as `host.example.ts.net:443`.
fn port_of(host_port: &str) -> Result<u16, TailscaleParseError> {
    host_port
        .rsplit_once(':')
        .and_then(|(_, port)| port.parse().ok())
        .ok_or_else(|| TailscaleParseError::HostPort(sanitize(host_port)))
}

/// The addresses behind a URL such as `http://127.0.0.1:3000/app`. A target
/// without a scheme and host, such as `unix:/run/app.sock`, has none.
fn proxy_addresses(url: &str) -> Vec<SocketAddr> {
    url.split_once("://")
        .and_then(|(_, rest)| rest.split(['/', '?', '#']).next())
        .map(socket_addresses)
        .unwrap_or_default()
}

/// Where a connection to `address` ends up: on Linux, connecting to `0.0.0.0`
/// or `::` reaches this host through loopback.
fn connected_address(address: SocketAddr) -> SocketAddr {
    let ip = match address.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip => ip,
    };
    SocketAddr::new(ip, address.port())
}

/// The addresses behind `127.0.0.1:3000`, `[::1]:3000` or `localhost:3000`.
/// Any other name would need a DNS lookup, and a scan sends no traffic, so it
/// has none.
fn socket_addresses(host_port: &str) -> Vec<SocketAddr> {
    if let Ok(address) = host_port.parse() {
        return vec![connected_address(address)];
    }
    let loopback = [
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ];
    host_port
        .rsplit_once(':')
        .filter(|(host, _)| host.eq_ignore_ascii_case(LOCALHOST))
        .and_then(|(_, port)| port.parse().ok())
        .map(|port| loopback.map(|ip| SocketAddr::new(ip, port)).to_vec())
        .unwrap_or_default()
}

/// Lists the ports in the output of `tailscale serve status --json`, sorted by
/// port number.
pub fn parse_serve_status(json: &str) -> Result<Vec<SharedPort>, TailscaleParseError> {
    let config: Option<RawConfig> = serde_json::from_str(json)?;
    let mut shared = BTreeMap::new();
    config.unwrap_or_default().add_to(&mut shared)?;
    Ok(shared.into_values().collect())
}
