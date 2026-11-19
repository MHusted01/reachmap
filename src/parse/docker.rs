//! Docker Engine inspect data and its published ports. Container names and
//! labels can come from whoever started the container, so they are sanitised here.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};

use serde::Deserialize;
use thiserror::Error;

use crate::docker::PublishedPort;
use crate::sanitize::sanitize;
use crate::service::Container;
use crate::socket::Protocol;

/// The label Docker Compose puts on a container to name its service.
const COMPOSE_SERVICE_LABEL: &str = "com.docker.compose.service";

/// Why Docker's output could not be understood.
#[derive(Debug, Error)]
pub enum DockerParseError {
    /// Docker returned an invalid ID in the list of running containers.
    #[error("{0:?} is not a container ID")]
    ContainerId(String),
    /// An inspect fixture did not contain the expected JSON.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// Docker returned an API response that the client could not decode.
    #[error("invalid JSON from the Docker Engine API")]
    ApiJson,
    /// A Docker API object omitted a field needed by the scan.
    #[error("Docker did not return {0}")]
    MissingField(&'static str),
    /// A port binding has a host address that is not an IP address.
    #[error("{0:?} is not an IP address")]
    HostIp(String),
    /// A port binding has a host port that is not a port number.
    #[error("{0:?} is not a port number")]
    HostPort(String),
}

/// One container in `docker inspect` output. Fields reachmap does not need
/// are ignored.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawContainer {
    name: String,
    config: RawConfig,
    network_settings: RawNetworkSettings,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawConfig {
    labels: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawNetworkSettings {
    /// Keyed by container port, e.g. `80/tcp`. A port that is exposed but not
    /// published has the value `null`.
    ports: Option<BTreeMap<String, Option<Vec<RawBinding>>>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawBinding {
    host_ip: String,
    host_port: String,
}

/// A container ID becomes a path segment in the inspect request.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn validate_container_id(id: &str) -> Result<&str, DockerParseError> {
    if id.is_empty() || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(DockerParseError::ContainerId(sanitize(id)));
    }
    Ok(id)
}

/// The TCP and UDP ports in an array of Docker inspect objects, in container order
/// and, within one container, ordered by the container ports as text.
pub fn parse_docker_inspect(json: &str) -> Result<Vec<PublishedPort>, DockerParseError> {
    let containers: Vec<RawContainer> = serde_json::from_str(json)?;
    let per_container = containers
        .iter()
        .map(published_ports)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(per_container.into_iter().flatten().collect())
}

/// Maps one Engine response to the same parser input used by inspect fixtures.
#[cfg(target_os = "linux")]
pub(crate) fn parse_inspected_container(
    response: bollard::models::ContainerInspectResponse,
) -> Result<Vec<PublishedPort>, DockerParseError> {
    let name = response
        .name
        .ok_or(DockerParseError::MissingField("Name"))?;
    let config = response
        .config
        .ok_or(DockerParseError::MissingField("Config"))?;
    let network = response
        .network_settings
        .ok_or(DockerParseError::MissingField("NetworkSettings"))?;
    let ports = network
        .ports
        .map(|ports| {
            ports
                .into_iter()
                .map(|(port, bindings)| {
                    let bindings = bindings
                        .map(|bindings| bindings.into_iter().map(RawBinding::try_from).collect())
                        .transpose()?;
                    Ok((port, bindings))
                })
                .collect::<Result<_, DockerParseError>>()
        })
        .transpose()?;
    published_ports(&RawContainer {
        name,
        config: RawConfig {
            labels: config.labels.map(|labels| labels.into_iter().collect()),
        },
        network_settings: RawNetworkSettings { ports },
    })
}

#[cfg(target_os = "linux")]
impl TryFrom<bollard::models::PortBinding> for RawBinding {
    type Error = DockerParseError;

    fn try_from(binding: bollard::models::PortBinding) -> Result<Self, Self::Error> {
        Ok(Self {
            host_ip: binding
                .host_ip
                .ok_or(DockerParseError::MissingField("HostIp"))?,
            host_port: binding
                .host_port
                .ok_or(DockerParseError::MissingField("HostPort"))?,
        })
    }
}

/// The published TCP and UDP ports of one container.
fn published_ports(raw: &RawContainer) -> Result<Vec<PublishedPort>, DockerParseError> {
    let container = container_of(raw);
    raw.network_settings
        .ports
        .iter()
        .flatten()
        .filter_map(|(port, bindings)| Some((protocol_of(port)?, bindings.as_ref()?)))
        .flat_map(|(protocol, bindings)| bindings.iter().map(move |binding| (protocol, binding)))
        // No host port means nothing is published (yet).
        .filter(|(_, binding)| !binding.host_port.is_empty())
        .map(|(protocol, binding)| {
            Ok(PublishedPort {
                protocol,
                address: host_address(&binding.host_ip)?,
                port: host_port(&binding.host_port)?,
                container: container.clone(),
            })
        })
        .collect()
}

/// The protocol of a container port as `docker inspect` names it, as in
/// `80/tcp`. `None` for one reachmap does not list, such as `sctp`.
fn protocol_of(port: &str) -> Option<Protocol> {
    match port.rsplit_once('/')?.1 {
        "tcp" => Some(Protocol::Tcp),
        "udp" => Some(Protocol::Udp),
        _ => None,
    }
}

/// The names of a container, cleaned for printing. Docker stores the name
/// with a leading `/`.
fn container_of(raw: &RawContainer) -> Container {
    let name = raw.name.strip_prefix('/').unwrap_or(&raw.name);
    let compose_service = raw
        .config
        .labels
        .as_ref()
        .and_then(|labels| labels.get(COMPOSE_SERVICE_LABEL))
        .filter(|service| !service.is_empty());
    Container {
        name: sanitize(name),
        compose_service: compose_service.map(|service| sanitize(service)),
    }
}

/// The address of a binding. An empty address means all of them; of the two
/// wildcards this one is certain, as every Docker host has IPv4 networking.
fn host_address(text: &str) -> Result<IpAddr, DockerParseError> {
    if text.is_empty() {
        return Ok(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    }
    text.parse()
        .map_err(|_| DockerParseError::HostIp(sanitize(text)))
}

fn host_port(text: &str) -> Result<u16, DockerParseError> {
    text.parse()
        .map_err(|_| DockerParseError::HostPort(sanitize(text)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    /// `docker inspect` output for one container with these name, labels and
    /// value of `NetworkSettings.Ports`.
    fn inspect(name: &str, labels: &str, ports: &str) -> String {
        format!(
            r#"[{{"Name": {name}, "Config": {{"Labels": {labels}}},
                 "NetworkSettings": {{"Ports": {ports}}}}}]"#
        )
    }

    fn one_binding(host_ip: &str, host_port: &str) -> String {
        let ports =
            format!(r#"{{"80/tcp": [{{"HostIp": "{host_ip}", "HostPort": "{host_port}"}}]}}"#);
        inspect(r#""/web""#, "null", &ports)
    }

    const ONE_PORT: &str = r#"{"80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}]}"#;

    #[test]
    fn only_nonempty_hex_ids_can_be_used_in_an_inspect_request() {
        assert_eq!(validate_container_id("0a1b2c").unwrap(), "0a1b2c");
        for id in ["", "../info", " 0a1b2c", "0a1b2c\n"] {
            assert!(matches!(
                validate_container_id(id),
                Err(DockerParseError::ContainerId(_))
            ));
        }
    }

    #[test]
    fn strips_the_leading_slash_from_the_name() {
        let parsed = parse_docker_inspect(&inspect(r#""/web""#, "{}", ONE_PORT)).unwrap();
        assert_eq!(parsed[0].container.name, "web");
    }

    #[test]
    fn names_and_labels_are_sanitised() {
        let labels = r#"{"com.docker.compose.service": "web\u001b[2J"}"#;
        let json = inspect(r#""/evil\u001b]0;owned\u0007""#, labels, ONE_PORT);

        let container = &parse_docker_inspect(&json).unwrap()[0].container;

        assert_eq!(container.name, "evil\\u{1b}]0;owned\\u{7}");
        assert_eq!(container.compose_service.as_deref(), Some("web\\u{1b}[2J"));
    }

    #[test]
    fn an_empty_compose_label_is_no_compose_service() {
        let labels = r#"{"com.docker.compose.service": ""}"#;
        let parsed = parse_docker_inspect(&inspect(r#""/web""#, labels, ONE_PORT)).unwrap();
        assert_eq!(parsed[0].container.compose_service, None);
    }

    #[test]
    fn no_ports_at_all_is_fine() {
        assert!(
            parse_docker_inspect(&inspect(r#""/web""#, "{}", "null"))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn an_empty_host_ip_means_all_ipv4_addresses() {
        let parsed = parse_docker_inspect(&one_binding("", "8080")).unwrap();
        assert_eq!(parsed[0].address, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    }

    #[test]
    fn reads_an_ipv6_host_ip() {
        let parsed = parse_docker_inspect(&one_binding("::1", "8080")).unwrap();
        assert_eq!(parsed[0].address, IpAddr::V6(Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn a_bad_host_ip_is_an_error_with_clean_text() {
        let error = parse_docker_inspect(&one_binding(r"bad\u001b", "8080")).unwrap_err();
        assert_eq!(error.to_string(), r#""bad\\u{1b}" is not an IP address"#);
    }

    #[test]
    fn a_binding_without_a_host_port_publishes_nothing() {
        let ports = r#"{
            "80/tcp": [{"HostIp": "0.0.0.0", "HostPort": ""}],
            "81/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8081"}]
        }"#;

        let parsed = parse_docker_inspect(&inspect(r#""/web""#, "null", ports)).unwrap();

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].port, 8081);
    }

    #[test]
    fn a_bad_host_port_is_an_error() {
        let error = parse_docker_inspect(&one_binding("0.0.0.0", "70000")).unwrap_err();
        assert_eq!(error.to_string(), r#""70000" is not a port number"#);
    }

    #[test]
    fn text_that_is_not_json_is_an_error() {
        assert!(matches!(
            parse_docker_inspect("nope"),
            Err(DockerParseError::Json(_))
        ));
    }
}
