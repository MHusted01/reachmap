//! Parsers for what the `docker` command prints: the container IDs from
//! `docker ps -q` and the published ports in `docker inspect` JSON. Everything
//! in that output comes from whoever started the container, so names and
//! labels are sanitised here.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};

use serde::Deserialize;
use thiserror::Error;

use crate::docker::PublishedPort;
use crate::sanitize::sanitize;
use crate::service::Container;

/// The label Docker Compose puts on a container to name its service.
const COMPOSE_SERVICE_LABEL: &str = "com.docker.compose.service";

/// How `docker inspect` ends the keys of TCP ports, as in `80/tcp`.
const TCP_SUFFIX: &str = "/tcp";

/// Why Docker's output could not be understood.
#[derive(Debug, Error)]
pub enum DockerParseError {
    /// `docker ps -q` printed a line that is not a container ID.
    #[error("{0:?} is not a container ID")]
    ContainerId(String),
    /// `docker inspect` printed something other than the expected JSON.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
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

/// The IDs in the output of `docker ps -q`, one per line. They become
/// arguments of `docker inspect`, so anything but a hexadecimal ID is refused.
pub fn parse_container_ids(text: &str) -> Result<Vec<&str>, DockerParseError> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| {
            if line.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                Ok(line)
            } else {
                Err(DockerParseError::ContainerId(sanitize(line)))
            }
        })
        .collect()
}

/// The TCP ports published by the containers in `docker inspect` JSON, in the
/// order of the containers and, within one, of the container ports as text.
pub fn parse_docker_inspect(json: &str) -> Result<Vec<PublishedPort>, DockerParseError> {
    let containers: Vec<RawContainer> = serde_json::from_str(json)?;
    let per_container = containers
        .iter()
        .map(published_ports)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(per_container.into_iter().flatten().collect())
}

/// The published TCP ports of one container.
fn published_ports(raw: &RawContainer) -> Result<Vec<PublishedPort>, DockerParseError> {
    let container = container_of(raw);
    raw.network_settings
        .ports
        .iter()
        .flatten()
        .filter(|(port, _)| port.ends_with(TCP_SUFFIX))
        .flat_map(|(_, bindings)| bindings.iter().flatten())
        .map(|binding| {
            Ok(PublishedPort {
                address: host_address(&binding.host_ip)?,
                port: host_port(&binding.host_port)?,
                container: container.clone(),
            })
        })
        .collect()
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
    fn reads_container_ids_one_per_line() {
        assert_eq!(
            parse_container_ids("0a1b2c3d4e5f\nabcdefabcdef\n").unwrap(),
            vec!["0a1b2c3d4e5f", "abcdefabcdef"]
        );
    }

    #[test]
    fn no_containers_is_an_empty_list() {
        assert!(parse_container_ids("").unwrap().is_empty());
        assert!(parse_container_ids("\n").unwrap().is_empty());
    }

    #[test]
    fn a_line_that_could_be_an_option_is_not_a_container_id() {
        let error = parse_container_ids("--host=evil\n").unwrap_err();
        assert_eq!(error.to_string(), r#""--host=evil" is not a container ID"#);
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
