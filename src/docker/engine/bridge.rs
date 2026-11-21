//! Read the local Engine metadata that identifies one published bridge endpoint.

use std::fs;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::unix::fs::{FileTypeExt, MetadataExt};

use bollard::Docker;
use bollard::models::{
    ContainerInspectResponse, ContainerStateStatusEnum, NetworkInspect, PortSummaryTypeEnum,
};
use tokio::runtime::Runtime;
use tokio::time;

use super::{DEFAULT_SOCKET, DockerSource, TIMEOUT, connect, request_error, socket_override};
use crate::errors::render_chain;
use crate::inbound_path::docker::Publish;
use crate::inbound_path::valid_interface_name;
use crate::parse::docker::validate_container_id;
use crate::sanitize::sanitize;

#[derive(PartialEq, Eq)]
pub(crate) struct Attachment {
    pub(crate) publish: Publish,
    pub(crate) pid: u32,
    id: String,
    started_at: String,
    network: NetworkAttachment,
}

#[derive(PartialEq, Eq)]
struct NetworkAttachment {
    id: String,
    name: String,
    endpoint_id: String,
}

pub(crate) struct LocalEngine {
    docker: Docker,
    runtime: Runtime,
}

impl LocalEngine {
    pub(crate) fn connect() -> Result<Self, String> {
        let host = std::env::var_os("DOCKER_HOST");
        if socket_override(host.as_deref())
            .map_err(|error| render_chain(&error))?
            .is_some_and(|path| path != DEFAULT_SOCKET)
        {
            return Err("Docker path capture requires the default local Engine socket".to_owned());
        }
        let metadata = fs::metadata(DEFAULT_SOCKET)
            .map_err(|error| format!("could not read {DEFAULT_SOCKET}: {error}"))?;
        if !metadata.file_type().is_socket() || metadata.uid() != 0 {
            return Err("Docker path capture requires a root-owned local Engine socket".to_owned());
        }
        let (docker, runtime) =
            connect(DEFAULT_SOCKET, TIMEOUT).map_err(|error| render_chain(&error))?;
        Ok(Self { docker, runtime })
    }

    pub(crate) fn find(&self, original: SocketAddrV4) -> Result<Option<Attachment>, String> {
        self.with_deadline(async {
            let rows = self
                .docker
                .list_containers(None)
                .await
                .map_err(|error| render_chain(&request_error(error, TIMEOUT)))?;
            let mut candidates = rows.iter().filter(|row| {
                row.ports.iter().flatten().any(|port| {
                    port.typ == Some(PortSummaryTypeEnum::TCP)
                        && port.public_port == Some(original.port())
                        && port
                            .ip
                            .as_deref()
                            .and_then(|ip| ip.parse::<Ipv4Addr>().ok())
                            .is_some_and(|ip| ip.is_unspecified() || ip == *original.ip())
                })
            });
            let Some(candidate) = candidates.next() else {
                return Ok(None);
            };
            if candidates.next().is_some() {
                return Err(
                    "more than one Docker container matches the published endpoint".to_owned(),
                );
            }
            let id = candidate
                .id
                .as_deref()
                .ok_or("Docker did not return the container ID")?;
            self.inspect(id, original).await.map(Some)
        })
    }

    pub(crate) fn verify(
        &self,
        attachment: &Attachment,
        original: SocketAddrV4,
    ) -> Result<(), String> {
        let current = self.with_deadline(self.inspect(&attachment.id, original))?;
        if current != *attachment {
            return Err("Docker container or publish changed during capture".to_owned());
        }
        Ok(())
    }

    pub(crate) fn bridge(&self, attachment: &Attachment) -> Result<String, String> {
        self.with_deadline(async {
            let network = self
                .docker
                .inspect_network(&attachment.network.id, None)
                .await
                .map_err(|error| render_chain(&request_error(error, TIMEOUT)))?;
            bridge_name(network, &attachment.network)
        })
    }

    async fn inspect(&self, id: &str, original: SocketAddrV4) -> Result<Attachment, String> {
        let id = validate_container_id(id).map_err(|error| render_chain(&error))?;
        let response = self
            .docker
            .inspect(id)
            .await
            .map_err(|error| render_chain(&error))?;
        attachment(response, id, original)
    }

    fn with_deadline<T>(&self, work: impl Future<Output = Result<T, String>>) -> Result<T, String> {
        self.runtime.block_on(async {
            time::timeout(TIMEOUT, work)
                .await
                .map_err(|_| "Docker Engine request timed out".to_owned())?
        })
    }
}

fn bridge_name(network: NetworkInspect, attachment: &NetworkAttachment) -> Result<String, String> {
    if network.id.as_deref() != Some(attachment.id.as_str())
        || network.name.as_deref() != Some(attachment.name.as_str())
    {
        return Err("Docker network inspect did not match the container attachment".to_owned());
    }
    if network.driver.as_deref() != Some("bridge") || network.scope.as_deref() != Some("local") {
        return Err("Docker path capture requires a local bridge network".to_owned());
    }
    let option = network
        .options
        .as_ref()
        .and_then(|options| options.get("com.docker.network.bridge.name"))
        .filter(|name| !name.is_empty());
    let bridge = match option {
        Some(name) => name.clone(),
        None if attachment.name == "bridge" => {
            return Err("Docker did not report the default bridge interface name".to_owned());
        }
        None => format!("br-{}", &attachment.id[..12]),
    };
    if !valid_interface_name(&bridge) {
        return Err("Docker reported an unsupported bridge interface name".to_owned());
    }
    Ok(bridge)
}

fn network_id(id: Option<String>) -> Option<String> {
    id.filter(|id| id.len() == 64 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
}

fn attachment(
    response: ContainerInspectResponse,
    id: &str,
    original: SocketAddrV4,
) -> Result<Attachment, String> {
    if response.id.as_deref() != Some(id) {
        return Err("Docker inspect returned a different container ID".to_owned());
    }
    let state = response
        .state
        .filter(|state| state.status == Some(ContainerStateStatusEnum::RUNNING))
        .ok_or("Docker container is not running")?;
    let pid = state
        .pid
        .and_then(|pid| u32::try_from(pid).ok())
        .filter(|pid| *pid > 0)
        .ok_or("Docker did not return a valid container PID")?;
    let started_at = state
        .started_at
        .filter(|time| !time.is_empty())
        .ok_or("Docker container start time is missing")?;
    let name = response
        .name
        .as_deref()
        .map(|name| sanitize(name.trim_start_matches('/')))
        .filter(|name| !name.is_empty())
        .ok_or("Docker container name is missing")?;
    let settings = response
        .network_settings
        .ok_or("Docker network settings are missing")?;
    let networks = settings
        .networks
        .ok_or("Docker network attachments are missing")?;
    if networks.len() != 1 {
        return Err("Docker path capture requires one attachment to an IPv4 bridge".to_owned());
    }
    let (network_name, endpoint) = networks
        .into_iter()
        .next()
        .ok_or("Docker network attachment is missing")?;
    let address = endpoint
        .ip_address
        .and_then(|ip| ip.parse::<Ipv4Addr>().ok())
        .filter(|ip| {
            !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast() && !ip.is_broadcast()
        })
        .ok_or("Docker did not report a valid IPv4 address for the network attachment")?;
    let network = NetworkAttachment {
        id: network_id(endpoint.network_id).ok_or("Docker did not report a valid network ID")?,
        name: network_name,
        endpoint_id: network_id(endpoint.endpoint_id)
            .ok_or("Docker did not report a valid network endpoint ID")?,
    };
    let ports = settings
        .ports
        .ok_or("Docker container port bindings are missing")?;
    let mut bindings = ports
        .iter()
        .filter_map(|(key, bindings)| {
            let port = key
                .strip_suffix("/tcp")?
                .parse::<u16>()
                .ok()
                .filter(|port| *port > 0)?;
            Some(bindings.iter().flatten().filter_map(move |binding| {
                let host_port = binding.host_port.as_deref()?.parse::<u16>().ok()?;
                let host = binding.host_ip.as_deref()?.parse::<Ipv4Addr>().ok()?;
                (host_port == original.port() && (host.is_unspecified() || host == *original.ip()))
                    .then_some((SocketAddrV4::new(host, host_port), port))
            }))
        })
        .flatten();
    let (host, port) = bindings
        .next()
        .ok_or("Docker inspect did not confirm the published IPv4 endpoint")?;
    if bindings.next().is_some() {
        return Err("Docker inspect returned more than one matching published endpoint".to_owned());
    }
    Ok(Attachment {
        publish: Publish {
            host,
            target: SocketAddrV4::new(address, port),
            name,
        },
        pid,
        id: id.to_owned(),
        started_at,
        network,
    })
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    const ID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn fixture() -> Value {
        serde_json::from_str(include_str!(
            "../../../tests/fixtures/docker-path-inspect.json"
        ))
        .unwrap()
    }

    fn read(fixture: Value) -> Result<Attachment, String> {
        attachment(
            serde_json::from_value(fixture).unwrap(),
            ID,
            "192.0.2.1:8443".parse().unwrap(),
        )
    }

    #[test]
    fn inspect_confirms_the_wildcard_ipv4_tcp_publish() {
        let result = read(fixture()).unwrap();
        assert_eq!(result.pid, 1042);
        assert_eq!(result.publish.host, "0.0.0.0:8443".parse().unwrap());
        assert_eq!(result.publish.target, "198.51.100.2:8080".parse().unwrap());
        assert_eq!(result.publish.name, "example-web");
    }

    #[test]
    fn network_inspect_resolves_default_generated_and_explicit_bridge_names() {
        for (name, option, expected) in [
            ("bridge", Some("docker0"), "docker0"),
            ("example_default", None, "br-0123456789ab"),
            ("example_default", Some("example-br"), "example-br"),
        ] {
            let mut data = fixture();
            let endpoint = data["NetworkSettings"]["Networks"]["bridge"].take();
            data["NetworkSettings"]["Networks"] = json!({(name): endpoint});
            let attachment = read(data).unwrap();
            let mut network = json!({"Id": ID, "Name": name, "Driver": "bridge", "Scope": "local"});
            if let Some(option) = option {
                network["Options"] = json!({"com.docker.network.bridge.name": option});
            }
            assert_eq!(
                bridge_name(
                    serde_json::from_value(network).unwrap(),
                    &attachment.network
                )
                .unwrap(),
                expected
            );
        }
    }

    #[test]
    fn network_inspect_requires_the_attached_local_bridge() {
        let attachment = read(fixture()).unwrap();
        let network = json!({"Id": ID, "Name": "bridge", "Driver": "bridge", "Scope": "local",
            "Options": {"com.docker.network.bridge.name": "docker0"}});
        for (path, value) in [
            ("/Id", json!("abcdef")),
            ("/Name", json!("different")),
            ("/Driver", json!("macvlan")),
            ("/Scope", json!("swarm")),
            ("/Options", Value::Null),
            (
                "/Options/com.docker.network.bridge.name",
                json!("../bridge"),
            ),
        ] {
            let mut invalid = network.clone();
            *invalid.pointer_mut(path).unwrap() = value;
            assert!(
                bridge_name(
                    serde_json::from_value(invalid).unwrap(),
                    &attachment.network
                )
                .is_err(),
                "{path}"
            );
        }
    }

    #[test]
    fn inspect_rejects_incompatible_or_ambiguous_attachments() {
        for (path, value, message) in [
            ("/Id", json!("fedcba9876543210"), "different container ID"),
            ("/State/Status", json!("exited"), "not running"),
            ("/State/Pid", json!(0), "valid container PID"),
            ("/State/StartedAt", json!(""), "start time"),
            ("/Name", json!("/"), "name is missing"),
            (
                "/NetworkSettings/Networks/bridge/NetworkID",
                Value::Null,
                "valid network ID",
            ),
            (
                "/NetworkSettings/Networks/bridge/EndpointID",
                json!("abc"),
                "valid network endpoint ID",
            ),
            (
                "/NetworkSettings/Networks",
                json!({
                    "bridge": {"IPAddress":"198.51.100.2"},
                    "other": {"IPAddress":"203.0.113.2"}
                }),
                "one attachment",
            ),
            (
                "/NetworkSettings/Ports/8080~1tcp/0/HostIp",
                json!("192.0.2.4"),
                "did not confirm",
            ),
            (
                "/NetworkSettings/Ports/8080~1tcp",
                json!([
                    {"HostIp":"0.0.0.0","HostPort":"8443"},
                    {"HostIp":"192.0.2.1","HostPort":"8443"}
                ]),
                "more than one",
            ),
        ] {
            let mut data = fixture();
            *data.pointer_mut(path).unwrap() = value;
            let error = read(data).err().unwrap();
            assert!(error.contains(message), "{path}: {error}");
        }
    }
}
