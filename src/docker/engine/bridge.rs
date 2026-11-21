//! Read the local Engine metadata that identifies one published default-bridge endpoint.

use std::fs;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::unix::fs::{FileTypeExt, MetadataExt};

use bollard::Docker;
use bollard::models::{ContainerInspectResponse, ContainerStateStatusEnum, PortSummaryTypeEnum};
use tokio::runtime::Runtime;
use tokio::time;

use super::{DEFAULT_SOCKET, DockerSource, TIMEOUT, connect, request_error, socket_override};
use crate::errors::render_chain;
use crate::inbound_path::docker::Publish;
use crate::parse::docker::validate_container_id;
use crate::sanitize::sanitize;

#[derive(PartialEq, Eq)]
pub(crate) struct Attachment {
    pub(crate) publish: Publish,
    pub(crate) pid: u32,
    id: String,
    started_at: String,
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
    let network = response
        .network_settings
        .ok_or("Docker network settings are missing")?;
    let networks = network
        .networks
        .ok_or("Docker network attachments are missing")?;
    let address = networks
        .get("bridge")
        .filter(|_| networks.len() == 1)
        .and_then(|bridge| bridge.ip_address.as_deref())
        .and_then(|ip| ip.parse::<Ipv4Addr>().ok())
        .filter(|ip| !ip.is_unspecified())
        .ok_or("Docker path capture supports one attachment to the default IPv4 bridge")?;
    let ports = network
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
    })
}
