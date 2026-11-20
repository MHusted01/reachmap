//! The local Docker inspect evidence needed to identify a shared namespace.

use std::fs;
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt};

use bollard::models::{ContainerInspectResponse, ContainerStateStatusEnum};
use thiserror::Error;
use tokio::time;

use super::{
    DEFAULT_SOCKET, DockerCollectError, DockerError, DockerSource, TIMEOUT, connect,
    socket_override,
};
use crate::egress::ContainerRef;
use crate::parse::docker::{DockerParseError, validate_container_id};

#[derive(Debug, Error)]
pub(crate) enum InspectError {
    #[error(transparent)]
    Endpoint(#[from] DockerCollectError),
    #[error("egress requires the local Docker daemon at {DEFAULT_SOCKET}")]
    DifferentEndpoint,
    #[error("could not access {DEFAULT_SOCKET}")]
    Socket(#[source] io::Error),
    #[error("egress requires a root-owned Docker socket at {DEFAULT_SOCKET}")]
    UntrustedSocket,
    #[error("could not connect to the local Docker daemon")]
    Connect(#[source] DockerError),
    #[error("Docker did not respond within {TIMEOUT:?}")]
    Timeout,
    #[error("could not inspect container {target}")]
    Request {
        target: String,
        #[source]
        source: DockerError,
    },
    #[error("container must use Docker's shared network mode (container: or Compose service:)")]
    NetworkMode,
    #[error("Docker returned an invalid network peer name or ID")]
    InvalidPeer,
    #[error("the container and its network peer must both be running")]
    NotRunning,
    #[error("Docker did not return a valid {0} for the running container")]
    MissingField(&'static str),
    #[error(transparent)]
    InvalidId(#[from] DockerParseError),
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Process {
    id: String,
    pub(crate) pid: u32,
    started_at: String,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SharedNetwork {
    pub(crate) workload: Process,
    pub(crate) peer: Process,
}

pub(crate) fn inspect(target: &ContainerRef) -> Result<SharedNetwork, InspectError> {
    let host = std::env::var_os("DOCKER_HOST");
    if socket_override(host.as_deref())?.is_some_and(|path| path != DEFAULT_SOCKET) {
        return Err(InspectError::DifferentEndpoint);
    }
    let metadata = fs::metadata(DEFAULT_SOCKET).map_err(InspectError::Socket)?;
    if !metadata.file_type().is_socket() || metadata.uid() != 0 {
        return Err(InspectError::UntrustedSocket);
    }
    let (docker, runtime) = connect(DEFAULT_SOCKET, TIMEOUT).map_err(InspectError::Connect)?;
    runtime.block_on(async {
        time::timeout(TIMEOUT, inspect_pair(&docker, target))
            .await
            .map_err(|_| InspectError::Timeout)?
    })
}

async fn inspect_pair(
    docker: &impl DockerSource,
    target: &ContainerRef,
) -> Result<SharedNetwork, InspectError> {
    let container = inspect_container(docker, target).await?;
    let peer = shared_with(&container)?;
    let workload = running_process(container)?;
    let peer = inspect_container(docker, &peer).await?;
    Ok(SharedNetwork {
        workload,
        peer: running_process(peer)?,
    })
}

async fn inspect_container(
    docker: &impl DockerSource,
    reference: &ContainerRef,
) -> Result<ContainerInspectResponse, InspectError> {
    docker
        .inspect(reference.as_str())
        .await
        .map_err(|source| InspectError::Request {
            target: reference.as_str().to_string(),
            source,
        })
}

fn shared_with(container: &ContainerInspectResponse) -> Result<ContainerRef, InspectError> {
    container
        .host_config
        .as_ref()
        .and_then(|config| config.network_mode.as_deref())
        .and_then(|mode| mode.strip_prefix("container:"))
        .ok_or(InspectError::NetworkMode)?
        .parse()
        .map_err(|_| InspectError::InvalidPeer)
}

fn running_process(container: ContainerInspectResponse) -> Result<Process, InspectError> {
    let id = container.id.ok_or(InspectError::MissingField("ID"))?;
    validate_container_id(&id)?;
    let state = container
        .state
        .filter(|state| state.status == Some(ContainerStateStatusEnum::RUNNING))
        .ok_or(InspectError::NotRunning)?;
    let pid = state
        .pid
        .and_then(|pid| u32::try_from(pid).ok())
        .filter(|&pid| pid > 0)
        .ok_or(InspectError::MissingField("PID"))?;
    let started_at = state
        .started_at
        .filter(|time| !time.is_empty())
        .ok_or(InspectError::MissingField("start time"))?;
    Ok(Process {
        id,
        pid,
        started_at,
    })
}
