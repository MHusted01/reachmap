//! Reads the local Docker Engine API. The scan stays synchronous and the
//! whole Docker read has one deadline, including response bodies.

use std::env;
use std::error::Error;
use std::ffi::OsStr;
use std::fs;
use std::io;
use std::path::Path;
use std::time::Duration;

use bollard::errors::Error as BollardError;
use bollard::models::ContainerInspectResponse;
use bollard::{API_DEFAULT_VERSION, Docker};
use tokio::{runtime::Builder, time};

use super::{DockerCollectError, DockerError, PublishedPort};
use crate::errors::render_chain;
use crate::parse::docker::{DockerParseError, parse_inspected_container, validate_container_id};
use crate::sanitize::sanitize;

const DEFAULT_SOCKET: &str = "/var/run/docker.sock";
const DAEMON_PATHS: &[&str] = &[
    "/usr/bin/dockerd",
    "/usr/local/bin/dockerd",
    "/usr/sbin/dockerd",
    "/snap/docker/current/bin/dockerd",
];
const TIMEOUT: Duration = Duration::from_secs(5);

pub(super) fn read_published_ports() -> Result<Vec<PublishedPort>, DockerError> {
    let host = env::var_os("DOCKER_HOST");
    let override_path = socket_override(host.as_deref())?;
    let path = override_path.unwrap_or(DEFAULT_SOCKET);
    if let Err(error) = fs::metadata(path) {
        if error.kind() == io::ErrorKind::NotFound
            && override_path.is_none()
            && !DAEMON_PATHS.iter().any(|path| Path::new(path).exists())
        {
            return Err(DockerError::NotInstalled);
        }
        return Err(DockerCollectError::Socket(error).into());
    }
    read_socket(path, TIMEOUT)
}

fn socket_override(host: Option<&OsStr>) -> Result<Option<&str>, DockerCollectError> {
    host.filter(|host| !host.is_empty())
        .map(|host| {
            host.to_str()
                .and_then(|host| host.strip_prefix("unix://"))
                .filter(|path| Path::new(path).is_absolute())
                .ok_or(DockerCollectError::InvalidHost)
        })
        .transpose()
}

fn read_socket(path: &str, deadline: Duration) -> Result<Vec<PublishedPort>, DockerError> {
    let docker = Docker::connect_with_unix(
        &format!("unix://{path}"),
        deadline.as_secs().max(1),
        API_DEFAULT_VERSION,
    )
    .map_err(|error| request_error(error, deadline))?;
    let runtime = Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(DockerCollectError::Runtime)?;
    runtime.block_on(async {
        time::timeout(deadline, published_ports(&docker))
            .await
            .map_err(|_| DockerCollectError::Timeout(deadline))?
    })
}

trait DockerSource {
    async fn running_ids(&self) -> Result<Vec<String>, DockerError>;
    async fn inspect(&self, id: &str) -> Result<ContainerInspectResponse, DockerError>;
}

impl DockerSource for Docker {
    async fn running_ids(&self) -> Result<Vec<String>, DockerError> {
        self.list_containers(None)
            .await
            .map_err(|error| request_error(error, self.timeout()))?
            .into_iter()
            .map(|container| {
                container
                    .id
                    .ok_or(DockerParseError::MissingField("Id").into())
            })
            .collect()
    }

    async fn inspect(&self, id: &str) -> Result<ContainerInspectResponse, DockerError> {
        self.inspect_container(id, None)
            .await
            .map_err(|error| request_error(error, self.timeout()))
    }
}

async fn published_ports(docker: &impl DockerSource) -> Result<Vec<PublishedPort>, DockerError> {
    let mut published = Vec::new();
    for id in docker.running_ids().await? {
        let id = validate_container_id(&id)?;
        let container = match docker.inspect(id).await {
            // Docker can remove a container after the list request returns.
            Err(DockerError::Collect(DockerCollectError::HttpStatus(404))) => continue,
            inspected => inspected?,
        };
        published.extend(parse_inspected_container(container)?);
    }
    Ok(published)
}

fn request_error(error: BollardError, deadline: Duration) -> DockerError {
    match error {
        BollardError::JsonDataError { .. } | BollardError::JsonSerdeError { .. } => {
            DockerParseError::ApiJson.into()
        }
        BollardError::DockerResponseServerError { status_code, .. } => {
            DockerCollectError::HttpStatus(status_code).into()
        }
        BollardError::RequestTimeoutError => DockerCollectError::Timeout(deadline).into(),
        BollardError::IOError { err } => DockerCollectError::Socket(err).into(),
        _ => {
            let permission_denied = std::iter::successors(error.source(), |&cause| cause.source())
                .any(|cause| {
                    cause
                        .downcast_ref::<io::Error>()
                        .is_some_and(|error| error.kind() == io::ErrorKind::PermissionDenied)
                });
            if permission_denied {
                return DockerCollectError::Socket(io::ErrorKind::PermissionDenied.into()).into();
            }
            DockerCollectError::Request(sanitize(&render_chain(&error))).into()
        }
    }
}

#[cfg(test)]
mod tests;
