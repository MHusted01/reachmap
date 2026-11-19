use super::*;
use crate::parse::docker::parse_docker_inspect;
use crate::scan::ISSUES_URL;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

const INSPECT: &str = include_str!("../../../tests/fixtures/docker_inspect.json");

#[derive(Default)]
struct FakeDocker {
    ids: Vec<String>,
    inspected: RefCell<Vec<String>>,
    responses: RefCell<VecDeque<Option<ContainerInspectResponse>>>,
}

impl DockerSource for FakeDocker {
    async fn running_ids(&self) -> Result<Vec<String>, DockerError> {
        Ok(self.ids.clone())
    }

    async fn inspect(&self, id: &str) -> Result<ContainerInspectResponse, DockerError> {
        self.inspected.borrow_mut().push(id.to_string());
        self.responses
            .borrow_mut()
            .pop_front()
            .ok_or_else(|| DockerError::from(DockerCollectError::HttpStatus(500)))?
            .ok_or_else(|| DockerCollectError::HttpStatus(404).into())
    }
}

#[tokio::test]
async fn engine_objects_preserve_the_existing_inspect_parser_output() {
    let responses: VecDeque<Option<ContainerInspectResponse>> =
        serde_json::from_str(INSPECT).unwrap();
    let ids: Vec<String> = (0..responses.len()).map(|id| format!("{id:06x}")).collect();
    let docker = FakeDocker {
        ids: ids.clone(),
        responses: RefCell::new(responses),
        ..FakeDocker::default()
    };

    assert_eq!(
        published_ports(&docker).await.unwrap(),
        parse_docker_inspect(INSPECT).unwrap()
    );
    assert_eq!(docker.inspected.into_inner(), ids);
}

#[tokio::test]
async fn only_valid_running_ids_are_inspected() {
    let empty = FakeDocker::default();
    assert!(published_ports(&empty).await.unwrap().is_empty());
    assert!(empty.inspected.into_inner().is_empty());

    let invalid = FakeDocker {
        ids: vec!["../info".to_string()],
        ..FakeDocker::default()
    };
    let error = published_ports(&invalid).await.unwrap_err();
    assert!(matches!(
        error,
        DockerError::Parse(DockerParseError::ContainerId(_))
    ));
    assert!(error.hint().unwrap().contains(ISSUES_URL));
    assert!(invalid.inspected.into_inner().is_empty());
}

#[tokio::test]
async fn a_failed_inspect_cannot_produce_a_partial_list() {
    let mut responses: VecDeque<Option<ContainerInspectResponse>> =
        serde_json::from_str(INSPECT).unwrap();
    responses.truncate(1);
    let docker = FakeDocker {
        ids: vec!["0a1b2c".to_string(), "123abc".to_string()],
        responses: RefCell::new(responses),
        ..FakeDocker::default()
    };
    assert!(matches!(
        published_ports(&docker).await,
        Err(DockerError::Collect(DockerCollectError::HttpStatus(500)))
    ));
}

#[tokio::test]
async fn a_removed_container_leaves_the_other_published_ports_visible() {
    let mut responses: VecDeque<Option<ContainerInspectResponse>> =
        serde_json::from_str(INSPECT).unwrap();
    responses.push_front(None);
    let docker = FakeDocker {
        ids: (0..responses.len()).map(|id| format!("{id:06x}")).collect(),
        responses: RefCell::new(responses),
        ..FakeDocker::default()
    };

    assert_eq!(
        published_ports(&docker).await.unwrap(),
        parse_docker_inspect(INSPECT).unwrap()
    );
}

#[test]
fn docker_host_can_only_select_local_absolute_unix_paths() {
    assert_eq!(socket_override(None).unwrap(), None);
    assert_eq!(socket_override(Some(OsStr::new(""))).unwrap(), None);
    assert_eq!(
        socket_override(Some(OsStr::new("unix:///run/user/1000/docker.sock"))).unwrap(),
        Some("/run/user/1000/docker.sock")
    );
    for host in [
        "tcp://192.0.2.10:2375",
        "ssh://192.0.2.10",
        "unix://relative.sock",
        "unix://",
    ] {
        assert!(matches!(
            socket_override(Some(OsStr::new(host))),
            Err(DockerCollectError::InvalidHost)
        ));
    }
}

#[test]
fn a_daemon_response_error_reports_only_the_http_status() {
    let error = request_error(
        BollardError::DockerResponseServerError {
            status_code: 500,
            message: "private details\n".to_string(),
        },
        TIMEOUT,
    );
    assert!(matches!(
        error,
        DockerError::Collect(DockerCollectError::HttpStatus(500))
    ));
    assert!(render_chain(&error).ends_with(": Docker returned HTTP status 500"));
}

struct TestSocket(PathBuf);

impl Drop for TestSocket {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

#[tokio::test]
async fn the_deadline_includes_the_response_body() {
    let path = env::temp_dir().join(format!("reachmap-docker-{}.sock", std::process::id()));
    let listener = UnixListener::bind(&path).unwrap();
    let socket = TestSocket(path.clone());
    let deadline = Duration::from_millis(500);
    let read = tokio::task::spawn_blocking(move || read_socket(path.to_str().unwrap(), deadline));
    let (stream, _) = time::timeout(Duration::from_secs(2), listener.accept())
        .await
        .unwrap()
        .unwrap();
    let mut stream = BufReader::new(stream);
    let mut request = String::new();
    time::timeout(Duration::from_secs(2), stream.read_line(&mut request))
        .await
        .unwrap()
        .unwrap();
    assert!(request.starts_with("GET ") && request.ends_with("/containers/json HTTP/1.1\r\n"));
    // Leave the body incomplete while the connection is still open.
    stream
        .get_mut()
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n[")
        .await
        .unwrap();
    let result = read.await.unwrap();
    assert!(
        matches!(result, Err(DockerError::Collect(DockerCollectError::Timeout(elapsed))) if elapsed == deadline),
        "{result:?}"
    );
    drop(socket);
}
