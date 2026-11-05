//! Ports published by Docker containers, and which listening socket belongs
//! to which container. A published port usually is a socket on the host, held
//! by `docker-proxy` or, with `userland-proxy: false`, by `dockerd` itself.
//! Neither says anything about the container, so sockets are matched by
//! address and port, not by who holds them. A published port can also have no
//! socket at all, with only firewall rules behind it.

use std::io::ErrorKind;
use std::net::IpAddr;

use thiserror::Error;

use crate::collect::{self, CollectError};
use crate::parse::docker::{DockerParseError, parse_container_ids, parse_docker_inspect};
use crate::scan::ISSUES_URL;
use crate::service::Container;
use crate::socket::{Endpoint, ListeningSocket, Protocol};

/// Why published ports are unknown. The scan still finishes: Docker is
/// optional, and sockets keep the owner found in `/proc`.
#[derive(Debug, Error)]
pub enum DockerError {
    /// There is no `docker` command on this host.
    #[error("Docker was not found, so published ports are not shown")]
    NotInstalled,
    /// `docker` failed, usually because the daemon is not reachable.
    #[error("could not ask Docker for its containers, so published ports are not shown")]
    Collect(#[source] CollectError),
    /// `docker` printed something reachmap does not understand.
    #[error("could not understand Docker's output, so published ports are not shown")]
    Parse(#[source] DockerParseError),
}

impl From<CollectError> for DockerError {
    fn from(error: CollectError) -> Self {
        match error {
            CollectError::Run { source, .. } if source.kind() == ErrorKind::NotFound => {
                DockerError::NotInstalled
            }
            other => DockerError::Collect(other),
        }
    }
}

impl DockerError {
    /// A suggestion for the user, when there is one beyond the message.
    pub fn hint(&self) -> Option<String> {
        match self {
            DockerError::Collect(CollectError::CommandFailed { stderr, .. })
                if stderr.to_lowercase().contains("permission denied") =>
            {
                Some("run with sudo to read Docker's published ports".to_string())
            }
            DockerError::NotInstalled | DockerError::Collect(_) => None,
            DockerError::Parse(_) => Some(format!(
                "this is likely a reachmap bug or a new Docker format; please report it at \
                 {ISSUES_URL} with your Docker version"
            )),
        }
    }
}

/// A TCP port on the host that Docker forwards to a running container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedPort {
    /// The host address, e.g. `127.0.0.1`, or `0.0.0.0` and `::` for all.
    pub address: IpAddr,
    /// The port on the host.
    pub port: u16,
    /// The container behind it.
    pub container: Container,
}

impl PublishedPort {
    /// Where this port accepts connections on the host.
    pub fn endpoint(&self) -> Endpoint {
        Endpoint {
            port: self.port,
            protocol: Protocol::Tcp,
            address: self.address,
        }
    }
}

/// Lists the ports published by this host's running containers.
pub fn read_published_ports() -> Result<Vec<PublishedPort>, DockerError> {
    published_ports(collect::list_containers, collect::inspect_containers)
}

/// Asks `list` for the running containers and `inspect` for their details.
/// `docker inspect` refuses to run without a container, so it is skipped when
/// none is running.
fn published_ports(
    list: impl FnOnce() -> Result<String, CollectError>,
    inspect: impl FnOnce(&[&str]) -> Result<String, CollectError>,
) -> Result<Vec<PublishedPort>, DockerError> {
    let listed = list()?;
    let ids = parse_container_ids(&listed).map_err(DockerError::Parse)?;
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    parse_docker_inspect(&inspect(&ids)?).map_err(DockerError::Parse)
}

/// The published port that `socket` serves, if any: the one with the same
/// address, or else one that the socket's wider address covers.
pub fn publisher_of<'a>(
    published: &'a [PublishedPort],
    socket: &ListeningSocket,
) -> Option<&'a PublishedPort> {
    let on_this_port = || published.iter().filter(|p| p.port == socket.port);
    on_this_port()
        .find(|p| same_address(socket.address, p.address))
        .or_else(|| on_this_port().find(|p| covers(socket.address, p.address)))
}

/// The published ports that no socket serves: firewall rules alone carry them.
pub fn without_socket<'a>(
    published: &'a [PublishedPort],
    sockets: &'a [ListeningSocket],
) -> impl Iterator<Item = &'a PublishedPort> {
    published.iter().filter(|p| {
        !sockets.iter().any(|socket| {
            socket.port == p.port
                && (same_address(socket.address, p.address) || covers(socket.address, p.address))
        })
    })
}

/// `::ffff:127.0.0.1` in a socket table is the same address as `127.0.0.1`.
fn same_address(socket: IpAddr, published: IpAddr) -> bool {
    socket.to_canonical() == published.to_canonical()
}

/// A dual-stack socket on `::` also accepts what Docker lists as `0.0.0.0`, so
/// one proxy socket can serve both bindings of `-p 8080:80`.
fn covers(socket: IpAddr, published: IpAddr) -> bool {
    socket.is_ipv6() && socket.is_unspecified() && published.is_ipv4() && published.is_unspecified()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::render_chain;
    use std::cell::Cell;
    use std::io;
    use std::process::{Command, ExitStatus};

    fn container(name: &str) -> Container {
        Container {
            name: name.to_string(),
            compose_service: None,
        }
    }

    fn published(address: &str, port: u16, name: &str) -> PublishedPort {
        PublishedPort {
            address: address.parse().unwrap(),
            port,
            container: container(name),
        }
    }

    fn socket(address: &str, port: u16) -> ListeningSocket {
        ListeningSocket {
            protocol: Protocol::Tcp,
            address: address.parse().unwrap(),
            port,
            inode: 1,
        }
    }

    fn failure_status() -> ExitStatus {
        Command::new("sh").args(["-c", "exit 1"]).status().unwrap()
    }

    fn failed(stderr: &str) -> CollectError {
        CollectError::CommandFailed {
            command: "docker ps -q".to_string(),
            status: failure_status(),
            stderr: stderr.to_string(),
        }
    }

    fn cannot_start(kind: ErrorKind) -> CollectError {
        CollectError::Run {
            command: "docker ps -q".to_string(),
            source: io::Error::new(kind, "no"),
        }
    }

    const INSPECTED: &str = r#"[{"Name": "/web", "Config": {"Labels": null},
        "NetworkSettings": {"Ports": {"80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}]}}}]"#;

    #[test]
    fn inspects_the_listed_containers() {
        let ports = published_ports(
            || Ok("0a1b2c\n3d4e5f\n".to_string()),
            |ids| {
                assert_eq!(ids, ["0a1b2c", "3d4e5f"]);
                Ok(INSPECTED.to_string())
            },
        )
        .unwrap();

        assert_eq!(ports, vec![published("0.0.0.0", 8080, "web")]);
    }

    #[test]
    fn inspect_is_skipped_when_no_container_runs() {
        let inspected = Cell::new(false);

        let ports = published_ports(
            || Ok(String::new()),
            |_| {
                inspected.set(true);
                Ok(String::new())
            },
        )
        .unwrap();

        assert!(ports.is_empty());
        assert!(!inspected.get());
    }

    #[test]
    fn a_missing_docker_command_says_so_without_a_hint() {
        let error = published_ports(
            || Err(cannot_start(ErrorKind::NotFound)),
            |_| unreachable!(),
        )
        .unwrap_err();

        assert!(matches!(error, DockerError::NotInstalled));
        assert_eq!(
            render_chain(&error),
            "Docker was not found, so published ports are not shown"
        );
        assert_eq!(error.hint(), None);
    }

    #[test]
    fn a_command_that_cannot_start_for_another_reason_keeps_its_cause() {
        let error = DockerError::from(cannot_start(ErrorKind::PermissionDenied));
        assert!(matches!(error, DockerError::Collect(_)));
    }

    #[test]
    fn an_unreachable_daemon_gives_docker_s_own_message() {
        let error =
            published_ports(|| Err(failed("failed to connect")), |_| unreachable!()).unwrap_err();

        assert_eq!(
            render_chain(&error),
            "could not ask Docker for its containers, so published ports are not shown: \
             `docker ps -q` failed with exit status: 1: failed to connect"
        );
        assert_eq!(error.hint(), None);
    }

    #[test]
    fn a_denied_socket_suggests_sudo() {
        let error = DockerError::from(failed("Got permission denied while trying to connect"));
        assert_eq!(
            error.hint().as_deref(),
            Some("run with sudo to read Docker's published ports")
        );
    }

    #[test]
    fn a_failing_inspect_is_an_error_too() {
        let error = published_ports(
            || Ok("0a1b2c\n".to_string()),
            |_| Err(failed("no such object")),
        )
        .unwrap_err();
        assert!(matches!(error, DockerError::Collect(_)));
    }

    #[test]
    fn output_reachmap_cannot_read_asks_for_a_bug_report() {
        let bad_ids = published_ports(|| Ok("--nope\n".to_string()), |_| unreachable!());
        let bad_json = published_ports(|| Ok("0a1b2c\n".to_string()), |_| Ok("nope".to_string()));

        for error in [bad_ids.unwrap_err(), bad_json.unwrap_err()] {
            assert!(matches!(error, DockerError::Parse(_)));
            assert!(error.hint().unwrap().contains(ISSUES_URL));
        }
    }

    #[test]
    fn a_socket_matches_the_port_published_on_its_address() {
        let ports = [
            published("127.0.0.1", 8080, "local"),
            published("192.168.1.20", 8080, "lan"),
        ];

        let found = publisher_of(&ports, &socket("192.168.1.20", 8080)).unwrap();

        assert_eq!(found.container.name, "lan");
    }

    #[test]
    fn the_same_port_on_another_address_is_not_a_match() {
        let ports = [published("127.0.0.1", 8080, "local")];
        assert_eq!(publisher_of(&ports, &socket("192.168.1.20", 8080)), None);
    }

    #[test]
    fn another_port_on_the_same_address_is_not_a_match() {
        let ports = [published("127.0.0.1", 8080, "local")];
        assert_eq!(publisher_of(&ports, &socket("127.0.0.1", 8081)), None);
    }

    #[test]
    fn an_ipv4_mapped_socket_matches_the_plain_ipv4_address() {
        let ports = [published("127.0.0.1", 8080, "local")];
        assert!(publisher_of(&ports, &socket("::ffff:127.0.0.1", 8080)).is_some());
    }

    #[test]
    fn a_dual_stack_socket_serves_the_ipv4_binding() {
        let ports = [published("0.0.0.0", 8080, "web")];
        assert!(publisher_of(&ports, &socket("::", 8080)).is_some());
        assert_eq!(without_socket(&ports, &[socket("::", 8080)]).count(), 0);
    }

    #[test]
    fn an_exact_match_beats_a_covered_one() {
        let ports = [
            published("0.0.0.0", 8080, "four"),
            published("::", 8080, "six"),
        ];

        let found = publisher_of(&ports, &socket("::", 8080)).unwrap();

        assert_eq!(found.container.name, "six");
    }

    #[test]
    fn an_ipv4_wildcard_socket_does_not_serve_the_ipv6_binding() {
        let ports = [published("::", 8080, "web")];
        assert_eq!(publisher_of(&ports, &socket("0.0.0.0", 8080)), None);
    }

    #[test]
    fn published_ports_without_a_socket_are_found() {
        let ports = [
            published("0.0.0.0", 8080, "served"),
            published("0.0.0.0", 9090, "forwarded"),
        ];
        let sockets = [socket("0.0.0.0", 8080), socket("0.0.0.0", 22)];

        let left: Vec<_> = without_socket(&ports, &sockets).collect();

        assert_eq!(left, vec![&ports[1]]);
    }

    #[test]
    fn a_published_port_knows_its_endpoint() {
        let endpoint = published("::1", 8080, "web").endpoint();
        assert_eq!(endpoint.protocol_name(), "tcp6");
        assert_eq!(endpoint.port, 8080);
    }
}
