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

/// A port on the host that Docker forwards to a running container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedPort {
    /// Transport protocol.
    pub protocol: Protocol,
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
            protocol: self.protocol,
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
    let on_this_port = || published.iter().filter(|p| same_port(socket, p));
    on_this_port()
        .find(|p| same_address(socket.address, p.address))
        .or_else(|| on_this_port().find(|p| covers(socket, p.address)))
}

/// The published ports that no socket serves: firewall rules alone carry them.
pub fn without_socket<'a>(
    published: &'a [PublishedPort],
    sockets: &'a [ListeningSocket],
) -> impl Iterator<Item = &'a PublishedPort> {
    published.iter().filter(|p| {
        !sockets.iter().any(|socket| {
            same_port(socket, p)
                && (same_address(socket.address, p.address) || covers(socket, p.address))
        })
    })
}

/// Port numbers of TCP and UDP are separate: `53/tcp` says nothing about `53/udp`.
fn same_port(socket: &ListeningSocket, published: &PublishedPort) -> bool {
    socket.port == published.port && socket.protocol == published.protocol
}

/// `::ffff:127.0.0.1` in a socket table is the same address as `127.0.0.1`.
fn same_address(socket: IpAddr, published: IpAddr) -> bool {
    socket.to_canonical() == published.to_canonical()
}

/// A dual-stack socket on `::` also accepts what Docker lists as `0.0.0.0`, so
/// one proxy socket can serve both bindings of `-p 8080:80`. A socket known to
/// be IPv6-only cannot. When that is not known, the socket counts as dual-stack:
/// its row then over-reports IPv4 reach like any other, so reach is not hidden.
fn covers(socket: &ListeningSocket, published: IpAddr) -> bool {
    socket.address.is_ipv6()
        && socket.address.is_unspecified()
        && !socket.is_ipv6_only()
        && published.is_ipv4()
        && published.is_unspecified()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::render_chain;
    use crate::socket::SocketOptions;
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
            protocol: Protocol::Tcp,
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
            options: None,
        }
    }

    fn udp_socket(address: &str, port: u16) -> ListeningSocket {
        ListeningSocket {
            protocol: Protocol::Udp,
            ..socket(address, port)
        }
    }

    fn udp_published(address: &str, port: u16, name: &str) -> PublishedPort {
        PublishedPort {
            protocol: Protocol::Udp,
            ..published(address, port, name)
        }
    }

    #[test]
    fn a_socket_of_another_protocol_serves_no_published_port() {
        let tcp_port = [published("0.0.0.0", 53, "dns")];
        let udp_port = [udp_published("0.0.0.0", 53, "dns")];

        assert_eq!(publisher_of(&tcp_port, &udp_socket("0.0.0.0", 53)), None);
        assert_eq!(publisher_of(&udp_port, &socket("0.0.0.0", 53)), None);
    }

    #[test]
    fn a_dual_stack_socket_covers_only_ports_of_its_own_protocol() {
        let tcp_port = [published("0.0.0.0", 53, "dns")];
        let udp_port = [udp_published("0.0.0.0", 53, "dns")];

        assert_eq!(publisher_of(&tcp_port, &udp_socket("::", 53)), None);
        assert_eq!(
            publisher_of(&udp_port, &udp_socket("::", 53)),
            Some(&udp_port[0])
        );
    }

    #[test]
    fn a_udp_socket_serves_the_udp_port_on_the_same_number() {
        let ports = [
            published("0.0.0.0", 53, "tcp-dns"),
            udp_published("0.0.0.0", 53, "udp-dns"),
        ];

        assert_eq!(
            publisher_of(&ports, &udp_socket("0.0.0.0", 53)),
            Some(&ports[1])
        );
    }

    #[test]
    fn a_socket_of_another_protocol_leaves_a_published_port_without_socket() {
        let ports = [udp_published("0.0.0.0", 53, "dns")];
        let tcp_only = [socket("0.0.0.0", 53)];
        let with_udp = [udp_socket("0.0.0.0", 53)];

        assert_eq!(without_socket(&ports, &tcp_only).count(), 1);
        assert_eq!(without_socket(&ports, &with_udp).count(), 0);
    }

    #[test]
    fn a_published_port_keeps_its_protocol_in_the_endpoint() {
        let endpoint = udp_published("0.0.0.0", 53, "dns").endpoint();

        assert_eq!(endpoint.protocol_name(), "udp");
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

    fn ipv6_only(socket: ListeningSocket) -> ListeningSocket {
        ListeningSocket {
            options: Some(SocketOptions {
                bound_device: None,
                ipv6_only: true,
            }),
            ..socket
        }
    }

    #[test]
    fn an_ipv6_only_socket_does_not_serve_the_ipv4_binding() {
        let ports = [published("0.0.0.0", 8080, "web")];
        let unrelated = ipv6_only(socket("::", 8080));

        assert_eq!(publisher_of(&ports, &unrelated), None);
        assert_eq!(
            without_socket(&ports, std::slice::from_ref(&unrelated)).count(),
            1
        );
    }

    #[test]
    fn an_ipv6_only_socket_still_serves_its_own_binding() {
        let ports = [published("::", 8080, "web")];
        assert_eq!(
            publisher_of(&ports, &ipv6_only(socket("::", 8080))),
            ports.first()
        );
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
