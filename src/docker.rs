//! Ports published by Docker containers, and which listening socket belongs
//! to which container. A published port usually is a socket on the host, held
//! by `docker-proxy` or, with `userland-proxy: false`, by `dockerd` itself.
//! Neither says anything about the container, so sockets are matched by
//! address and port, not by who holds them. A published port can also have no
//! socket at all, with only firewall rules behind it.

use std::io;
use std::net::IpAddr;
use std::time::Duration;

use thiserror::Error;

use crate::parse::docker::DockerParseError;
use crate::scan::ISSUES_URL;
use crate::service::Container;
use crate::socket::{Endpoint, ListeningSocket, Protocol};

#[cfg(target_os = "linux")]
mod engine;

/// Why published ports are unknown. The scan still finishes: Docker is
/// optional, and sockets keep the owner found in `/proc`.
#[derive(Debug, Error)]
pub enum DockerError {
    /// Neither the default socket nor a standard Docker daemon installation was found.
    #[error("Docker was not found, so published ports are not shown")]
    NotInstalled,
    /// The Docker Engine API could not be reached or a request failed.
    #[error("could not ask Docker for its containers, so published ports are not shown")]
    Collect(#[from] DockerCollectError),
    /// Docker returned data reachmap does not understand.
    #[error("could not understand Docker's output, so published ports are not shown")]
    Parse(#[from] DockerParseError),
}

/// Why the host's Docker Engine API could not be queried.
#[derive(Debug, Error)]
pub enum DockerCollectError {
    /// This operating system has no Docker collector yet.
    #[error("the Docker collector is Linux only for now")]
    UnsupportedOs,
    /// The configured endpoint is outside the supported local Unix transport.
    #[error("DOCKER_HOST must be a unix:// endpoint with an absolute socket path")]
    InvalidHost,
    /// The Tokio runtime could not be started.
    #[error("could not start the Docker client runtime")]
    Runtime(#[source] io::Error),
    /// The socket was inaccessible.
    #[error("could not access the Docker Unix socket")]
    Socket(#[source] io::Error),
    /// The API did not finish within the collection deadline.
    #[error("Docker did not respond within {0:?}")]
    Timeout(Duration),
    /// The daemon rejected the request.
    #[error("Docker returned HTTP status {0}")]
    HttpStatus(u16),
    /// The client or daemon returned an error.
    #[error("{0}")]
    Request(String),
}

impl DockerError {
    /// A suggestion for the user, when there is one beyond the message.
    pub fn hint(&self) -> Option<String> {
        match self {
            DockerError::Collect(DockerCollectError::Socket(source))
                if source.kind() == io::ErrorKind::PermissionDenied =>
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
#[cfg(target_os = "linux")]
pub fn read_published_ports() -> Result<Vec<PublishedPort>, DockerError> {
    engine::read_published_ports()
}

/// The Docker collector currently runs on Linux.
#[cfg(not(target_os = "linux"))]
pub fn read_published_ports() -> Result<Vec<PublishedPort>, DockerError> {
    Err(DockerCollectError::UnsupportedOs.into())
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
    use crate::socket::SocketOptions;

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

    #[test]
    fn a_denied_socket_suggests_sudo() {
        let error = DockerError::from(DockerCollectError::Socket(
            io::ErrorKind::PermissionDenied.into(),
        ));
        assert_eq!(
            error.hint().as_deref(),
            Some("run with sudo to read Docker's published ports")
        );
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
