//! Plain-text table output for `reachmap scan`.

use std::fmt;

use crate::scan::{Listener, ScannedPort};

/// Printed instead of an empty table.
pub const NO_SOCKETS: &str = "No listening TCP sockets found.";

/// Number of columns in the table.
const COLUMNS: usize = 6;

/// Column titles, in order.
const HEADERS: [&str; COLUMNS] = [
    "PORT",
    "PROTO",
    "ADDRESS",
    "SERVICE",
    "REACHABLE FROM",
    "WHY",
];

/// Space between columns.
const GAP: &str = "  ";

/// Added to WHY for a published port that no socket listens on.
const NO_HOST_SOCKET: &str = "no host socket, Docker forwards this port";

/// Displays scanned ports as an aligned table, one row per port in the order
/// given, every line ending in a newline. Use it with `{}` or `to_string()`.
#[derive(Debug, Clone, Copy)]
pub struct Table<'a>(pub &'a [ScannedPort]);

impl fmt::Display for Table<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            return writeln!(f, "{NO_SOCKETS}");
        }

        let rows: Vec<[String; COLUMNS]> = self.0.iter().map(cells).collect();
        // Characters, not bytes: `{:<width$}` pads by characters, and process
        // names may contain non-ASCII text.
        let widths: [usize; COLUMNS] = std::array::from_fn(|column| {
            rows.iter()
                .map(|row| row[column].chars().count())
                .fold(HEADERS[column].len(), usize::max)
        });

        write_row(f, &HEADERS, &widths)?;
        rows.iter().try_for_each(|row| write_row(f, row, &widths))
    }
}

/// The text of each column for one port.
fn cells(scanned: &ScannedPort) -> [String; COLUMNS] {
    let endpoint = &scanned.endpoint;
    let reason = &scanned.verdict.reason;
    [
        endpoint.port.to_string(),
        endpoint.protocol_name(),
        endpoint.address.to_string(),
        scanned.service.to_string(),
        scanned.verdict.reach.to_string(),
        match scanned.listener {
            Listener::HostSocket => reason.to_string(),
            Listener::DockerForward => format!("{reason}; {NO_HOST_SOCKET}"),
        },
    ]
}

/// Writes one line. Every column but the last is padded to its width; the
/// last is written as is, so lines never end in spaces.
fn write_row(
    f: &mut fmt::Formatter<'_>,
    cells: &[impl AsRef<str>; COLUMNS],
    widths: &[usize; COLUMNS],
) -> fmt::Result {
    let [padded @ .., last] = cells;
    for (cell, width) in padded.iter().zip(widths) {
        write!(f, "{:<width$}{GAP}", cell.as_ref())?;
    }
    writeln!(f, "{}", last.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::HostAddress;
    use crate::reach::classify;
    use crate::service::{Container, Process, Service, UnknownReason};
    use crate::socket::{Endpoint, Protocol};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    const LOCAL_V4: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
    const NEEDS_ROOT: Service = Service::Unknown(UnknownReason::NeedsRoot);

    /// A host with loopback and one LAN address on `enp1s0`.
    fn host() -> Vec<HostAddress> {
        [
            ("lo", "127.0.0.1"),
            ("lo", "::1"),
            ("enp1s0", "192.168.1.20"),
        ]
        .map(|(interface, ip)| HostAddress {
            interface: interface.to_string(),
            ip: ip.parse().unwrap(),
        })
        .to_vec()
    }

    fn row(address: IpAddr, port: u16, service: Service) -> ScannedPort {
        ScannedPort {
            endpoint: Endpoint {
                port,
                protocol: Protocol::Tcp,
                address,
            },
            listener: Listener::HostSocket,
            service,
            verdict: classify(address, Some(&host())),
        }
    }

    fn process(name: &str, pid: u32) -> Service {
        Service::Process(Process {
            pid,
            name: name.to_string(),
        })
    }

    #[test]
    fn renders_aligned_columns_with_a_header() {
        let rows = [
            row(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 22, process("sshd", 812)),
            row(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 22, process("sshd", 812)),
            row(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 53)), 53, NEEDS_ROOT),
            row(LOCAL_V4, 3306, process("mysqld", 1201)),
            row(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)),
                8080,
                process("python3", 4410),
            ),
        ];
        let expected = "\
PORT  PROTO  ADDRESS       SERVICE                              REACHABLE FROM  WHY
22    tcp    0.0.0.0       sshd (812)                           this host, LAN  all IPv4 addresses (bound device not checked)
22    tcp6   ::            sshd (812)                           this host, LAN  all IPv6 and IPv4 addresses (IPv6-only and bound device not checked)
53    tcp    127.0.0.53    unknown (run with sudo for details)  this host       loopback address
3306  tcp    127.0.0.1     mysqld (1201)                        this host       loopback address
8080  tcp    192.168.1.20  python3 (4410)                       LAN             only on enp1s0
";
        assert_eq!(Table(&rows).to_string(), expected);
    }

    #[test]
    fn short_values_still_get_header_width_columns() {
        let rows = [row(IpAddr::V6(Ipv6Addr::LOCALHOST), 1, process("a", 2))];
        assert_eq!(
            Table(&rows).to_string(),
            "PORT  PROTO  ADDRESS  SERVICE  REACHABLE FROM  WHY\n\
             1     tcp6   ::1      a (2)    this host       loopback address\n"
        );
    }

    #[test]
    fn a_five_digit_port_widens_the_port_column() {
        let rows = [
            row(LOCAL_V4, 22, process("sshd", 1)),
            row(LOCAL_V4, 41641, process("tailscaled", 2)),
        ];
        assert_eq!(
            Table(&rows).to_string(),
            "PORT   PROTO  ADDRESS    SERVICE         REACHABLE FROM  WHY\n\
             22     tcp    127.0.0.1  sshd (1)        this host       loopback address\n\
             41641  tcp    127.0.0.1  tailscaled (2)  this host       loopback address\n"
        );
    }

    #[test]
    fn a_published_port_without_a_socket_is_marked_in_why() {
        let container = Service::Container(Container {
            name: "shop-web-1".to_string(),
            compose_service: Some("web".to_string()),
        });
        let rows = [ScannedPort {
            listener: Listener::DockerForward,
            ..row(LOCAL_V4, 8080, container)
        }];
        assert_eq!(
            Table(&rows).to_string(),
            "PORT  PROTO  ADDRESS    SERVICE                     REACHABLE FROM  WHY\n\
             8080  tcp    127.0.0.1  web (container shop-web-1)  this host       \
             loopback address; no host socket, Docker forwards this port\n"
        );
    }

    #[test]
    fn no_sockets_prints_a_sentence_instead_of_an_empty_table() {
        assert_eq!(Table(&[]).to_string(), format!("{NO_SOCKETS}\n"));
    }
}
