//! Plain-text table output for `reachmap scan`.

use crate::socket::ListeningSocket;

/// Printed instead of an empty table.
pub const NO_SOCKETS: &str = "No listening TCP sockets found.";

/// Renders the sockets as an aligned table, one row per socket, in the
/// order given. Every line ends with a newline.
pub fn render_table(sockets: &[ListeningSocket]) -> String {
    if sockets.is_empty() {
        return format!("{NO_SOCKETS}\n");
    }

    let rows: Vec<[String; 3]> = sockets
        .iter()
        .map(|s| {
            [
                s.port.to_string(),
                s.protocol.to_string(),
                s.address.to_string(),
            ]
        })
        .collect();
    let port_width = column_width("PORT", rows.iter().map(|row| row[0].len()));
    let proto_width = column_width("PROTO", rows.iter().map(|row| row[1].len()));
    let line = |port: &str, proto: &str, address: &str| {
        format!("{port:<port_width$}{GAP}{proto:<proto_width$}{GAP}{address}\n")
    };

    let mut output = line("PORT", "PROTO", "ADDRESS");
    for [port, proto, address] in &rows {
        output.push_str(&line(port, proto, address));
    }
    output
}

/// Space between columns.
const GAP: &str = "  ";

/// The widest of the header and all value lengths in one column.
fn column_width(header: &str, value_lengths: impl Iterator<Item = usize>) -> usize {
    value_lengths.fold(header.len(), usize::max)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::socket::Protocol;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn socket(protocol: Protocol, address: IpAddr, port: u16) -> ListeningSocket {
        ListeningSocket {
            protocol,
            address,
            port,
            inode: 1,
        }
    }

    #[test]
    fn renders_aligned_columns_with_a_header() {
        let sockets = vec![
            socket(Protocol::Tcp, IpAddr::V4(Ipv4Addr::UNSPECIFIED), 22),
            socket(Protocol::Tcp6, IpAddr::V6(Ipv6Addr::UNSPECIFIED), 22),
            socket(Protocol::Tcp, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 53)), 53),
            socket(Protocol::Tcp, IpAddr::V4(Ipv4Addr::LOCALHOST), 3306),
        ];
        let expected = "\
PORT  PROTO  ADDRESS
22    tcp    0.0.0.0
22    tcp6   ::
53    tcp    127.0.0.53
3306  tcp    127.0.0.1
";
        assert_eq!(render_table(&sockets), expected);
    }

    #[test]
    fn short_values_still_get_header_width_columns() {
        let sockets = vec![socket(Protocol::Tcp, IpAddr::V4(Ipv4Addr::LOCALHOST), 1)];
        assert_eq!(
            render_table(&sockets),
            "PORT  PROTO  ADDRESS\n1     tcp    127.0.0.1\n"
        );
    }

    #[test]
    fn a_five_digit_port_widens_the_port_column() {
        let sockets = vec![
            socket(Protocol::Tcp, IpAddr::V4(Ipv4Addr::LOCALHOST), 22),
            socket(Protocol::Tcp, IpAddr::V4(Ipv4Addr::LOCALHOST), 41641),
        ];
        assert_eq!(
            render_table(&sockets),
            "PORT   PROTO  ADDRESS\n22     tcp    127.0.0.1\n41641  tcp    127.0.0.1\n"
        );
    }

    #[test]
    fn no_sockets_prints_a_sentence_instead_of_an_empty_table() {
        assert_eq!(render_table(&[]), format!("{NO_SOCKETS}\n"));
    }
}
