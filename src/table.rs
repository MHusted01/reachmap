//! Plain-text table output for `reachmap scan`.

use std::fmt;

use crate::socket::ListeningSocket;

/// Printed instead of an empty table.
pub const NO_SOCKETS: &str = "No listening TCP sockets found.";

/// Space between columns.
const GAP: &str = "  ";

/// Displays sockets as an aligned table, one row per socket in the order
/// given, every line ending in a newline. Use it with `{}` or `to_string()`.
#[derive(Debug, Clone, Copy)]
pub struct Table<'a>(pub &'a [ListeningSocket]);

impl fmt::Display for Table<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            return writeln!(f, "{NO_SOCKETS}");
        }

        let rows: Vec<[String; 3]> = self
            .0
            .iter()
            .map(|s| [s.port.to_string(), s.protocol_name(), s.address.to_string()])
            .collect();
        let port_width = column_width("PORT", rows.iter().map(|row| row[0].len()));
        let proto_width = column_width("PROTO", rows.iter().map(|row| row[1].len()));
        let mut line = |port: &str, proto: &str, address: &str| {
            writeln!(
                f,
                "{port:<port_width$}{GAP}{proto:<proto_width$}{GAP}{address}"
            )
        };

        line("PORT", "PROTO", "ADDRESS")?;
        for [port, proto, address] in &rows {
            line(port, proto, address)?;
        }
        Ok(())
    }
}

/// The widest of the header and all value lengths in one column.
fn column_width(header: &str, value_lengths: impl Iterator<Item = usize>) -> usize {
    value_lengths.fold(header.len(), usize::max)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::socket::Protocol;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn socket(address: IpAddr, port: u16) -> ListeningSocket {
        ListeningSocket {
            protocol: Protocol::Tcp,
            address,
            port,
            inode: 1,
        }
    }

    #[test]
    fn renders_aligned_columns_with_a_header() {
        let sockets = [
            socket(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 22),
            socket(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 22),
            socket(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 53)), 53),
            socket(IpAddr::V4(Ipv4Addr::LOCALHOST), 3306),
        ];
        let expected = "\
PORT  PROTO  ADDRESS
22    tcp    0.0.0.0
22    tcp6   ::
53    tcp    127.0.0.53
3306  tcp    127.0.0.1
";
        assert_eq!(Table(&sockets).to_string(), expected);
    }

    #[test]
    fn short_values_still_get_header_width_columns() {
        let sockets = [socket(IpAddr::V4(Ipv4Addr::LOCALHOST), 1)];
        assert_eq!(
            Table(&sockets).to_string(),
            "PORT  PROTO  ADDRESS\n1     tcp    127.0.0.1\n"
        );
    }

    #[test]
    fn a_five_digit_port_widens_the_port_column() {
        let sockets = [
            socket(IpAddr::V4(Ipv4Addr::LOCALHOST), 22),
            socket(IpAddr::V4(Ipv4Addr::LOCALHOST), 41641),
        ];
        assert_eq!(
            Table(&sockets).to_string(),
            "PORT   PROTO  ADDRESS\n22     tcp    127.0.0.1\n41641  tcp    127.0.0.1\n"
        );
    }

    #[test]
    fn no_sockets_prints_a_sentence_instead_of_an_empty_table() {
        assert_eq!(Table(&[]).to_string(), format!("{NO_SOCKETS}\n"));
    }
}
