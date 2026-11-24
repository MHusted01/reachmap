//! Parse the NUL-delimited process and file records from macOS lsof.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::sanitize::sanitize;
use crate::service::Process;
use crate::socket::{Endpoint, Protocol};

#[derive(Debug)]
pub(crate) struct ParseError {
    pub(crate) record: usize,
}

#[cfg(test)]
pub(crate) fn parse(text: &str) -> Result<Vec<(Endpoint, Process)>, ParseError> {
    Ok(parse_with_zones(text)?
        .into_iter()
        .map(|(endpoint, process, _)| (endpoint, process))
        .collect())
}

pub(crate) fn parse_with_zones(
    text: &str,
) -> Result<Vec<(Endpoint, Process, Option<String>)>, ParseError> {
    if text.is_empty() {
        return Ok(Vec::new());
    }
    let mut sockets = Vec::new();
    let mut owner = None;
    let Some(text) = text.strip_suffix("\0\n") else {
        return Err(ParseError {
            record: text.matches("\0\n").count() + 1,
        });
    };
    let records = text.split("\0\n");
    for (index, record) in records.enumerate() {
        let error = || ParseError { record: index + 1 };
        let mut fields = record.split('\0');
        let header = fields.next().unwrap_or_default();
        if let Some(pid) = header.strip_prefix('p') {
            let pid = pid.parse().map_err(|_| error())?;
            let name = fields
                .find_map(|field| field.strip_prefix('c'))
                .filter(|name| !name.is_empty())
                .map_or_else(|| "unknown".to_owned(), sanitize);
            owner = Some(Process { pid, name });
        } else if header.starts_with('f') {
            let process = owner.as_ref().ok_or_else(error)?;
            if let Some((endpoint, zone)) = parse_file(fields).map_err(|()| error())? {
                sockets.push((endpoint, process.clone(), zone));
            }
        } else {
            return Err(error());
        }
    }
    sockets.sort_by_key(|(endpoint, process, zone)| {
        (*endpoint, process.pid, zone.map(ToOwned::to_owned))
    });
    sockets.dedup_by_key(|(endpoint, process, zone)| {
        (*endpoint, process.pid, zone.map(ToOwned::to_owned))
    });
    Ok(sockets
        .into_iter()
        .map(|(endpoint, process, zone)| (endpoint, process, zone.map(ToOwned::to_owned)))
        .collect())
}

fn parse_file<'a>(
    fields: impl Iterator<Item = &'a str>,
) -> Result<Option<(Endpoint, Option<&'a str>)>, ()> {
    let mut protocol = "";
    let mut family = "";
    let mut name = "";
    let mut listening = false;
    for field in fields {
        match field.as_bytes().first() {
            Some(b'P') => protocol = &field[1..],
            Some(b't') => family = &field[1..],
            Some(b'n') => name = &field[1..],
            Some(b'T') if field == "TST=LISTEN" => listening = true,
            _ => {}
        }
    }
    let protocol = match protocol {
        "TCP" if listening => Protocol::Tcp,
        "UDP" if !name.contains("->") => Protocol::Udp,
        _ => return Ok(None),
    };
    let (host, port) = name.rsplit_once(':').ok_or(())?;
    if port == "*" || port == "0" {
        return Ok(None);
    }
    let port = port.parse().map_err(|_| ())?;
    let (address, zone) = match (family, host) {
        ("IPv4", "*") => (IpAddr::V4(Ipv4Addr::UNSPECIFIED), None),
        ("IPv6", "*") => (IpAddr::V6(Ipv6Addr::UNSPECIFIED), None),
        ("IPv4", _) => (IpAddr::V4(host.parse().map_err(|_| ())?), None),
        ("IPv6", _) => {
            let (address, zone) = parse_ipv6(host)?;
            (IpAddr::V6(address), zone)
        }
        _ => return Err(()),
    };
    Ok(Some((
        Endpoint {
            port,
            protocol,
            address,
        },
        zone,
    )))
}

fn parse_ipv6(host: &str) -> Result<(Ipv6Addr, Option<&str>), ()> {
    // lsof prints mapped addresses in dotted form, even on an IPv6 record.
    if let Ok(mapped) = host.parse::<Ipv4Addr>() {
        return Ok((mapped.to_ipv6_mapped(), None));
    }
    let address = host
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .ok_or(())?;
    // A zone can distinguish sockets for deduplication. The shared report
    // displays the address and makes no reachability claim from the zone.
    let (address, zone) = address
        .split_once('%')
        .map_or((address, None), |(ip, zone)| (ip, Some(zone)));
    Ok((address.parse().map_err(|_| ())?, zone))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = concat!(
        "p42\0cdemo daemon\0\n",
        "f3\0tIPv4\0PTCP\0n127.0.0.1:31001\0TST=LISTEN\0TQR=0\0\n",
        "f4\0tIPv6\0PTCP\0n*:31002\0TST=LISTEN\0\n",
        "f5\0tIPv6\0PUDP\0n[fe80::1234%test0]:31003\0\n",
        "f6\0tIPv4\0PUDP\0n*:31004\0\n",
        "f7\0tIPv4\0PTCP\0n127.0.0.1:31001\0TST=LISTEN\0\n",
        "f8\0tIPv4\0PTCP\0n192.0.2.2:31005->192.0.2.3:443\0TST=ESTABLISHED\0\n",
        "f9\0tIPv4\0PUDP\0n192.0.2.2:31006->192.0.2.3:53\0\n",
        "f10\0tIPv4\0PUDP\0n*:*\0\n",
        "p43\0cworker\x1b\0\n",
        "f3\0tIPv4\0PTCP\0n127.0.0.1:31001\0TST=LISTEN\0\n",
    );

    #[test]
    fn lists_receiving_sockets_and_keeps_distinct_owners() {
        let sockets = parse(FIXTURE).unwrap();
        let actual: Vec<_> = sockets
            .iter()
            .map(|(endpoint, owner)| {
                (
                    endpoint.port,
                    endpoint.protocol,
                    endpoint.address.to_string(),
                    owner.pid,
                    owner.name.as_str(),
                )
            })
            .collect();
        assert_eq!(
            actual,
            [
                (
                    31001,
                    Protocol::Tcp,
                    "127.0.0.1".to_owned(),
                    42,
                    "demo daemon"
                ),
                (
                    31001,
                    Protocol::Tcp,
                    "127.0.0.1".to_owned(),
                    43,
                    "worker\\u{1b}"
                ),
                (31002, Protocol::Tcp, "::".to_owned(), 42, "demo daemon"),
                (
                    31003,
                    Protocol::Udp,
                    "fe80::1234".to_owned(),
                    42,
                    "demo daemon"
                ),
                (
                    31004,
                    Protocol::Udp,
                    "0.0.0.0".to_owned(),
                    42,
                    "demo daemon"
                ),
            ]
        );
    }

    #[test]
    fn an_ipv6_record_can_print_an_ipv4_mapped_bind_in_dotted_form() {
        let sockets =
            parse("p42\0cfixture\0\nf3\0tIPv6\0PTCP\0n127.0.0.1:31001\0TST=LISTEN\0\n").unwrap();
        assert_eq!(
            sockets[0].0.address,
            IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped())
        );
    }

    #[test]
    fn identical_scoped_binds_from_one_pid_are_kept_for_each_zone() {
        let sockets = parse(concat!(
            "p42\0cfixture\0\n",
            "f3\0tIPv6\0PUDP\0n[fe80::1234%test0]:31001\0\n",
            "f4\0tIPv6\0PUDP\0n[fe80::1234%test1]:31001\0\n",
            "f5\0tIPv6\0PUDP\0n[fe80::1234%test0]:31001\0\n",
        ))
        .unwrap();
        assert_eq!(sockets.len(), 2);
    }

    #[test]
    fn empty_output_is_valid_but_truncated_or_invalid_records_are_errors() {
        assert!(parse("").unwrap().is_empty());
        assert_eq!(parse("p42\0cworker").unwrap_err().record, 1);
        assert!(parse("f3\0tIPv4\0PUDP\0n*:31004\0\n").is_err());
        assert!(parse("p42\0\nf3\0tIPv4\0PUDP\0n[::1]:31004\0\n").is_err());
    }
}
