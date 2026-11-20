//! Pure parsers for observer responses and resolver configuration.

use std::net::IpAddr;

use crate::socket::AddressFamily;

pub(super) fn parse_ip(text: &str, family: AddressFamily) -> Option<IpAddr> {
    let address = text.trim().parse::<IpAddr>().ok()?.to_canonical();
    match (address, family) {
        (IpAddr::V4(_), AddressFamily::Ipv4) | (IpAddr::V6(_), AddressFamily::Ipv6) => {
            Some(address)
        }
        _ => None,
    }
}

pub(super) fn https_observed_ip(response: &str, family: AddressFamily) -> Result<IpAddr, String> {
    let (body, status) = response
        .rsplit_once('\n')
        .ok_or_else(|| "the HTTPS observer response did not include a status".to_string())?;
    if status != "200" {
        return Err(format!("the HTTPS observer returned status {status}"));
    }
    parse_ip(body, family).ok_or_else(|| {
        "the HTTPS observer did not return an address in the requested family".into()
    })
}

pub(super) fn ipv6_route_unreachable(status: Option<i32>, stderr: &str) -> bool {
    status == Some(2)
        && matches!(
            stderr.trim(),
            "RTNETLINK answers: Network is unreachable"
                | "ip: RTNETLINK answers: Network unreachable"
        )
}

pub(super) fn nameservers(text: &str) -> Result<Vec<IpAddr>, &'static str> {
    text.lines()
        .filter_map(|line| {
            let mut fields = line.split(['#', ';']).next()?.split_whitespace();
            (fields.next()? == "nameserver").then(|| {
                fields
                    .next()
                    .and_then(|address| address.parse().ok())
                    .ok_or("resolv.conf contains an unsupported nameserver address")
            })
        })
        .take(3)
        .collect()
}

pub(super) fn resolver_ip(reply: &str) -> Option<IpAddr> {
    let mut addresses = reply
        .lines()
        .flat_map(|line| {
            let mut words = line.split_whitespace();
            let first = words.next();
            let second = words.next();
            let mut addresses = Vec::new();
            if second.is_none() {
                addresses.extend(first.and_then(quoted_ip));
            } else {
                // Akamai puts the recursive address in its ns field. Other fields
                // describe EDNS Client Subnet and cannot identify a resolver.
                let mut fields = first.into_iter().chain(second).chain(words);
                while let (Some(key), Some(value)) = (fields.next(), fields.next()) {
                    if key == "\"ns\"" {
                        addresses.extend(quoted_ip(value));
                    }
                }
            }
            addresses
        })
        .map(|address| address.to_canonical());
    let first = addresses.next()?;
    addresses.all(|address| address == first).then_some(first)
}

fn quoted_ip(word: &str) -> Option<IpAddr> {
    word.strip_prefix('"')?.strip_suffix('"')?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_observation_takes_the_ip_from_a_successful_response() {
        assert_eq!(
            https_observed_ip("192.0.2.1\n\n200", AddressFamily::Ipv4),
            Ok("192.0.2.1".parse().unwrap())
        );
        assert!(
            https_observed_ip("192.0.2.1\n301", AddressFamily::Ipv4)
                .unwrap_err()
                .contains("status 301")
        );
        assert!(https_observed_ip("192.0.2.1", AddressFamily::Ipv4).is_err());
        assert!(https_observed_ip("192.0.2.1\n200", AddressFamily::Ipv6).is_err());
    }

    #[test]
    fn ipv6_no_route_requires_a_known_kernel_diagnostic_and_status() {
        const IPROUTE: &str = "RTNETLINK answers: Network is unreachable\n";
        const BUSYBOX: &str = "ip: RTNETLINK answers: Network unreachable";
        assert!(ipv6_route_unreachable(Some(2), IPROUTE));
        assert!(ipv6_route_unreachable(Some(2), BUSYBOX));
        assert!(!ipv6_route_unreachable(Some(1), IPROUTE));
        assert!(!ipv6_route_unreachable(
            Some(2),
            "RTNETLINK answers: Permission denied"
        ));
        assert!(!ipv6_route_unreachable(None, BUSYBOX));
    }

    #[test]
    fn parses_nameservers_in_order_and_honors_the_resolver_limit() {
        let text = "search example\n# nameserver 192.0.2.9\nnameserver 127.0.0.53 # stub\n\
                    nameserver 2001:db8::53;comment\nnameserver 192.0.2.53\nnameserver 192.0.2.54";
        let expected =
            ["127.0.0.53", "2001:db8::53", "192.0.2.53"].map(|ip| ip.parse::<IpAddr>().unwrap());
        assert_eq!(nameservers(text).unwrap(), expected);
        assert!(nameservers("nameserver fe80::1%eth0\nnameserver 192.0.2.53").is_err());
    }

    #[test]
    fn selects_the_recursive_ip_and_ignores_client_subnet_records() {
        let text = "\"ecs\" \"192.0.2.0/24/24\"\n\"ip\" \"192.0.2.7\"\n\"ns\" \"2001:db8::53\"";
        assert_eq!(resolver_ip(text), Some("2001:db8::53".parse().unwrap()));
        assert_eq!(
            resolver_ip("\"198.51.100.53\""),
            Some("198.51.100.53".parse().unwrap())
        );
        assert_eq!(resolver_ip("\"ip\" \"192.0.2.7\""), None);
        assert_eq!(
            resolver_ip("\"192.0.2.53\"\n\"ns\" \"198.51.100.53\""),
            None
        );
    }

    #[test]
    fn accepts_only_an_address_in_the_requested_family() {
        assert_eq!(
            parse_ip("192.0.2.1\n", AddressFamily::Ipv4),
            Some("192.0.2.1".parse().unwrap())
        );
        assert_eq!(parse_ip("192.0.2.1\n200", AddressFamily::Ipv4), None);
        assert_eq!(parse_ip("::ffff:192.0.2.1", AddressFamily::Ipv6), None);
    }
}
