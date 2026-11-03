//! Parser for the JSON that `ip -j addr` prints: one object per network
//! interface, each with a list of assigned addresses.

use std::net::IpAddr;

use serde::Deserialize;

use crate::network::HostAddress;

/// One interface as `ip -j addr` prints it. Fields reachmap does not use
/// (MTU, MAC address, flags, ...) are ignored.
#[derive(Deserialize)]
struct Link {
    ifname: String,
    /// Missing or empty for an interface without addresses.
    #[serde(default)]
    addr_info: Vec<AddrInfo>,
}

/// One address of an interface.
#[derive(Deserialize)]
struct AddrInfo {
    /// The address itself, e.g. `"192.168.1.20"`. serde parses the text
    /// into an `IpAddr`.
    local: IpAddr,
}

/// Turns `ip -j addr` output into one [`HostAddress`] per assigned address,
/// in the order the command printed them.
pub fn parse_ip_addr(json: &str) -> Result<Vec<HostAddress>, serde_json::Error> {
    let links: Vec<Link> = serde_json::from_str(json)?;
    Ok(links
        .into_iter()
        .flat_map(|link| {
            let Link { ifname, addr_info } = link;
            addr_info.into_iter().map(move |addr| HostAddress {
                interface: ifname.clone(),
                ip: addr.local,
            })
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(json: &str) -> Vec<(String, String)> {
        parse_ip_addr(json)
            .unwrap()
            .into_iter()
            .map(|a| (a.interface, a.ip.to_string()))
            .collect()
    }

    #[test]
    fn yields_every_address_of_every_interface_in_order() {
        let json = r#"[
            {"ifindex": 1, "ifname": "lo", "addr_info": [
                {"family": "inet", "local": "127.0.0.1", "prefixlen": 8},
                {"family": "inet6", "local": "::1", "prefixlen": 128}
            ]},
            {"ifindex": 2, "ifname": "enp1s0", "mtu": 1500, "addr_info": [
                {"family": "inet", "local": "192.168.1.20", "prefixlen": 24, "dynamic": true}
            ]}
        ]"#;

        assert_eq!(
            pairs(json),
            [
                ("lo".to_string(), "127.0.0.1".to_string()),
                ("lo".to_string(), "::1".to_string()),
                ("enp1s0".to_string(), "192.168.1.20".to_string()),
            ]
        );
    }

    #[test]
    fn interfaces_without_addresses_yield_nothing() {
        let json = r#"[
            {"ifname": "wlp2s0", "addr_info": []},
            {"ifname": "dummy0"}
        ]"#;
        assert!(pairs(json).is_empty());
    }

    #[test]
    fn no_interfaces_yield_nothing() {
        assert!(pairs("[]").is_empty());
    }

    #[test]
    fn output_that_is_not_json_is_an_error() {
        assert!(parse_ip_addr("Object \"addr\" is unknown").is_err());
    }

    #[test]
    fn an_address_that_is_not_an_ip_is_an_error() {
        let json = r#"[{"ifname": "eth0", "addr_info": [{"local": "not-an-ip"}]}]"#;
        assert!(parse_ip_addr(json).is_err());
    }

    #[test]
    fn an_interface_without_a_name_is_an_error() {
        assert!(parse_ip_addr(r#"[{"addr_info": []}]"#).is_err());
    }
}
