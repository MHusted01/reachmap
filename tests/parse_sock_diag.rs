//! Parses replies captured from a real kernel, one dump per address family.
//! The listeners used invented ports; socket cookies and cgroup IDs are zeroed.
//! Interface 2 was `eth0` and interface 3 a dummy link with `fe80::1`.

// Test helpers may panic: a failed test should stop loudly.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use reachmap::parse::sock_diag::{Dump, parse_dump};
use reachmap::socket::SocketOptions;

const IPV4: &[u8] = include_bytes!("fixtures/sock_diag_ipv4.bin");
const IPV6: &[u8] = include_bytes!("fixtures/sock_diag_ipv6.bin");
const UDP_IPV4: &[u8] = include_bytes!("fixtures/sock_diag_udp_ipv4.bin");
const UDP_IPV6: &[u8] = include_bytes!("fixtures/sock_diag_udp_ipv6.bin");

fn options(bound_device: Option<u32>, ipv6_only: bool) -> SocketOptions {
    SocketOptions {
        bound_device,
        ipv6_only,
    }
}

#[test]
fn an_ipv4_dump_gives_the_bound_device_of_each_socket() {
    let Dump { sockets, done } = parse_dump(IPV4).unwrap();

    assert!(done);
    assert_eq!(
        sockets,
        [
            (68171, options(Some(2), false)),
            (68170, options(None, false)),
        ]
    );
}

#[test]
fn an_ipv6_dump_gives_the_ipv6_only_flag_of_each_socket() {
    let Dump { sockets, done } = parse_dump(IPV6).unwrap();

    assert!(done);
    assert_eq!(
        sockets,
        [
            (68172, options(None, false)),
            (68173, options(None, true)),
            (68174, options(Some(2), true)),
            // The kernel binds a link-local socket to its scope's interface.
            (68175, options(Some(3), true)),
        ]
    );
}

#[test]
fn a_udp_ipv4_dump_gives_the_bound_device_of_each_socket() {
    let Dump { sockets, done } = parse_dump(UDP_IPV4).unwrap();

    assert!(done);
    assert_eq!(
        sockets,
        [
            (81557, options(None, false)),
            (81558, options(Some(2), false)),
        ]
    );
}

#[test]
fn a_udp_ipv6_dump_gives_the_ipv6_only_flag_of_each_socket() {
    let Dump { sockets, done } = parse_dump(UDP_IPV6).unwrap();

    assert!(done);
    assert_eq!(
        sockets,
        [(81559, options(None, false)), (81560, options(None, true)),]
    );
}
