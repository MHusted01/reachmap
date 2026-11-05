//! Runs the `docker inspect` parser against a fixture in the format of a real
//! Docker daemon, with invented values.

// Test helpers may panic: a failed test should stop loudly.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::net::IpAddr;

use reachmap::docker::PublishedPort;
use reachmap::parse::docker::parse_docker_inspect;
use reachmap::service::Container;

const FIXTURE: &str = include_str!("fixtures/docker_inspect.json");

fn published(address: &str, port: u16, name: &str, compose: Option<&str>) -> PublishedPort {
    PublishedPort {
        address: address.parse::<IpAddr>().unwrap(),
        port,
        container: Container {
            name: name.to_string(),
            compose_service: compose.map(str::to_string),
        },
    }
}

#[test]
fn reads_every_published_tcp_port_of_every_container() {
    assert_eq!(
        parse_docker_inspect(FIXTURE).unwrap(),
        vec![
            published("0.0.0.0", 8443, "shop-web-1", Some("web")),
            published("::", 8443, "shop-web-1", Some("web")),
            published("127.0.0.1", 8080, "shop-web-1", Some("web")),
            published("::1", 9100, "metrics", None),
        ]
    );
}
