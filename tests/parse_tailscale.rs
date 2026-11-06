//! The parser for `tailscale serve status --json`, against a fixture with
//! every part of the serve config that reachmap reads.

// Test helpers may panic: a failed test should stop loudly.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::net::SocketAddr;

use reachmap::parse::tailscale::{TailscaleParseError, parse_serve_status};
use reachmap::tailscale::{SharedPort, Sharing};

const SERVE_STATUS: &str = include_str!("fixtures/tailscale_serve.json");

fn targets(addresses: &[&str]) -> BTreeSet<SocketAddr> {
    addresses
        .iter()
        .map(|address| address.parse().unwrap())
        .collect()
}

fn shared(port: u16, sharing: Sharing, addresses: &[&str]) -> SharedPort {
    SharedPort {
        port,
        sharing,
        targets: targets(addresses),
    }
}

/// The targets of the one port a config with this `Proxy` value shares.
fn proxy_targets(proxy: &str) -> BTreeSet<SocketAddr> {
    let json = format!(
        r#"{{"Web": {{"host.example.ts.net:443": {{"Handlers": {{"/": {{"Proxy": "{proxy}"}}}}}}}}}}"#
    );
    parse_serve_status(&json).unwrap().remove(0).targets
}

/// The targets of the one port a config with this `TCPForward` value shares.
fn forward_targets(forward: &str) -> BTreeSet<SocketAddr> {
    let json = format!(r#"{{"TCP": {{"5432": {{"TCPForward": "{forward}"}}}}}}"#);
    parse_serve_status(&json).unwrap().remove(0).targets
}

#[test]
fn every_part_of_the_config_is_read() {
    assert_eq!(
        parse_serve_status(SERVE_STATUS).unwrap(),
        vec![
            shared(443, Sharing::Funnel, &["127.0.0.1:3000"]),
            shared(5432, Sharing::Tailnet, &["127.0.0.1:5432"]),
            shared(6379, Sharing::Tailnet, &["127.0.0.1:6379", "[::1]:6379"]),
            shared(8443, Sharing::Tailnet, &["127.0.0.1:9443", "[::1]:9443"]),
            shared(9100, Sharing::Tailnet, &["127.0.0.1:9100"]),
            shared(10000, Sharing::Funnel, &["[::1]:4000"]),
        ]
    );
}

#[test]
fn a_host_without_a_config_shares_nothing() {
    assert_eq!(parse_serve_status("null\n").unwrap(), Vec::new());
    assert_eq!(parse_serve_status("{}\n").unwrap(), Vec::new());
}

#[test]
fn a_port_without_a_handler_is_still_shared() {
    let json = r#"{"AllowFunnel": {"host.example.ts.net:443": true}}"#;
    assert_eq!(
        parse_serve_status(json).unwrap(),
        vec![shared(443, Sharing::Funnel, &[])]
    );
}

#[test]
fn a_web_server_without_handlers_is_read() {
    let json = r#"{"Web": {"host.example.ts.net:443": {"Handlers": null}}}"#;
    assert_eq!(
        parse_serve_status(json).unwrap(),
        vec![shared(443, Sharing::Tailnet, &[])]
    );
}

#[test]
fn funnel_in_a_foreground_session_marks_the_port_of_the_background_config() {
    let json = r#"{
        "TCP": {"443": {"HTTPS": true}},
        "Foreground": {"a1b2c3": {"AllowFunnel": {"host.example.ts.net:443": true}}}
    }"#;
    assert_eq!(
        parse_serve_status(json).unwrap(),
        vec![shared(443, Sharing::Funnel, &[])]
    );
}

#[test]
fn a_disabled_funnel_shares_nothing_by_itself() {
    let json = r#"{"AllowFunnel": {"host.example.ts.net:443": false}}"#;
    assert_eq!(parse_serve_status(json).unwrap(), Vec::new());
}

#[test]
fn proxy_targets_on_this_host_are_understood() {
    assert_eq!(
        proxy_targets("http://127.0.0.1:3000"),
        targets(&["127.0.0.1:3000"])
    );
    assert_eq!(
        proxy_targets("https://localhost:8443/app?x=1"),
        targets(&["127.0.0.1:8443", "[::1]:8443"])
    );
    assert_eq!(proxy_targets("http://[::1]:3000"), targets(&["[::1]:3000"]));
}

#[test]
fn a_target_on_a_wildcard_address_means_this_host() {
    assert_eq!(
        proxy_targets("http://0.0.0.0:3000"),
        targets(&["127.0.0.1:3000"])
    );
    assert_eq!(proxy_targets("http://[::]:3000"), targets(&["[::1]:3000"]));
    assert_eq!(
        forward_targets("0.0.0.0:5432"),
        targets(&["127.0.0.1:5432"])
    );
}

#[test]
fn funnel_on_one_name_counts_for_the_whole_port() {
    let json = r#"{
        "Web": {
            "one.example.ts.net:443": {"Handlers": {"/": {"Proxy": "http://127.0.0.1:3000"}}},
            "two.example.ts.net:443": {"Handlers": {"/": {"Proxy": "http://127.0.0.1:4000"}}}
        },
        "AllowFunnel": {"one.example.ts.net:443": true}
    }"#;
    assert_eq!(
        parse_serve_status(json).unwrap(),
        vec![shared(
            443,
            Sharing::Funnel,
            &["127.0.0.1:3000", "127.0.0.1:4000"]
        )]
    );
}

#[test]
fn a_proxy_target_without_a_port_uses_the_port_of_its_scheme() {
    assert_eq!(
        proxy_targets("http://192.0.2.10"),
        targets(&["192.0.2.10:80"])
    );
    assert_eq!(
        proxy_targets("https://127.0.0.1/app"),
        targets(&["127.0.0.1:443"])
    );
    assert_eq!(
        proxy_targets("https+insecure://[::1]"),
        targets(&["[::1]:443"])
    );
    assert_eq!(
        proxy_targets("http://localhost"),
        targets(&["127.0.0.1:80", "[::1]:80"])
    );
}

#[test]
fn a_user_in_a_proxy_target_is_left_out() {
    assert_eq!(
        proxy_targets("http://user:secret@127.0.0.1:3000"),
        targets(&["127.0.0.1:3000"])
    );
}

#[test]
fn proxy_targets_that_name_no_address_have_no_target() {
    for proxy in [
        "https://db.example.com:5432",
        "https://db.example.com",
        "unix:/run/app.sock",
    ] {
        assert_eq!(proxy_targets(proxy), BTreeSet::new(), "{proxy}");
    }
}

#[test]
fn tcp_forwards_are_understood() {
    assert_eq!(
        forward_targets("192.0.2.10:5432"),
        targets(&["192.0.2.10:5432"])
    );
    assert_eq!(
        forward_targets("localhost:5432"),
        targets(&["127.0.0.1:5432", "[::1]:5432"])
    );
    assert_eq!(forward_targets("unix:/run/db.sock"), BTreeSet::new());
    assert_eq!(forward_targets("db.example.com:5432"), BTreeSet::new());
}

#[test]
fn text_that_is_not_a_config_is_an_error() {
    assert!(matches!(
        parse_serve_status("No serve config\n"),
        Err(TailscaleParseError::Json(_))
    ));
    assert!(matches!(
        parse_serve_status(""),
        Err(TailscaleParseError::Json(_))
    ));
}

#[test]
fn a_key_without_a_port_is_an_error_that_names_it() {
    let json = r#"{"AllowFunnel": {"host.example.ts.net": true}}"#;
    let error = parse_serve_status(json).unwrap_err();
    assert!(matches!(error, TailscaleParseError::HostPort(_)));
    assert_eq!(
        error.to_string(),
        r#""host.example.ts.net" is not a host and port"#
    );
}

#[test]
fn a_key_with_control_characters_is_sanitised() {
    let json = r#"{"AllowFunnel": {"host\u001b[31m": true}}"#;
    let error = parse_serve_status(json).unwrap_err();
    assert!(!error.to_string().contains('\u{1b}'));
}
