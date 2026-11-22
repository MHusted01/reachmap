//! Pure projectors for Nginx `listen`, `server_name`, and shared uncertainty helpers.

use std::borrow::Cow;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::nginx::{ListenAddress, ListenEndpoint, ServerName, Uncertainty, UncertaintyKind};
use crate::sanitize::sanitize;

const DEFAULT_HTTP_PORT: u16 = 80;

pub(super) fn push_uncertainty(
    uncertainties: &mut Vec<Uncertainty>,
    kind: UncertaintyKind,
    directive: &str,
    source_file: Option<&str>,
    line: usize,
) {
    uncertainties.push(Uncertainty {
        kind,
        directive: bound_directive(directive),
        source_file: source_file.map(sanitize),
        line: Some(line),
    });
}

fn bound_directive(name: &str) -> String {
    let clean = sanitize(name);
    match clean.char_indices().nth(64) {
        Some((end, _)) => format!("{}…", &clean[..end]),
        None => clean,
    }
}

pub(super) fn parse_nonzero_port(port: &str) -> Option<u16> {
    port.parse::<u16>().ok().filter(|&port| port != 0)
}

pub(super) fn parse_listen(
    args: &[Cow<'_, str>],
    source_file: Option<&str>,
    line: usize,
    uncertainties: &mut Vec<Uncertainty>,
) -> Option<ListenEndpoint> {
    let Some(first) = args.first() else {
        push_uncertainty(
            uncertainties,
            UncertaintyKind::InvalidDirective,
            "listen",
            source_file,
            line,
        );
        return None;
    };
    let raw = first.as_ref();
    if raw.starts_with("unix:") {
        push_uncertainty(
            uncertainties,
            UncertaintyKind::UnsupportedTransport,
            "listen",
            source_file,
            line,
        );
        return None;
    }

    let (address, port) = match parse_listen_addr_port(raw) {
        ListenTarget::Parsed(addr, port) => (addr, port),
        ListenTarget::UnresolvedHost => {
            push_uncertainty(
                uncertainties,
                UncertaintyKind::UnresolvedHost,
                "listen",
                source_file,
                line,
            );
            return None;
        }
        ListenTarget::Invalid => {
            push_uncertainty(
                uncertainties,
                UncertaintyKind::InvalidDirective,
                "listen",
                source_file,
                line,
            );
            return None;
        }
    };

    let mut endpoint = ListenEndpoint {
        address,
        port,
        ssl: false,
        default_server: false,
        ipv6only: None,
    };

    for option in &args[1..] {
        match option.as_ref() {
            "ssl" => endpoint.ssl = true,
            "default_server" | "default" => endpoint.default_server = true,
            "ipv6only=on" => endpoint.ipv6only = Some(true),
            "ipv6only=off" => endpoint.ipv6only = Some(false),
            flag if is_benign_listen_flag(flag) => {}
            _ => {
                push_uncertainty(
                    uncertainties,
                    UncertaintyKind::UnsupportedListenOption,
                    "listen",
                    source_file,
                    line,
                );
            }
        }
    }

    Some(endpoint)
}

enum ListenTarget {
    Parsed(ListenAddress, u16),
    UnresolvedHost,
    Invalid,
}

fn parse_listen_addr_port(raw: &str) -> ListenTarget {
    if let Some(rest) = raw.strip_prefix('[') {
        let Some((addr_str, after)) = rest.split_once(']') else {
            return ListenTarget::Invalid;
        };
        let Ok(ip) = addr_str.parse::<Ipv6Addr>() else {
            return ListenTarget::Invalid;
        };
        let address = if ip.is_unspecified() {
            ListenAddress::AnyIpv6 {}
        } else {
            ListenAddress::Ipv6 { ip }
        };
        let port = if after.is_empty() {
            DEFAULT_HTTP_PORT
        } else if let Some(port_str) = after.strip_prefix(':') {
            let Some(port) = parse_nonzero_port(port_str) else {
                return ListenTarget::Invalid;
            };
            port
        } else {
            return ListenTarget::Invalid;
        };
        return ListenTarget::Parsed(address, port);
    }

    if let Some((host, port_str)) = raw.rsplit_once(':') {
        if host.contains(':') {
            return ListenTarget::Invalid;
        }
        let Some(port) = parse_nonzero_port(port_str) else {
            return ListenTarget::Invalid;
        };
        if host.is_empty() || host == "*" {
            return ListenTarget::Parsed(ListenAddress::AnyIpv4 {}, port);
        }
        if let Ok(ip) = host.parse::<Ipv4Addr>() {
            let address = if ip.is_unspecified() {
                ListenAddress::AnyIpv4 {}
            } else {
                ListenAddress::Ipv4 { ip }
            };
            return ListenTarget::Parsed(address, port);
        }
        return ListenTarget::UnresolvedHost;
    }

    if let Some(port) = parse_nonzero_port(raw) {
        return ListenTarget::Parsed(ListenAddress::AnyIpv4 {}, port);
    }
    if raw == "*" {
        return ListenTarget::Parsed(ListenAddress::AnyIpv4 {}, DEFAULT_HTTP_PORT);
    }
    if let Ok(ip) = raw.parse::<Ipv4Addr>() {
        let address = if ip.is_unspecified() {
            ListenAddress::AnyIpv4 {}
        } else {
            ListenAddress::Ipv4 { ip }
        };
        return ListenTarget::Parsed(address, DEFAULT_HTTP_PORT);
    }
    if raw.is_empty() || raw.contains('$') {
        return ListenTarget::Invalid;
    }
    ListenTarget::UnresolvedHost
}

fn is_benign_listen_flag(flag: &str) -> bool {
    matches!(
        flag,
        "http2" | "http3" | "quic" | "reuseport" | "deferred" | "bind"
    ) || flag.starts_with("backlog=")
        || flag.starts_with("rcvbuf=")
        || flag.starts_with("sndbuf=")
        || flag.starts_with("so_keepalive=")
        || flag.starts_with("fastopen=")
        || flag.starts_with("setfib=")
        || flag.starts_with("accept_filter=")
}

pub(super) fn parse_server_names(
    args: &[Cow<'_, str>],
    source_file: Option<&str>,
    line: usize,
    uncertainties: &mut Vec<Uncertainty>,
) -> Vec<ServerName> {
    if args.is_empty() {
        push_uncertainty(
            uncertainties,
            UncertaintyKind::InvalidDirective,
            "server_name",
            source_file,
            line,
        );
        return Vec::new();
    }

    let mut names = Vec::new();
    for arg in args {
        let raw = arg.as_ref();
        if raw.starts_with('~') {
            push_uncertainty(
                uncertainties,
                UncertaintyKind::RegexMatch,
                "server_name",
                source_file,
                line,
            );
            continue;
        }
        if raw.contains('$') {
            push_uncertainty(
                uncertainties,
                UncertaintyKind::DynamicRouting,
                "server_name",
                source_file,
                line,
            );
            continue;
        }
        if raw == "_" || raw.is_empty() {
            names.push(ServerName::CatchAll {});
            continue;
        }
        if let Some(suffix) = raw.strip_prefix("*.").or_else(|| raw.strip_prefix('.')) {
            if suffix.is_empty() || suffix.contains('*') {
                push_uncertainty(
                    uncertainties,
                    UncertaintyKind::DynamicRouting,
                    "server_name",
                    source_file,
                    line,
                );
            } else {
                names.push(ServerName::LeadingWildcard {
                    suffix: sanitize(&suffix.to_ascii_lowercase()),
                });
            }
            continue;
        }
        if let Some(prefix) = raw.strip_suffix(".*") {
            if prefix.is_empty() || prefix.contains('*') {
                push_uncertainty(
                    uncertainties,
                    UncertaintyKind::DynamicRouting,
                    "server_name",
                    source_file,
                    line,
                );
            } else {
                names.push(ServerName::TrailingWildcard {
                    prefix: sanitize(&prefix.to_ascii_lowercase()),
                });
            }
            continue;
        }
        if raw.contains('*') {
            push_uncertainty(
                uncertainties,
                UncertaintyKind::DynamicRouting,
                "server_name",
                source_file,
                line,
            );
            continue;
        }
        names.push(ServerName::Exact {
            host: sanitize(&raw.to_ascii_lowercase()),
        });
    }
    names
}
