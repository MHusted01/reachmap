//! Pure projectors for Nginx `upstream server` and `proxy_pass` targets.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::nginx::{
    ProxyScheme, ProxyTarget, Uncertainty, UncertaintyKind, UnsupportedProxyReason, UpstreamGroup,
    UpstreamServer,
};
use crate::sanitize::sanitize;

use super::listen::{parse_nonzero_port, push_uncertainty};

const DEFAULT_HTTP_PORT: u16 = 80;
const DEFAULT_HTTPS_PORT: u16 = 443;

pub(super) fn parse_upstream_server(
    args: &[Cow<'_, str>],
    source_file: Option<&str>,
    line: usize,
    uncertainties: &mut Vec<Uncertainty>,
) -> Option<UpstreamServer> {
    let Some(first) = args.first() else {
        push_uncertainty(
            uncertainties,
            UncertaintyKind::InvalidDirective,
            "server",
            source_file,
            line,
        );
        return None;
    };
    let raw = first.as_ref();
    if raw.contains('$') {
        push_uncertainty(
            uncertainties,
            UncertaintyKind::DynamicTarget,
            "server",
            source_file,
            line,
        );
        return None;
    }
    if raw.starts_with("unix:") {
        push_uncertainty(
            uncertainties,
            UncertaintyKind::UnsupportedTransport,
            "server",
            source_file,
            line,
        );
        return None;
    }

    let targets = match resolve_host_port(raw, DEFAULT_HTTP_PORT) {
        HostPortResolution::Resolved(targets) => targets,
        HostPortResolution::UnresolvedHost { .. } => {
            push_uncertainty(
                uncertainties,
                UncertaintyKind::UnresolvedHost,
                "server",
                source_file,
                line,
            );
            return None;
        }
        HostPortResolution::Invalid => {
            push_uncertainty(
                uncertainties,
                UncertaintyKind::InvalidDirective,
                "server",
                source_file,
                line,
            );
            return None;
        }
    };

    let mut backup = false;
    let mut down = false;
    for flag in &args[1..] {
        match flag.as_ref() {
            "backup" => backup = true,
            "down" => down = true,
            "resolve" => {
                push_uncertainty(
                    uncertainties,
                    UncertaintyKind::UnresolvedHost,
                    "server",
                    source_file,
                    line,
                );
                return None;
            }
            opt if is_benign_upstream_param(opt) => {}
            _ => {
                push_uncertainty(
                    uncertainties,
                    UncertaintyKind::UnmodeledDirective,
                    "server",
                    source_file,
                    line,
                );
                return None;
            }
        }
    }

    Some(UpstreamServer {
        targets,
        backup,
        down,
    })
}

fn is_benign_upstream_param(flag: &str) -> bool {
    flag.starts_with("weight=")
        || flag.starts_with("max_conns=")
        || flag.starts_with("max_fails=")
        || flag.starts_with("fail_timeout=")
        || flag.starts_with("slow_start=")
}

pub(super) fn parse_proxy_pass(
    args: &[Cow<'_, str>],
    upstreams: &BTreeMap<String, UpstreamGroup>,
    source_file: Option<&str>,
    line: usize,
    uncertainties: &mut Vec<Uncertainty>,
) -> ProxyTarget {
    if args.len() != 1 {
        push_uncertainty(
            uncertainties,
            UncertaintyKind::InvalidDirective,
            "proxy_pass",
            source_file,
            line,
        );
        return ProxyTarget::Unsupported {
            reason: UnsupportedProxyReason::InvalidTarget,
        };
    }

    let raw = args[0].as_ref();
    if raw.contains('$') {
        push_uncertainty(
            uncertainties,
            UncertaintyKind::DynamicTarget,
            "proxy_pass",
            source_file,
            line,
        );
        return ProxyTarget::Unsupported {
            reason: UnsupportedProxyReason::Variable,
        };
    }
    if raw.starts_with("unix:")
        || raw.starts_with("http://unix:")
        || raw.starts_with("https://unix:")
    {
        push_uncertainty(
            uncertainties,
            UncertaintyKind::UnsupportedTransport,
            "proxy_pass",
            source_file,
            line,
        );
        return ProxyTarget::Unsupported {
            reason: UnsupportedProxyReason::UnixSocket,
        };
    }

    let without_qf = raw.split(['?', '#']).next().unwrap_or("");
    let Some((scheme_str, rest)) = without_qf.split_once("://") else {
        push_uncertainty(
            uncertainties,
            UncertaintyKind::InvalidDirective,
            "proxy_pass",
            source_file,
            line,
        );
        return ProxyTarget::Unsupported {
            reason: UnsupportedProxyReason::InvalidTarget,
        };
    };

    let (scheme, scheme_name, default_port) = match scheme_str.to_ascii_lowercase().as_str() {
        "http" => (ProxyScheme::Http, "http", DEFAULT_HTTP_PORT),
        "https" => (ProxyScheme::Https, "https", DEFAULT_HTTPS_PORT),
        _ => {
            push_uncertainty(
                uncertainties,
                UncertaintyKind::UnsupportedTransport,
                "proxy_pass",
                source_file,
                line,
            );
            return ProxyTarget::Unsupported {
                reason: UnsupportedProxyReason::UnsupportedScheme,
            };
        }
    };

    let path_start = rest.find('/').unwrap_or(rest.len());
    let (authority, path) = rest.split_at(path_start);
    let host_port = authority.rsplit('@').next().unwrap_or("");
    if host_port.is_empty() {
        push_uncertainty(
            uncertainties,
            UncertaintyKind::InvalidDirective,
            "proxy_pass",
            source_file,
            line,
        );
        return ProxyTarget::Unsupported {
            reason: UnsupportedProxyReason::InvalidTarget,
        };
    }

    if !host_port.contains(':')
        && let Some(group) = upstreams.get(host_port)
    {
        let targets = group
            .servers
            .iter()
            .filter(|server| !server.down)
            .flat_map(|server| server.targets.iter().copied())
            .collect();
        return ProxyTarget::Upstream {
            scheme,
            name: group.name.clone(),
            targets,
            complete: group.complete,
        };
    }

    match resolve_host_port(host_port, default_port) {
        HostPortResolution::Resolved(targets) => ProxyTarget::StaticHttp {
            scheme,
            endpoint: sanitize(&format!("{scheme_name}://{host_port}{path}")),
            targets,
        },
        HostPortResolution::UnresolvedHost { host, port } => {
            push_uncertainty(
                uncertainties,
                UncertaintyKind::UnresolvedHost,
                "proxy_pass",
                source_file,
                line,
            );
            ProxyTarget::UnresolvedHost {
                scheme,
                host: sanitize(&host),
                port,
            }
        }
        HostPortResolution::Invalid => {
            push_uncertainty(
                uncertainties,
                UncertaintyKind::InvalidDirective,
                "proxy_pass",
                source_file,
                line,
            );
            ProxyTarget::Unsupported {
                reason: UnsupportedProxyReason::InvalidTarget,
            }
        }
    }
}

enum HostPortResolution {
    Resolved(Vec<SocketAddr>),
    UnresolvedHost { host: String, port: u16 },
    Invalid,
}

fn resolve_host_port(host_port: &str, default_port: u16) -> HostPortResolution {
    let (host, port) = if let Some(rest) = host_port.strip_prefix('[') {
        let Some((addr, after)) = rest.split_once(']') else {
            return HostPortResolution::Invalid;
        };
        let port = if after.is_empty() {
            default_port
        } else if let Some(port_str) = after.strip_prefix(':') {
            let Some(port) = parse_nonzero_port(port_str) else {
                return HostPortResolution::Invalid;
            };
            port
        } else {
            return HostPortResolution::Invalid;
        };
        if let Ok(ip) = addr.parse::<Ipv6Addr>() {
            return HostPortResolution::Resolved(vec![SocketAddr::new(IpAddr::V6(ip), port)]);
        }
        return HostPortResolution::Invalid;
    } else if let Some((host, port_str)) = host_port.rsplit_once(':') {
        if host.is_empty() || host.contains(':') {
            return HostPortResolution::Invalid;
        }
        let Some(port) = parse_nonzero_port(port_str) else {
            return HostPortResolution::Invalid;
        };
        (host, port)
    } else {
        (host_port, default_port)
    };

    if host.is_empty() {
        return HostPortResolution::Invalid;
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return HostPortResolution::Resolved(vec![SocketAddr::new(ip, port)]);
    }
    if host.eq_ignore_ascii_case("localhost") {
        return HostPortResolution::Resolved(vec![
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port),
        ]);
    }
    HostPortResolution::UnresolvedHost {
        host: host.to_owned(),
        port,
    }
}
