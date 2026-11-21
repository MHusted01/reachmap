//! Keep route identity and recover individual records from partial Serve status.

use std::collections::BTreeSet;
use std::fmt;
use std::net::SocketAddr;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::{default_port, proxy_addresses};
use crate::sanitize::sanitize;
use crate::tailscale::Sharing;

type Object = Map<String, Value>;

#[derive(Debug, Default)]
pub(crate) struct ConfiguredRoutes {
    pub routes: Vec<Route>,
    pub notes: Vec<String>,
    pub unsupported_services: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct Route {
    pub entry: EntryPoint,
    pub mount: Option<String>,
    pub backend: Backend,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct EntryPoint {
    pub host: Option<String>,
    pub port: u16,
    pub sharing: Option<Sharing>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum Backend {
    HttpProxy {
        endpoint: String,
        targets: Vec<SocketAddr>,
    },
    Unsupported {
        handler: UnsupportedHandler,
        endpoint: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum UnsupportedHandler {
    InvalidConfiguration,
    TcpForwarding,
    UnknownTcp,
    UnknownWeb,
    FileOrDirectory,
    StaticText,
    Redirect,
    UnixSocketProxy,
    ProxyScheme,
}

impl fmt::Display for UnsupportedHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidConfiguration => "invalid configuration",
            Self::TcpForwarding => "TCP forwarding",
            Self::UnknownTcp => "unrecognised TCP handler",
            Self::UnknownWeb => "unrecognised web handler",
            Self::FileOrDirectory => "file or directory",
            Self::StaticText => "static text",
            Self::Redirect => "redirect",
            Self::UnixSocketProxy => "Unix socket proxy",
            Self::ProxyScheme => "proxy scheme",
        })
    }
}

pub(crate) fn parse_routes(json: &str) -> Result<ConfiguredRoutes, serde_json::Error> {
    let root: Option<Object> = serde_json::from_str(json)?;
    let mut report = ConfiguredRoutes::default();
    let Some(root) = root.as_ref() else {
        return Ok(report);
    };

    let foreground = optional_map(root, "Foreground", &mut report.notes);
    let configs: Vec<&Object> = std::iter::once(root)
        .chain(
            foreground
                .into_iter()
                .flat_map(Object::values)
                .filter_map(|value| {
                    let config = value.as_object();
                    if config.is_none() {
                        report.notes.push("invalid foreground configuration".into());
                    }
                    config
                }),
        )
        .collect();
    let mut funnel = Funnel {
        incomplete: !report.notes.is_empty(),
        ..Funnel::default()
    };
    for config in &configs {
        funnel.read(config, &mut report.notes);
    }
    for config in configs {
        report.read_web(config, &funnel);
        report.read_tcp(config, &funnel);
        report.unsupported_services |= optional_map(config, "Services", &mut report.notes)
            .is_some_and(|services| !services.is_empty());
    }
    Ok(report)
}

#[derive(Default)]
struct Funnel<'a> {
    enabled: BTreeSet<&'a str>,
    incomplete: bool,
}

impl<'a> Funnel<'a> {
    fn read(&mut self, config: &'a Object, notes: &mut Vec<String>) {
        let before = notes.len();
        if let Some(permissions) = optional_map(config, "AllowFunnel", notes) {
            for (entry, allowed) in permissions {
                match (host_port(entry), allowed.as_bool()) {
                    (Some(_), Some(true)) => {
                        self.enabled.insert(entry);
                    }
                    (Some(_), Some(false)) => {}
                    _ => notes.push("invalid AllowFunnel entry".into()),
                }
            }
        }
        self.incomplete |= notes.len() != before;
    }

    fn scope(&self, key: &str) -> Option<Sharing> {
        if self.enabled.contains(key) {
            Some(Sharing::Funnel)
        } else {
            (!self.incomplete).then_some(Sharing::Tailnet)
        }
    }
}

impl ConfiguredRoutes {
    fn read_web(&mut self, config: &Object, funnel: &Funnel<'_>) {
        let Some(web) = optional_map(config, "Web", &mut self.notes) else {
            return;
        };
        for (key, server) in web {
            let (Some((host, port)), Some(server)) = (host_port(key), server.as_object()) else {
                self.notes.push("invalid Web entry point".into());
                continue;
            };
            let handlers = optional_map(server, "Handlers", &mut self.notes);
            for (mount, handler) in handlers.into_iter().flatten() {
                let backend = handler
                    .as_object()
                    .and_then(read_backend)
                    .unwrap_or_else(|| {
                        self.notes.push("invalid Web handler".into());
                        unsupported(UnsupportedHandler::InvalidConfiguration, None)
                    });
                self.routes.push(Route {
                    entry: EntryPoint {
                        host: Some(sanitize(host)),
                        port,
                        sharing: funnel.scope(key),
                    },
                    mount: Some(sanitize(mount)),
                    backend,
                });
            }
        }
    }

    fn read_tcp(&mut self, config: &Object, funnel: &Funnel<'_>) {
        let Some(tcp) = optional_map(config, "TCP", &mut self.notes) else {
            return;
        };
        for (port, handler) in tcp {
            let (Some(port), Some(handler)) = (parse_port(port), handler.as_object()) else {
                self.notes.push("invalid TCP entry".into());
                continue;
            };
            // A TCP entry with only HTTP(S) enabled dispatches to the Web handlers.
            let forward = handler
                .get("TCPForward")
                .and_then(Value::as_str)
                .filter(|target| !target.is_empty());
            if forward.is_none()
                && ["HTTP", "HTTPS"]
                    .iter()
                    .any(|key| handler.get(*key) == Some(&Value::Bool(true)))
            {
                continue;
            }
            let configured_host = handler
                .get("TerminateTLS")
                .and_then(Value::as_str)
                .filter(|host| !host.is_empty());
            let matching_funnels = funnel
                .enabled
                .iter()
                .filter_map(|key| host_port(key))
                .filter(|&(_, entry_port)| entry_port == port);
            let mut entries: Vec<_> = matching_funnels
                .map(|(host, _)| (Some(host), Some(Sharing::Funnel)))
                .collect();
            if entries.is_empty()
                || configured_host
                    .is_some_and(|known| !entries.iter().any(|(host, _)| *host == Some(known)))
            {
                let scope = (!funnel.incomplete).then_some(Sharing::Tailnet);
                entries.push((configured_host, scope));
            }
            for (host, sharing) in entries {
                self.routes.push(Route {
                    entry: EntryPoint {
                        host: host.map(sanitize),
                        port,
                        sharing,
                    },
                    mount: None,
                    backend: match forward {
                        Some(target) => unsupported(
                            UnsupportedHandler::TcpForwarding,
                            Some(display_endpoint(target)),
                        ),
                        None => unsupported(UnsupportedHandler::UnknownTcp, None),
                    },
                });
            }
        }
    }
}

fn optional_map<'a>(object: &'a Object, key: &str, notes: &mut Vec<String>) -> Option<&'a Object> {
    match object.get(key) {
        None | Some(Value::Null) => None,
        Some(Value::Object(map)) => Some(map),
        Some(_) => {
            notes.push(format!("invalid {key} section"));
            None
        }
    }
}

fn host_port(key: &str) -> Option<(&str, u16)> {
    let (host, port) = key.rsplit_once(':')?;
    (!host.is_empty()).then_some((host, parse_port(port)?))
}

fn parse_port(port: &str) -> Option<u16> {
    port.parse().ok().filter(|&port| port != 0)
}

fn read_backend(handler: &Object) -> Option<Backend> {
    let mut kinds = ["Proxy", "Path", "Text", "Redirect"]
        .into_iter()
        .filter_map(|kind| handler.get(kind).map(|value| (kind, value)))
        .filter(|(_, value)| !value.is_null() && value.as_str() != Some(""));
    let Some((kind, value)) = kinds.next() else {
        return Some(unsupported(UnsupportedHandler::UnknownWeb, None));
    };
    if kinds.next().is_some() {
        return None;
    }
    let value = value.as_str()?;
    Some(match kind {
        "Proxy" => proxy_backend(value),
        "Path" => unsupported(UnsupportedHandler::FileOrDirectory, Some(sanitize(value))),
        "Text" => unsupported(UnsupportedHandler::StaticText, None),
        _ => unsupported(UnsupportedHandler::Redirect, Some(display_endpoint(value))),
    })
}

fn unsupported(handler: UnsupportedHandler, endpoint: Option<String>) -> Backend {
    Backend::Unsupported { handler, endpoint }
}

fn proxy_backend(value: &str) -> Backend {
    let endpoint = display_endpoint(value);
    if value.starts_with("unix:") {
        return unsupported(UnsupportedHandler::UnixSocketProxy, Some(endpoint));
    }
    let targets = match value.split_once("://") {
        Some((scheme, _)) if default_port(scheme).is_none() => {
            return unsupported(UnsupportedHandler::ProxyScheme, Some(endpoint));
        }
        Some(_) => proxy_addresses(value),
        None if parse_port(value).is_some() => {
            proxy_addresses(&format!("http://127.0.0.1:{value}"))
        }
        None => proxy_addresses(&format!("http://{value}")),
    };
    let targets = targets
        .into_iter()
        .filter(|target| target.port() != 0 && target.ip().to_canonical().is_loopback())
        .collect();
    Backend::HttpProxy { endpoint, targets }
}

/// URL credentials, queries and fragments can carry secrets. The authority and
/// path still identify the backend in this opt-in report.
fn display_endpoint(value: &str) -> String {
    let value = value.split(['?', '#']).next().unwrap_or_default();
    let (prefix, rest) = if value.starts_with("//") {
        value.split_at(2)
    } else {
        value
            .find("://")
            .map_or(("", value), |index| value.split_at(index + 3))
    };
    let (authority, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
    let authority = authority.rsplit('@').next().unwrap_or_default();
    sanitize(&format!("{prefix}{authority}{path}"))
}
