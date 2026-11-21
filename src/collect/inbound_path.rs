//! Read-only Linux evidence collection for an inbound TCP flow.

use std::fs::File;
use std::io::{self, ErrorKind};
use std::net::IpAddr;
use std::path::Path;

use super::{command, linux};
use crate::artifact::read_limited;
use crate::errors::render_chain;
use crate::host_input_snapshot::Evidence;
use crate::inbound_path::{Flow, Listener, ListenerOptions, PathEvidence};
use crate::parse::proc_net::parse_proc_net;
use crate::socket::{AddressFamily, Protocol};
use crate::socket_options::read_socket_options;

mod docker;

const MAX_COLLECT_BYTES: u64 = 4 * 1024 * 1024;

pub(crate) fn capture(flow: &Flow) -> PathEvidence {
    let family = match flow.family() {
        AddressFamily::Ipv4 => "-4",
        AddressFamily::Ipv6 => "-6",
    };
    let mut evidence = PathEvidence {
        link: ip(&["-j", "-details", "link", "show", "dev", &flow.ingress]),
        ipv6_disabled: (flow.family() == AddressFamily::Ipv6).then(|| ipv6_disabled(&flow.ingress)),
        legacy_tables: legacy_tables(flow.family()),
        xfrm_policies: ip(&["xfrm", "policy", "list"]),
        xfrm_defaults: ip(&["xfrm", "policy", "getdefault"]),
        nftables: run(linux::NFT_PATHS, linux::NFT_ARGS, "nft"),
        routing_rules: ip(&[family, "-j", "rule", "show"]),
        route: route(flow, flow.destination, flow.port.get()),
        listeners: match listeners(
            flow.family(),
            flow.port.get(),
            Path::new("/proc/thread-self/net"),
        ) {
            Ok(data) => Evidence::Collected { data },
            Err(reason) => Evidence::Failed { reason },
        },
        docker: None,
    };
    evidence.docker = docker::capture(flow, &evidence);
    evidence
}

fn route(flow: &Flow, destination: IpAddr, port: u16) -> Evidence<String> {
    let family = if destination.is_ipv4() { "-4" } else { "-6" };
    ip(&[
        family,
        "-j",
        "route",
        "get",
        &destination.to_string(),
        "from",
        &flow.source.to_string(),
        "iif",
        &flow.ingress,
        "ipproto",
        "tcp",
        "dport",
        &port.to_string(),
    ])
}

fn ip(args: &[&str]) -> Evidence<String> {
    run(linux::IP_PATHS, args, "ip")
}

fn run(paths: &[&str], args: &[&str], name: &str) -> Evidence<String> {
    let Some(program) = paths.iter().find(|path| Path::new(path).is_file()) else {
        return Evidence::Unavailable {
            reason: format!("{name} was not found in the standard system paths"),
        };
    };
    match command::run_isolated_with_limit(program, args, linux::COMMAND_TIMEOUT, MAX_COLLECT_BYTES)
    {
        Ok(data) => Evidence::Collected { data },
        Err(error) => Evidence::Failed {
            reason: render_chain(&error),
        },
    }
}

fn read_proc(path: &Path) -> io::Result<String> {
    let file = File::open(path)?;
    read_limited(file, MAX_COLLECT_BYTES)?
        .ok_or_else(|| io::Error::other("kernel table exceeds the capture size limit"))
}

fn ipv6_disabled(ingress: &str) -> Evidence<bool> {
    let path = Path::new("/proc/sys/net/ipv6/conf")
        .join(ingress)
        .join("disable_ipv6");
    match read_proc(&path).as_deref().map(str::trim) {
        Ok("0") => Evidence::Collected { data: false },
        Ok("1") => Evidence::Collected { data: true },
        Ok(_) => Evidence::Failed {
            reason: "invalid value for ingress IPv6 disable_ipv6".to_owned(),
        },
        Err(error) => Evidence::Failed {
            reason: format!("could not read {}: {error}", path.display()),
        },
    }
}

fn legacy_tables(family: AddressFamily) -> Evidence<String> {
    let file = match family {
        AddressFamily::Ipv4 => "/proc/thread-self/net/ip_tables_names",
        AddressFamily::Ipv6 => "/proc/thread-self/net/ip6_tables_names",
    };
    match read_proc(Path::new(file)) {
        Ok(data) => Evidence::Collected { data },
        Err(error)
            if error.kind() == ErrorKind::NotFound
                && Path::new("/proc/thread-self/net").is_dir() =>
        {
            // Legacy xtables only creates this file when the backend is registered.
            Evidence::Collected {
                data: String::new(),
            }
        }
        Err(error) => Evidence::Failed {
            reason: format!("could not read {file}: {error}"),
        },
    }
}

fn listeners(family: AddressFamily, port: u16, directory: &Path) -> Result<Vec<Listener>, String> {
    let mut candidates = Vec::new();
    let sources = linux::socket_sources().into_iter().filter(|source| {
        source.protocol == Protocol::Tcp
            && (family == AddressFamily::Ipv4 || source.family == AddressFamily::Ipv6)
    });
    for source in sources {
        let file = match source.family {
            AddressFamily::Ipv4 => "tcp",
            AddressFamily::Ipv6 => "tcp6",
        };
        let path = directory.join(file);
        let text = match read_proc(&path) {
            Ok(text) => text,
            Err(error) if source.optional && error.kind() == ErrorKind::NotFound => continue,
            Err(error) => return Err(format!("could not read {}: {error}", path.display())),
        };
        let sockets = parse_proc_net(&text, source.family, source.protocol)
            .map_err(|error| format!("could not parse {}: {error}", path.display()))?;
        candidates.extend(sockets.into_iter().filter(|socket| socket.port == port));
    }
    if candidates.is_empty() {
        return Ok(Vec::new());
    }
    let options = read_socket_options();
    Ok(candidates
        .into_iter()
        .map(|socket| Listener {
            address: socket.address,
            inode: socket.inode,
            options: options
                .by_inode
                .get(&socket.inode)
                .map(|options| ListenerOptions {
                    bound_device: options.bound_device,
                    ipv6_only: options.ipv6_only,
                }),
        })
        .collect())
}
