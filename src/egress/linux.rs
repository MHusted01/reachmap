//! Runs fixed host tools in the host and the pinned container net namespace.

use std::fs::{self, File};
use std::io::{self, Read};
use std::net::IpAddr;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::Duration;

use rustix::fs::{Mode, OFlags, ResolveFlags, open, openat2};

use super::parse::{nameservers, parse_ip, resolver_ip};
use super::{ContainerRef, DnsSample, Observation, Observations, ObserverName, Report, SetupError};
use crate::collect::{CollectError, command};
use crate::docker::engine::egress as docker;
use crate::errors::render_chain;
use crate::socket::AddressFamily;

const TIMEOUT: Duration = Duration::from_secs(5);
const MAX_RESOLV_CONF: u64 = 16 * 1024;

pub(super) fn check(
    target: ContainerRef,
    ip_host: &ObserverName,
    dns_name: &ObserverName,
) -> Result<Report, SetupError> {
    let tools = Tools::find()?;
    let shared = docker::inspect(&target)?;
    let namespace = Entry::open(&shared)?;
    let container_dns = container_resolv_conf(shared.workload.pid);
    verify_identity(&target, &shared)?;

    let host = Probe {
        tools: &tools,
        netns: None,
    };
    let container = Probe {
        tools: &tools,
        netns: Some(&namespace.argument),
    };
    let ipv4 = host.endpoint(ip_host, AddressFamily::Ipv4);
    let ipv6 = host.endpoint(ip_host, AddressFamily::Ipv6);
    let host = host.observe(
        ip_host,
        dns_name,
        &ipv4,
        &ipv6,
        fs::read_to_string("/etc/resolv.conf"),
    );
    let observed = container.observe(ip_host, dns_name, &ipv4, &ipv6, container_dns);
    let unreachable_ipv6_observer = ipv6
        .ok()
        .filter(|&destination| observed.ipv6.is_err() && container.no_ipv6_route(destination));
    verify_identity(&target, &shared)?;

    Ok(Report {
        target,
        host,
        container: observed,
        unreachable_ipv6_observer,
    })
}

fn verify_identity(
    target: &ContainerRef,
    initial: &docker::SharedNetwork,
) -> Result<(), SetupError> {
    if docker::inspect(target)? == *initial {
        Ok(())
    } else {
        Err(SetupError::ContainerChanged)
    }
}

struct Entry {
    _file: File,
    argument: String,
}

impl Entry {
    fn open(shared: &docker::SharedNetwork) -> Result<Self, SetupError> {
        let read_netns = |pid| {
            File::open(format!("/proc/{pid}/ns/net"))
                .map_err(|source| SetupError::OpenNamespace { pid, source })
        };
        let workload = read_netns(shared.workload.pid)?;
        let peer = read_netns(shared.peer.pid)?;
        let host = read_netns(std::process::id())?;
        let identity = |file: &File| {
            file.metadata()
                .map(|metadata| (metadata.dev(), metadata.ino()))
                .map_err(SetupError::NamespaceIdentity)
        };
        let workload_id = identity(&workload)?;
        if workload_id != identity(&peer)? {
            return Err(SetupError::DifferentNamespace);
        }
        if workload_id == identity(&host)? {
            return Err(SetupError::HostNetwork);
        }
        // Keep the namespace pinned across probes instead of asking nsenter to
        // look up a container PID that may have been recycled.
        let argument = format!(
            "--net=/proc/{}/fd/{}",
            std::process::id(),
            workload.as_raw_fd()
        );
        Ok(Self {
            _file: workload,
            argument,
        })
    }
}

fn container_resolv_conf(pid: u32) -> io::Result<String> {
    let root = File::open(format!("/proc/{pid}/root"))?;
    read_resolv_conf(&root)
}

fn read_resolv_conf(root: &File) -> io::Result<String> {
    // Resolve even absolute symlinks inside the container's root. Opening a
    // path handle first lets us reject devices and pipes before reading it.
    let file = File::from(openat2(
        root,
        "etc/resolv.conf",
        OFlags::PATH | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::IN_ROOT | ResolveFlags::NO_MAGICLINKS,
    )?);
    if !file.metadata()?.is_file() {
        return Err(io::Error::other("resolv.conf is not a regular file"));
    }
    let mut text = String::new();
    File::from(open(
        format!("/proc/self/fd/{}", file.as_raw_fd()),
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?)
    .take(MAX_RESOLV_CONF + 1)
    .read_to_string(&mut text)?;
    if text.len() as u64 > MAX_RESOLV_CONF {
        return Err(io::Error::other("resolv.conf is too large"));
    }
    Ok(text)
}

struct Tools {
    nsenter: &'static str,
    curl: &'static str,
    dig: &'static str,
    ip: &'static str,
}

impl Tools {
    fn find() -> Result<Self, SetupError> {
        Ok(Self {
            nsenter: installed("nsenter", &["/usr/bin/nsenter", "/bin/nsenter"])?,
            curl: installed("curl", &["/usr/bin/curl", "/bin/curl"])?,
            dig: installed("dig", &["/usr/bin/dig", "/bin/dig"])?,
            ip: installed(
                "ip",
                &["/usr/sbin/ip", "/usr/bin/ip", "/sbin/ip", "/bin/ip"],
            )?,
        })
    }
}

fn installed(name: &'static str, candidates: &[&'static str]) -> Result<&'static str, SetupError> {
    candidates
        .iter()
        .copied()
        .find(|path| {
            Path::new(path)
                .metadata()
                .is_ok_and(|file| file.is_file() && file.uid() == 0 && file.mode() & 0o022 == 0)
        })
        .ok_or(SetupError::MissingTool(name))
}

struct Probe<'a> {
    tools: &'a Tools,
    netns: Option<&'a str>,
}

impl Probe<'_> {
    fn run(&self, program: &str, args: &[&str]) -> Result<String, CollectError> {
        if let Some(netns) = self.netns {
            let args: Vec<_> = [netns, "--", program]
                .into_iter()
                .chain(args.iter().copied())
                .collect();
            command::run_isolated(self.tools.nsenter, &args, TIMEOUT)
        } else {
            command::run_isolated(program, args, TIMEOUT)
        }
    }

    fn query(
        &self,
        server: Option<IpAddr>,
        name: &ObserverName,
        record: &str,
    ) -> Observation<String> {
        let name = format!("{}.", name.0);
        let server = server.map(|address| format!("@{address}"));
        let mut args = vec!["-r", "+short", "+tries=1", "+time=2", "+nosearch"];
        args.extend(server.as_deref());
        args.extend([&name, record]);
        self.run(self.tools.dig, &args)
            .map_err(|error| render_chain(&error))
    }

    fn endpoint(&self, host: &ObserverName, family: AddressFamily) -> Observation<IpAddr> {
        let record = match family {
            AddressFamily::Ipv4 => "A",
            AddressFamily::Ipv6 => "AAAA",
        };
        self.query(None, host, record)?
            .lines()
            .find_map(|line| parse_ip(line, family))
            .ok_or_else(|| {
                format!(
                    "{} returned no {record} address for the HTTPS observer",
                    host.0
                )
            })
    }

    fn observe(
        &self,
        ip_host: &ObserverName,
        dns_name: &ObserverName,
        ipv4: &Observation<IpAddr>,
        ipv6: &Observation<IpAddr>,
        resolv_conf: io::Result<String>,
    ) -> Observations {
        Observations {
            ipv4: self.public_ip(ip_host, ipv4),
            ipv6: self.public_ip(ip_host, ipv6),
            dns: self.dns(dns_name, resolv_conf),
        }
    }

    fn public_ip(
        &self,
        host: &ObserverName,
        endpoint: &Observation<IpAddr>,
    ) -> Observation<IpAddr> {
        let address = *endpoint.as_ref().map_err(Clone::clone)?;
        let (family, force_family, literal) = match address {
            IpAddr::V4(ip) => (AddressFamily::Ipv4, "--ipv4", ip.to_string()),
            IpAddr::V6(ip) => (AddressFamily::Ipv6, "--ipv6", format!("[{ip}]")),
        };
        let resolve = format!("{}:443:{literal}", host.0);
        let url = format!("https://{}/", host.0);
        let response = self
            .run(
                self.tools.curl,
                &[
                    "--disable",
                    "--silent",
                    "--show-error",
                    "--fail",
                    "--max-time",
                    "4",
                    "--max-filesize",
                    "1024",
                    "--noproxy",
                    "*",
                    "--proto",
                    "=https",
                    "--resolve",
                    &resolve,
                    force_family,
                    "--write-out",
                    "\n%{http_code}",
                    "--",
                    &url,
                ],
            )
            .map_err(|error| render_chain(&error))?;
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

    fn dns(
        &self,
        name: &ObserverName,
        resolv_conf: io::Result<String>,
    ) -> Observation<Vec<DnsSample>> {
        let text = resolv_conf.map_err(|error| format!("could not read resolv.conf: {error}"))?;
        let servers = nameservers(&text)?;
        if servers.is_empty() {
            return Err("resolv.conf lists no supported nameserver addresses".into());
        }
        Ok(servers
            .into_iter()
            .map(|configured| DnsSample {
                configured,
                observed: self.query(Some(configured), name, "TXT").and_then(|reply| {
                    resolver_ip(&reply)
                        .ok_or_else(|| "the DNS observer did not identify one resolver IP".into())
                }),
            })
            .collect())
    }

    fn no_ipv6_route(&self, destination: IpAddr) -> bool {
        matches!(
            self.run(self.tools.ip, &["-6", "route", "get", &destination.to_string()]),
            Err(CollectError::CommandFailed { status, stderr, .. })
                if status.code() == Some(2) && matches!(
                    stderr.as_str(),
                    "RTNETLINK answers: Network is unreachable" | "ip: RTNETLINK answers: Network unreachable"
                )
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collect::test_support::TempDir;

    #[test]
    fn resolver_symlinks_stay_inside_the_container_root() {
        let root = TempDir::new("egress-resolver-root");
        let text = "nameserver 192.0.2.53\n";
        root.file("run/network/resolv.conf", text);
        root.symlink("etc/resolv.conf", "/run/network/resolv.conf");

        let directory = File::open(root.path()).unwrap();
        assert_eq!(read_resolv_conf(&directory).unwrap(), text);
    }

    #[test]
    fn rejects_a_directory_in_place_of_container_resolver_configuration() {
        let root = TempDir::new("egress-resolver-directory");
        root.dir("etc/resolv.conf");
        let directory = File::open(root.path()).unwrap();
        let error = read_resolv_conf(&directory).unwrap_err();
        assert!(error.to_string().contains("not a regular file"));
    }
}
