//! Compares egress observations from a Linux host and a Docker network namespace.

use std::collections::BTreeSet;
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use thiserror::Error;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(any(target_os = "linux", test))]
mod parse;

/// A Docker container name or ID that can safely occupy one API path segment.
#[derive(Clone)]
pub struct ContainerRef(String);

#[cfg(target_os = "linux")]
impl ContainerRef {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for ContainerRef {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let mut bytes = value.bytes();
        if bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
            && bytes.all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
        {
            return Ok(Self(value.to_string()));
        }
        Err("expected a Docker container name or ID")
    }
}

/// A literal DNS name supplied by the user, without a search suffix.
#[derive(Clone)]
pub struct ObserverName(String);

impl FromStr for ObserverName {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let name = value.strip_suffix('.').unwrap_or(value);
        if name.len() <= 253
            && name.contains('.')
            && name.split('.').all(|label| {
                (1..=63).contains(&label.len())
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            })
            && name
                .rsplit('.')
                .next()
                .is_some_and(|label| label.bytes().any(|byte| byte.is_ascii_alphabetic()))
        {
            return Ok(Self(name.to_ascii_lowercase()));
        }
        Err("expected a fully qualified DNS name, such as observer.example")
    }
}

/// The observations and results of one egress check.
pub struct Report {
    target: ContainerRef,
    host: Observations,
    container: Observations,
    unreachable_ipv6_observer: Option<IpAddr>,
}

type Observation<T> = Result<T, String>;

#[cfg_attr(not(any(target_os = "linux", test)), allow(dead_code))]
struct Observations {
    ipv4: Observation<IpAddr>,
    ipv6: Observation<IpAddr>,
    dns: Observation<Vec<DnsSample>>,
}

struct DnsSample {
    configured: IpAddr,
    observed: Observation<IpAddr>,
}

#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    Same,
    Different,
    NoRoute,
    Unknown,
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Same => "matches host",
            Self::Different => "differs from host",
            Self::NoRoute => "no route to the IPv6 observer",
            Self::Unknown => "unknown",
        })
    }
}

impl Report {
    /// Whether all three checks have the requested evidence.
    pub fn is_clean(&self) -> bool {
        self.ipv4() == Verdict::Different
            && self.ipv6() == Verdict::NoRoute
            && self.dns() == Verdict::Different
    }

    fn ipv4(&self) -> Verdict {
        compare_ip(&self.host.ipv4, &self.container.ipv4)
    }

    fn ipv6(&self) -> Verdict {
        if self.unreachable_ipv6_observer.is_some() {
            return Verdict::NoRoute;
        }
        compare_ip(&self.host.ipv6, &self.container.ipv6)
    }

    fn dns(&self) -> Verdict {
        let (Ok(host), Ok(container)) = (&self.host.dns, &self.container.dns) else {
            return Verdict::Unknown;
        };
        let observed = |samples: &[DnsSample]| {
            samples
                .iter()
                .filter_map(|sample| sample.observed.as_ref().ok().copied())
                .collect::<BTreeSet<_>>()
        };
        let host_ips = observed(host);
        let container_ips = observed(container);
        if !host_ips.is_disjoint(&container_ips) {
            Verdict::Same
        } else if host_ips.is_empty()
            || container_ips.is_empty()
            || host
                .iter()
                .chain(container)
                .any(|sample| sample.observed.is_err())
        {
            Verdict::Unknown
        } else {
            Verdict::Different
        }
    }
}

fn compare_ip(host: &Observation<IpAddr>, container: &Observation<IpAddr>) -> Verdict {
    match (host, container) {
        (Ok(host), Ok(container)) if host == container => Verdict::Same,
        (Ok(_), Ok(_)) => Verdict::Different,
        _ => Verdict::Unknown,
    }
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Egress for {}", self.target.0)?;
        writeln!(f, "IPv4: {}", self.ipv4())?;
        print_ip(f, "host", &self.host.ipv4)?;
        print_ip(f, "container", &self.container.ipv4)?;
        writeln!(f, "IPv6: {}", self.ipv6())?;
        print_ip(f, "host", &self.host.ipv6)?;
        if let Some(destination) = self.unreachable_ipv6_observer {
            writeln!(f, "  container: kernel reports no route to {destination}")?;
        } else {
            print_ip(f, "container", &self.container.ipv6)?;
        }
        writeln!(f, "DNS: {}", self.dns())?;
        print_dns(f, "host", &self.host.dns)?;
        print_dns(f, "container", &self.container.dns)
    }
}

fn print_ip(f: &mut fmt::Formatter<'_>, source: &str, ip: &Observation<IpAddr>) -> fmt::Result {
    match ip {
        Ok(ip) => writeln!(f, "  {source}: {ip}"),
        Err(reason) => writeln!(f, "  {source}: unknown ({reason})"),
    }
}

fn print_dns(
    f: &mut fmt::Formatter<'_>,
    source: &str,
    samples: &Observation<Vec<DnsSample>>,
) -> fmt::Result {
    match samples {
        Ok(samples) => {
            for sample in samples {
                write!(f, "  {source} nameserver {}: ", sample.configured)?;
                match &sample.observed {
                    Ok(ip) => writeln!(f, "observed {ip}")?,
                    Err(reason) => writeln!(f, "unknown ({reason})")?,
                }
            }
            Ok(())
        }
        Err(reason) => writeln!(f, "  {source}: unknown ({reason})"),
    }
}

/// A prerequisite failed before the egress report could be completed.
#[derive(Debug, Error)]
#[error(transparent)]
pub struct CheckError(#[from] SetupError);

#[derive(Debug, Error)]
enum SetupError {
    #[cfg(not(target_os = "linux"))]
    #[error("container egress checks require Linux and a local Docker daemon")]
    UnsupportedOs,
    #[cfg(target_os = "linux")]
    #[error(transparent)]
    Docker(#[from] crate::docker::engine::egress::InspectError),
    #[cfg(target_os = "linux")]
    #[error("install {0} at a standard system path to run egress")]
    MissingTool(&'static str),
    #[cfg(target_os = "linux")]
    #[error("could not open the network namespace for PID {pid}; run on the Docker host with sudo")]
    OpenNamespace {
        pid: u32,
        #[source]
        source: std::io::Error,
    },
    #[cfg(target_os = "linux")]
    #[error("could not read the network namespace identity")]
    NamespaceIdentity(#[source] std::io::Error),
    #[cfg(target_os = "linux")]
    #[error("Docker's workload and network peer do not share a live network namespace")]
    DifferentNamespace,
    #[cfg(target_os = "linux")]
    #[error("the container shares the host network namespace")]
    HostNetwork,
    #[cfg(target_os = "linux")]
    #[error("the container or its network peer changed during the check; retry when it is stable")]
    ContainerChanged,
}

/// Observe the named container using the explicitly supplied HTTPS and DNS observers.
///
/// An error means the check could not start. Individual probe failures appear
/// in the report so they do not hide other available evidence.
pub fn check(
    target: ContainerRef,
    ip_host: &ObserverName,
    dns_name: &ObserverName,
) -> Result<Report, CheckError> {
    #[cfg(target_os = "linux")]
    return Ok(linux::check(target, ip_host, dns_name)?);
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (target, &ip_host.0, &dns_name.0);
        Err(SetupError::UnsupportedOs.into())
    }
}

#[cfg(test)]
mod tests;
