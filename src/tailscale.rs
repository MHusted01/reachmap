//! Ports that Tailscale shares through `tailscale serve` and `tailscale funnel`.
//! Tailscale accepts these connections itself and forwards them, usually to a
//! program on loopback, so that program's socket says nothing about them.

use std::collections::BTreeSet;
use std::fmt;
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr};

use serde::Serialize;
use thiserror::Error;

use crate::collect::{self, CollectError};
use crate::network::Network;
use crate::parse::tailscale::{TailscaleParseError, parse_serve_status};
use crate::reach::{Reach, Reason, Verdict};
use crate::scan::ISSUES_URL;
use crate::socket::{Endpoint, Protocol};

/// What `tailscale` prints when it cannot reach its daemon, in lower case.
const DAEMON_DOWN: &str = "failed to connect to local tailscale daemon";

/// Why it is unknown what Tailscale shares. The scan still finishes: rows keep
/// the reach of their socket, and a warning says that more may be shared.
#[derive(Debug, Error)]
pub enum TailscaleError {
    /// `tailscale` failed, usually because its daemon is not running.
    #[error("could not ask Tailscale what it shares, so that reach is not shown")]
    Collect(#[source] CollectError),
    /// `tailscale` printed something reachmap does not understand.
    #[error("could not understand Tailscale's output, so that reach is not shown")]
    Parse(#[source] TailscaleParseError),
}

impl TailscaleError {
    /// A suggestion for the user, when there is one beyond the message.
    pub fn hint(&self) -> Option<String> {
        match self {
            TailscaleError::Collect(CollectError::CommandFailed { stderr, .. })
                if stderr.to_lowercase().contains(DAEMON_DOWN) =>
            {
                Some("tailscaled is not running; start it to see what Tailscale shares".to_string())
            }
            TailscaleError::Collect(_) => None,
            TailscaleError::Parse(_) => Some(format!(
                "this is likely a reachmap bug or a new Tailscale format; please report it at \
                 {ISSUES_URL} with your Tailscale version"
            )),
        }
    }
}

/// Who Tailscale shares a port with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Sharing {
    /// Devices on the tailnet: `tailscale serve`.
    Tailnet,
    /// Anyone on the internet, and the tailnet: `tailscale funnel`.
    Funnel,
}

impl Sharing {
    /// The networks that can connect.
    fn networks(self) -> &'static [Network] {
        match self {
            Sharing::Tailnet => &[Network::Tailnet],
            Sharing::Funnel => &[Network::Tailnet, Network::Internet],
        }
    }
}

impl fmt::Display for Sharing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Sharing::Tailnet => "Serve",
            Sharing::Funnel => "Funnel",
        })
    }
}

/// A port that Tailscale accepts connections on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedPort {
    /// The port clients connect to.
    pub port: u16,
    /// Who can connect.
    pub sharing: Sharing,
    /// Where connections are forwarded to. Empty when reachmap cannot name an
    /// address: Tailscale answers itself, or the target is a Unix socket or a
    /// host name.
    pub targets: BTreeSet<SocketAddr>,
}

impl SharedPort {
    /// Whether connections to this port end up at `endpoint`. Tailscale
    /// forwards over TCP only.
    fn forwards_to(&self, endpoint: Endpoint) -> bool {
        endpoint.protocol == Protocol::Tcp
            && self.targets.iter().any(|target| {
                target.port() == endpoint.port && accepts(endpoint.address, target.ip())
            })
    }

    /// Where clients connect to this port on `address`.
    pub fn endpoint_on(&self, address: IpAddr) -> Endpoint {
        Endpoint {
            port: self.port,
            protocol: Protocol::Tcp,
            address,
        }
    }

    /// Where this port can be reached from, when it forwards to no row.
    pub fn verdict(&self) -> Verdict {
        Verdict {
            reach: Reach::From {
                networks: self.sharing.networks().iter().copied().collect(),
            },
            reason: Reason::TailscaleAccepts {
                sharing: self.sharing,
            },
        }
    }
}

/// Whether a socket bound to `listening` takes connections to `target`. A `::`
/// socket counts as dual-stack, because a row does not say whether it is
/// IPv6-only. That reports more reach rather than less.
fn accepts(listening: IpAddr, target: IpAddr) -> bool {
    let (listening, target) = (listening.to_canonical(), target.to_canonical());
    listening == target || (listening.is_unspecified() && (listening.is_ipv6() || target.is_ipv4()))
}

/// Lists the ports Tailscale shares on this host.
pub fn read_shared_ports() -> Result<Vec<SharedPort>, TailscaleError> {
    shared_ports(collect::read_serve_status)
}

/// Asks `read` for the serve config. A host without `tailscale` shares nothing,
/// so unlike a failed command, that is no missing fact.
fn shared_ports(
    read: impl FnOnce() -> Result<String, CollectError>,
) -> Result<Vec<SharedPort>, TailscaleError> {
    match read() {
        Ok(json) => parse_serve_status(&json).map_err(TailscaleError::Parse),
        Err(CollectError::Run { source, .. }) if source.kind() == ErrorKind::NotFound => {
            Ok(Vec::new())
        }
        Err(error) => Err(TailscaleError::Collect(error)),
    }
}

/// The shared ports that forward to none of `rows`: a file, a text, a redirect,
/// a Unix socket, another host or a program that is not running. No row shows
/// these ports, so they need one of their own.
pub fn without_row<'a>(shared: &'a [SharedPort], rows: &[Endpoint]) -> Vec<&'a SharedPort> {
    shared
        .iter()
        .filter(|port| !rows.iter().any(|row| port.forwards_to(*row)))
        .collect()
}

/// Adds what Tailscale shares to the verdict of `endpoint`. An unknown reach
/// stays unknown, as other networks may connect too, and the reason names
/// Tailscale's ports.
pub fn widen(verdict: Verdict, endpoint: Endpoint, shared: &[SharedPort]) -> Verdict {
    let behind: Vec<&SharedPort> = shared
        .iter()
        .filter(|port| port.forwards_to(endpoint))
        .collect();
    if behind.is_empty() {
        return verdict;
    }
    let ports_with = |sharing| -> BTreeSet<u16> {
        behind
            .iter()
            .filter(|port| port.sharing == sharing)
            .map(|port| port.port)
            .collect()
    };
    let added = behind.iter().flat_map(|port| port.sharing.networks());
    let reach = match verdict.reach {
        Reach::From { networks } => Reach::From {
            networks: networks.into_iter().chain(added.copied()).collect(),
        },
        Reach::Unknown => Reach::Unknown,
    };
    Verdict {
        reach,
        reason: Reason::TailscaleShared {
            served_on: ports_with(Sharing::Tailnet),
            funnel_on: ports_with(Sharing::Funnel),
            direct: Box::new(verdict.reason),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::render_chain;
    use crate::reach::classify;
    use std::io;
    use std::process::ExitStatus;
    use std::time::Duration;

    fn endpoint(address: &str, port: u16) -> Endpoint {
        Endpoint {
            port,
            protocol: Protocol::Tcp,
            address: address.parse().unwrap(),
        }
    }

    fn shared(port: u16, sharing: Sharing, target: &str) -> SharedPort {
        SharedPort {
            port,
            sharing,
            targets: BTreeSet::from([target.parse().unwrap()]),
        }
    }

    fn loopback() -> Verdict {
        classify("127.0.0.1".parse().unwrap(), None, None)
    }

    fn networks<const N: usize>(networks: [Network; N]) -> Reach {
        Reach::From {
            networks: BTreeSet::from(networks),
        }
    }

    fn is_widened(address: &str, target: &str) -> bool {
        let shares = [shared(443, Sharing::Tailnet, target)];
        widen(loopback(), endpoint(address, 3000), &shares) != loopback()
    }

    fn command_failed(stderr: &str) -> TailscaleError {
        TailscaleError::Collect(CollectError::CommandFailed {
            command: "tailscale serve status --json".to_string(),
            status: ExitStatus::default(),
            stderr: stderr.to_string(),
        })
    }

    #[test]
    fn a_port_nothing_forwards_to_keeps_its_verdict() {
        let shares = [shared(443, Sharing::Funnel, "127.0.0.1:3000")];
        let verdict = widen(loopback(), endpoint("127.0.0.1", 8080), &shares);
        assert_eq!(verdict, loopback());
    }

    #[test]
    fn serve_adds_the_tailnet_and_keeps_the_reason_of_the_socket() {
        let shares = [shared(8443, Sharing::Tailnet, "127.0.0.1:3000")];
        let verdict = widen(loopback(), endpoint("127.0.0.1", 3000), &shares);
        assert_eq!(
            verdict,
            Verdict {
                reach: networks([Network::ThisHost, Network::Tailnet]),
                reason: Reason::TailscaleShared {
                    served_on: BTreeSet::from([8443]),
                    funnel_on: BTreeSet::new(),
                    direct: Box::new(Reason::Loopback),
                },
            }
        );
        assert_eq!(
            verdict.reason.to_string(),
            "loopback address; shared by Tailscale Serve on 8443"
        );
    }

    #[test]
    fn funnel_adds_the_tailnet_and_the_internet() {
        let shares = [shared(443, Sharing::Funnel, "127.0.0.1:3000")];
        let verdict = widen(loopback(), endpoint("127.0.0.1", 3000), &shares);
        assert_eq!(
            verdict.reach,
            networks([Network::ThisHost, Network::Tailnet, Network::Internet])
        );
        assert_eq!(
            verdict.reason.to_string(),
            "loopback address; shared by Tailscale Funnel on 443"
        );
    }

    #[test]
    fn a_row_behind_serve_and_funnel_names_both() {
        let shares = [
            shared(443, Sharing::Funnel, "127.0.0.1:3000"),
            shared(8443, Sharing::Tailnet, "127.0.0.1:3000"),
            shared(10000, Sharing::Tailnet, "127.0.0.1:3000"),
        ];
        let verdict = widen(loopback(), endpoint("127.0.0.1", 3000), &shares);
        assert_eq!(
            verdict.reason.to_string(),
            "loopback address; shared by Tailscale Serve on 8443, 10000 and Funnel on 443"
        );
    }

    #[test]
    fn an_unknown_reach_stays_unknown_and_the_reason_names_tailscale() {
        let unknown = classify("0.0.0.0".parse().unwrap(), None, None);
        let shares = [shared(443, Sharing::Funnel, "127.0.0.1:3000")];
        let verdict = widen(unknown, endpoint("0.0.0.0", 3000), &shares);
        assert_eq!(verdict.reach, Reach::Unknown);
        assert_eq!(
            verdict.reason.to_string(),
            "could not list interfaces; shared by Tailscale Funnel on 443"
        );
    }

    #[test]
    fn a_socket_takes_what_is_sent_to_its_address() {
        assert!(is_widened("127.0.0.1", "127.0.0.1:3000"));
        assert!(is_widened("::1", "[::1]:3000"));
        assert!(is_widened("::ffff:127.0.0.1", "127.0.0.1:3000"));
        assert!(!is_widened("127.0.0.1", "[::1]:3000"));
        assert!(!is_widened("192.0.2.10", "127.0.0.1:3000"));
    }

    #[test]
    fn a_wildcard_socket_takes_what_is_sent_to_any_address_it_covers() {
        assert!(is_widened("0.0.0.0", "127.0.0.1:3000"));
        assert!(is_widened("::", "127.0.0.1:3000"));
        assert!(is_widened("::", "[::1]:3000"));
        assert!(!is_widened("0.0.0.0", "[::1]:3000"));
    }

    #[test]
    fn tailscale_forwards_to_tcp_only() {
        let shares = [shared(443, Sharing::Funnel, "127.0.0.1:3000")];
        let udp = Endpoint {
            protocol: Protocol::Udp,
            ..endpoint("127.0.0.1", 3000)
        };
        assert_eq!(widen(loopback(), udp, &shares), loopback());
    }

    #[test]
    fn a_host_without_tailscale_shares_nothing() {
        let shared = shared_ports(|| {
            Err(CollectError::Run {
                command: "tailscale serve status --json".to_string(),
                source: io::Error::new(io::ErrorKind::NotFound, "No such file or directory"),
            })
        });
        assert_eq!(shared.unwrap(), Vec::new());
    }

    #[test]
    fn the_output_of_the_command_is_parsed() {
        let json = r#"{"TCP": {"5432": {"TCPForward": "127.0.0.1:5432"}}}"#;
        let shared_now = shared_ports(|| Ok(json.to_string()));
        assert_eq!(
            shared_now.unwrap(),
            [shared(5432, Sharing::Tailnet, "127.0.0.1:5432")]
        );
    }

    #[test]
    fn a_tailscale_that_fails_is_an_error_not_an_empty_list() {
        let error = shared_ports(|| {
            Err(CollectError::TimedOut {
                command: "tailscale serve status --json".to_string(),
                timeout: Duration::from_secs(5),
            })
        })
        .unwrap_err();
        assert_eq!(
            render_chain(&error),
            "could not ask Tailscale what it shares, so that reach is not shown: \
             `tailscale serve status --json` did not finish within 5s"
        );
        assert_eq!(error.hint(), None);
    }

    #[test]
    fn output_that_is_no_config_is_an_error_with_a_hint() {
        let error = shared_ports(|| Ok("No serve config\n".to_string())).unwrap_err();
        assert!(matches!(error, TailscaleError::Parse(_)));
        assert!(error.hint().unwrap().contains("reachmap bug"));
    }

    #[test]
    fn a_stopped_daemon_gets_a_hint() {
        let error = command_failed("Failed to connect to local Tailscale daemon for /x");
        assert_eq!(
            error.hint().unwrap(),
            "tailscaled is not running; start it to see what Tailscale shares"
        );
    }

    #[test]
    fn other_failures_have_no_hint() {
        assert_eq!(command_failed("something else").hint(), None);
    }

    #[test]
    fn only_a_share_that_forwards_to_no_row_is_without_a_row() {
        let shares = [
            shared(443, Sharing::Funnel, "127.0.0.1:3000"),
            shared(8443, Sharing::Tailnet, "127.0.0.1:4000"),
        ];
        let rows = [endpoint("127.0.0.1", 3000)];
        assert_eq!(without_row(&shares, &rows), [&shares[1]]);
    }

    #[test]
    fn a_share_with_no_target_is_without_a_row() {
        let share = SharedPort {
            port: 443,
            sharing: Sharing::Tailnet,
            targets: BTreeSet::new(),
        };
        let shares = [share];
        let rows = [endpoint("127.0.0.1", 443)];
        assert_eq!(without_row(&shares, &rows), [&shares[0]]);
    }

    #[test]
    fn a_udp_row_is_not_what_a_share_forwards_to() {
        let shares = [shared(443, Sharing::Tailnet, "127.0.0.1:3000")];
        let udp = Endpoint {
            protocol: Protocol::Udp,
            ..endpoint("127.0.0.1", 3000)
        };
        assert_eq!(without_row(&shares, &[udp]), [&shares[0]]);
    }

    #[test]
    fn serve_alone_reaches_the_tailnet() {
        let verdict = shared(8443, Sharing::Tailnet, "127.0.0.1:3000").verdict();
        assert_eq!(verdict.reach, networks([Network::Tailnet]));
        assert_eq!(
            verdict.reason.to_string(),
            "accepted by Tailscale Serve; no listening port behind it"
        );
    }

    #[test]
    fn funnel_reaches_the_tailnet_and_the_internet() {
        let verdict = shared(443, Sharing::Funnel, "127.0.0.1:3000").verdict();
        assert_eq!(
            verdict.reach,
            networks([Network::Tailnet, Network::Internet])
        );
        assert_eq!(
            verdict.reason.to_string(),
            "accepted by Tailscale Funnel; no listening port behind it"
        );
    }

    #[test]
    fn a_shared_port_is_a_tcp_endpoint_on_the_address() {
        let share = shared(443, Sharing::Tailnet, "127.0.0.1:3000");
        assert_eq!(
            share.endpoint_on("100.64.0.1".parse().unwrap()),
            endpoint("100.64.0.1", 443)
        );
    }
}
