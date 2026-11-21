//! Collect one authenticated Linux snapshot and compare it with a local TCP attempt.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::num::{NonZeroU16, NonZeroU64};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use thiserror::Error;
use tokio::net::TcpSocket;
use tokio::runtime::Builder;

use super::audit::{self, Capture, Comparison, Ingress, Observation, Scope};
use super::{Flow, PathError, PathEvidence, parse, valid_interface_name};
use crate::host_input_snapshot::Evidence;
use crate::probe::attempt;

mod ssh;
#[cfg(test)]
mod tests;

const SSH_TIMEOUT: Duration = Duration::from_secs(30);
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_CAPTURE_AGE_SECONDS: u64 = 60;

/// Explicit SSH and flow inputs for `reachmap audit`.
#[derive(clap::Args)]
pub struct Args {
    #[command(flatten)]
    ssh: ssh::Config,
    /// Numeric [IPv6]:port or IPv4:port to probe from this machine
    #[arg(long)]
    endpoint: SocketAddr,
    /// Local source IP to bind for the probe
    #[arg(long)]
    source: IpAddr,
    /// Expected ingress interface on the Linux collector host
    #[arg(long, value_parser = parse_ingress)]
    ingress: String,
    /// Confirm the endpoint belongs to the SSH host, the path is direct, and clocks are comparable
    #[arg(long = "confirm-direct-path", required = true, action = clap::ArgAction::SetTrue)]
    _confirm_direct_path: bool,
}

/// An audit ended before it could emit a report.
#[derive(Debug, Error)]
#[error(transparent)]
pub struct Error(#[from] Failure);

#[derive(Debug, Error)]
enum Failure {
    #[error("use a TCP endpoint with a nonzero port")]
    Port,
    #[error("use an IPv6 flow that does not require a link-local zone")]
    Ipv6Zone,
    #[error(transparent)]
    Flow(#[from] PathError),
    #[error("could not start the TCP probe runtime")]
    Runtime(#[source] io::Error),
    #[error("could not bind the TCP probe to source address {address}")]
    Bind { address: IpAddr, source: io::Error },
    #[error(transparent)]
    Ssh(#[from] ssh::Error),
    #[error("the collector returned a snapshot for a different TCP flow")]
    DifferentFlow,
    #[error("could not format the audit report")]
    Encode(#[from] serde_json::Error),
}

#[derive(Serialize)]
struct Report<'a> {
    report_version: u32,
    client_bind: SocketAddr,
    evidence_gaps: Vec<EvidenceGap>,
    #[serde(flatten)]
    correlation: audit::Report<'a>,
}

#[derive(Serialize)]
struct EvidenceGap {
    collector: &'static str,
    reason: String,
}

/// Run the read-only audit, returning its JSON and exit status.
pub fn run(args: Args) -> Result<(String, u8), Error> {
    Ok(run_with(args, "/usr/bin/ssh", SSH_TIMEOUT)?)
}

fn run_with(args: Args, program: &str, ssh_timeout: Duration) -> Result<(String, u8), Failure> {
    let port = NonZeroU16::new(args.endpoint.port()).ok_or(Failure::Port)?;
    let flow = Flow::new(args.source, args.ingress, args.endpoint.ip(), port)?;
    if [flow.source, flow.destination]
        .into_iter()
        .any(|address| matches!(address, IpAddr::V6(ip) if ip.is_unicast_link_local()))
        || matches!(args.endpoint, SocketAddr::V6(address) if address.scope_id() != 0)
    {
        return Err(Failure::Ipv6Zone);
    }

    let runtime = Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(Failure::Runtime)?;
    let (socket, client_bind) = bind(flow.source).map_err(|source| Failure::Bind {
        address: flow.source,
        source,
    })?;

    let snapshot = parse(&args.ssh.collect(&flow, program, ssh_timeout)?)?;
    if snapshot.flow != flow {
        return Err(Failure::DifferentFlow);
    }

    let started_at = now();
    let outcome = runtime.block_on(attempt(socket.connect(args.endpoint), PROBE_TIMEOUT));
    let finished_at = now();

    let identity = args.ssh.identity();
    let scope = Some(Scope {
        collector_identity: &identity,
        network_context: "operator-declared direct path",
    });
    let capture = Capture {
        snapshot: &snapshot,
        scope,
    };
    let observation = Observation {
        scope,
        source: Some(client_bind.ip()),
        destination: args.endpoint,
        ingress: Some(Ingress::Declared(&flow.ingress)),
        started_at_unix_seconds: started_at,
        finished_at_unix_seconds: finished_at,
        outcome: &outcome,
    };
    let correlation = audit::correlate(Some(capture), Some(observation), MAX_CAPTURE_AGE_SECONDS);
    let status = match correlation.comparison {
        Comparison::Consistent => 0,
        Comparison::Disagrees => 1,
        Comparison::Unavailable(_) => 2,
    };
    let report = Report {
        report_version: 1,
        client_bind,
        evidence_gaps: evidence_gaps(&snapshot.evidence),
        correlation,
    };
    Ok((
        format!("{}\n", serde_json::to_string_pretty(&report)?),
        status,
    ))
}

fn bind(source: IpAddr) -> io::Result<(TcpSocket, SocketAddr)> {
    let socket = if source.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    socket.bind(SocketAddr::new(source, 0))?;
    let local = socket.local_addr()?;
    Ok((socket, local))
}

fn now() -> Option<NonZeroU64> {
    NonZeroU64::new(SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs())
}

fn parse_ingress(text: &str) -> Result<String, PathError> {
    if valid_interface_name(text) {
        Ok(text.to_owned())
    } else {
        Err(PathError::Ingress)
    }
}

fn evidence_gaps(evidence: &PathEvidence) -> Vec<EvidenceGap> {
    fn gap<T>(collector: &'static str, evidence: &Evidence<T>) -> Option<EvidenceGap> {
        evidence
            .as_result()
            .err()
            .map(|reason| EvidenceGap { collector, reason })
    }

    let mut gaps: Vec<_> = [
        gap("link", &evidence.link),
        evidence
            .ipv6_disabled
            .as_ref()
            .and_then(|value| gap("ipv6_disabled", value)),
        gap("legacy_tables", &evidence.legacy_tables),
        gap("xfrm_policies", &evidence.xfrm_policies),
        gap("xfrm_defaults", &evidence.xfrm_defaults),
        gap("nftables", &evidence.nftables),
        gap("routing_rules", &evidence.routing_rules),
        gap("route", &evidence.route),
        gap("listeners", &evidence.listeners),
    ]
    .into_iter()
    .flatten()
    .collect();

    if let Some(docker) = &evidence.docker {
        gaps.extend(
            [
                gap("docker.publish", &docker.publish),
                gap("docker.bridge", &docker.bridge),
                gap("docker.route", &docker.route),
                docker
                    .local_source
                    .as_ref()
                    .and_then(|value| gap("docker.local_source", value)),
                gap("docker.forwarding", &docker.forwarding),
                gap("docker.container", &docker.container),
            ]
            .into_iter()
            .flatten(),
        );
    }
    gaps
}
