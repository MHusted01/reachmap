//! Correlates a sampled Linux inbound SYN prediction with one TCP handshake observation.

use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU64;

use serde::Serialize;

use super::{Prediction, Snapshot, evaluate::Verdict, validate_format};
use crate::probe::Outcome;

/// Caller-established identity and network scope for one audited endpoint.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Scope<'a> {
    /// Identity of the authenticated collector that produced the capture.
    pub collector_identity: &'a str,
    /// Context that identifies the audited address space and the applicable client path.
    pub network_context: &'a str,
}

impl Scope<'_> {
    fn is_known(&self) -> bool {
        !self.collector_identity.trim().is_empty() && !self.network_context.trim().is_empty()
    }
}

/// An inbound path snapshot and the trusted scope attached to that capture.
#[derive(Debug, Clone, Copy)]
pub struct Capture<'a> {
    /// Evidence returned by the collector. Its host label is descriptive.
    pub snapshot: &'a Snapshot,
    /// Supply only when authenticated provenance and capture context have been established.
    pub scope: Option<Scope<'a>>,
}

/// How the ingress interface for the probe flow was established.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Ingress<'a> {
    /// Interface assumed to receive the SYN on the audited host.
    Declared(&'a str),
    /// Interface independently evidenced for the SYN on the audited host.
    Observed(&'a str),
}

impl Ingress<'_> {
    fn interface(&self) -> &str {
        match self {
            Self::Declared(interface) | Self::Observed(interface) => interface,
        }
    }
}

/// One TCP attempt from the operator's client, with its own evidence context.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Observation<'a> {
    /// The independently established binding of the numeric destination to the audited
    /// collector identity and network context. Leave absent when that binding is unknown.
    pub scope: Option<Scope<'a>>,
    /// Actual client source IP for the attempt, if available. Address translation
    /// that could change this source or the selected destination leaves scope unknown.
    pub source: Option<IpAddr>,
    /// Address and port the client actually attempted, before any host-side Docker DNAT.
    pub destination: SocketAddr,
    /// The audited host's ingress for the attempted flow, if declared or observed.
    pub ingress: Option<Ingress<'a>>,
    /// Start and finish use Unix seconds on a clock comparable to the capture clock.
    /// Leave the time absent when comparability cannot be established.
    pub started_at_unix_seconds: Option<NonZeroU64>,
    /// Time when the attempt completed or timed out.
    pub finished_at_unix_seconds: Option<NonZeroU64>,
    /// The probe result. Open records a handshake from this client to this endpoint.
    pub outcome: &'a Outcome,
}

/// How the two scoped results relate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "status", content = "reason", rename_all = "snake_case")]
pub enum Comparison {
    /// The observation is consistent with the prediction within its limited scope.
    Consistent,
    /// The prediction and observation differ. The report does not assign a cause.
    Disagrees,
    /// There is insufficient evidence to compare the two results.
    Unavailable(Gap),
}

/// The first evidence gap preventing a comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum Gap {
    /// No capture was supplied.
    #[error("collect a Linux inbound TCP path capture for this endpoint")]
    CaptureMissing,
    /// No probe observation was supplied.
    #[error("record a TCP handshake attempt from the intended client")]
    ObservationMissing,
    /// The capture format or flow is invalid.
    #[error("use a valid, supported Linux inbound TCP path capture")]
    InvalidCapture,
    /// Capture provenance or context is missing.
    #[error("establish the authenticated collector identity and capture network context")]
    CaptureScopeMissing,
    /// The probe destination cannot be bound to an authenticated collector and context.
    #[error("establish which audited collector and network context own the probe destination")]
    ObservationScopeMissing,
    /// The probe and capture refer to different authenticated collector identities.
    #[error("verify that the probe destination belongs to the authenticated capture host")]
    CollectorMismatch,
    /// The capture and observation refer to different network contexts.
    #[error("use capture and probe evidence from the same audited network context")]
    NetworkMismatch,
    /// The probe did not use the captured destination address and port.
    #[error("use the captured destination address and TCP port before any host-side translation")]
    DestinationMismatch,
    /// The actual probe source address is missing.
    #[error("record the source IP used by the client for this attempt")]
    SourceMissing,
    /// The client source did not match the source used for the prediction.
    #[error("recapture the path using the actual client source IP")]
    SourceMismatch,
    /// IPv6 interface scope cannot be matched to the current snapshot format.
    #[error("use an IPv6 flow that does not require a link-local zone")]
    Ipv6ZoneUnsupported,
    /// The attempt has no declared or independently evidenced ingress.
    #[error("declare or verify which interface receives the client's SYN on the audited host")]
    IngressMissing,
    /// The attempted flow and capture specify different ingress interfaces.
    #[error("recapture the path using the ingress interface for this attempt")]
    IngressMismatch,
    /// A capture or probe timestamp is missing or untrusted.
    #[error("record capture and probe times on comparable clocks")]
    CaptureOrProbeTimeMissing,
    /// The capture timestamp follows the start of the probe.
    #[error("finish capturing the path before starting the probe")]
    CaptureAfterProbe,
    /// The probe finished before it started according to its recorded times.
    #[error("record ordered start and finish times for the probe")]
    ProbeTimeReversed,
    /// The probe finished outside the allowed capture age.
    #[error("take a fresh capture and repeat the probe within the allowed capture age")]
    CaptureStale,
    /// The existing path evaluator could not resolve the scoped prediction.
    #[error("review the final prediction stage for missing or unsupported evidence")]
    PredictionInconclusive,
    /// The probe failed without observing the result of a handshake attempt.
    #[error("resolve the reported probe error and retry the attempt")]
    ProbeFailed,
}

/// The original results, with the scope and outcome of their comparison.
#[derive(Debug, Serialize)]
pub struct Report<'a> {
    /// Trusted scope attached to the capture, when available.
    pub capture_scope: Option<Scope<'a>>,
    /// Ordered SYN prediction, including the stage and reason if it is unknown.
    pub prediction: Option<Prediction<'a>>,
    /// TCP outcome and client evidence, when available.
    pub observation: Option<Observation<'a>>,
    /// Maximum permitted age of the capture when the probe finishes.
    pub max_capture_age_seconds: u64,
    /// Comparison status and the reason when a comparison is unavailable.
    pub comparison: Comparison,
}

/// Evaluates the snapshot and compares it with a single client observation.
///
/// The caller must wait for collection to finish before probing. The age window
/// runs from the capture timestamp (the start of collection) through probe finish.
/// This function performs no network operations and trusts scope only as supplied
/// by the caller. A negative observation cannot establish a firewall verdict.
#[must_use]
pub fn correlate<'a>(
    capture: Option<Capture<'a>>,
    observation: Option<Observation<'a>>,
    max_capture_age_seconds: u64,
) -> Report<'a> {
    let prediction = capture
        .filter(|capture| {
            let snapshot = capture.snapshot;
            validate_format(&snapshot.scope, snapshot.snapshot_version).is_ok()
                && snapshot.validate_details().is_ok()
        })
        .map(|capture| capture.snapshot.predict());
    let comparison = compare(
        capture,
        prediction.as_ref(),
        observation,
        max_capture_age_seconds,
    )
    .unwrap_or_else(Comparison::Unavailable);
    Report {
        capture_scope: capture.and_then(|capture| capture.scope),
        prediction,
        observation,
        max_capture_age_seconds,
        comparison,
    }
}

fn compare(
    capture: Option<Capture<'_>>,
    prediction: Option<&Prediction<'_>>,
    observation: Option<Observation<'_>>,
    max_age: u64,
) -> Result<Comparison, Gap> {
    let capture = capture.ok_or(Gap::CaptureMissing)?;
    let prediction = prediction.ok_or(Gap::InvalidCapture)?;
    let observation = observation.ok_or(Gap::ObservationMissing)?;
    match_scope(capture.scope, observation.scope)?;
    match_flow(prediction, &observation)?;
    check_age(prediction.captured_at_unix_seconds, &observation, max_age)?;

    let listener_reachable = match prediction.verdict {
        Verdict::ListenerReachable => true,
        Verdict::Blocked | Verdict::NoListener => false,
        Verdict::NotLocal | Verdict::Unknown => return Err(Gap::PredictionInconclusive),
    };
    let handshake_succeeded = match observation.outcome {
        Outcome::Open => true,
        Outcome::Closed | Outcome::NoAnswer | Outcome::Unreachable => false,
        Outcome::Failed { .. } => return Err(Gap::ProbeFailed),
    };
    Ok(if listener_reachable == handshake_succeeded {
        Comparison::Consistent
    } else {
        Comparison::Disagrees
    })
}

fn match_scope(capture: Option<Scope<'_>>, observation: Option<Scope<'_>>) -> Result<(), Gap> {
    let capture = capture
        .filter(Scope::is_known)
        .ok_or(Gap::CaptureScopeMissing)?;
    let observation = observation
        .filter(Scope::is_known)
        .ok_or(Gap::ObservationScopeMissing)?;
    if capture.collector_identity != observation.collector_identity {
        return Err(Gap::CollectorMismatch);
    }
    if capture.network_context != observation.network_context {
        return Err(Gap::NetworkMismatch);
    }
    Ok(())
}

fn match_flow(prediction: &Prediction<'_>, observation: &Observation<'_>) -> Result<(), Gap> {
    let flow = prediction.flow;
    let source = observation.source.ok_or(Gap::SourceMissing)?;
    let link_local = |ip| matches!(ip, IpAddr::V6(address) if address.is_unicast_link_local());
    if link_local(source)
        || link_local(observation.destination.ip())
        || matches!(observation.destination, SocketAddr::V6(address) if address.scope_id() != 0)
    {
        return Err(Gap::Ipv6ZoneUnsupported);
    }
    let destination = SocketAddr::new(flow.destination, flow.port.get());
    if observation.destination != destination {
        return Err(Gap::DestinationMismatch);
    }
    if source != flow.source {
        return Err(Gap::SourceMismatch);
    }
    let ingress = observation.ingress.ok_or(Gap::IngressMissing)?;
    if ingress.interface() != flow.ingress {
        return Err(Gap::IngressMismatch);
    }
    Ok(())
}

fn check_age(captured_at: u64, observation: &Observation<'_>, max_age: u64) -> Result<(), Gap> {
    let missing = Gap::CaptureOrProbeTimeMissing;
    let captured_at = NonZeroU64::new(captured_at).ok_or(missing)?.get();
    let started_at = observation.started_at_unix_seconds.ok_or(missing)?.get();
    let finished_at = observation.finished_at_unix_seconds.ok_or(missing)?.get();
    if captured_at > started_at {
        return Err(Gap::CaptureAfterProbe);
    }
    if started_at > finished_at {
        return Err(Gap::ProbeTimeReversed);
    }
    if finished_at - captured_at > max_age {
        return Err(Gap::CaptureStale);
    }
    Ok(())
}
