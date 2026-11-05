//! The network side of a probe: name lookup and connection attempts. The
//! connector is a parameter, so tests can decide what each attempt does.

use std::collections::BTreeSet;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::time::Duration;

use tokio::net::lookup_host;
use tokio::task::{JoinError, JoinSet};
use tokio::time::timeout;

use super::{Outcome, ProbeError, ProbedPort, RESOLVE_TIMEOUT_SECONDS};
use crate::parse::probe_args::PortList;
use crate::sanitize::sanitize;

/// Every address of `host`, without duplicates.
pub(super) async fn resolve(host: &str) -> Result<BTreeSet<SocketAddr>, ProbeError> {
    let limit = Duration::from_secs(RESOLVE_TIMEOUT_SECONDS);
    let found = timeout(limit, lookup_host((host, 0)))
        .await
        .map_err(|_| ProbeError::ResolveTimeout {
            host: sanitize(host),
        })?
        .map_err(|source| ProbeError::Resolve {
            host: sanitize(host),
            source,
        })?;
    let addresses: BTreeSet<_> = found.collect();
    if addresses.is_empty() {
        return Err(ProbeError::NoAddresses {
            host: sanitize(host),
        });
    }
    Ok(addresses)
}

/// One target per address and port.
pub(super) fn targets(addresses: &BTreeSet<SocketAddr>, ports: &PortList) -> Vec<SocketAddr> {
    addresses
        .iter()
        .flat_map(|&address| ports.iter().map(move |port| with_port(address, port)))
        .collect()
}

/// `address` with another port. It keeps the scope of a link-local IPv6
/// address, which the IP address alone would lose.
fn with_port(mut address: SocketAddr, port: u16) -> SocketAddr {
    address.set_port(port);
    address
}

/// Waits up to `limit` for `connecting` and says how it ended. The connection,
/// if there is one, closes when it is dropped here.
pub(super) async fn attempt<T>(
    connecting: impl Future<Output = io::Result<T>>,
    limit: Duration,
) -> Outcome {
    match timeout(limit, connecting).await {
        Ok(Ok(_connection)) => Outcome::Open,
        Ok(Err(error)) => Outcome::from_error(&error),
        Err(_elapsed) => Outcome::NoAnswer,
    }
}

/// Runs `connect` for every target, at most `limit` at a time, and returns the
/// results by port, then address.
pub(super) async fn probe_all<C, F>(
    targets: Vec<SocketAddr>,
    limit: NonZeroUsize,
    connect: C,
) -> Result<Vec<ProbedPort>, JoinError>
where
    C: Fn(SocketAddr) -> F,
    F: Future<Output = Outcome> + Send + 'static,
{
    let mut results = Vec::with_capacity(targets.len());
    let mut running = JoinSet::new();
    for target in targets {
        if running.len() == limit.get() {
            results.extend(running.join_next().await.transpose()?);
        }
        let connecting = connect(target);
        running.spawn(async move {
            ProbedPort {
                port: target.port(),
                address: target.into(),
                result: connecting.await,
            }
        });
    }
    while let Some(finished) = running.join_next().await {
        results.push(finished?);
    }
    results.sort_by_key(|probed| (probed.port, probed.address));
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::ProbedAddress;
    use std::future::pending;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV6};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const SHORT: Duration = Duration::from_millis(10);

    fn v4(last: u8, port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, last)), port)
    }

    fn limit(value: usize) -> NonZeroUsize {
        NonZeroUsize::new(value).unwrap()
    }

    #[test]
    fn makes_a_target_for_every_address_and_port() {
        let v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0);
        let addresses = BTreeSet::from([v4(1, 0), v6]);
        let ports = "22,80".parse().unwrap();

        let mut found = targets(&addresses, &ports);
        found.sort();

        let mut expected = vec![
            v4(1, 22),
            v4(1, 80),
            SocketAddr::new(v6.ip(), 22),
            SocketAddr::new(v6.ip(), 80),
        ];
        expected.sort();
        assert_eq!(found, expected);
    }

    #[test]
    fn targets_keep_the_scope_of_a_link_local_address() {
        let link_local = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let on = |scope| SocketAddr::V6(SocketAddrV6::new(link_local, 0, 0, scope));
        let addresses = BTreeSet::from([on(3), on(4)]);

        let found = targets(&addresses, &"22".parse().unwrap());

        let expected =
            [3, 4].map(|scope| SocketAddr::V6(SocketAddrV6::new(link_local, 22, 0, scope)));
        assert_eq!(found, expected);
    }

    #[tokio::test]
    async fn a_connection_is_open() {
        assert_eq!(attempt(async { Ok(()) }, SHORT).await, Outcome::Open);
    }

    #[tokio::test]
    async fn an_error_is_classified() {
        let refused = async { Err::<(), _>(io::Error::from(io::ErrorKind::ConnectionRefused)) };
        assert_eq!(attempt(refused, SHORT).await, Outcome::Closed);
    }

    #[tokio::test]
    async fn silence_past_the_limit_is_no_answer() {
        let silent = pending::<io::Result<()>>();
        assert_eq!(attempt(silent, SHORT).await, Outcome::NoAnswer);
    }

    #[tokio::test]
    async fn results_come_back_by_port_then_address() {
        let found = probe_all(
            vec![v4(2, 80), v4(1, 443), v4(1, 80)],
            limit(2),
            |_| async { Outcome::Open },
        )
        .await
        .unwrap();

        let order: Vec<_> = found
            .iter()
            .map(|probed| (probed.port, probed.address))
            .collect();
        let expected = [v4(1, 80), v4(2, 80), v4(1, 443)]
            .map(|target| (target.port(), ProbedAddress::from(target)));
        assert_eq!(order, expected);
    }

    #[tokio::test]
    async fn each_target_gets_its_own_outcome() {
        let found = probe_all(vec![v4(1, 22), v4(1, 80)], limit(2), |target| async move {
            if target.port() == 22 {
                Outcome::Open
            } else {
                Outcome::Closed
            }
        })
        .await
        .unwrap();

        let outcomes: Vec<_> = found.into_iter().map(|probed| probed.result).collect();
        assert_eq!(outcomes, vec![Outcome::Open, Outcome::Closed]);
    }

    #[tokio::test]
    async fn never_runs_more_attempts_at_once_than_the_limit() {
        let running = Arc::new(AtomicUsize::new(0));
        let highest = Arc::new(AtomicUsize::new(0));
        let targets: Vec<_> = (1..=50).map(|port| v4(1, port)).collect();

        let found = probe_all(targets, limit(3), |_| {
            let running = Arc::clone(&running);
            let highest = Arc::clone(&highest);
            async move {
                let now = running.fetch_add(1, Ordering::SeqCst) + 1;
                highest.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(1)).await;
                running.fetch_sub(1, Ordering::SeqCst);
                Outcome::Open
            }
        })
        .await
        .unwrap();

        assert_eq!(found.len(), 50);
        assert_eq!(highest.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn resolves_an_ip_address_to_itself() {
        let addresses = resolve("192.0.2.1").await.unwrap();
        let ips: Vec<_> = addresses.iter().map(SocketAddr::ip).collect();
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))]);
    }
}
