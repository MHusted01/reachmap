# Container egress

Run `reachmap egress` on the Linux Docker host. Name the workload that uses
`network_mode: service:<vpn>` in Compose or `--network container:<vpn>` in Docker.
Reachmap checks that both containers are running and share a network namespace.
It uses a root-owned local Docker socket at `/var/run/docker.sock`. Run with
`sudo` so it can read the container's resolver configuration and enter its
network namespace. The host needs `nsenter`, `curl`, `dig`, and `ip` at their
standard system paths.

```sh
sudo reachmap egress workload \
  --ip-host api64.ipify.org \
  --dns-name whoami.ds.akahelp.net
```

Both observer names are required. This example sends HTTPS requests to ipify and
TXT queries through the configured DNS resolvers to Akamai. The HTTPS observer
sees the source address of each request. The DNS observer sees the address of
the recursive resolver and can also receive EDNS Client Subnet data from it.
[ipify API](https://www.ipify.org/) ·
[Akamai resolver diagnostics](https://www.akamai.com/blog/developers/introducing-new-whoami-tool-dns-resolver-information)

For a different observer, provide a hostname with A and AAAA records whose
HTTPS root returns HTTP 200 and a single IP address as plain text. The DNS name
must return a TXT record with the observed resolver's IP, either alone or as
the value of an `ns` field in Akamai's format.

## Reading the results

- **IPv4.** The host resolves the observer once per address family. Reachmap
  uses the same selected destination for both vantage points, with proxies and
  redirects disabled. A match means the two requests exposed the same IPv4
  address. A different address is evidence that their egress differed for
  that destination.
- **DNS.** Reachmap asks up to three nameservers in each side's
  `/etc/resolv.conf`. It shows the configured address and the recursive address
  returned by the observer. A shared observed address is a match, even when
  the configured addresses are different local stubs. Reachmap reports
  `unknown` when it cannot complete the comparison. Resolver caches and
  pools can affect a single sample.
- **IPv6.** A successful request shows IPv6 egress. A different public address
  still needs attention if the intent is to disable IPv6. After a failed
  request, Reachmap reports `no route to the IPv6 observer` only when the
  container's route lookup reports that the selected destination is
  unreachable. Other failures leave the comparison `unknown`.

Exit status **0** means the observed IPv4 and DNS results differ from the host's
and the route lookup found no route to the IPv6 observer. Exit status **1**
means at least one check needs attention, is inconclusive, or could not start.
Invalid arguments exit with **2**.

The report describes one check against the named observers. Actual applications
can use different resolvers, proxies, users, or routing policy. Reachmap runs
the host's tools with the workload's network namespace for the container
measurements. The check uses Docker inspect and sends the requested probes
without changing containers, firewall rules, or settings.
