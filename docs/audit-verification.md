# Verify Linux TCP audits

Use a fresh disposable Linux collector and synthetic endpoints. The lab
exercises the installed `reachmap audit` entry point with real OpenSSH,
Linux TCP sockets, and an independent client network namespace. The audit
predicts the inbound SYN path and reports a separate handshake observation.
See the [path scope](scan.md#linux-inbound-tcp-paths) and
[audit requirements](audit.md).

## Run the Linux lab

Build a static Linux binary for the architecture of the Docker engine. This
example builds on Linux ARM64. Use `x86_64-unknown-linux-musl` on Linux x86-64.
The lab can also run from a Mac with a Linux Docker engine and the matching
Linux binary.

```sh
rustup target add aarch64-unknown-linux-musl
cargo build --locked --target aarch64-unknown-linux-musl
scripts/test-audit.sh target/aarch64-unknown-linux-musl/debug/reachmap
```

The script needs a Docker engine that can run a privileged test container.
It installs tools inside a pinned Docker-in-Docker image, creates temporary
SSH keys and logins, and changes firewall rules only inside the container's
network namespace. It uses a veth link over `192.0.2.0/24` and
`2001:db8::/64`. Docker uses its native nftables backend for the IPv4
publish, with the userland proxy disabled. The nested daemon leaves IPv6
firewall programming disabled for this IPv4-only publish. Its IPv6
prerouting hooks can make the native IPv6 listener path unknown.

The script first checks the HTTP response from the client namespace for each
working endpoint. For each privileged audit that emits a report, it replays
the exact SSH snapshot in an empty network namespace and compares the full
prediction. The script prints tool versions, asserts the results below, and
removes the disposable container with its namespace, firewall rules, SSH
keys, and nested daemon when it exits.

| Case | Prediction | Handshake | Comparison and exit |
| --- | --- | --- | --- |
| IPv4 and IPv6 host listeners on TCP 8443 | `listener_reachable` | `open` | `consistent`, 0 |
| IPv4 Docker bridge publish on TCP 8444 | `listener_reachable`, including DNAT and forwarding | `open` | `consistent`, 0 |
| Input rule drops packets to the listener | `blocked` at input | `no_answer` | `consistent`, 0 |
| Output rule drops the SYN-ACK | `listener_reachable` | `no_answer` | `unavailable`, 2 |
| Extra prerouting hook | `unknown` at destination NAT | `open` | `unavailable`, 2 |
| Unprivileged collector lacks nftables access | `unknown` with an evidence gap | `open` | `unavailable`, 2 |

The lab checks nftables counters for both drops. The input verdict comes
from the observed input ruleset. For the return-path case, the counter
confirms that a SYN-ACK hit the output drop, which explains why the inbound
prediction and the handshake describe different events. A failed
connection alone establishes no firewall verdict.

The lab also supplies a wrong pinned host key, rejects the capture command,
returns an unsupported snapshot version, and returns a snapshot for a
different port. Each case produces a diagnostic on stderr, exits with 2,
and leaves stdout empty. A counter on the endpoint remains at zero through
all four cases.

## Verify a macOS operator

Use a fresh Linux host with a direct route from the Mac. Install the Linux
collector at `/usr/local/bin/reachmap`. Configure an SSH login with read
access to the evidence required by the collector and pin the Linux host key
using an independently verified copy. Give the two machines addresses on
an isolated test link and run a listener on the Linux address. For example,
use `192.0.2.10` for Linux and `192.0.2.20` for macOS. Replace `eth0` with
the actual receiving interface.

On the Linux host, start the listener in an empty fixture directory.

```sh
python3 -m http.server 8443 --bind 192.0.2.10
```

In another shell with packet-capture permission, record the handshake on
the receiving interface.

```sh
tcpdump -nn -i eth0 -c 3 'host 192.0.2.20 and tcp port 8443'
```

Run the macOS build from Terminal with the synthetic SSH identity and
known-hosts file in an existing private directory.

```sh
umask 077
reachmap audit --ssh-host 192.0.2.10 --ssh-user auditor \
  --known-hosts "$HOME/audit-lab/known_hosts" \
  --identity-file "$HOME/audit-lab/client" \
  --endpoint 192.0.2.10:8443 --source 192.0.2.20 --ingress eth0 \
  --confirm-direct-path > audit.json
jq '{client_bind, prediction: .prediction.verdict,
     outcome: .observation.outcome, comparison}' audit.json
```

Expect exit 0, `listener_reachable`, `open`, and `consistent`. Match the
captured SYN, SYN-ACK, and ACK to the address and port in `client_bind`.
To check replay on macOS, collect a snapshot with the same flow while the
test setup is stable. Copy it to the Mac and run the following.

```sh
# Linux collector, from a login with the same read access as the audit
umask 077
/usr/local/bin/reachmap path capture --host-ref example-collector \
  --source 192.0.2.20 --ingress eth0 --destination 192.0.2.10 --port 8443 \
  > inbound.json

# macOS operator, after copying inbound.json
reachmap path replay inbound.json --json > replay.json
diff -u <(jq -S '.prediction | {flow,verdict,steps}' audit.json) \
        <(jq -S '{flow,verdict,steps}' replay.json)
```

If an app-launched audit reaches SSH but the probe reports `unreachable`,
repeat it from Terminal. For app-launched commands, the parent app's
Local Network access can affect the probe.
[Apple's Local Network privacy documentation](https://developer.apple.com/documentation/technotes/tn3179-understanding-local-network-privacy)
describes the Terminal execution context.

When finished, stop the listener and packet capture, remove the disposable
collector and link, and remove the test SSH keys. Captures include firewall
and socket evidence. Keep any retained reports and snapshots private.

## Verification record

The Linux matrix passed using Reachmap 0.4.0 from `d9f7877`, Linux 7.2.12
on ARM64, Docker Engine 29.1.3, nftables 1.1.5, iproute2 6.17.0, and
OpenSSH 10.2p1. The IPv4 audit also passed from Terminal on macOS 27.2.1
(ARM64, OpenSSH 10.5p1) over a directly connected test bridge. The Linux
collector saw the handshake with the reported source address and port.
Offline replay on macOS reproduced the exact audit prediction.

Local checks included `make check` and the Linux inbound path, Docker
bridge path, and Docker/UFW scan integration scripts. The lab covers
macOS as an operator for an IPv4 test endpoint and Linux as the collector
for both IP families and the supported IPv4 Docker publish.
