# Why Docker ports can bypass UFW

UFW filters traffic in the firewall's `INPUT` chain: packets addressed to the
host itself. When Docker publishes a container port (`ports: "5055:5055"` in
Compose), it adds NAT rules that rewrite incoming packets to the container's
address. Those packets are then *forwarded* to the container and never pass
through `INPUT`, so UFW's rules do not apply to them.

The result: `ufw status` can show a port as closed while it is reachable from
the network.

## How to avoid it

- Publish only to localhost when the service is used by a reverse proxy or
  other containers on the same host: `ports: "127.0.0.1:5055:5055"`.
- Do not publish ports that only other containers need; use a shared Docker
  network instead.
- Put filtering rules in Docker's `DOCKER-USER` chain, which Docker evaluates
  before its own rules, or use a helper such as
  [ufw-docker](https://github.com/chaifeng/ufw-docker).

## What reachmap reports

`reachmap scan` reads `ENABLED` in `/etc/ufw/ufw.conf`. That file holds what UFW
was last told to do, which is what it applies at boot; the rules in the kernel
are not checked. A missing file means UFW is not installed, which counts as off.

When UFW is active, every Docker port published on anything but loopback gets
`Docker port: UFW does not apply` in WHY, and a summary follows the table:

```
PORT  PROTO  ADDRESS    SERVICE                     REACHABLE FROM  WHY
8080  tcp    0.0.0.0    web (container shop-web-1)  this host, LAN  all IPv4 addresses (bound device not checked); Docker port: UFW does not apply
9000  tcp    127.0.0.1  api (container shop-api-1)  this host       loopback address

warning: UFW is active, but it does not apply to these Docker ports: 8080
warning: DOCKER-USER has rules, so filtering may apply, not verified
```

A port published on one LAN address counts too: Docker forwards it past UFW just
like a port on all addresses. A port on `127.0.0.1` is not flagged. reachmap
never says a Docker port is protected by UFW.

Any warning makes `scan` exit with status 1, so it fits scripts. Status 1 also
means a failed scan; a failed scan prints `error:` on stderr and no table.

| Warning | Meaning |
|---------|---------|
| `UFW is active, but it does not apply to these Docker ports` | The ports listed are forwarded past UFW. |
| `could not tell whether UFW is active` | `ufw.conf` could not be read or understood; the warning gives the reason. If UFW is active, the ports listed are forwarded past it. |
| `UFW is active and Docker could not be asked` | The published ports are unknown, so this is not a clean result. Without access to Docker's socket, run with `sudo`. When Docker is not installed there is no warning. |
| `DOCKER-USER has rules, so filtering may apply, not verified` | The chain holds rules. reachmap does not evaluate them, so the ports stay flagged. |
| `DOCKER-USER rules were not checked` | `iptables -S DOCKER-USER` needs root, or it failed; the warning gives the reason. |

The chain is read with `iptables` only when a port is flagged, and only for IPv4.
Rules in the IPv6 chain are not noticed yet.
