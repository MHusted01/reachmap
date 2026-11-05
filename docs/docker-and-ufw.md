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

A coming version of reachmap flags ports that Docker publishes on all
interfaces while UFW is active, so you can see where this applies on your host
([#6](https://github.com/MHusted01/reachmap/issues/6)).
