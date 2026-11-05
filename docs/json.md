# JSON output

`reachmap scan --json` prints the same findings as the table, as one JSON
document on standard output, for scripts and other tools. For example, the
ports the LAN can reach on the host from [the scan page](scan.md):

```
$ sudo reachmap scan --json | jq -r '.ports[] | select(.reach.networks // [] | index("lan")) | .port'
22
22
8080
9000
```

The table and the JSON come from the same scan, so they never disagree. The
JSON holds facts as typed values, not the sentences of the table.

## Stability

`schema_version` is `1`. It goes up when a change would break an existing
script: a field is removed or renamed, or a value changes meaning. New fields
and new `kind` values can appear without a new version, so ignore what you do
not know, and treat an unknown `kind` as unknown rather than as fine.

Every field listed here is always present; a missing value is `null`, not an
absent key.

## Exit status

The same as without `--json` (see [the scan page](scan.md#exit-status)):

| Status | Standard output | Meaning |
|--------|-----------------|---------|
| 0 | the document | The scan finished, `warnings` is empty. |
| 1 | the document | The scan finished, `warnings` is not empty. |
| 1 | empty | The scan failed; standard error says why. |
| 2 | empty | The arguments were wrong. |

`warning:`, `note:` and `hint:` lines stay on standard error, so they never mix
with the document.

## Document

```json
{
  "schema_version": 1,
  "ports": [
    {
      "port": 8443,
      "protocol": "tcp",
      "address": "0.0.0.0",
      "listener": "docker_forward",
      "service": {
        "kind": "container",
        "name": "shop-web-1",
        "compose_service": "web"
      },
      "reach": {
        "kind": "from",
        "networks": ["this_host", "docker", "tailnet", "lan"]
      },
      "reason": {
        "kind": "all_addresses",
        "family": "ipv4"
      },
      "warning": "ufw_bypassed"
    }
  ],
  "warnings": [
    {
      "kind": "ufw_bypassed",
      "ports": [8443]
    }
  ],
  "collector_errors": []
}
```

| Field | Type | Meaning |
|-------|------|---------|
| `schema_version` | number | See [Stability](#stability). |
| `ports` | array | One object per row of the table, in the same order: by port, then address. Empty when nothing listens. |
| `warnings` | array | The summary under the table. Any entry means exit status 1. |
| `collector_errors` | array | Optional facts that could not be collected. |

## Ports

| Field | Type | Meaning |
|-------|------|---------|
| `port` | number | The TCP port. |
| `protocol` | string | Always `tcp` for now. The table's `tcp6` is `tcp` with an IPv6 `address`. |
| `address` | string | The local address, e.g. `0.0.0.0` or `::1`. |
| `listener` | string | `host_socket`, or `docker_forward` when Docker publishes the port and no socket listens on the host. |
| `service` | object | Who the connections end up with. |
| `reach` | object | Which networks can connect. |
| `reason` | object | Why. |
| `warning` | string or null | What the firewall facts add for this port. |

### `service`

| `kind` | Other fields | Meaning |
|--------|--------------|---------|
| `process` | `pid` (number), `name` (string) | The process that has the socket open. |
| `container` | `name` (string), `compose_service` (string or null) | The Docker container the port is published for. |
| `unknown` | `reason` (string) | No owner was found. `needs_root`: some processes could not be inspected or may be hidden by `hidepid`, so run with sudo. `no_process`: no process holds the socket. |

### `reach`

| `kind` | Other fields | Meaning |
|--------|--------------|---------|
| `from` | `networks` (array of strings, never empty) | Clients on these networks can connect, narrowest first. |
| `unknown` | | reachmap lacks the facts to decide; `reason` says which. Never read this as unreachable. |

Each network is one of `this_host`, `docker`, `tailnet`, `lan` or `internet`.
`internet` means what the table says in full: reachable from the internet if
nothing upstream filters it. reachmap cannot see such filters. Like the table,
`reach` is decided before firewall rules; see
[Reading REACHABLE FROM and WHY](scan.md#reading-reachable-from-and-why).

### `reason`

| `kind` | Other fields | Meaning |
|--------|--------------|---------|
| `loopback` | | Bound to a loopback address. |
| `on_interfaces` | `interfaces` (array of strings) | Bound to one address, carried by these interfaces. |
| `all_addresses` | `family` (`ipv4` or `ipv6`) | Bound to the wildcard address of this family. The bound device and IPv6-only flag are not checked, so the widest case is assumed. |
| `not_on_host` | | Bound to an address no interface has. |
| `no_addresses` | `family` (`ipv4` or `ipv6`) | Bound to a wildcard address, but no interface has an address it covers. |
| `interfaces_unknown` | | The interfaces could not be listed. |

### `warning`

| Value | Meaning |
|-------|---------|
| `ufw_bypassed` | UFW is active, and Docker forwards this port past it. |
| `ufw_unknown` | UFW's state is unknown; if it is active, Docker forwards this port past it. |

See [Docker and UFW](docker-and-ufw.md), including the setups where this
overstates the risk.

## Warnings

| `kind` | Other fields | Meaning |
|--------|--------------|---------|
| `ufw_bypassed` | `ports` (array of numbers) | UFW is active, and these ports are forwarded past it. |
| `ufw_unknown` | `ports` (array of numbers), `reason` (string) | UFW's state is unknown, and these ports would be forwarded past it. |
| `docker_unknown` | `ufw_reason` (string or null) | Docker could not be asked, so ports that bypass UFW may be missing. `ufw_reason` says why UFW's state is unknown too, when it is. |
| `docker_user_rules` | | `DOCKER-USER` has rules that may filter these ports. Not verified. |
| `docker_user_unchecked` | `reason` (string) | `DOCKER-USER` could not be read. |

The `reason` strings are for people; their wording can change.

## Collector errors

A scan finishes without Docker or without the interface list. Each collector
that failed adds one entry, so facts that are missing never look like facts
that are absent: an empty `ports` list with a `docker` entry here does not mean
that no port is published.

| Field | Type | Meaning |
|-------|------|---------|
| `collector` | string | `interfaces` or `docker`. |
| `message` | string | What went wrong, for people. The wording can change. |
| `hint` | string or null | What to try, for people. |
