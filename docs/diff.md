# reachmap diff

`reachmap scan` says what a host exposes now. `reachmap diff` says what changed
since you last looked: save a scan once, then compare against it, by hand or
from a cron job.

```
$ sudo reachmap scan --json > baseline.json
$ sudo reachmap diff baseline.json
CHANGE      PORT  PROTO  ADDRESS    DETAIL
changed     22    tcp    0.0.0.0    reachable from: this host, LAN -> this host, tailnet, LAN
removed     3306  tcp    127.0.0.1  mysqld; reachable from this host
new         9000  tcp    0.0.0.0    python3; reachable from this host, Docker, tailnet, LAN
```

`reachmap scan` exits with 1 when it has warnings, and the file is still
complete. In a script that stops at the first failure, allow for that when you
save a baseline.

reachmap only reads the files. It never updates a baseline: when a change is
what you wanted, save a new one.

## Two forms

| Command | Compares |
|---------|----------|
| `reachmap diff baseline.json` | The file with a fresh scan of this host. Needs Linux, like [`reachmap scan`](scan.md). |
| `reachmap diff baseline.json current.json` | Two saved scans. Runs anywhere, without root. |

Run the baseline and the fresh scan the same way, both with `sudo` or both
without. Without root, reachmap may not be able to name every owner. Those rows
then show as changed, and a note says why.

The document does not record which host it came from, so reachmap cannot catch a
baseline from another host.

## What counts as a difference

Rows match on port, protocol and address.

| Change | Meaning |
|--------|---------|
| `new` | The row is not in the baseline. |
| `removed` | The row is gone. |
| `changed` | The row is still there, but its reachable networks, owner, listener or warning differ. DETAIL lists each one. |
| `unverified` | The row is missing now, but this scan could not have seen it, so it may still be there. |

Some things are left out on purpose:

- **The process ID.** A restart is no change in exposure, so owners are compared
  by program name.
- **WHY.** The same networks for another reason are no new exposure.
- **The warnings under the table.** A port's own warning is compared. The summary
  of a scan is not: run `reachmap scan` for that.

A service that moves from `127.0.0.1` to `0.0.0.0` has another address, so it
shows as one `new` and one `removed` row, next to each other.

Sockets can share a port, protocol and address, for example with `SO_REUSEPORT`.
Identical rows count once, so eight workers instead of four change nothing.

## Tailscale

`diff` compares rows, so a port that Tailscale starts to share shows as a change
when it adds a network to a row. Two cases do not show:

- A row that already lists those networks. The same reach for another reason is
  no new exposure, so WHY is not compared.
- A shared port with no row, such as a Funnel port that serves a file. `scan`
  still lists every Funnel port in its warning, so run `scan` too if that
  matters to you.

## Missing facts

A scan finishes without Docker, the interface list, the socket options or
Tailscale. That must not read as "nothing changed", so:

- A Docker-forwarded port without a host socket is only known from Docker. When
  Docker could not be asked, such a row is `unverified`, not `removed`.
- A note names the facts either side lacks.
- If the current scan lacks facts the baseline has, the status is 1 even when
  every row matches, and the line above the notes says `No differences in the
  rows.` instead of `No differences.`

Facts missing from both sides do not change the status, because a host without
Docker lacks them on every run. The price is that a Docker daemon that was down
for both scans goes unnoticed, apart from the notes.

A row with an unknown reach or owner is compared like any other. Unknown on one
side and known on the other is a change, and unknown on both sides is not.

## UDP rows

A UDP client that sent without connecting looks like a server (see
[UDP](scan.md#udp)), so short-lived rows on high ports can appear as `new` or
`removed` between runs. reachmap cannot tell them apart, so it reports them, with
a note. Expect this to set off an unattended check now and then.

## Exit status

| Status | Standard output | Meaning |
|--------|-----------------|---------|
| 0 | the result | Nothing needs attention. |
| 1 | the result | There are differences, or the current scan lacks facts the baseline has. |
| 2 | empty | Nothing could be compared, or the arguments were wrong; standard error says why. |

This follows the `diff` tool, so a cron job can tell a change from a broken
check:

```sh
reachmap diff /var/lib/reachmap/baseline.json > /tmp/reachmap-diff
case $? in
  0) ;;
  1) mail -s "Exposure changed" admin@example.com < /tmp/reachmap-diff ;;
  *) echo "reachmap diff could not compare" >&2 ;;
esac
```

A file is refused when it is not a `reachmap scan --json` document, when it is
over 64 MiB, or when its `schema_version` is one this reachmap does not read.
Save it again in that last case.
New fields are ignored. A value this version does not know counts as unknown, so
the diff still runs.

## JSON output

`--json` prints one document on standard output. Stability follows the same
rules as [the scan's JSON](json.md#stability): `schema_version` goes up when a
change would break an existing script, and new fields and new `kind` values can
appear without a new version. Treat an unknown `kind` as a difference.

```json
{
  "schema_version": 1,
  "differences": [
    {
      "port": 22,
      "protocol": "tcp",
      "address": "0.0.0.0",
      "kind": "changed",
      "was": {
        "listener": "host_socket",
        "service": {
          "kind": "process",
          "name": "sshd"
        },
        "reach": {
          "kind": "from",
          "networks": ["this_host", "lan"]
        },
        "warning": null
      },
      "now": {
        "listener": "host_socket",
        "service": {
          "kind": "process",
          "name": "sshd"
        },
        "reach": {
          "kind": "from",
          "networks": ["this_host", "tailnet", "lan"]
        },
        "warning": null
      }
    }
  ],
  "baseline_collector_errors": [],
  "current_collector_errors": ["docker"],
  "privileges_differ": false
}
```

| Field | Type | Meaning |
|-------|------|---------|
| `schema_version` | number | The version of this document, counted apart from the scan's. |
| `differences` | array | One object per difference, by port, then protocol, then address. |
| `baseline_collector_errors` | array of strings | The facts the baseline lacks: `interfaces`, `docker`, `socket_options`, `tailscale`, or `unknown` for a value this version cannot read. |
| `current_collector_errors` | array of strings | The same for the current scan. |
| `privileges_differ` | boolean | Only one of the scans could inspect every process, so owners can differ for that reason alone. |

### `differences`

| Field | Type | Meaning |
|-------|------|---------|
| `port` | number | The TCP or UDP port. |
| `protocol` | string | `tcp`, `udp`, or `unknown` for a value this version cannot read. |
| `address` | string | The local address. |
| `kind` | string | `new`, `removed`, `changed` or `unverified`. |
| `was` | object | What the baseline says. Present for all but `new`. |
| `now` | object | What the current scan says. Present for `new` and `changed`. |

`was` and `now` hold the [scan's fields](json.md#ports) of the same name, with
these differences:

- `listener` and `warning` can also be `unknown`.
- `service` has no `pid`, and its `unknown` kind has no `reason`.
- There is no `reason` field.
