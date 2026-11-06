# reachmap probe

`reachmap scan` says what a host should allow, before firewall rules.
`reachmap probe` tests it: run it on another machine, name the host and the
ports, and it tries to connect to each one from there. Give it a saved scan, and
it [reports where the two disagree](#comparing-with-a-scan).

```
$ reachmap probe server.example --ports 22,80,443,8000-8001
PORT  ADDRESS       RESULT
22    192.0.2.10    open
22    2001:db8::10  unreachable
80    192.0.2.10    closed
443   192.0.2.10    no answer
8000  192.0.2.10    closed
8001  192.0.2.10    closed

note: no answer means the connection timed out; a firewall and a host that is down look the same from here
```

It runs on Linux and macOS and does not need root.

## What it sends

reachmap opens a TCP connection to each port and closes it straight away. It
sends no data. It contacts only the host you name, plus your DNS server when
that is a name. The target may log the connections, so probe only hosts you are
allowed to test.

UDP is not probed: without a handshake, silence proves nothing. See
[UDP](scan.md#udp).

## Options

| Option | Default | Meaning |
|--------|---------|---------|
| `--ports` | | Ports and ranges, separated by commas: `22,80,8000-8100`. There is no default list, so name the ports or use `--scan`. |
| `--scan` | | A saved `reachmap scan --json`: probe its TCP ports and [compare](#comparing-with-a-scan). Cannot be combined with `--ports`. |
| `--from` | from the address | With `--scan`: the network this machine is on. One of `this_host`, `docker`, `tailnet`, `lan` or `internet`. |
| `--timeout` | `2` | Seconds to wait for each connection, for example `0.5`. |
| `--concurrency` | `100` | How many connections may be in progress at once. |
| `--json` | | Print [JSON](#json-output) instead of a table. |

The slowest case is a host that answers nothing: every attempt takes the whole
timeout. Each address and port is one attempt, so 1000 ports on one address take
about 20 seconds at the defaults, and twice that on a host with two addresses.
Looking up a name can add up to 10 seconds.

## Results

| Result | Meaning |
|--------|---------|
| `open` | The connection succeeded, so something accepts connections on that port from this machine. |
| `closed` | The host refused the connection. A firewall can send the same refusal, so this does not prove the host itself answered. |
| `no answer` | The connection timed out. A firewall that drops packets and a host that is down look the same from here. |
| `unreachable` | This machine or a router on the way reports that the host cannot be reached. A missing route, a firewall and a host that is down can all cause that. |
| `failed: ...` | The attempt failed in a way that says nothing about the port, and the message says why. The port was not tested. |

The results describe this machine, on this network, right now. A port that is
`open` from your laptop can be `no answer` from somewhere else.

A host name can have several addresses, and IPv4 and IPv6 can behave differently,
so every address is tried: one row per address and port, by port, then address.
A link-local IPv6 address exists per interface, so it shows the interface's
number: `fe80::1%3`.

`failed: Too many open files (os error 24)` means `--concurrency` is above what
this machine allows. Lower it, or raise the limit with `ulimit -n`.

## Comparing with a scan

`reachmap scan` decides what a host should allow before firewall rules. With
`--scan`, the probe tests that claim: save a scan on the host, copy the file to
another machine, and probe from there.

```
$ sudo reachmap scan --json > scan.json        # on the host
$ reachmap probe 10.0.0.10 --scan scan.json    # on another machine
PORT  ADDRESS    RESULT
22    10.0.0.10  open
3000  10.0.0.10  closed
5432  10.0.0.10  open
8080  10.0.0.10  no answer

compared with the scan from LAN (worked out from the address; --from overrides it)
PORT  FROM  DIFFERENCE
5432  LAN   connected, but the scan says this network cannot reach it
8080  LAN   did not connect, but the scan says this network can reach it; a firewall can cause that

note: no answer means the connection timed out; a firewall and a host that is down look the same from here
note: the scan has no verdict for these ports from at least one network, so only the probe result counts there: 3000
note: rows that are not TCP are left out, because a connect probe cannot confirm them: 53, 5353
```

The probe tries every TCP port in the file, and the rows of a port count
together. There are two kinds of difference, the more serious one first:

| Difference | Meaning |
|------------|---------|
| Connected | The scan says this network cannot reach the port, but the connection succeeded. Something is more exposed than the scan shows. |
| Did not connect | The scan says this network can reach the port, but no connection succeeded. A firewall can cause this, because the scan decides `reach` before firewall rules. So can a service that stopped after the scan. |

Some ports only show the probe result, and a note lists them:

- A port the scan marks as `unknown`.
- A port Tailscale forwards to, from `tailnet` and `internet`. Clients there use
  the port Tailscale shares, usually another one, so the row cannot say whether
  its own port answers them. From other networks the row counts as usual. The
  port Tailscale shares has no row, so it is not probed. See
  [Tailscale](scan.md#tailscale).

UDP rows are left out, because a connect probe cannot confirm them. The port of
a `failed` attempt is not called a difference either, unless another address of
that port connected: the attempt says nothing about the port, and it sets exit
status 1 by itself.

### Which network the probe comes from

reachmap works the network out from the address it connects to, because a scan
describes networks and this machine does not know which one it counts as:

| Address | Network |
|---------|---------|
| Loopback | `this_host` |
| `100.64.0.0/10` and `fd7a:115c:a1e0::/48` | `tailnet` |
| Private or link-local | `lan` |
| Anything else | `internet` |

The guess can be wrong. A private address may sit behind a VPN, and ISPs use
`100.64.0.0/10` too. Give the right network with `--from`, which then counts for
every address. reachmap says which network it used, and whether it worked it out.

A host name can have addresses on several networks, such as a private IPv4
address and a public IPv6 address. Each address then counts for its own network,
and the differences are worked out per port and network. One connection is
enough for a network, so a service that listens on IPv4 alone is not reported
because its IPv6 address refused.

### What it trusts

The file is read for numbers and enum values only, so no text from it reaches
the terminal. Unknown fields are ignored, a value this version cannot read counts
as `unknown`, and another `schema_version` is refused before any traffic is sent.

The document does not record which host it came from. reachmap cannot notice a
file compared against the wrong host, so check that yourself. A scan is also a
moment in time: a difference can simply mean the host changed since.

## Exit status

| Status | Standard output | Meaning |
|--------|-----------------|---------|
| 0 | the results | Every port was tested, whatever the results: a closed port is not a failure. With `--scan`, the probe and the scan agree as well. |
| 1 | the results | At least one attempt is `failed`, so that port was not tested, or the probe and the scan differ. |
| 1 | empty | The probe did not run, for example because the host name could not be resolved or the scan file could not be used; standard error says why. |
| 2 | empty | The arguments were wrong. |

## JSON output

`--json` prints one document on standard output. Stability follows the same
rules as [the scan's JSON](json.md#stability): `schema_version` goes up when a
change would break an existing script, and new fields and new `kind` values can
appear without a new version. Treat an unknown `kind` as not tested.

```json
{
  "schema_version": 1,
  "host": "server.example",
  "results": [
    {
      "port": 22,
      "address": "192.0.2.10",
      "result": {
        "kind": "open"
      }
    },
    {
      "port": 8080,
      "address": "192.0.2.10",
      "result": {
        "kind": "failed",
        "message": "Too many open files (os error 24)"
      }
    }
  ]
}
```

| Field | Type | Meaning |
|-------|------|---------|
| `schema_version` | number | The version of this document, counted apart from the scan's. |
| `host` | string | The host as you named it. |
| `results` | array | One object per row of the table, in the same order. |
| `port` | number | The TCP port. |
| `address` | string | The address connected to, with the interface's number for a link-local IPv6 address: `fe80::1%3`. |
| `result` | object | What happened. |

`result.kind` is `open`, `closed`, `no_answer`, `unreachable` or `failed`. Only
`failed` has another field: `message` (string), the system's error message.

With `--scan` the document has one more field, `comparison`, and `results` stays
as it is. Without `--scan` the field is left out.

```json
{
  "comparison": {
    "from": ["lan"],
    "guessed": true,
    "differences": [
      {
        "kind": "unexpected_connection",
        "port": 5432,
        "from": "lan"
      },
      {
        "kind": "missing_connection",
        "port": 8080,
        "from": "lan"
      }
    ],
    "unknown_ports": [3000],
    "skipped_ports": [53, 5353]
  }
}
```

| Field | Type | Meaning |
|-------|------|---------|
| `from` | array of strings | The networks the probe came from, narrowest first. |
| `guessed` | boolean | `true` when they were worked out from the addresses, `false` with `--from`. |
| `differences` | array | Where the probe and the scan disagree, most serious first, then by port. |
| `differences[].kind` | string | `unexpected_connection` when it connected although the scan says the network cannot reach the port, `missing_connection` when it did not connect although the scan says the network can. |
| `differences[].port` | number | The TCP port. |
| `differences[].from` | string | The network this difference is about. |
| `unknown_ports` | array of numbers | Probed ports the scan has no verdict for from at least one network in `from`. Such a port can have a difference from another network. |
| `skipped_ports` | array of numbers | Ports of rows that are not TCP, left out of the comparison. A port can be in this list and be probed, if it has a TCP row as well. |

Networks use the names in [the scan's JSON](json.md). Treat an unknown
`differences[].kind` as a difference.
