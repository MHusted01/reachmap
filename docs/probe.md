# reachmap probe

`reachmap scan` says what a host should allow, before firewall rules.
`reachmap probe` tests it: run it on another machine, name the host and the
ports, and it tries to connect to each one from there.

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
| `--ports` | required | Ports and ranges, separated by commas: `22,80,8000-8100`. There is no default list. |
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

## Exit status

| Status | Standard output | Meaning |
|--------|-----------------|---------|
| 0 | the results | Every port was tested, whatever the results: a closed port is not a failure. |
| 1 | the results | At least one attempt is `failed`, so that port was not tested. |
| 1 | empty | The probe did not run, for example because the host name could not be resolved; standard error says why. |
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
