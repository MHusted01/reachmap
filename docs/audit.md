# Audit one Linux TCP endpoint

`reachmap audit` asks an installed Linux collector for one inbound SYN
prediction, then makes one TCP connection attempt from the operator's Linux
or macOS machine. It reports both results and how they compare. The prediction
uses the same evidence and [scope as `reachmap path`](scan.md#linux-inbound-tcp-paths).

```sh
reachmap audit --ssh-host server.example --ssh-user auditor \
  --known-hosts "$HOME/.ssh/audit_known_hosts" \
  --identity-file "$HOME/.ssh/audit_ed25519" \
  --endpoint 192.0.2.10:8443 --source 192.0.2.20 --ingress eth0 \
  --confirm-direct-path
```

Use one numeric endpoint such as `192.0.2.10:8443` or `[2001:db8::10]:8443`.
`--source` must be configured on the client and match the destination's IP
family. `--ingress` is the receiving interface on the collector host. The
client binds the source before asking the collector for a prediction, then
uses that same socket for the probe. The probe sends no application data.

Supply the SSH transport separately with `--ssh-host` and `--ssh-user`.
`--ssh-port` defaults to 22. With `--confirm-direct-path` you attest that
the endpoint belongs to the authenticated collector's network namespace,
the named interface receives the probe SYN, and the source and destination
reach that interface unchanged. Docker DNAT covered by the prediction occurs
after that point. Use comparable host and client clocks. Leave the audit for
cases where you can make these assertions. The collector's SSH host key
authenticates the SSH session. The endpoint binding and ingress come from
your declaration. IPv6 addresses requiring a zone are outside this scope.

## SSH trust and permissions

The remote operator provisions the Linux collector at
`/usr/local/bin/reachmap` and grants the login whatever read access is
appropriate. The collector's fixed command is `reachmap path capture`.
Reachmap performs no installation, remote writes, sudo, service discovery
or port-range probe. A restricted account can still provide partial
evidence, with gaps such as permission failures in `evidence_gaps`.

Pass absolute paths to an existing identity file and a known-hosts file
containing the independently verified key or host CA for the SSH
destination. For port 22, a host key entry uses `server.example`. For a
custom port, it uses `[server.example]:2222`. The local `/usr/bin/ssh`
verifies that file strictly and uses only the selected public-key identity.
For an identity that needs a passphrase, load the matching key into your
existing SSH agent first. Client configuration, interactive prompts, host
key updates, connection sharing and forwarding are disabled.

SSH has a five-second connect timeout and a 30-second overall limit, with
stdout capped at 64 MiB and stderr capped at 16 KiB. A failed SSH session,
invalid or incompatible snapshot, or mismatched flow prevents the probe.
A valid partial snapshot still allows the explicitly requested handshake.
The handshake has two seconds to complete. Comparison uses a maximum
capture age of 60 seconds through probe completion.

## Report and exit status

A completed audit writes one JSON report with `report_version: 1`. It
contains the authenticated SSH destination and declared network scope,
the prediction and its timestamp and stages, the client's bound address
and ephemeral port, the exact endpoint and handshake outcome, probe
timestamps, evidence gaps and the comparison.

| Exit | Result |
| --- | --- |
| 0 | `consistent` within the recorded scope. |
| 1 | `disagrees` within the recorded scope. Report both results without assigning a cause. |
| 2 | Comparison `unavailable` with a reason in the JSON. Errors that prevent a report go to stderr. |

An open connection confirms a TCP handshake from this client at the
reported time. A refusal, timeout or unreachable result cannot establish
a firewall verdict. Use the prediction stages and evidence gaps to
understand what the collector could determine.
