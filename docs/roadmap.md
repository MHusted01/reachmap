# Reachmap roadmap

Reachmap aims to become a local-first, open-source network exposure analysis
tool for Linux, Windows and macOS. It is for developers, sysadmins, DevOps and
security engineers working on anything from a workstation or homelab to an
enterprise fleet.

**Which services are reachable, from where, through which network paths, why is
that access possible, and how can unintended exposure be corrected?**

A standalone CLI on an individual machine is the starting point. An exposure
report should connect a client or network vantage point to an entry point and
the service behind it, through any relevant routing, NAT, firewalls, containers,
proxies, tunnels and upstream infrastructure. The report should show the
evidence behind each result and identify where the evidence runs out.

## Current capabilities

| Status | Capabilities | Evidence limits |
| --- | --- | --- |
| Released in [v0.1.0](https://github.com/MHusted01/reachmap/releases/tag/v0.1.0) | Linux TCP socket and process inventory, address coverage, Docker published ports, UFW warnings and JSON output. Linux and macOS binaries are available. | Bind scope and warning signals describe potential exposure. Local scanning requires Linux. |
| Merged on main, unreleased | [v0.2 Probe and diff](https://github.com/MHusted01/reachmap/milestone/2) adds Linux UDP inventory, Tailscale Serve and Funnel configuration, TCP probes with saved-scan comparison, and baseline diffs with port exclusions. [#13](https://github.com/MHusted01/reachmap/issues/13) starts [v0.3 Deeper checks](https://github.com/MHusted01/reachmap/milestone/3) with Docker Engine API collection over a local Unix socket. | Probes observe TCP from the initiating machine. The saved-scan comparison can infer a network label from the target address, and the saved scan lacks host identity. Tailscale status and Docker bindings describe configuration. Full firewall, forwarding and upstream paths remain unmodeled. |
| Open PR | [#14](https://github.com/MHusted01/reachmap/issues/14) ([PR #69](https://github.com/MHusted01/reachmap/pull/69)) evaluates simple nftables input rules for native Linux sockets. | One applicable filter base chain per family, exact interface and transport destination-port matches, and accept/drop or chain policy. It assumes the packet reaches the input hook. Multiple applicable chains, relevant unsupported rules and unavailable evidence yield unknown. Docker publishes and Tailscale shares are outside this check. |

See the current command and output contracts in [scan](scan.md), [probe](probe.md),
[diff](diff.md), [JSON](json.md) and [Docker and UFW](docker-and-ufw.md).

## Platform targets

The deep-analysis priorities below govern engineering effort. First-class
support means maintained native collection and analysis, documented limits and
OS-specific verification. Each support level can ship independently.

| Priority and platform | CLI availability | Remote auditing | Local service discovery | Reachability analysis target |
| --- | --- | --- | --- | --- |
| **P0 Linux** | Released | First collector target and an audit operator platform | TCP/UDP sockets, owning processes and containers on main. Extend to native service ownership where evidence is available. | Reference platform for Netfilter, routing, NAT, namespaces, Docker and stateful packet paths. |
| **P1 Windows 11 and supported Windows Server versions** | Planned | Planned as operator and audited host, with transport and privilege support validated separately | Native listening ports, owning processes, services and network inventory | Windows Firewall profiles and policy, Windows Filtering Platform (WFP), and relevant enterprise, virtual and container networking. |
| **P2 macOS** | Released. TCP probes and offline diffs are on main. | Planned as operator and audited host. The audit command is pending. | Native sockets, owning processes and services, starting with [#16](https://github.com/MHusted01/reachmap/issues/16) | pf and the application firewall, with emphasis on local development and virtualized networking. |

The lightweight macOS inventory can ship before deep Windows analysis. Building
a CLI for an OS, running it as an audit client, collecting evidence from that OS
and evaluating its firewall each require their own support claim.

## Architecture and evidence

Keep the existing split between a pure analysis core and thin system collectors.
Evolve a shared Rust model for evidence, endpoints, network contexts, path
segments, observations and explanations. Platform collectors acquire facts and
platform evaluators implement native packet or policy semantics. Shared reports
must work without assumptions about /proc, Netfilter hooks, interface names or
Linux namespaces. Preserve native terminology and rule identifiers in evidence
so an operator can find the source of a decision.

Describe the source vantage point, destination and protocol, the scope and time
of the evidence, and relevant collection failures or missing stages. Model
translations such as NAT as changes to a flow and proxying as a new connection
to a backend. Correlate evidence only where the host, network context, endpoint
and observation scope support the match. Keep inventory and configured
exposure visible as facts in their own right.

| Result | Evidence needed |
| --- | --- |
| **Verified reachable** | A successful observation for the stated vantage point, endpoint, protocol and time. State what succeeded (such as a TCP handshake) and which parts of the path are known. |
| **Predicted reachable** | The declared path is supported by the collected facts and evaluation within explicit scope and assumptions. Name any upstream boundary beyond that scope. |
| **Predicted blocked** | The evidence establishes a blocking decision for the stated traffic and scope. If an unmodeled behavior could change that decision, use unknown. |
| **Unknown** | Missing, stale, incompatible or unsupported evidence could change the result. Explain where and why. Failed probes or UDP silence alone establish no firewall verdict. |

Report prediction and observation independently so disagreements survive.
Distinguish a listening socket, a configured route to a service, successful
transport and application access. Record application authentication separately,
with its own evidence and limits. A public address, an accepting rule or a
client failing to connect is insufficient evidence for a general safety claim.

## Next actionable milestone: trustworthy Linux input checks

**Outcome.** Explain a bounded Linux host-input decision for IPv4 and IPv6 and
identify Docker publishes that need IPv6-specific evidence. Use the existing
v0.3 milestone and its issue order.

**Dependencies and scope.**

- Finish [#14](https://github.com/MHusted01/reachmap/issues/14) through its
  existing PR. From there, the next implementation issue is
  [#15](https://github.com/MHusted01/reachmap/issues/15). Inventory IPv6 and
  dual-stack Docker publishes and identify gaps in IPv6 firewall evidence.
  Base any IPv4-only finding on positive evidence about both families and
  leave effective Docker forwarding to the packet-path milestone below.
- Build on #14 with [#70](https://github.com/MHusted01/reachmap/issues/70)
  for base-chain priority and combined verdicts,
  [#71](https://github.com/MHusted01/reachmap/issues/71) for bounded
  jump/goto/return traversal and observational statements, and
  [#72](https://github.com/MHusted01/reachmap/issues/72) for interface and
  port sets, ranges, negation and transport matches.
- Keep the existing companion work in the v0.3 queue.
  [#16](https://github.com/MHusted01/reachmap/issues/16) starts macOS inventory.
  [#17](https://github.com/MHusted01/reachmap/issues/17) explores explicit VPN
  egress observations for containers. [#56](https://github.com/MHusted01/reachmap/issues/56)
  and [#58](https://github.com/MHusted01/reachmap/issues/58) improve diff and
  broadcast reporting. These issues have their own acceptance criteria and
  do not gate the Linux input or packet-path design.

**Done when.** Supported native TCP and UDP input decisions identify the IP
family, ingress interface, decisive chain or rule and any relevant uncertainty.
Fixtures cover multiple chains, control flow, sets and missing or unsupported
inputs. Repeatable Linux network tests compare decisions with observed delivery
and blocking on representative IPv4 and IPv6 paths. Docker findings distinguish
known publish configuration, firewall evidence for each family and unknown
effective forwarding. Existing JSON and exit behavior retain documented
compatibility.

**Open questions.** What can be proved when base-chain priority ties or an
earlier unsupported action could change the packet or control flow? Which
Docker versions and firewall backends expose reliable family-specific
evidence? Keep the supported subset explicit and test it against kernel
behavior. An accept in one base chain permits processing to continue.
[Netfilter hook order](https://wiki.nftables.org/wiki-nftables/index.php/Netfilter_hooks) ·
[nftables base-chain behavior](https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains) ·
[Docker port publishing](https://docs.docker.com/engine/network/port-publishing/)

## Medium-term development

### Linux packet paths and evidence snapshots

**Outcome.** Explain paths from a stated source through Linux to a local socket
or forwarded backend. Build on the input evaluator and shared evidence model.
Add interface and namespace context, route and forwarding decisions, relevant
Netfilter hooks and priorities, NAT, Docker networking and supported subsets of
nftables and iptables. Correlate Docker Engine evidence with the observed
network mode and actual path, including IPv4, IPv6 and dual-stack handling.

**Done when.** Tested paths explain original and translated endpoints, routing,
applicable firewall decisions and the destination service or blocking point.
Controlled networks verify representative local, forwarded and Docker paths
over both families, with new-flow and supported connection-tracking scenarios,
including return traffic where required. Replayable evidence snapshots identify
the host, collection scope, schema version and gaps. Older scan files remain
usable for their documented comparisons.

**Open questions.** Decide how to represent iptables-nft alongside nftables
without double-counting rules, which legacy iptables semantics to support, and
which routing rules, marks, connection states and dynamic or offloaded paths
can be reproduced reliably. Start with explicit flow assumptions and bounded
evaluation. Use unknown where an omitted stage could change the result.
[Docker firewall behavior](https://docs.docker.com/engine/network/packet-filtering-firewalls/)

### Proxy and tunnel paths

**Outcome.** Trace configured entry points through Nginx, Caddy, Traefik,
Cloudflare Tunnel (cloudflared), and Tailscale Serve and Funnel to backends,
including localhost services. Continue the existing Tailscale work from
[#12](https://github.com/MHusted01/reachmap/issues/12) and
[#45](https://github.com/MHusted01/reachmap/issues/45). Add other proxies, VPNs
and tunnels where their evidence supports reliable correlation. Use the
endpoint and evidence model from the packet-path milestone.

**Done when.** Supported configurations report the listener or tunnel,
routing conditions such as host names, the target backend and any unresolved
links. Fixtures and disposable deployments cover external access to loopback
backends, multiple routes and missing or stale configuration. Scoped probes
can corroborate individual entry points. Reports distinguish loaded or
configured routes, observed reachability and application authentication.

**Open questions.** Determine where running configuration is observable,
how to handle includes and dynamic provider state, and which external tunnel
or identity policies a local collector can see. Avoid collecting secrets by
default. Test each adapter before claiming support for its path.

### Integrated remote auditing

**Outcome.** Bring remote collection, local probes and correlation into one
explicit audit, such as `reachmap audit ssh://user@host`. Start with Linux
host evidence, versioned snapshots and the existing TCP probe and
saved-scan comparison. Support an installed remote collector first if that
provides a dependable, least-privilege baseline.

**Done when.** An operator can collect evidence from an authenticated remote
host and correlate it with bounded probes from the operator's machine
against explicitly approved targets. Results record the audited host, evidence
time and scope, probe origin and resolved destination. Tests cover SSH host
identity, denied privileges, transport failure, schema mismatch and partial
evidence. Inferred network labels are marked as inferred. Probe observations
apply to their actual vantage point and time.

**Open questions.** Spike installation-free or temporary collection, including
binary provenance, permissions, platform and architecture negotiation, remote
execution constraints and cleanup. A temporary executable requires explicit
opt-in. A host may block the mechanism or forbid writes. Keep remote support
levels separate for each audited OS and operator platform.

### Remediation, policy and drift

**Outcome.** Convert explained paths into stack-aware, persistent configuration
recommendations and reusable local policies. Build on stable path evidence and
versioned snapshots, and extend `diff` from listener changes to exposure and
policy drift. Provide policy-as-code and CI/CD gates without a hosted dependency.

**Done when.** A supported finding identifies the stack and configuration
layer responsible, explains a persistent change and shows how to verify it
with a fresh scan or scoped probe. Reports distinguish exposure changes from
missing or changed evidence. Versioned policies evaluate local or saved
evidence reproducibly, with documented output and CI exit behavior for known
violations and indeterminate results.

**Open questions.** Decide how to identify the persistent source of runtime
rules and grant exceptions across stacks. Define how unknowns affect policy
gates and how policies migrate. Start with recommendations. Any future
automatic remediation is exploratory and requires a separate design decision,
explicit authorization, a safe preview and verifiable execution and recovery.
Read-only remains the default.

### Native Windows and macOS analysis

**Outcome.** Extend the shared core with native inventory collectors and
platform evaluators. Start with capability discovery and explicit privilege
boundaries. Prioritize Windows analysis for Windows 11 and supported Windows
Server versions, while shipping macOS inventory independently where practical.
Use platform evidence in the same reporting and auditing contracts.

**Done when.** Each supported OS level has installable builds, native fixtures
and tests on actual operating systems. Windows covers documented Windows
Firewall profiles and policy plus a verified WFP subset. macOS covers a
documented pf subset and application firewall state, including common local
development paths. Both report unsupported layers, partial data and tested
platform scope.

**Open questions.** Investigate how much effective WFP callout, group policy
and virtual networking behavior can be observed without privileged agents.
On macOS, validate pf anchors, application decisions and Network Extension or
virtualized networking boundaries. Preserve distinct semantics when combining
platform evidence. [Microsoft WFP architecture](https://learn.microsoft.com/en-us/windows/win32/fwp/about-windows-filtering-platform) ·
[Apple macOS firewall security](https://support.apple.com/guide/security/firewall-security-in-macos-seca0e83763f/web)

## Long-term objectives

### Infrastructure and multi-host topology

**Outcome.** Combine host and proxy evidence with optional read-only
infrastructure adapters. Candidates are AWS, Azure and other major cloud
providers, Hetzner, DigitalOcean, Proxmox and other hypervisors, and Kubernetes
and its container networking. Choose each adapter by practical value,
accuracy, evidence availability and maintenance cost. Add adapters after
the shared path model and snapshot contracts can represent their evidence.

**Done when.** Supported adapters explain paths spanning host and infrastructure
boundaries, including relevant cloud firewalls, routes, load balancers,
hypervisor networks or Kubernetes Services, ingress and NetworkPolicy.
Each adapter documents privileges, supported variants and unknown boundaries.
Controlled environments verify multi-host paths and partial evidence. The
standalone CLI works without integrations, credentials or external services.

**Open questions.** Decide how to join identities across hosts, accounts and
clusters and reason about private, overlapping networks, asynchronous snapshots
and controller-specific enforcement. A Kubernetes manifest alone leaves
important behavior dependent on the observed network implementation.
[Kubernetes networking](https://kubernetes.io/docs/concepts/services-networking/)

### Pre-deployment exposure analysis

**Outcome.** Evaluate intended infrastructure or application changes against
exposure policies before deployment, after runtime evidence and policy
evaluation are reliable for the relevant stacks.

**Done when.** For a supported plan, show predicted new or changed paths,
policy violations, assumptions and unresolved runtime dependencies. Compare
predictions with post-deployment observations in test environments and document
where those predictions are reliable enough for a CI gate.

**Open questions.** Identify inputs that describe a complete enough intended
state and a defensible way to account for generated rules, provider defaults
and runtime state. Start with a feasibility spike on one representative stack.

### Optional fleet operations

**Outcome.** Add self-hostable multi-host coordination, service and network
topology visualization, exposure monitoring, historical evidence and audit
trails, RBAC, SSO and centralized policy. Build on remote auditing,
multi-host identity, versioned evidence and local policy evaluation.

**Done when.** A representative fleet can collect authorized evidence from
multiple vantage points, explain topology and changes, enforce access
boundaries and replay the evidence behind a finding. Incremental analysis
re-evaluates affected paths and recovers from missed or failed collections.
Measure performance against representative workloads and publish the limits.
Users can still run the CLI, compare snapshots and evaluate policies locally.

**Open questions.** Resolve evidence retention and redaction, tenant isolation,
identity federation, trust in distributed collectors, consistency under partial
delivery and incremental invalidation. Validate these before committing to
a coordinator architecture or operational targets.

## Engineering principles

- **Correctness and explainability.** Support a configuration only when its
  verdict and evidence can be explained and tested. Broaden coverage after
  the supported subset behaves reliably.
- **Security and local control.** Keep default analysis read-only with least
  privilege and no telemetry. Bound and sanitize untrusted rules, snapshots and
  command output. Network collection and probes require operator intent.
  Provide useful standalone operation without a cloud account, subscription,
  coordinator or required external service.
- **Reliability and performance.** Degrade gracefully when collection is partial,
  report actionable failures and keep processing bounded and reproducible.
  Measure representative workloads before choosing optimizations. Use
  incremental analysis where evidence dependencies can be tracked reliably.
- **Maintainability and testability.** Keep system access thin, use small
  platform modules and pure evaluation where practical, and prefer minimal
  dependencies. Verify parsers and decisions with reproducible fixtures and
  actual behavior in controlled networks.
- **Compatibility and quality.** Preserve documented CLI and JSON contracts.
  Version breaking changes and document migrations for existing snapshots and
  consumers. Favor correctness, security and long-term maintainability over
  release speed.

## How this maps to GitHub

The roadmap defines outcomes and dependencies. The
[issue tracker](https://github.com/MHusted01/reachmap/issues) holds actionable
work, and [milestones](https://github.com/MHusted01/reachmap/milestones) track
its delivery. Keep the completed [v0.1](https://github.com/MHusted01/reachmap/milestone/1)
and [v0.2](https://github.com/MHusted01/reachmap/milestone/2) issue history.
Use the existing v0.3 queue for the next work. Later headings above describe
development stages without assigning release numbers or dates.

Before opening an issue, check open and closed issues for the scope and
dependencies. Refine an existing issue when it covers the work. File only
missing tasks for the next actionable milestone, with explicit scope,
dependencies and observable acceptance criteria. Use a research spike when
feasibility or evidence quality needs resolving before implementation. Create
later issues once those milestones become actionable. Follow the existing
[contribution workflow](../CONTRIBUTING.md).
