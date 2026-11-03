# Security policy

## Reporting a vulnerability

Please report security issues privately through GitHub:
**Security > Report a vulnerability** on this repository
(private vulnerability reporting). Do not open a public issue.

Include the reachmap version, your operating system and steps to reproduce.
You can expect a first reply within a week.

## Scope

reachmap reads system state (sockets, processes, Docker, firewall
configuration) and is often run with `sudo`. Issues of particular interest:

- Output that reports a service as unreachable or protected when it is not
- Any change to the system made by reachmap (it must be read-only)
- Ways to make reachmap run commands or read files the user did not ask for,
  for example through crafted container names or labels
- Network traffic the user did not start

## Supported versions

Only the latest release receives fixes.
