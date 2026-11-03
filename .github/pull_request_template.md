## What and why

<!-- One feature per PR. The title must be a conventional commit (feat: ..., fix: ...). -->

Closes #

## How it was tested

- [ ] `make test` (unit and integration tests, coverage >= 80%)
- [ ] `make lint` (rustfmt and clippy)
- [ ] `make deny`
- [ ] Manual check (describe host, OS, what you ran):

## Checklist

- [ ] Read-only: nothing changes firewall rules, containers or system settings
- [ ] Tests written before the implementation
- [ ] No `unwrap()`/`expect()` outside tests, no `unsafe`
- [ ] `CHANGELOG.md` and docs updated if behaviour changed
- [ ] All review comments addressed and resolved
