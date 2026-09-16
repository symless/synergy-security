# Synergy Security

Proof-of-concept scripts for security vulnerabilities in Synergy.

This repository mirrors [deskflow/security][deskflow-security], with each PoC
lightly adapted to fit Synergy — branding in banners and prose, and anything
that differs in our tree. Keep the adaptations minimal so a PoC can be diffed
against its upstream counterpart when either side changes.

## Scope: published advisories only

**This repository contains PoCs for vulnerabilities that are already published
and fixed upstream.** Every script here corresponds to a GitHub Security
Advisory on [deskflow/deskflow][advisories] that has been published.

Work on unpublished or embargoed advisories does not belong here. Deskflow keeps
those in a private embargo repository until the advisory is published, at which
point the PoC is copied across in a fresh commit.

A PoC being present says nothing about whether Synergy carries the fix. Synergy
forks Deskflow at a point in time, so an advisory can be published and scripted
here while our branch is still behind. Track the port itself in Jira under `S1`.

If you are reporting a new vulnerability, do not open a pull request here. Use
private vulnerability reporting on the Synergy repository.

[deskflow-security]: https://github.com/deskflow/security
[advisories]: https://github.com/deskflow/deskflow/security/advisories

## Layout

```
poc/
  cve_<year>_<id>_<area>_<class>.py   # one PoC per CVE
  utils.py                            # shared helpers
```

Where an advisory has no CVE assigned yet, name the file for its GHSA ID
(`ghsa_<id>_<area>_<class>.py`) and rename it once a CVE is issued.

## Prerequisites

- Python 3.9+
- A running Synergy instance to target

## Running a PoC

```bash
python poc/<script>.py --host <target_ip> [--port <port>]
```

All PoCs default to `localhost:24800` and support `--help`.

Only run these against instances you own or are authorised to test.

## Adding a PoC

1. Confirm the advisory is **published** on [deskflow/deskflow][advisories].
   If it is not, this is the wrong repository.
2. Add a file in `poc/` named `cve_YYYY_NNNNN_<area>_<class>.py`.
3. Reuse helpers from `poc/utils.py` where it makes sense.
4. Exit non-zero (or print a clear `[FAIL]`/`VULNERABLE` line).
5. Keep the diff against the upstream PoC as small as the adaptation allows.
