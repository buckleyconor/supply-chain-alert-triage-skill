---
name: supply-chain-alert-triage
description: >
  Triage a software supply-chain security alert against the local development
  machine to determine whether it is affected. Use when the user shares a
  vulnerability/compromise notification (email, Slack, advisory URL) about
  malicious or compromised open-source packages — especially npm, PyPI (pip),
  or Cargo dependency-confusion / typosquat / hijacked-package / RAT campaigns
  such as Shai-Hulud, Miasma, or similar — and wants to check whether their
  environment (installed packages, lockfiles, or host) is impacted. Report-only:
  it identifies affected lockfiles and host indicators of compromise and
  produces a remediation checklist; it does not modify dependencies, delete
  files, or kill processes.
license: MIT
metadata:
  author: Conor Buckley
  version: "1.1.0"
  repository: https://github.com/buckleyconor/supply-chain-alert-triage-skill
---

# Supply Chain Alert Triage

## Overview

Given a supply-chain security alert, determine whether THIS machine (a Linux dev
station by default) is affected. The workflow is a hybrid: an LLM parses the
unstructured alert into structured IOCs, then **deterministic scripts** do the
actual scanning across npm, PyPI, and Cargo, corroborated by established SCA
tools. The skill is **report-only** — it surfaces findings and a remediation
checklist for the user to act on; it never changes dependencies, deletes files,
or kills processes.

Covered ecosystems: **npm, PyPI (pip), Cargo**. Corroborating scanners:
**osv-scanner** and **npm audit**.

## Workflow

Run these steps in order. Steps 2–4 are the deterministic scans and can run in
parallel once `iocs.json` exists.

### Step 1 — Parse the alert into `iocs.json`

Read `references/alert_parsing.md` for the exact schema and extraction rules,
then write an `iocs.json`. Capture every affected package + version (including
alpha/beta/rc tags), plus any host IOCs (drop paths, SHA-256 hashes, process
patterns, C2 IPs/domains). If the alert references an advisory URL, read it to
recover hashes/C2/drop-paths the email omits. Record the safe/fixed versions in
notes (not in `iocs.json`) for the final report.

### Step 2 — Scan packages (lockfiles + installed trees)

```bash
python3 scripts/scan_packages.py --iocs iocs.json \
  --roots ~/  --out packages_report.json
```

Point `--roots` at the directories that hold the user's projects (e.g.
`~/dev ~/projects`), or `~/` for a broad sweep. Scans `package-lock.json`,
`yarn.lock`, `pnpm-lock.yaml`, and `node_modules` (npm); `requirements*.txt`,
`poetry.lock`, `Pipfile.lock`, `uv.lock`, and installed `dist-info`/`egg-info` (PyPI); and
`Cargo.lock` (Cargo). Reports exact `name@version` matches with file paths —
PyPI names are matched with PEP 503 normalization, so `-`/`_`/`.` variants
cannot slip through. Exit 2 means the `iocs.json` is invalid: fix it and
re-run, don't trust a partial scan. Every report carries a `coverage` block
(roots walked/skipped, per-ecosystem file counts, read errors, `confidence`):
never report "clean" without checking it — `confidence: check` or a zero
scan count for an IOC ecosystem means the scan never actually looked there.

### Step 3 — Scan host for active-infection IOCs

```bash
python3 scripts/scan_host_iocs.py --iocs iocs.json --out host_report.json
```

Checks malware drop paths, SHA-256 matches under the cache dirs named in
`iocs.json`, suspicious running processes, active connections to known C2
indicators, and persistence locations (user/system cron, systemd units,
autostart `.desktop`, shell rc files) grepped for IOC paths and patterns — a
report-only inert grep. A hit in the first four classes means likely **active
infection**, not just exposure. `persistence_matches` is a weaker but still
serious signal: the infection was dormant or survives reboot — same
remediation urgency; verify each match before dismissing it.

### Step 4 — Corroborate with established scanners

```bash
bash scripts/run_scanners.sh ./scanout ~/dev ~/projects
```

Runs `osv-scanner` (if installed) and `npm audit` over the project roots and
writes raw JSON into `./scanout`. Degrades gracefully if a tool is absent — note
in the report which corroboration was available. Use this to catch related
advisories the alert didn't mention, and to confirm the deterministic hits.

### Step 5 — Synthesize the report

Combine the three outputs into a concise report for the user. Distinguish the two
evidence levels explicitly (see `references/remediation.md`):

- **Package hit only** → *potentially exposed*. This malware family fires at
  module **load time** (`require()`/import), not at install, so exposure depends
  on whether the code was actually loaded. Remediate the dependency; rotation is
  precautionary.
- **Host IOC hit** (live class, or a `persistence_matches` entry) → *active or
  dormant infection*. Assume the box and all credentials on it are compromised;
  do full rotation.

Then present the tailored remediation checklist from `references/remediation.md`.
Always: report confirmed hits to the security / Threat VM team, and flag that
org-level directives (registry blocks, CI/CD scans, shared-token rotation) are
out of scope for a single-station triage.

## Key facts to keep in mind

- **Presence ≠ execution, but treat presence as suspect.** Report a resolved bad
  version even without a host IOC.
- **Transitive dependencies matter most.** Widely-used packages appear deep in
  the tree, so always scan resolved lockfiles, never just top-level manifests.
- **"Zero hits" needs coverage before relief.** A clean-looking `packages_report.json`
  with skipped roots, an unscanned IOC ecosystem, or `confidence: check` is
  inconclusive, not clean — fix roots/IOCs and re-run.
- **Do not "upgrade to latest" blindly.** In some campaigns the latest tag was
  itself the payload — pin to the specific safe version from the alert.
- **AI-tooling is a target.** This family includes a module that poisons AI dev
  assistants (Claude Code, Copilot, Cursor); if a host IOC is found, include the
  agentic/dev-assistant config and MCP credentials in the rotation scope.

## Resources

- `scripts/scan_packages.py` — npm/PyPI/Cargo lockfile + installed-package scanner.
- `scripts/scan_host_iocs.py` — drop-file, hash, process, C2-connection, and persistence checks.
- `scripts/run_scanners.sh` — osv-scanner + npm audit corroboration wrapper.
- `references/alert_parsing.md` — `iocs.json` schema and extraction rules. Read in Step 1.
- `references/remediation.md` — evidence-level definitions and remediation checklist. Read in Step 5.
- `tests/test_scanners.py` — stdlib-only self-tests: `python3 -m unittest discover -s tests -v` (CI runs these on every push).