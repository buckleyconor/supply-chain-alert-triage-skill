# Supply-Chain Alert Triage (agent skill)

An agent skill that triages a **software supply-chain security alert** — a vulnerability or compromise notification about malicious or hijacked open-source packages — against a **local Linux development machine** and determines whether that machine is affected.

It is designed for campaigns such as npm / PyPI / Cargo dependency-confusion, typosquatting, hijacked-package, or RAT incidents (e.g. the Miasma / Shai-Hulud family), where a vendor or security team emails a list of compromised package versions and asks engineers to check their environment.

## Guarantees

- **Report-only.** The skill surfaces findings and a remediation checklist; it never modifies dependencies, deletes files, or kills processes. Destructive steps (removing a dropped payload, terminating a process) are handed to the user with exact paths/PIDs.
- **Deterministic scanning.** An LLM parses the unstructured alert into structured IOCs once; the actual scanning is done by plain Python/bash scripts that anyone can audit and re-run by hand.
- **Single-station scope.** It triages one dev box. Org-level directives (registry version blocks, CI/CD scans, shared org token rotation) are flagged for the security team, not executed.

## Ecosystems & corroborating scanners

| Ecosystem | Artifacts scanned |
|---|---|
| npm | `package-lock.json` (v1 + v2/v3), `yarn.lock`, `pnpm-lock.yaml`, installed `node_modules/**/package.json` |
| PyPI (pip) | `requirements*.txt`, `poetry.lock`, `Pipfile.lock`, `uv.lock`, installed `*.dist-info` / `*.egg-info` metadata |
| Cargo | `Cargo.lock` |

Corroboration (best-effort, degrades gracefully if absent): **osv-scanner** and **npm audit**.

## How it works

The agent runs these steps in order. Steps 2–4 are deterministic and can run in parallel once `iocs.json` exists.

| Step | What happens | Artifact |
|---|---|---|
| 1. Parse alert | LLM reads the alert (email / Slack / advisory URL — it will follow advisory links to recover hashes, C2, and drop paths the email omits) and writes the structured IOC file | `iocs.json` |
| 2. Scan packages | `python3 scripts/scan_packages.py --iocs iocs.json --roots ~/ --out packages_report.json` | `packages_report.json` |
| 3. Scan host IOCs | `python3 scripts/scan_host_iocs.py --iocs iocs.json --out host_report.json` | `host_report.json` |
| 4. Corroborate | `bash scripts/run_scanners.sh ./scanout ~/dev ~/projects` (osv-scanner + npm audit) | `scanout/*.json` |
| 5. Synthesize | Agent combines the three outputs into a report with a tailored remediation checklist | final report |

Point `--roots` at the directories that hold the user's projects (e.g. `~/dev ~/projects`), or `~/` for a broad sweep.

## Inputs

### What the user provides

1. **The alert itself** — pasted email body, Slack message, or advisory URL (or a mix). This is the only required input.
2. **Project roots** (optional) — directories to sweep; defaults to `~/`.

### Intermediate contract: `iocs.json`

Produced in Step 1 and consumed by both scanner scripts. Full field rules live in `references/alert_parsing.md`.

```json
{
  "alert_title": "Example npm Supply-Chain Compromise",
  "packages": [
    {"ecosystem": "npm",   "name": "@example/specs",   "versions": ["6.11.2", "6.11.2-alpha.1"]},
    {"ecosystem": "pypi",  "name": "example-lib",      "versions": ["1.2.3"]},
    {"ecosystem": "cargo", "name": "example-crate",    "versions": []}
  ],
  "host_iocs": {
    "file_paths": ["~/.local/share/NodeJS/sync.js", "~/.config/**/NodeJS/sync.js"],
    "file_hashes": {
      "9b2e65db...c690233b": "@example/specs-6.11.2.tgz"
    },
    "hash_scan_dirs": ["~/.npm", "~/.cache", "~/.cargo", "~/.local/share"],
    "processes": ["node .*-e .*spawn", "NodeJS/sync\\.js"],
    "network": ["203.0.113.7", "ipfs.io", "example-c2[.]com"]
  }
}
```

Field notes:

- `ecosystem` — `npm` | `pypi` | `cargo` (lowercase); enforced at scan time — unknown values abort with exit 2 rather than silently skipping the ecosystem.
- `name` — exact package name including npm scope; the scanner normalizes case itself, and PyPI names are matched with PEP 503 normalization (`-`, `_`, `.` interchangeable), so an IOC of `acme-lib` matches an installed `acme_lib`.
- `versions` — every compromised version verbatim, **including pre-release tags** (missing one is the most common triage failure). An empty list `[]` means *any* installed version of that package is flagged (whole package malicious).
- `file_paths` — malware drop locations; globs (`**`) and `~` supported.
- `file_hashes` — `sha256 -> label` map (SHA-256 only), matched against files under `hash_scan_dirs` (kept tight — package caches — because hashing large trees is slow).
- `processes` — regex patterns matched against `ps -eo pid,args`.
- `network` — plain IPs or domain substrings matched against active connections (`ss`/`netstat`). Defanged forms (`hxxp`, `[.]`) must be converted to real form first.
- Safe/fixed versions are deliberately **not** in `iocs.json` — they're kept in agent notes for the final report.

### Script CLI options

| Script | Required | Optional |
|---|---|---|
| `scan_packages.py` | `--iocs FILE --roots DIR [DIR ...]` | `--max-depth N` (default 14), `--out FILE`; exits **2** on invalid `iocs.json` |
| `scan_host_iocs.py` | `--iocs FILE` | `--max-hash-mb N` (default 32; files larger are skipped when hashing), `--out FILE`; exits **2** on invalid `iocs.json` |
| `run_scanners.sh` | `OUTDIR ROOT [ROOT ...]` | — (always exits 0; note in the report which tools were available) |

## Outputs

All JSON reports are printed to stdout **and** written to the `--out` path / `OUTDIR` when given.

### `packages_report.json` — compromised versions present locally

```json
{
  "schema_version": 2,
  "alert_title": "Example npm Supply-Chain Compromise",
  "hit_count": 2,
  "hits": [
    {"ecosystem": "npm", "name": "@example/specs", "version": "6.11.2",
     "source": "/home/dev/proj-a/package-lock.json",
     "detail": "node_modules/@example/specs"}
  ],
  "coverage": {
    "confidence": "high",
    "confidence_notes": [],
    "roots_requested": ["/home/dev"],
    "roots_walked": ["/home/dev"],
    "roots_skipped": [],
    "max_depth": 14,
    "depth_pruned_dirs": 0,
    "attempted_files": 142,
    "read_errors": 0,
    "scanned_files": 142,
    "scanned_by_ecosystem": {"npm": 90, "pypi": 40, "cargo": 12},
    "iocs": {"npm": {"packages": 4, "any_version": 0}}
  }
}
```

Each hit names the exact `ecosystem / name / version`, the file it was found in (`source`), and where in that file (`detail`: lockfile path, dependency chain, or `installed in node_modules` / `installed (site-packages)`).

The `coverage` block is the confidence control: `high` means every IOC
ecosystem was actually exercised under valid roots with no meaningful read-error
backlog; `check`/`none` comes with `confidence_notes` saying why (skipped root,
zero manifests for an affected ecosystem, file parse errors, depth prunes).
**Never report "clean" on `confidence: check` or `none`** — fix roots/IOCs and
re-run. Top-level `scanned_files`/`hit_count`/`hits` are kept for backward
compatibility.

### `host_report.json` — active-infection indicators

```json
{
  "dropped_files": [
    {"path": "/home/dev/.local/share/NodeJS/sync.js", "size": 18432, "mtime": 1750000000.0}
  ],
  "hash_matches": [
    {"path": "/home/dev/.npm/_cacache/.../x.tgz", "sha256": "9b2e...33b", "label": "@example/specs-6.11.2.tgz"}
  ],
  "suspicious_processes": [
    {"process": "node -e \"spawn(...)\"", "pattern": "node .*-e .*spawn"}
  ],
  "network_matches": [
    {"connection": "ESTAB 10.0.0.5:51234 203.0.113.7:443 users:(\"node\",pid=4711)", "indicator": "203.0.113.7"}
  ],
  "persistence_matches": [
    {"file": "/home/dev/.bashrc", "kind": "user-rc", "line_no": 42,
     "matched_pattern": ".local/share/NodeJS/sync.js", "pattern_kind": "drop-path",
     "line": "nohup node ~/.local/share/NodeJS/sync.js &"}
  ],
  "total_host_iocs": 4,
  "total_persistence_matches": 1,
  "ioc_warnings": []
}
```

Any hit in the first four classes (dropped payload, matching hash, rogue
process, live C2 connection) is an **active-infection** signal, not mere
exposure. `persistence_matches` is an inert grep of user/system cron, systemd
units, autostart entries, and shell rc files for IOC paths/patterns — evidence
the infection is **dormant or survives reboot**; treat with the same urgency,
but confirm each match isn't a lookalike before reporting it. Persistence
matches are counted separately (`total_persistence_matches`) and never inflate
`total_host_iocs`.

### `scanout/` — raw scanner output

`osv_<root>.json` (one per scanned root, plus `.err`) and `npmaudit_N.json` (one per npm project with a `package-lock.json`). Used to catch related advisories the alert didn't mention and to confirm deterministic hits.

### Final report (agent-produced)

A concise synthesis that explicitly distinguishes the two evidence levels:

- **Package hit only** → *potentially exposed*. This malware family fires at module **load time** (`require()`/import), not at install, so exposure depends on whether the code was actually loaded. Remediate the dependency; credential rotation is precautionary.
- **Host IOC hit** → *active infection*. Assume the box and every credential on it is compromised; full rotation immediately.

Plus a tailored remediation checklist from `references/remediation.md`, which always ends with: report confirmed hits to the security / Threat VM team, and flag org-level directives (registry blocks, CI/CD scans, shared-token rotation) as out of scope for a single-station triage.

## Requirements

- **Required:** `python3` (stdlib only), Linux. Targeted at a Linux dev station; host-IOC checks use `ps`, and connection checks use `ss` (falling back to `netstat`).
- **Optional:** `osv-scanner` (corroboration), `npm` (for `npm audit`), `ss`/`netstat`. Absent tools degrade gracefully and are noted in the report.

## Tests

Stdlib-only self-tests with synthetic fixture projects (no network, no real
malware): `python3 -m unittest discover -s tests -v`. GitHub Actions
(`.github/workflows/ci.yml`) runs them on every push/PR — run them before
trusting any edit to the scanners.

## Files

```
SKILL.md                      Agent entry point: triggers, workflow, judgment rules
README.md                     This file
LICENSE                       MIT
references/alert_parsing.md   iocs.json schema + extraction rules (read in step 1)
references/remediation.md     Evidence-level definitions + remediation checklist (read in step 5)
scripts/scan_packages.py      npm/PyPI/Cargo lockfile + installed-package scanner (coverage/confidence report)
scripts/scan_host_iocs.py     Drop-file, hash, process, C2-connection, and persistence checks
scripts/run_scanners.sh       osv-scanner + npm audit corroboration wrapper
tests/                        Fixture-based scanner self-tests (stdlib only)
.github/workflows/ci.yml      CI: byte-compile + self-tests on push/PR
```

## Installation

For a pi agent: copy this directory (keeping its name, which must match the `name` frontmatter) into a skill location — e.g. `~/.pi/agent/skills/supply-chain-alert-triage/` for a user skill, or `.agents/skills/supply-chain-alert-triage/` for a project skill. Pi discovers `SKILL.md` directories recursively; if you're unpacking the distributed tarball, just extract it where the skills live (it already carries the `supply-chain-alert-triage/` top-level directory). Run `/reload` (or start a new session) after installing or editing. No other registration is needed — the `SKILL.md` frontmatter `name`/`description` drives discovery, and the skill activates when the user shares a supply-chain alert and asks whether their environment is affected. To force-load it regardless: `/skill:supply-chain-alert-triage`.

## Limitations & caveats

- **Presence ≠ execution**, but presence is still reported as suspect — a resolved bad version is always a finding.
- **Transitive dependencies matter most** — compromised packages usually sit deep in the tree, which is why resolved lockfiles (not just top-level manifests) are scanned.
- **Never "upgrade to latest" blindly** — in some campaigns the latest tag was itself the payload; pin to the specific safe version named in the alert.
- **AI tooling is a target** — the covered malware family includes a module that poisons AI dev assistants (Claude Code, Copilot, Cursor); on a host-IOC hit, agentic/dev-assistant config and MCP credentials are in the rotation scope.
- The reference docs carry family-specific defaults (e.g. the `~/.local/share/NodeJS/sync.js` drop path, IPFS beacons) tuned to the Miasma/Shai-Hulud-style campaigns; for other campaigns, Step 1 must recover the real IOCs from the advisory.
- The scripts read many files under `--roots`; on a broad `~/` sweep with large caches, keep `hash_scan_dirs` tight and `--max-hash-mb` at its default.
- **A zero-hit report is only as good as its coverage** — check `coverage.confidence` and `scanned_by_ecosystem` before concluding clean; the tool tells you when it looked at nothing.

## License

MIT — see [LICENSE](LICENSE).
