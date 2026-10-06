# Alert Parsing: Building `iocs.json`

The first step of every triage is turning an unstructured security alert (email,
Slack post, advisory URL) into a structured `iocs.json` file that the scanner
scripts consume. This is the one step that genuinely needs judgment — do it
carefully, because everything downstream keys off it.

## Target schema

```json
{
  "alert_title": "AsyncAPI npm Supply Chain Miasma Compromise",
  "packages": [
    {"ecosystem": "npm",   "name": "@asyncapi/specs",              "versions": ["6.11.2", "6.11.2-alpha.1"]},
    {"ecosystem": "npm",   "name": "@asyncapi/generator",          "versions": ["3.3.1"]},
    {"ecosystem": "npm",   "name": "@asyncapi/generator-helpers",  "versions": ["1.1.1"]},
    {"ecosystem": "npm",   "name": "@asyncapi/generator-components","versions": ["0.7.1"]}
  ],
  "host_iocs": {
    "file_paths": [
      "~/.local/share/NodeJS/sync.js",
      "~/.config/**/NodeJS/sync.js"
    ],
    "file_hashes": {
      "9b2e65db653ca8575c9b10eefb9a80c6006404812c2ec212bf5675e3c690233b": "@asyncapi/specs-6.11.2.tgz"
    },
    "hash_scan_dirs": ["~/.npm", "~/.cache", "~/.cargo", "~/.local/share"],
    "processes": ["node .*-e .*spawn", "NodeJS/sync\\.js"],
    "network": ["85.137.53.71", "ipfs.io", "ipfs.io/ipfs/QmQobZSp"]
  }
}
```

## Field rules

- `ecosystem` — one of `npm`, `pypi`, `cargo` (lowercase). Map language/registry
  names: npm/Node/yarn/pnpm -> `npm`; pip/PyPI/poetry/pipenv -> `pypi`;
  crates.io/Cargo/Rust -> `cargo`.
- `name` — exact package name including npm scope (`@scope/pkg`). Do NOT lowercase
  or strip the scope; the scanner normalizes case itself.
- `versions` — list every compromised version string verbatim, including
  pre-release tags (`6.11.2-alpha.1`). Strip a leading `v`/`^`/`~`/`=` if present.
  If the alert says the *entire package* is malicious (no safe version), use an
  empty list `[]` — the scanner then flags ANY installed version.
- `file_paths` — malware drop locations. Glob patterns (`**`) and `~` are
  supported. On Linux the common Node drop path is `~/.local/share/NodeJS/sync.js`.
- `file_hashes` — map of `sha256 -> label`. Only include SHA-256 values. The
  scanner hashes files under `hash_scan_dirs` and flags matches.
- `hash_scan_dirs` — where to look for hash matches. Keep this tight (package
  caches, drop dirs) — hashing large trees is slow. Default to package-manager
  caches: `~/.npm`, `~/.cache/pip`, `~/.cargo`.
- `processes` — Python regex patterns matched against `ps -eo pid,args`.
- `network` — plain IPs or domain substrings matched against active connections
  (`ss`/`netstat`). Do not include `hxxp`/`[.]` defanging — convert to real form.

## Extraction guidance

- Capture EVERY affected version listed, including alpha/beta/rc tags. Missing one
  is the most common triage failure.
- Record the safe/fixed versions separately in your notes (not in `iocs.json`) so
  the final report can tell the user what to pin to. The email usually names them;
  if not, "one patch below the compromised version" is the usual answer.
- If an advisory URL is referenced, read it (Glean Document Reader / web search)
  to recover hashes, C2 IPs, and drop paths that the email omits.
- Defang carefully: `hxxps://ipfs[.]io` -> `ipfs.io`, `85.137.53[.]71` -> `85.137.53.71`.
- When the alert gives no host IOCs at all (only a package list), still populate
  `file_paths`/`processes` if the malware family is known — e.g. the Miasma/
  Shai-Hulud family consistently drops `sync.js` to the platform NodeJS app-data
  directory and beacons over IPFS gateways.
- If unsure whether something is a version constraint or an exact version, prefer
  the exact string as written in the alert.