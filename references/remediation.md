# Remediation Checklist

This skill is **report-only** — it never modifies dependencies, deletes files, or
kills processes. Present the checklist below to the user, tailored to what the
scan actually found. Distinguish clearly between the two evidence levels:

- **Package hit only** (compromised version resolved in a lockfile / installed,
  but no host IOC): *potentially exposed*. Because this malware family fires at
  module **load time** (`require()`), not at install, exposure depends on whether
  the module was actually loaded by a build or dev run. Treat as suspect and
  remediate the dependency, but full-blown credential rotation is precautionary.
- **Host IOC hit** (dropped `sync.js`, matching hash, rogue process, live C2
  connection, or a `persistence_matches` entry in `host_report.json` referencing
  IOC paths/patterns): *active infection* — a persistence-only hit means the
  infection is dormant or survives reboot, which is still compromise, not
  history. Assume the machine and every credential on it
  is compromised. Do the full rotation immediately.

## If a compromised package version was found

1. **Do not `npm install`/`npm update` to "latest" blindly.** In some campaigns
   (e.g. the Red Hat one) the latest tag was itself the payload. Pin to the
   specific safe version named in the alert.
2. Delete and regenerate the affected lockfile, then reinstall from clean state:
   - npm: remove `node_modules` + `package-lock.json`, pin the safe version in
     `package.json`, `npm install`.
   - pip: pin the safe version in `requirements.txt`/`poetry.lock`, recreate the
     virtualenv.
   - cargo: `cargo update -p <crate> --precise <safe-version>`.
3. Purge any private-registry/proxy cache (Artifactory, Verdaccio, local npm
   cache `npm cache clean --force`) so the bad tarball isn't re-served.
4. Re-run this skill to confirm the hit is gone.

## If a host IOC was found (active infection)

1. **Isolate the machine** from the network if feasible before further work.
2. Rotate every credential that was present on the box (the alert's directive
   list is the baseline): GitHub PATs/tokens, cloud keys, HashiCorp Vault tokens,
   Kubernetes service-account tokens, SSH private keys, Docker registry creds,
   npm tokens, and browser-saved passwords. Miasma harvests browser data, SSH
   keys, npm/GitHub CLI tokens, cloud secrets, and crypto wallets.
3. Terminate the detached malware process and remove the dropped payload
   (`sync.js` and its drop directory). **The user performs these destructive
   steps themselves** — provide the exact paths/PIDs found, do not run them.
4. Check for persistence: start with `persistence_matches` in `host_report.json`
   — it greps user crontabs, `/etc/cron*`, systemd user/system units, autostart
   entries, and shell rc files for IOC paths and patterns (report-only). Confirm
   each match is the malware and not a lookalike; removal is the user's action.
5. Because this family includes an **AI-tool poisoning** module (Claude Code,
   Copilot, Cursor), audit the agentic/dev-assistant config and any MCP or agent
   credentials on the box, and rotate those too.
6. Review build/CI logs for outbound connections to the C2 IP, IPFS gateways,
   Nostr relays, or BitTorrent DHT during the exposure window.

## Always

- **Notify the security / Threat VM team** with the concrete findings: which
  lockfiles pinned which bad versions, download/consumption evidence, and any
  host IOC hits. Report-only triage still requires escalation of confirmed hits.
- Note the scope boundary: this skill triages **one dev station**. Org-level
  directives in the alert (block versions in Artifactory, scan all CI/CD, rotate
  shared org tokens) are outside its scope — flag them for the security team.