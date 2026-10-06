#!/usr/bin/env python3
"""Scan the local host for indicators of compromise (IOCs) from a supply-chain alert.

Report-only — it never deletes, kills, or modifies anything. Checks five IOC classes:
  1. file_paths   - known malware drop locations (globs, ~ expanded)
  2. file_hashes  - SHA-256 values; scans candidate dirs and flags matches
  3. processes    - regex patterns matched against the live process table
  4. network      - IPs / domains matched against active connections
  5. persistence  - user/system cron, systemd units, autostart entries, and
                    shell rc files that REFERENCE IOC paths/patterns. This is
                    an inert grep: it catches infections that were dormant,
                    exited, or restart themselves after reboot — the classes
                    above only see a live infection.

Classes 1-4 hits => active-infection signal (total_host_iocs).
Persistence matches => weaker but still serious: a past or dormant infection
(total_persistence_matches, reported separately — do not conflate).

IOC file format (JSON):
{
  "host_iocs": {
    "file_paths": [
      "~/.local/share/NodeJS/sync.js",
      "~/.config/**/NodeJS/sync.js"
    ],
    "file_hashes": {
      "9b2e65db653ca8575c9b10eefb9a80c6006404812c2ec212bf5675e3c690233b": "@asyncapi/specs-6.11.2.tgz"
    },
    "hash_scan_dirs": ["~/.npm", "~/.cache"],
    "processes": ["node .*-e .*spawn", "sync\\.js"],
    "network": ["85.137.53.71", "ipfs.io"]
  }
}

Usage:
  scan_host_iocs.py --iocs iocs.json [--max-hash-mb 32] [--out host_report.json]

Exit codes: 0 = scan completed (with or without hits), 2 = invalid iocs.json.
"""
import argparse
import glob
import hashlib
import json
import os
import re
import subprocess
import sys

MAX_PERSISTENCE_FILE_BYTES = 1_000_000  # persistence files are config-sized; skip anomalies
MAX_MATCHES_PER_FILE = 10
HEX64 = re.compile(r"[0-9a-fA-F]{64}")


def expand(p):
    return os.path.expanduser(os.path.expandvars(p))


def check_file_paths(patterns):
    found = []
    for pat in patterns:
        for match in glob.glob(expand(pat), recursive=True):
            if os.path.exists(match):
                st = os.stat(match)
                found.append({"path": match, "size": st.st_size, "mtime": st.st_mtime})
    return found


def sha256(path, max_bytes):
    h = hashlib.sha256()
    n = 0
    with open(path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            n += len(chunk)
            if n > max_bytes:
                return None
            h.update(chunk)
    return h.hexdigest()


def check_hashes(hashes, dirs, max_hash_mb):
    """Return (matches, warnings). Non-SHA-256 hash IOCs are skipped with a warning."""
    warnings = []
    clean = {}
    for k, v in (hashes or {}).items():
        if HEX64.fullmatch(str(k)):
            clean[str(k).lower()] = v
        else:
            warnings.append(f"skipping malformed file_hash IOC (not a 64-char hex SHA-256): {str(k)[:80]!r}")
    if not clean:
        return [], warnings
    max_bytes = max_hash_mb * 1024 * 1024
    found = []
    for d in dirs:
        d = expand(d)
        if not os.path.isdir(d):
            warnings.append(f"hash_scan_dir not found, skipped: {d}")
            continue
        for dirpath, _, filenames in os.walk(d):
            for fn in filenames:
                fp = os.path.join(dirpath, fn)
                try:
                    if os.path.getsize(fp) > max_bytes:
                        continue
                    digest = sha256(fp, max_bytes)
                except Exception:
                    continue
                if digest and digest.lower() in clean:
                    found.append({"path": fp, "sha256": digest, "label": clean[digest.lower()]})
    return found, warnings


def check_processes(patterns):
    if not patterns:
        return []
    try:
        out = subprocess.run(["ps", "-eo", "pid,args"], capture_output=True, text=True, timeout=15).stdout
    except Exception:
        return [{"error": "could not read process table"}]
    found = []
    regexes = []
    for p in patterns:
        try:
            regexes.append((p, re.compile(p, re.I)))
        except re.error as exc:
            found.append({"error": f"invalid process IOC regex {p!r}: {exc}"})
    for line in out.splitlines()[1:]:
        for pat, rx in regexes:
            if rx.search(line):
                found.append({"process": line.strip()[:300], "pattern": pat})
                break
    return found


def check_network(indicators):
    if not indicators:
        return []
    conns = ""
    for cmd in (["ss", "-tunp"], ["netstat", "-tunp"]):
        try:
            conns = subprocess.run(cmd, capture_output=True, text=True, timeout=15).stdout
            if conns:
                break
        except Exception:
            continue
    found = []
    for line in conns.splitlines():
        for ind in indicators:
            if ind in line:
                found.append({"connection": line.strip()[:300], "indicator": ind})
    return found


# ---------- persistence (report-only grep; never executes what it reads) ----------
def persistence_sources():
    """(kind, path) pairs for every readable persistence location that exists."""
    out = []

    def add(kind, pat):
        for p in sorted(glob.glob(expand(pat))):
            if os.path.isfile(p) and os.access(p, os.R_OK):
                out.append((kind, p))

    add("user-rc", "~/.bashrc")
    add("user-rc", "~/.bash_profile")
    add("user-rc", "~/.bash_logout")
    add("user-rc", "~/.profile")
    add("user-rc", "~/.zshrc")
    add("user-rc", "~/.zshenv")
    add("user-rc", "~/.zprofile")
    add("user-rc", "~/.config/fish/config.fish")
    add("systemd-user", "~/.config/systemd/user/*.service")
    add("systemd-user", "~/.config/systemd/user/*.timer")
    add("systemd-user", "~/.config/systemd/user/*.socket")
    add("systemd-system", "/etc/systemd/system/*.service")
    add("systemd-system", "/etc/systemd/system/*.timer")
    add("systemd-system", "/etc/systemd/system/multi-user.target.wants/*.service")
    add("systemd-system", "/usr/lib/systemd/system/*.service")
    add("autostart", "~/.config/autostart/*.desktop")
    add("cron", "/etc/crontab")
    add("cron", "/etc/cron.d/*")
    for d in ("hourly", "daily", "weekly", "monthly"):
        add("cron", f"/etc/cron.{d}/*")
    add("cron", "/var/spool/cron/crontabs/*")
    add("cron", "/var/spool/cron/*")
    return out


def user_crontab_text():
    try:
        r = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=15)
        if r.returncode == 0:
            return r.stdout
    except Exception:
        pass
    return ""


def literal_candidates(path_pat):
    """Grep-able literal substrings derived from a drop-path pattern.

    '~/.local/share/NodeJS/sync.js'  -> ['.local/share/NodeJS/sync.js', 'NodeJS/sync.js']
    '~/.config/**/NodeJS/sync.js'    -> ['NodeJS/sync.js']
    """
    segs = [s for s in str(path_pat).split("/") if s]
    cands = []
    if any(re.search(r"[*?\[]", s) for s in segs):
        last_glob = max(i for i, s in enumerate(segs) if re.search(r"[*?\[]", s))
        tail = segs[last_glob + 1:]
        if tail:
            cands.append("/".join(tail))
    else:
        full = "/".join(s for s in segs if s != "~")
        cands.append(full)
        if len(segs) >= 2:
            cands.append("/".join(segs[-2:]))
    return [c for c in cands if len(c) >= 6]


def persistence_patterns(iocs):
    """Compiled (kind, display, rx) grep patterns derived from the IOC set."""
    pats = []
    for rx in iocs.get("processes", []) or []:
        try:
            pats.append(("process-regex", str(rx), re.compile(str(rx), re.I)))
        except re.error:
            continue  # already reported by check_processes
    for path_pat in iocs.get("file_paths", []) or []:
        for lit in literal_candidates(path_pat):
            pats.append(("drop-path", lit, re.compile(re.escape(lit), re.I)))
    for label in (iocs.get("file_hashes", {}) or {}).values():
        if isinstance(label, str) and len(label) >= 6:
            pats.append(("hash-label", label, re.compile(re.escape(label), re.I)))
    return pats


def check_persistence(iocs):
    pats = persistence_patterns(iocs)
    if not pats:
        return []
    sources = persistence_sources()
    crontab = user_crontab_text()
    if crontab.strip():
        sources.append(("crontab-user", "<crontab -l>"))
    found = []
    for kind, path in sources:
        try:
            if path == "<crontab -l>":
                text = crontab
            else:
                if os.path.getsize(path) > MAX_PERSISTENCE_FILE_BYTES:
                    continue
                text = open(path, encoding="utf-8", errors="replace").read()
        except Exception:
            continue
        file_matches = 0
        for line_no, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            for pkind, disp, rx in pats:
                if rx.search(line):
                    found.append({
                        "file": path, "kind": kind, "line_no": line_no,
                        "matched_pattern": disp, "pattern_kind": pkind,
                        "line": line.strip()[:200],
                    })
                    file_matches += 1
                    break
            if file_matches >= MAX_MATCHES_PER_FILE:
                break
    return found


def load_host_iocs(path):
    """Parse iocs.json; return (host_iocs, errors). Missing host_iocs is OK (empty)."""
    try:
        with open(path, encoding="utf-8") as f:
            iocs = json.load(f)
    except FileNotFoundError:
        return None, [f"iocs file not found: {path}"]
    except json.JSONDecodeError as exc:
        return None, [f"iocs.json is not valid JSON: {exc}"]
    if not isinstance(iocs, dict):
        return None, ["top-level of iocs.json must be a JSON object"]
    hi = iocs.get("host_iocs", {})
    if not isinstance(hi, dict):
        return None, ["'host_iocs' must be a JSON object"]
    for key in ("file_paths", "hash_scan_dirs", "processes", "network"):
        v = hi.get(key, [])
        if not isinstance(v, list) or any(not isinstance(x, str) for x in v):
            return None, [f"'host_iocs.{key}' must be a list of strings"]
    hashes = hi.get("file_hashes", {})
    if not isinstance(hashes, dict):
        return None, ["'host_iocs.file_hashes' must be a {sha256: label} object"]
    return hi, []


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iocs", required=True)
    ap.add_argument("--max-hash-mb", type=int, default=32)
    ap.add_argument("--out", default="")
    args = ap.parse_args()

    hi, errors = load_host_iocs(args.iocs)
    if errors:
        print("iocs.json validation failed — nothing was scanned:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        sys.exit(2)

    hash_matches, hash_warnings = check_hashes(hi.get("file_hashes", {}),
                                               hi.get("hash_scan_dirs", []),
                                               args.max_hash_mb)
    result = {
        "dropped_files": check_file_paths(hi.get("file_paths", [])),
        "hash_matches": hash_matches,
        "suspicious_processes": check_processes(hi.get("processes", [])),
        "network_matches": check_network(hi.get("network", [])),
        "persistence_matches": check_persistence(hi),
    }
    total = sum(len(result[k]) for k in
                ("dropped_files", "hash_matches", "suspicious_processes", "network_matches"))
    result["total_host_iocs"] = total
    result["total_persistence_matches"] = len(result["persistence_matches"])
    result["ioc_warnings"] = hash_warnings
    out = json.dumps(result, indent=2)
    if args.out:
        open(args.out, "w").write(out)
    print(out)

    if total:
        print(f"\n[!] {total} host IOC hit(s) found — active-infection signals. Treat as compromised.", file=sys.stderr)
    else:
        print("\n[ok] No host IOCs found (no dropped payload / rogue process / C2 connection detected).", file=sys.stderr)
    if result["total_persistence_matches"]:
        print(f"[!] {result['total_persistence_matches']} persistence match(es) in cron/systemd/rc/autostart — "
              f"dormant or reboot-surviving infection evidence. Verify each before dismissing.", file=sys.stderr)
    for w in hash_warnings:
        print(f"[warn] {w}", file=sys.stderr)


if __name__ == "__main__":
    main()
