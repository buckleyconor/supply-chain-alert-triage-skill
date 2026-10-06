#!/usr/bin/env python3
"""Scan the local host for indicators of compromise (IOCs) from a supply-chain alert.

Report-only. Checks four IOC classes described in an IOC file:
  1. file_paths     - known malware drop locations (globs, ~ expanded)
  2. file_hashes    - SHA-256 values; scans candidate dirs and flags matches
  3. processes      - regex patterns matched against the running process table
  4. network        - IPs / domains matched against active connections

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
  scan_host_iocs.py --iocs iocs.json [--max-hash-mb 32]
"""
import argparse
import glob
import hashlib
import json
import os
import re
import subprocess
import sys


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
    if not hashes:
        return []
    wanted = {k.lower(): v for k, v in hashes.items()}
    max_bytes = max_hash_mb * 1024 * 1024
    found = []
    for d in dirs:
        d = expand(d)
        if not os.path.isdir(d):
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
                if digest and digest.lower() in wanted:
                    found.append({"path": fp, "sha256": digest, "label": wanted[digest.lower()]})
    return found


def check_processes(patterns):
    if not patterns:
        return []
    try:
        out = subprocess.run(["ps", "-eo", "pid,args"], capture_output=True, text=True, timeout=15).stdout
    except Exception:
        return [{"error": "could not read process table"}]
    found = []
    regexes = [re.compile(p, re.I) for p in patterns]
    for line in out.splitlines()[1:]:
        for rx in regexes:
            if rx.search(line):
                found.append({"process": line.strip()[:300], "pattern": rx.pattern})
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iocs", required=True)
    ap.add_argument("--max-hash-mb", type=int, default=32)
    ap.add_argument("--out", default="")
    args = ap.parse_args()

    iocs = json.load(open(args.iocs)).get("host_iocs", {})
    result = {
        "dropped_files": check_file_paths(iocs.get("file_paths", [])),
        "hash_matches": check_hashes(iocs.get("file_hashes", {}),
                                     iocs.get("hash_scan_dirs", []), args.max_hash_mb),
        "suspicious_processes": check_processes(iocs.get("processes", [])),
        "network_matches": check_network(iocs.get("network", [])),
    }
    total = sum(len(v) for v in result.values())
    result["total_host_iocs"] = total
    out = json.dumps(result, indent=2)
    if args.out:
        open(args.out, "w").write(out)
    print(out)
    if total:
        print(f"\n[!] {total} host IOC hit(s) found — active-infection signals. Treat as compromised.", file=sys.stderr)
    else:
        print("\n[ok] No host IOCs found (no dropped payload / rogue process / C2 connection detected).", file=sys.stderr)


if __name__ == "__main__":
    main()