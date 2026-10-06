#!/usr/bin/env python3
"""Scan a machine for compromised package versions across npm, PyPI, and Cargo.

Report-only. Reads an IOC file describing affected packages and searches
lockfiles, manifests, and installed package trees for matching name@version
pairs. Prints a JSON report to stdout and a human summary to stderr.

IOC file format (JSON):
{
  "packages": [
    {"ecosystem": "npm",   "name": "@asyncapi/specs",     "versions": ["6.11.2", "6.11.2-alpha.1"]},
    {"ecosystem": "npm",   "name": "@asyncapi/generator",  "versions": ["3.3.1"]},
    {"ecosystem": "pypi",  "name": "some-pkg",             "versions": ["1.2.3"]},
    {"ecosystem": "cargo", "name": "some-crate",           "versions": ["0.1.0"]}
  ]
}

If "versions" is omitted or empty, ANY installed version is reported as a hit
(useful when the whole package is considered suspect).

Usage:
  scan_packages.py --iocs iocs.json --roots /home/user/dev ~/projects [--max-depth 12]
"""
import argparse
import json
import os
import re
import sys

SKIP_DIRS = {".git", ".hg", ".svn", ".cache", "__pycache__", ".venv-cache"}


def norm(v):
    return str(v).strip().lstrip("=^~v").strip()


def build_index(packages):
    """Return {ecosystem: {name_lower: set(versions or empty=any)}}."""
    idx = {}
    for p in packages:
        eco = p.get("ecosystem", "").lower()
        name = p.get("name", "").strip()
        if not eco or not name:
            continue
        vers = {norm(v) for v in p.get("versions", []) if str(v).strip()}
        idx.setdefault(eco, {})[name.lower()] = vers
    return idx


def match(idx, eco, name, version):
    """Return the matched clause if (name, version) is compromised, else None."""
    names = idx.get(eco, {})
    key = name.strip().lower()
    if key not in names:
        return None
    wanted = names[key]
    v = norm(version)
    if not wanted or v in wanted:
        return {"ecosystem": eco, "name": name, "version": version or "(unspecified)"}
    return None


# ---------- npm ----------
def scan_npm_package_lock(path, idx, hits):
    try:
        data = json.load(open(path, encoding="utf-8"))
    except Exception:
        return
    # lockfile v2/v3: "packages" map keyed by node_modules/<name>
    for loc, meta in (data.get("packages") or {}).items():
        if not loc:
            continue
        name = meta.get("name")
        if not name:
            m = re.search(r"node_modules/((?:@[^/]+/)?[^/]+)$", loc)
            name = m.group(1) if m else None
        if name:
            m = match(idx, "npm", name, meta.get("version", ""))
            if m:
                hits.append({**m, "source": path, "detail": loc})
    # lockfile v1: "dependencies" recursive
    def walk(deps, prefix=""):
        for name, meta in (deps or {}).items():
            m = match(idx, "npm", name, meta.get("version", ""))
            if m:
                hits.append({**m, "source": path, "detail": prefix + name})
            walk(meta.get("dependencies"), prefix + name + ">")
    walk(data.get("dependencies"))


def scan_yarn_lock(path, idx, hits):
    try:
        txt = open(path, encoding="utf-8").read()
    except Exception:
        return
    blocks = re.split(r"\n(?=\S)", txt)
    for b in blocks:
        header = b.splitlines()[0] if b.strip() else ""
        vm = re.search(r'^\s*version:?\s*"?([^"\n]+)"?', b, re.M)
        if not vm:
            continue
        version = vm.group(1).strip()
        for spec in header.split(","):
            spec = spec.strip().strip('"').strip(":")
            nm = re.match(r"^((?:@[^/]+/)?[^@]+)@", spec)
            if nm:
                m = match(idx, "npm", nm.group(1), version)
                if m:
                    hits.append({**m, "source": path, "detail": spec})


def scan_pnpm_lock(path, idx, hits):
    try:
        txt = open(path, encoding="utf-8").read()
    except Exception:
        return
    for m in re.finditer(r"/((?:@[^/]+/)?[^/@\s]+)@([\d][^\s:()]*)", txt):
        hit = match(idx, "npm", m.group(1), m.group(2))
        if hit:
            hits.append({**hit, "source": path, "detail": m.group(0)})


def scan_node_modules_pkg(path, idx, hits):
    try:
        data = json.load(open(path, encoding="utf-8"))
    except Exception:
        return
    m = match(idx, "npm", data.get("name", ""), data.get("version", ""))
    if m:
        hits.append({**m, "source": path, "detail": "installed in node_modules"})


# ---------- PyPI ----------
def scan_requirements(path, idx, hits):
    try:
        for line in open(path, encoding="utf-8"):
            line = line.split("#")[0].strip()
            m = re.match(r"^([A-Za-z0-9._-]+)\s*==\s*([^\s;]+)", line)
            if m:
                h = match(idx, "pypi", m.group(1), m.group(2))
                if h:
                    hits.append({**h, "source": path, "detail": line})
    except Exception:
        return


def scan_poetry_lock(path, idx, hits):
    try:
        txt = open(path, encoding="utf-8").read()
    except Exception:
        return
    for block in txt.split("[[package]]"):
        nm = re.search(r'name\s*=\s*"([^"]+)"', block)
        vm = re.search(r'version\s*=\s*"([^"]+)"', block)
        if nm and vm:
            h = match(idx, "pypi", nm.group(1), vm.group(1))
            if h:
                hits.append({**h, "source": path, "detail": nm.group(1)})


def scan_pipfile_lock(path, idx, hits):
    try:
        data = json.load(open(path, encoding="utf-8"))
    except Exception:
        return
    for section in ("default", "develop"):
        for name, meta in (data.get(section) or {}).items():
            ver = norm(meta.get("version", "")) if isinstance(meta, dict) else ""
            h = match(idx, "pypi", name, ver)
            if h:
                hits.append({**h, "source": path, "detail": section})


def scan_uv_lock(path, idx, hits):
    try:
        txt = open(path, encoding="utf-8").read()
    except Exception:
        return
    # uv.lock is TOML: [[package]] blocks with name/version at the top of each
    # block (same shape as poetry.lock / Cargo.lock). Includes the project's
    # own package entry (virtual/workspace source) — harmless if it never
    # matches a compromised name.
    for block in txt.split("[[package]]"):
        nm = re.search(r'name\s*=\s*"([^"]+)"', block)
        vm = re.search(r'version\s*=\s*"([^"]+)"', block)
        if nm and vm:
            h = match(idx, "pypi", nm.group(1), vm.group(1))
            if h:
                hits.append({**h, "source": path, "detail": nm.group(1)})


def scan_dist_info(path, idx, hits):
    # path is a *.dist-info/METADATA or a *.egg-info/PKG-INFO
    try:
        name = version = ""
        for line in open(path, encoding="utf-8", errors="ignore"):
            if line.startswith("Name:"):
                name = line.split(":", 1)[1].strip()
            elif line.startswith("Version:"):
                version = line.split(":", 1)[1].strip()
            if name and version:
                break
        h = match(idx, "pypi", name, version)
        if h:
            hits.append({**h, "source": path, "detail": "installed (site-packages)"})
    except Exception:
        return


# ---------- Cargo ----------
def scan_cargo_lock(path, idx, hits):
    try:
        txt = open(path, encoding="utf-8").read()
    except Exception:
        return
    for block in txt.split("[[package]]"):
        nm = re.search(r'name\s*=\s*"([^"]+)"', block)
        vm = re.search(r'version\s*=\s*"([^"]+)"', block)
        if nm and vm:
            h = match(idx, "cargo", nm.group(1), vm.group(1))
            if h:
                hits.append({**h, "source": path, "detail": nm.group(1)})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iocs", required=True)
    ap.add_argument("--roots", nargs="+", required=True)
    ap.add_argument("--max-depth", type=int, default=14)
    ap.add_argument("--out", default="")
    args = ap.parse_args()

    idx = build_index(json.load(open(args.iocs))["packages"])
    ecos = set(idx.keys())
    hits = []
    scanned = 0

    for root in args.roots:
        root = os.path.expanduser(root)
        if not os.path.isdir(root):
            continue
        base_depth = root.rstrip("/").count("/")
        for dirpath, dirnames, filenames in os.walk(root):
            if dirpath.count("/") - base_depth > args.max_depth:
                dirnames[:] = []
                continue
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fn in filenames:
                fp = os.path.join(dirpath, fn)
                try:
                    if "npm" in ecos:
                        if fn == "package-lock.json":
                            scan_npm_package_lock(fp, idx, hits); scanned += 1
                        elif fn == "yarn.lock":
                            scan_yarn_lock(fp, idx, hits); scanned += 1
                        elif fn == "pnpm-lock.yaml":
                            scan_pnpm_lock(fp, idx, hits); scanned += 1
                        elif fn == "package.json" and os.sep + "node_modules" + os.sep in fp:
                            scan_node_modules_pkg(fp, idx, hits); scanned += 1
                    if "pypi" in ecos:
                        if fn in ("requirements.txt",) or (fn.startswith("requirements") and fn.endswith(".txt")):
                            scan_requirements(fp, idx, hits); scanned += 1
                        elif fn == "poetry.lock":
                            scan_poetry_lock(fp, idx, hits); scanned += 1
                        elif fn == "Pipfile.lock":
                            scan_pipfile_lock(fp, idx, hits); scanned += 1
                        elif fn == "uv.lock":
                            scan_uv_lock(fp, idx, hits); scanned += 1
                        elif fn == "METADATA" and dirpath.endswith(".dist-info"):
                            scan_dist_info(fp, idx, hits); scanned += 1
                        elif fn == "PKG-INFO" and dirpath.endswith(".egg-info"):
                            scan_dist_info(fp, idx, hits); scanned += 1
                    if "cargo" in ecos and fn == "Cargo.lock":
                        scan_cargo_lock(fp, idx, hits); scanned += 1
                except Exception:
                    continue

    report = {"scanned_files": scanned, "hit_count": len(hits), "hits": hits}
    out = json.dumps(report, indent=2)
    if args.out:
        open(args.out, "w").write(out)
    print(out)
    if hits:
        print(f"\n[!] {len(hits)} compromised package match(es) found across {scanned} manifest/lock files.", file=sys.stderr)
    else:
        print(f"\n[ok] No compromised package versions found across {scanned} manifest/lock files.", file=sys.stderr)


if __name__ == "__main__":
    main()