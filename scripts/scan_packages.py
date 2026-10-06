#!/usr/bin/env python3
"""Scan a machine for compromised package versions across npm, PyPI, and Cargo.

Report-only. Reads an IOC file describing affected packages and searches
lockfiles, manifests, and installed package trees for matching name@version
pairs. Prints a JSON report to stdout and a human summary to stderr.

Every report carries a "coverage" block (roots walked/skipped, per-ecosystem
file counts, read errors, depth prunes, confidence) so a run that found
nothing but scanned nothing is distinguishable from a genuinely clean run.
Check coverage before reporting "no hits".

PyPI names are matched with PEP 503 normalization (case-insensitive; runs of
-, _, . are equivalent), so an IOC of "acme-lib" matches an installed
"acme_lib" dist-info. npm/Cargo names are matched case-insensitively.

IOC file format (JSON):
{
  "alert_title": "optional, echoed into the report",
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
  scan_packages.py --iocs iocs.json --roots /home/user/dev ~/projects [--max-depth 14] [--out report.json]

Exit codes: 0 = scan completed (with or without hits), 2 = invalid iocs.json.
"""
import argparse
import json
import os
import re
import sys

SKIP_DIRS = {".git", ".hg", ".svn", ".cache", "__pycache__", ".venv-cache"}
ECOSYSTEMS = ("npm", "pypi", "cargo")


def norm(v):
    return str(v).strip().lstrip("=^~v").strip()


def norm_name(eco, name):
    """Ecosystem-aware package name normalization (matching keys)."""
    n = str(name).strip()
    if eco == "pypi":
        # PEP 503: lowercase, collapse runs of - _ . into a single -
        return re.sub(r"[-_.]+", "-", n).lower()
    return n.lower()


def validate_iocs(path):
    """Parse and structurally validate iocs.json. Returns (iocs, errors)."""
    try:
        with open(path, encoding="utf-8") as f:
            iocs = json.load(f)
    except FileNotFoundError:
        return None, [f"iocs file not found: {path}"]
    except json.JSONDecodeError as exc:
        return None, [f"iocs.json is not valid JSON: {exc}"]
    if not isinstance(iocs, dict):
        return None, ["top-level of iocs.json must be a JSON object"]
    errors = []
    pkgs = iocs.get("packages")
    if not isinstance(pkgs, list) or not pkgs:
        errors.append("missing or empty 'packages' key — expected a non-empty "
                      "list of {ecosystem, name, versions}; nothing to scan")
        return None, errors
    for i, p in enumerate(pkgs):
        if not isinstance(p, dict):
            errors.append(f"packages[{i}] is not a JSON object")
            continue
        eco = str(p.get("ecosystem", "")).strip().lower()
        if eco not in ECOSYSTEMS:
            errors.append(f"packages[{i}]: ecosystem {p.get('ecosystem')!r} "
                          f"is not one of {', '.join(ECOSYSTEMS)} (lowercase)")
        if not str(p.get("name", "")).strip():
            errors.append(f"packages[{i}]: missing or empty 'name'")
        vers = p.get("versions", [])
        if vers is not None and not isinstance(vers, list):
            errors.append(f"packages[{i}]: 'versions' must be a list (or omitted for 'any version')")
    return (iocs if not errors else None), errors


def build_index(packages):
    """Return {ecosystem: {normalized_name: set(versions or empty=any)}}."""
    idx = {}
    for p in packages:
        eco = str(p.get("ecosystem", "")).lower()
        name = p.get("name", "")
        if not eco or not str(name).strip():
            continue
        vers = {norm(v) for v in p.get("versions") or [] if str(v).strip()}
        idx.setdefault(eco, {})[norm_name(eco, name)] = vers
    return idx


def match(idx, eco, name, version):
    """Return the matched clause if (name, version) is compromised, else None."""
    names = idx.get(eco, {})
    key = norm_name(eco, name)
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
        return False
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
    return True


def scan_yarn_lock(path, idx, hits):
    try:
        txt = open(path, encoding="utf-8").read()
    except Exception:
        return False
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
    return True


def scan_pnpm_lock(path, idx, hits):
    try:
        txt = open(path, encoding="utf-8").read()
    except Exception:
        return False
    for m in re.finditer(r"/((?:@[^/]+/)?[^/@\s]+)@([\d][^\s:()]*)", txt):
        hit = match(idx, "npm", m.group(1), m.group(2))
        if hit:
            hits.append({**hit, "source": path, "detail": m.group(0)})
    return True


def scan_node_modules_pkg(path, idx, hits):
    try:
        data = json.load(open(path, encoding="utf-8"))
    except Exception:
        return False
    m = match(idx, "npm", data.get("name", ""), data.get("version", ""))
    if m:
        hits.append({**m, "source": path, "detail": "installed in node_modules"})
    return True


# ---------- PyPI ----------
def scan_requirements(path, idx, hits):
    try:
        lines = open(path, encoding="utf-8").readlines()
    except Exception:
        return False
    for line in lines:
        line = line.split("#")[0].strip()
        m = re.match(r"^([A-Za-z0-9._-]+)\s*==\s*([^\s;]+)", line)
        if m:
            h = match(idx, "pypi", m.group(1), m.group(2))
            if h:
                hits.append({**h, "source": path, "detail": line})
    return True


def scan_poetry_lock(path, idx, hits):
    try:
        txt = open(path, encoding="utf-8").read()
    except Exception:
        return False
    for block in txt.split("[[package]]"):
        nm = re.search(r'name\s*=\s*"([^"]+)"', block)
        vm = re.search(r'version\s*=\s*"([^"]+)"', block)
        if nm and vm:
            h = match(idx, "pypi", nm.group(1), vm.group(1))
            if h:
                hits.append({**h, "source": path, "detail": nm.group(1)})
    return True


def scan_pipfile_lock(path, idx, hits):
    try:
        data = json.load(open(path, encoding="utf-8"))
    except Exception:
        return False
    for section in ("default", "develop"):
        for name, meta in (data.get(section) or {}).items():
            ver = norm(meta.get("version", "")) if isinstance(meta, dict) else ""
            h = match(idx, "pypi", name, ver)
            if h:
                hits.append({**h, "source": path, "detail": section})
    return True


def scan_uv_lock(path, idx, hits):
    try:
        txt = open(path, encoding="utf-8").read()
    except Exception:
        return False
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
    return True


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
        return True
    except Exception:
        return False


# ---------- Cargo ----------
def scan_cargo_lock(path, idx, hits):
    try:
        txt = open(path, encoding="utf-8").read()
    except Exception:
        return False
    for block in txt.split("[[package]]"):
        nm = re.search(r'name\s*=\s*"([^"]+)"', block)
        vm = re.search(r'version\s*=\s*"([^"]+)"', block)
        if nm and vm:
            h = match(idx, "cargo", nm.group(1), vm.group(1))
            if h:
                hits.append({**h, "source": path, "detail": nm.group(1)})
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iocs", required=True)
    ap.add_argument("--roots", nargs="+", required=True)
    ap.add_argument("--max-depth", type=int, default=14)
    ap.add_argument("--out", default="")
    args = ap.parse_args()

    iocs, errors = validate_iocs(args.iocs)
    if errors:
        print("iocs.json validation failed — nothing was scanned:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        sys.exit(2)

    idx = build_index(iocs["packages"])
    ecos = set(idx.keys())
    hits = []

    # coverage bookkeeping
    scanned_by_eco = {e: 0 for e in ECOSYSTEMS}
    read_errors = 0
    depth_pruned = 0
    roots_walked = []
    roots_skipped = []
    attempted = 0

    for root in args.roots:
        root_exp = os.path.expanduser(root)
        if not os.path.isdir(root_exp):
            roots_skipped.append({"root": root, "reason": "not-found-or-not-a-directory"})
            continue
        roots_walked.append(root_exp)
        base_depth = root_exp.rstrip("/").count("/")
        for dirpath, dirnames, filenames in os.walk(root_exp):
            if dirpath.count("/") - base_depth > args.max_depth:
                if dirnames:
                    depth_pruned += 1
                dirnames[:] = []
                continue
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fn in filenames:
                fp = os.path.join(dirpath, fn)
                try:
                    if "npm" in ecos:
                        if fn == "package-lock.json":
                            scanned_by_eco["npm"] += 1
                            if not scan_npm_package_lock(fp, idx, hits):
                                read_errors += 1
                        elif fn == "yarn.lock":
                            scanned_by_eco["npm"] += 1
                            if not scan_yarn_lock(fp, idx, hits):
                                read_errors += 1
                        elif fn == "pnpm-lock.yaml":
                            scanned_by_eco["npm"] += 1
                            if not scan_pnpm_lock(fp, idx, hits):
                                read_errors += 1
                        elif fn == "package.json" and os.sep + "node_modules" + os.sep in fp:
                            scanned_by_eco["npm"] += 1
                            if not scan_node_modules_pkg(fp, idx, hits):
                                read_errors += 1
                    if "pypi" in ecos:
                        if fn == "requirements.txt" or (fn.startswith("requirements") and fn.endswith(".txt")):
                            scanned_by_eco["pypi"] += 1
                            if not scan_requirements(fp, idx, hits):
                                read_errors += 1
                        elif fn == "poetry.lock":
                            scanned_by_eco["pypi"] += 1
                            if not scan_poetry_lock(fp, idx, hits):
                                read_errors += 1
                        elif fn == "Pipfile.lock":
                            scanned_by_eco["pypi"] += 1
                            if not scan_pipfile_lock(fp, idx, hits):
                                read_errors += 1
                        elif fn == "uv.lock":
                            scanned_by_eco["pypi"] += 1
                            if not scan_uv_lock(fp, idx, hits):
                                read_errors += 1
                        elif fn == "METADATA" and dirpath.endswith(".dist-info"):
                            scanned_by_eco["pypi"] += 1
                            if not scan_dist_info(fp, idx, hits):
                                read_errors += 1
                        elif fn == "PKG-INFO" and dirpath.endswith(".egg-info"):
                            scanned_by_eco["pypi"] += 1
                            if not scan_dist_info(fp, idx, hits):
                                read_errors += 1
                    if "cargo" in ecos and fn == "Cargo.lock":
                        scanned_by_eco["cargo"] += 1
                        if not scan_cargo_lock(fp, idx, hits):
                            read_errors += 1
                except Exception:
                    read_errors += 1
                    continue

    attempted = sum(scanned_by_eco.values())

    # iocs summary: packages + any-version flags per ecosystem
    iocs_summary = {}
    for p in iocs["packages"]:
        e = str(p.get("ecosystem", "")).lower()
        s = iocs_summary.setdefault(e, {"packages": 0, "any_version": 0})
        s["packages"] += 1
        if not p.get("versions"):
            s["any_version"] += 1

    # confidence: distinguish "clean" from "didn't look"
    confidence = "high"
    notes = []
    if not roots_walked:
        confidence = "none"
        notes.append("no valid roots — nothing was scanned")
    for e in sorted(ecos):
        if scanned_by_eco[e] == 0:
            notes.append(f"no {e} manifests found under the given roots — {e} is not actually covered")
            if confidence == "high":
                confidence = "check"
    if roots_skipped:
        notes.append("roots skipped: " + ", ".join(r["root"] for r in roots_skipped))
        if confidence == "high":
            confidence = "check"
    if read_errors:
        pct = (100.0 * read_errors / attempted) if attempted else 100.0
        notes.append(f"{read_errors} file(s) failed to open/parse ({pct:.1f}% of attempted)")
        if attempted == 0 or pct > 10:
            confidence = "check" if confidence != "none" else confidence
    if depth_pruned:
        notes.append(f"{depth_pruned} directory(ies) pruned at max-depth — deep trees may be missed; raise --max-depth to cover")
        if confidence == "high":
            confidence = "check"

    scanned_files = attempted
    report = {
        "schema_version": 2,
        "alert_title": iocs.get("alert_title", ""),
        "hit_count": len(hits),
        "hits": hits,
        "coverage": {
            "confidence": confidence,
            "confidence_notes": notes,
            "roots_requested": list(args.roots),
            "roots_walked": roots_walked,
            "roots_skipped": roots_skipped,
            "max_depth": args.max_depth,
            "depth_pruned_dirs": depth_pruned,
            "attempted_files": attempted,
            "read_errors": read_errors,
            "scanned_files": scanned_files,
            "scanned_by_ecosystem": scanned_by_eco,
            "iocs": iocs_summary,
        },
    }
    out = json.dumps(report, indent=2)
    if args.out:
        open(args.out, "w").write(out)
    print(out)

    if hits:
        print(f"\n[!] {len(hits)} compromised package match(es) found across {scanned_files} manifest/lock files.", file=sys.stderr)
    else:
        print(f"\n[ok] No compromised package versions found across {scanned_files} manifest/lock files.", file=sys.stderr)
    eco_str = " ".join(f"{e}={scanned_by_eco[e]}" for e in ECOSYSTEMS)
    print(f"coverage: roots walked {len(roots_walked)} (skipped {len(roots_skipped)}) | {eco_str} | "
          f"read_errors={read_errors} depth_pruned={depth_pruned} | confidence={confidence}", file=sys.stderr)
    if confidence != "high":
        for n in notes:
            print(f"  [!] {n}", file=sys.stderr)


if __name__ == "__main__":
    main()
