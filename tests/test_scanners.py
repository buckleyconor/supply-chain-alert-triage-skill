#!/usr/bin/env python3
"""Stdlib-only self-tests for the supply-chain-alert-triage scanners.

Run from the repo root:
    python3 -m unittest discover -s tests -v

Covers: deterministic package scanning across npm/PyPI/Cargo lockfiles and
installed trees, PEP 503 name normalization, the coverage/confidence block,
iocs.json validation (exit 2), and the host IOC scanner (drop files, hashes,
processes, persistence greps) against a synthetic HOME. No network needed.
"""
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(ROOT, "scripts")
FIXTURES = os.path.join(ROOT, "tests", "fixtures")
PROJECTS = os.path.join(FIXTURES, "projects")
IOCS = os.path.join(FIXTURES, "iocs.json")
PY = sys.executable


def run_script(script, args, env=None):
    return subprocess.run([PY, os.path.join(SCRIPTS, script)] + args,
                          capture_output=True, text=True, env=env, timeout=120)


def norm_name(eco, name):
    if eco == "pypi":
        return re.sub(r"[-_.]+", "-", name).lower()
    return name.lower()


def write_file(base, rel, content):
    p = os.path.join(base, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        f.write(content)
    return p


class ScanPackagesTest(unittest.TestCase):
    def scan(self, roots=(PROJECTS,), extra=()):
        return run_script("scan_packages.py",
                          ["--iocs", IOCS, "--roots", *[str(r) for r in roots], *extra])

    def hit_tuples(self, report):
        return {(h["ecosystem"], norm_name(h["ecosystem"], h["name"]),
                 h["version"], os.path.basename(h["source"])) for h in report["hits"]}

    def test_lockfiles_installed_trees_and_normalization(self):
        r = self.scan()
        self.assertEqual(r.returncode, 0, r.stderr)
        report = json.loads(r.stdout)
        got = self.hit_tuples(report)
        expected = {
            # npm: lockfiles v3 + v1 (transitive), installed node_modules, yarn, pnpm
            ("npm", "@acme/widgets", "2.0.0", "package-lock.json"),
            ("npm", "@acme/widgets", "2.0.0", "package.json"),
            ("npm", "@acme/widgets", "2.0.0", "yarn.lock"),
            ("npm", "@acme/widgets", "2.0.0", "pnpm-lock.yaml"),
            # PyPI: all four lockfile shapes + installed dist-info whose
            # METADATA name is acme_lib (PEP 503 normalizes to the IOC acme-lib)
            ("pypi", "acme-lib", "1.2.3", "requirements.txt"),
            ("pypi", "acme-lib", "1.2.3", "poetry.lock"),
            ("pypi", "acme-lib", "1.2.3", "Pipfile.lock"),
            ("pypi", "acme-lib", "1.2.3", "uv.lock"),
            ("pypi", "acme-lib", "1.2.3", "METADATA"),
            # Cargo: empty IOC versions means ANY installed version is a hit
            ("cargo", "acme-crate", "0.1.0", "Cargo.lock"),
        }
        missing = expected - got
        self.assertFalse(missing, f"missed hits: {missing}")
        # clean project must not produce hits
        self.assertFalse([h for h in report["hits"] if "/clean/" in h["source"]])

    def test_coverage_block(self):
        r = self.scan()
        report = json.loads(r.stdout)
        cov = report["coverage"]
        self.assertEqual(cov["confidence"], "high", cov["confidence_notes"])
        self.assertEqual(cov["roots_skipped"], [])
        self.assertEqual(cov["roots_walked"], [PROJECTS])
        self.assertEqual(cov["read_errors"], 0)
        self.assertEqual(cov["scanned_by_ecosystem"], {"npm": 6, "pypi": 5, "cargo": 1})
        self.assertEqual(cov["scanned_files"], report["coverage"]["attempted_files"])
        self.assertEqual(report["hit_count"], len(report["hits"]))
        self.assertEqual(cov["iocs"], {
            "npm": {"packages": 1, "any_version": 0},
            "pypi": {"packages": 1, "any_version": 0},
            "cargo": {"packages": 1, "any_version": 1},
        })

    def test_missing_root_is_skipped_and_lowers_confidence(self):
        r = self.scan(roots=(PROJECTS, "/nonexistent-triage-root"))
        self.assertEqual(r.returncode, 0)
        cov = json.loads(r.stdout)["coverage"]
        self.assertEqual([s["root"] for s in cov["roots_skipped"]], ["/nonexistent-triage-root"])
        self.assertEqual(cov["confidence"], "check")
        self.assertTrue(any("nonexistent" in n for n in cov["confidence_notes"]))

    def test_out_file_matches_stdout(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        out = os.path.join(tmp, "packages_report.json")
        r = self.scan(extra=["--out", out])
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(out, encoding="utf-8") as f:
            self.assertEqual(json.load(f), json.loads(r.stdout))

    def _bad_iocs(self, content):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        path = os.path.join(tmp, "iocs.json")
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return run_script("scan_packages.py", ["--iocs", path, "--roots", PROJECTS])

    def test_invalid_iocs_exit_2(self):
        cases = {
            "not json at all": ("not json", "valid JSON"),
            "missing packages": ('{"alert_title": "x"}', "packages"),
            "bad ecosystem": ('{"packages": [{"ecosystem": "conda", "name": "x", "versions": []}]}', "ecosystem"),
            "missing name": ('{"packages": [{"ecosystem": "npm", "versions": ["1.0"]}]}', "name"),
        }
        for content, expect_in_stderr in cases.values():
            r = self._bad_iocs(content)
            self.assertEqual(r.returncode, 2, f"input: {content!r} -> {r.stderr}")
            self.assertIn("validation failed", r.stderr)
            self.assertIn(expect_in_stderr, r.stderr)
            self.assertEqual(r.stdout.strip(), "")


class HostIocTest(unittest.TestCase):
    PAYLOAD = b"acme-fixture-payload-not-a-real-binary"

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.home = os.path.join(self.tmp, "home")
        write_file(self.home, ".local/share/NodeJS/sync.js", "// dropped malware\n")
        write_file(self.home, ".npm/acme-payload.tgz", self.PAYLOAD.decode("latin-1"))
        write_file(self.home, ".bashrc",
                   "# regular stuff\nnohup node ~/.local/share/NodeJS/sync.js &\n")
        write_file(self.home, ".config/systemd/user/acme-sync.service",
                   "[Unit]\nDescription=acme\n[Service]\n"
                   "ExecStart=/usr/bin/node /home/tester/.local/share/NodeJS/sync.js\n")
        self.payload_sha = hashlib.sha256(self.PAYLOAD).hexdigest()
        iocs = {
            "alert_title": "host fixture",
            "host_iocs": {
                "file_paths": ["~/.local/share/NodeJS/sync.js"],
                "file_hashes": {self.payload_sha: "acme-payload.tgz"},
                "hash_scan_dirs": ["~/.npm"],
                "processes": ["sleep 42424"],
                "network": ["192.0.2.99"],
            },
        }
        self.iocs_path = write_file(self.tmp, "iocs.json", json.dumps(iocs))
        self.env = dict(os.environ, HOME=self.home)
        self.proc = subprocess.Popen(["sleep", "42424"])
        self.addCleanup(self._kill)
        time.sleep(0.3)

    def _kill(self):
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except Exception:
            self.proc.kill()

    def scan_host(self, iocs=None):
        return run_script("scan_host_iocs.py",
                          ["--iocs", iocs or self.iocs_path], env=self.env)

    def test_active_and_persistence_iocs(self):
        r = self.scan_host()
        self.assertEqual(r.returncode, 0, r.stderr)
        rep = json.loads(r.stdout)
        self.assertTrue(any(h["path"].endswith("NodeJS/sync.js") for h in rep["dropped_files"]))
        self.assertEqual(len(rep["hash_matches"]), 1)
        self.assertEqual(rep["hash_matches"][0]["label"], "acme-payload.tgz")
        self.assertTrue(any("sleep 42424" in p.get("process", "") for p in rep["suspicious_processes"]))
        self.assertEqual(rep["network_matches"], [])  # 192.0.2.99 is TEST-NET, never connected
        # persistence (inert grep) must find the rc line and the systemd unit
        kinds = {(os.path.basename(m["file"]), m["kind"]) for m in rep["persistence_matches"]}
        self.assertIn(".bashrc", {k[0] for k in kinds})
        self.assertIn("user-rc", {k[1] for k in kinds})
        self.assertIn("acme-sync.service", {k[0] for k in kinds})
        self.assertIn("systemd-user", {k[1] for k in kinds})
        self.assertGreaterEqual(rep["total_persistence_matches"], 2)
        # persistence must NOT inflate the active-infection counter
        self.assertEqual(rep["total_host_iocs"], 3)  # drop + hash + process
        self.assertEqual(rep["ioc_warnings"], [])

    def test_malformed_hash_ioc_warns_not_crashes(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        iocs = {"host_iocs": {"file_hashes": {"deadbeef": "x.tgz"}, "hash_scan_dirs": [self.home]}}
        path = write_file(tmp, "iocs.json", json.dumps(iocs))
        r = self.scan_host(iocs=path)
        self.assertEqual(r.returncode, 0, r.stderr)
        rep = json.loads(r.stdout)
        self.assertEqual(rep["hash_matches"], [])
        self.assertEqual(len(rep["ioc_warnings"]), 1)
        self.assertIn("malformed", rep["ioc_warnings"][0])

    def test_missing_host_iocs_is_not_an_error(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        path = write_file(tmp, "iocs.json", json.dumps({"packages": []}))
        r = self.scan_host(iocs=path)
        self.assertEqual(r.returncode, 0, r.stderr)
        rep = json.loads(r.stdout)
        self.assertEqual(rep["total_host_iocs"], 0)
        self.assertEqual(rep["total_persistence_matches"], 0)

    def test_invalid_json_exit_2(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        path = write_file(tmp, "iocs.json", "{broken")
        r = self.scan_host(iocs=path)
        self.assertEqual(r.returncode, 2)
        self.assertIn("validation failed", r.stderr)


if __name__ == "__main__":
    unittest.main()
