#!/usr/bin/env python3
"""Offline tests for polyswarm_enrich.py.

No API key and no network required: the HTTP layer is stubbed and the fixtures
are trimmed copies of real PolySwarm v3 responses.

    python3 -m unittest discover -s polyswarm-enrich-tool -v
"""

from __future__ import annotations

import contextlib
import csv
import importlib.util
import io
import json
import os
import pathlib
import sys
import unittest

_spec = importlib.util.spec_from_file_location(
    "polyswarm_enrich", pathlib.Path(__file__).with_name("polyswarm_enrich.py")
)
pe = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pe)

SHA256 = "5da5a1e3983982a92341953929d4c7726da65fe5125d264dd8932a870f2f154a"
MD5 = "c8b762d1a8a174cbfd0af11cd93b16de"
MISSING = "b" * 64

# Trimmed from a real GET /v3/search/hash/sha256 response.
HASH_RESPONSE = {
    "has_more": False, "limit": 50, "status": "OK",
    "result": [{
        "sha256": SHA256, "sha1": "14c296a711a623f576408ae90ddc34fc789187a9", "md5": MD5,
        "size": 152576, "extended_type": "PE32 executable (GUI) Intel 80386, for MS Windows",
        "polyscore": 0.9999145539979074,
        "result": True,  # NOT a verdict - see test_result_field_is_not_a_verdict
        "detections": {"benign": 2, "malicious": 6, "total": 8},
        "first_seen": "2023-02-26T10:21:00.615335+00:00",
        "last_seen": "2026-07-09T14:09:03.933311+00:00",
        "permalink": f"https://polyswarm.network/scan/results/file/{SHA256}/75499664076494037",
        "assertions": [
            {"author_name": "XVirus", "engine": {"name": "XVirus"}, "verdict": False},
            {"author_name": "ClamAV", "engine": {"name": "ClamAV"}, "verdict": True},
            {"author_name": "Ikarus", "engine": {"name": "Ikarus"}, "verdict": True},
            {"author_name": "Qihoo 360", "engine": {"name": "Qihoo 360"}, "verdict": True},
            # verdict null = engine did not assert; must not count as malicious
            {"author_name": "Cyberstanc_scrutiny", "engine": {"name": "Cyberstanc_scrutiny"},
             "verdict": None},
        ],
        "metadata": [
            {"tool": "polyunite", "tool_metadata": {
                "labels": ["ransomware", "trojan"], "malware_family": "BlackMatter"}},
            {"tool": "pefile", "tool_metadata": {
                "imphash": "41fb8cb2943df6de998b35a9d28668e8",
                "peid": "AHTeam EP Protector 0.3 (fake PCGuard 4.03-4.15)"}},
        ],
    }],
}

# Trimmed from a real GET /v3/search/url response for https://polyswarm.io - a
# benign URL that nonetheless comes back with result=true.
BENIGN_URL_RECORD = {
    "sha256": "078e6c2d6ba818466fb9944a8717e249b3820c13addc9b7ebf59e3ca79166541",
    "polyscore": 0.33460048640798623,
    "result": True,
    "detections": {"benign": 2, "malicious": 0, "total": 2},
    "assertions": [
        {"engine": {"name": "Quttera"}, "verdict": None},
        {"engine": {"name": "XVirus"}, "verdict": False},
        {"engine": {"name": "CRDF"}, "verdict": False},
    ],
    "metadata": [{"tool": "polyunite",
                  "tool_metadata": {"labels": [], "malware_family": None}}],
}


class TestHashDetection(unittest.TestCase):
    def test_lengths_map_to_types(self):
        self.assertEqual(pe.detect_hash_type("a" * 32), "md5")
        self.assertEqual(pe.detect_hash_type("a" * 40), "sha1")
        self.assertEqual(pe.detect_hash_type("a" * 64), "sha256")

    def test_rejects_non_hashes(self):
        for bad in ("a" * 63, "z" * 64, "", "not-a-hash", "5da5a1e3 983982a9"):
            self.assertIsNone(pe.detect_hash_type(bad), bad)


class TestAssessment(unittest.TestCase):
    def test_thresholds(self):
        self.assertEqual(pe.assess(0.95, 0.8), "malicious")
        self.assertEqual(pe.assess(0.80, 0.8), "malicious")
        self.assertEqual(pe.assess(0.50, 0.8), "suspicious")
        self.assertEqual(pe.assess(0.40, 0.8), "suspicious")
        self.assertEqual(pe.assess(0.39, 0.8), "likely_benign")
        self.assertEqual(pe.assess(None, 0.8), "unknown")

    def test_result_field_is_not_a_verdict(self):
        """Regression: `result` tracks scan settlement, not maliciousness.

        https://polyswarm.io returns result=true with 0 of 2 engines flagging it.
        An earlier version of the Sentinel playbook branched on this field first
        and reported every settled scan as Malicious.
        """
        parsed = pe.parse_scan_record(BENIGN_URL_RECORD, 0.8)
        self.assertIs(parsed["scan_settled"], True)
        self.assertEqual(parsed["assessment"], "likely_benign")
        self.assertEqual(parsed["malicious_engines"], [])


class TestParsing(unittest.TestCase):
    def setUp(self):
        self.parsed = pe.parse_scan_record(HASH_RESPONSE["result"][0], 0.8)

    def test_core_fields(self):
        p = self.parsed
        self.assertEqual(p["assessment"], "malicious")
        self.assertAlmostEqual(p["polyscore"], 0.9999145539979074)
        self.assertEqual((p["malicious"], p["benign"], p["total"]), (6, 2, 8))
        self.assertEqual(p["malware_family"], "BlackMatter")
        self.assertEqual(p["labels"], ["ransomware", "trojan"])
        self.assertEqual(p["imphash"], "41fb8cb2943df6de998b35a9d28668e8")
        self.assertTrue(p["packer"].startswith("AHTeam"))

    def test_only_true_verdicts_count_as_malicious(self):
        engines = self.parsed["malicious_engines"]
        self.assertEqual(sorted(engines), ["ClamAV", "Ikarus", "Qihoo 360"])
        self.assertNotIn("Cyberstanc_scrutiny", engines)  # verdict was null
        self.assertNotIn("XVirus", engines)               # verdict was false

    def test_missing_metadata_degrades_cleanly(self):
        parsed = pe.parse_scan_record({"polyscore": 0.9}, 0.8)
        self.assertEqual(parsed["labels"], [])
        self.assertIsNone(parsed["malware_family"])
        self.assertIsNone(parsed["imphash"])


class TestRenderers(unittest.TestCase):
    def setUp(self):
        hit = pe.parse_scan_record(HASH_RESPONSE["result"][0], 0.8)
        self.records = [
            {"query": SHA256, "hash_type": "sha256", **hit},
            {"query": MISSING, "hash_type": "sha256", **pe.empty_record()},
        ]

    def test_json(self):
        self.assertEqual(len(json.loads(pe.render_json(self.records))), 2)

    def test_csv_flattens_lists(self):
        rows = list(csv.DictReader(pe.render_csv(self.records).splitlines()))
        self.assertEqual(len(rows), 2)
        self.assertEqual(list(rows[0].keys()), pe.CSV_COLUMNS)
        self.assertEqual(rows[0]["labels"], "ransomware;trojan")
        self.assertIn("ClamAV", rows[0]["malicious_engines"])

    def test_stix_bundle(self):
        bundle = json.loads(pe.render_stix(self.records, 0.8))
        self.assertEqual(bundle["type"], "bundle")
        self.assertTrue(bundle["id"].startswith("bundle--"))
        # Only the flagged artifact becomes an indicator.
        self.assertEqual(len(bundle["objects"]), 1)
        ind = bundle["objects"][0]
        self.assertEqual(ind["spec_version"], "2.1")
        self.assertEqual(ind["pattern"], f"[file:hashes.'SHA-256' = '{SHA256}']")
        self.assertEqual(ind["pattern_type"], "stix")
        self.assertEqual(ind["confidence"], 100)
        self.assertEqual(ind["external_references"][0]["source_name"], "PolySwarm")

    def test_stix_omits_benign_and_unseen(self):
        benign = {"query": "c" * 64, "hash_type": "sha256",
                  **pe.parse_scan_record(BENIGN_URL_RECORD, 0.8)}
        bundle = json.loads(pe.render_stix([benign], 0.8))
        self.assertEqual(bundle["objects"], [])


class TestCli(unittest.TestCase):
    """Drives main() with the HTTP layer stubbed out."""

    def setUp(self):
        self.calls: list[tuple[str, str]] = []
        outer = self

        def fake_get(self, path, params):  # noqa: N805
            outer.calls.append((path, params["hash"]))
            if params["hash"] in (SHA256, MD5):
                return 200, HASH_RESPONSE
            return 404, None

        self._real_get = pe.PolySwarmClient.get
        pe.PolySwarmClient.get = fake_get
        os.environ["POLYSWARM_API_KEY"] = "test-key-not-real"

    def tearDown(self):
        pe.PolySwarmClient.get = self._real_get
        os.environ.pop("POLYSWARM_API_KEY", None)

    def run_cli(self, argv, stdin=None):
        out, err = io.StringIO(), io.StringIO()
        saved, self.calls = sys.stdin, []
        if stdin is not None:
            sys.stdin = io.StringIO(stdin)
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = pe.main(argv + ["--rate-limit", "0"])
        finally:
            sys.stdin = saved
        return code, out.getvalue(), err.getvalue()

    def test_mixed_input(self):
        code, out, _ = self.run_cli([SHA256, MISSING, "nothex"])
        records = json.loads(out)
        self.assertEqual(len(records), 3)
        self.assertEqual(records[0]["assessment"], "malicious")
        self.assertEqual(records[1]["assessment"], "not_found")
        self.assertIsNone(records[1]["error"])        # 404 is not an error
        self.assertIsNotNone(records[2]["error"])     # malformed input is
        self.assertEqual(code, 1)
        self.assertEqual(len(self.calls), 2)          # invalid hash never queried

    def test_dedupes_case_insensitively_and_keeps_order(self):
        _, out, _ = self.run_cli([SHA256, SHA256.upper(), MISSING, SHA256])
        records = json.loads(out)
        self.assertEqual([r["query"] for r in records], [SHA256, MISSING])
        self.assertEqual(len(self.calls), 2)

    def test_md5_routes_to_md5_endpoint(self):
        self.run_cli([MD5])
        self.assertEqual(self.calls[0][0], "/search/hash/md5")

    def test_reads_stdin(self):
        _, out, _ = self.run_cli(["-"], stdin=f"{SHA256}\n{MISSING}\n")
        self.assertEqual(len(json.loads(out)), 2)

    def test_exit_codes(self):
        self.assertEqual(self.run_cli([SHA256])[0], 0)
        self.assertEqual(self.run_cli([SHA256, "--threshold", "1.5"])[0], 2)
        self.assertEqual(self.run_cli([], stdin="")[0], 2)
        os.environ.pop("POLYSWARM_API_KEY")
        self.assertEqual(self.run_cli([SHA256])[0], 2)
        os.environ["POLYSWARM_API_KEY"] = "test-key-not-real"

    def test_api_key_never_reaches_output(self):
        _, out, err = self.run_cli([SHA256, "--verbose"])
        self.assertNotIn("test-key-not-real", out + err)


if __name__ == "__main__":
    unittest.main(verbosity=2)
