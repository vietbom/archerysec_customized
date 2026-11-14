"""Golden hashes captured from the original parsers before restoring dup_hash."""
import json
from pathlib import Path
from xml.etree import ElementTree

from django.test import SimpleTestCase

from scanners.report_formats import gitleaks_report, semgrep_report, trivy_report, zap_report


class LegacyFingerprintTests(SimpleTestCase):
    def test_original_parser_hashes_are_preserved(self):
        # Expected hashes were captured by executing the original parser functions
        # from Git HEAD, stopping at build_fingerprint before any DB writes.
        fixtures = json.loads((Path(__file__).parent / "fixtures/legacy_fingerprints.json").read_text(encoding="utf-8"))
        for case in fixtures:
            with self.subTest(case=case["name"]):
                if case["scanner"] == "zap_scan":
                    findings, _ = zap_report(ElementTree.fromstring(case["report"]))
                else:
                    parser = {"gitleaks": gitleaks_report, "semgrepscan": semgrep_report, "trivy": trivy_report}[case["scanner"]]
                    findings = parser(case["report"])
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0].duplicate_hash, case["expected_hash"])
                if case["name"] in ("semgrep-info", "zap-info"):
                    self.assertEqual(findings[0].values["severity"], "Informational")
