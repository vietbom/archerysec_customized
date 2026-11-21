"""Relocation, exact FP adoption and lossless evidence/package locations."""
import copy
import hashlib
import json
from xml.etree import ElementTree

from django.test import SimpleTestCase, TestCase
from django.urls import reverse

from projects.models import ProjectDb
from scanners.report_formats import ReportValidationError, semgrep_report, trivy_report, zap_report
from scanners import test_finding_lifecycle as lifecycle
from scanners.test_finding_lifecycle import make_report
from staticscanners.models import StaticScanResultsDb
from user_management.models import Organization, UserProfile, UserRoles


def anchored_report(code="eval(input)", path="/build/one/app.js", line=1):
    report = make_report("semgrepscan", ["A"])
    item = report["results"][0]
    item.update(path=path, start={"line": line, "col": 1}, end={"line": line, "col": 12})
    item["extra"].update(fingerprint="requires login", lines="requires login", archerysec={
        "version": 1, "relative_path": "app.js", "match_sha256": hashlib.sha256(code.encode()).hexdigest(),
        "context_sha256": hashlib.sha256(("context:" + code).encode()).hexdigest()})
    return report


class SourceParserTests(SimpleTestCase):
    def test_source_hash_survives_line_and_runner_directory_changes(self):
        first = semgrep_report(anchored_report())[0]
        moved = semgrep_report(anchored_report(path="/build/two/app.js", line=99))[0]
        self.assertEqual(first.identity_hash, moved.identity_hash)
        self.assertNotEqual(first.identity_hash, semgrep_report(anchored_report(code="eval(other)"))[0].identity_hash)
        self.assertNotIn("eval(input)", json.dumps(first.identity_payload))

    def test_identical_ambiguous_matches_keep_separate_positions(self):
        report = anchored_report()
        other = copy.deepcopy(report["results"][0])
        other["start"]["line"] = other["end"]["line"] = 20
        report["results"].append(other)
        self.assertEqual(len({f.identity_hash for f in semgrep_report(report)}), 2)
        for finding in semgrep_report(report):
            self.assertIn("position", finding.identity_payload)

    def test_placeholder_does_not_hide_a_real_native_match_based_id(self):
        report = make_report("semgrepscan", ["A"])
        report["results"][0]["extra"].update(fingerprint="requires login", match_based_id="native-stable-id")
        original = semgrep_report(report)[0]
        report["results"][0]["start"]["line"] = 99
        self.assertEqual(original.identity_hash, semgrep_report(report)[0].identity_hash)
        self.assertEqual(original.identity_payload["native_id"], "native-stable-id")

    def test_source_identity_validation_rejects_paths_and_invalid_hashes(self):
        for field, value in (("relative_path", "../app.js"), ("relative_path", "another.js"),
                             ("match_sha256", "not-a-hash"), ("version", 2)):
            report = anchored_report()
            report["results"][0]["extra"]["archerysec"][field] = value
            with self.subTest(field=field), self.assertRaises(ReportValidationError):
                semgrep_report(report)

    def test_zap_keeps_all_distinct_evidence_for_the_same_endpoint(self):
        root = ElementTree.fromstring(make_report("zap_scan", ["A"]))
        instances = root.find(".//instances")
        ElementTree.SubElement(instances[0], "evidence").text = "First observation"
        second = copy.deepcopy(instances[0])
        second.find("evidence").text = '<img src=x onerror="alert(1)">'
        instances.extend([second, copy.deepcopy(second)])
        findings, _ = zap_report(root)
        self.assertEqual(len(findings), 1)
        self.assertEqual(len(json.loads(findings[0].values["instance"])), 2)

    def test_trivy_keeps_distinguishing_package_paths_in_display_values(self):
        report = make_report("trivy", ["A"])
        first = report["Results"][0]["Vulnerabilities"][0]
        first["PkgPath"] = "node_modules/a/node_modules/lib/package.json"
        second = copy.deepcopy(first)
        second["PkgPath"] = "node_modules/b/node_modules/lib/package.json"
        report["Results"][0]["Vulnerabilities"].append(second)
        findings = trivy_report(report)
        self.assertEqual(len({f.identity_hash for f in findings}), 2)
        self.assertEqual(len({f.values["filePath"] for f in findings}), 2)
        self.assertTrue(all(f.values["filePath"] in f.values["description"] for f in findings))


class SourceIdentityLifecycleTests(TestCase):
    upload = lifecycle.FindingLifecycleTests.upload
    models = lifecycle.FindingLifecycleTests.models

    def setUp(self):
        self.org = Organization.objects.create(name="Source identity audit")
        self.user = UserProfile.objects.create(email="source@example.test", name="Analyst",
            role=UserRoles.objects.create(role="Analyst"), organization=self.org)
        self.project = ProjectDb.objects.create(project_name="develop", organization=self.org)
        self.client.force_login(self.user)

    def test_exact_old_location_adopts_anchor_then_fp_survives_relocation(self):
        original = anchored_report()
        del original["results"][0]["extra"]["archerysec"]
        self.upload("semgrepscan", original)
        finding = StaticScanResultsDb.objects.get(project=self.project)
        old_id = finding.vuln_id
        response = self.client.post(reverse("staticscanners:vuln_mark"), {
            "vuln_id": finding.vuln_id, "scan_id": finding.scan_id, "false": "Yes", "status": "Closed", "note": "Reviewed"})
        self.assertEqual(response.status_code, 302)
        self.upload("semgrepscan", anchored_report())
        self.upload("semgrepscan", original)
        self.assertEqual(StaticScanResultsDb.objects.filter(project=self.project).count(), 1)
        self.upload("semgrepscan", anchored_report(path="/different/runner/app.js", line=120))
        finding.refresh_from_db()
        self.assertEqual(StaticScanResultsDb.objects.filter(project=self.project).count(), 1)
        self.assertEqual((finding.vuln_id, finding.false_positive, finding.vuln_status, finding.note),
                         (old_id, "Yes", "Closed", "Reviewed"))
        self.upload("semgrepscan", anchored_report(code="eval(different)", path="/different/runner/app.js", line=120))
        self.assertEqual(StaticScanResultsDb.objects.filter(project=self.project).count(), 2)
        self.assertEqual(StaticScanResultsDb.objects.filter(project=self.project, false_positive="No", vuln_status="Open").count(), 1)

    def test_real_native_id_adopts_old_placeholder_finding_before_relocation(self):
        original = anchored_report()
        del original["results"][0]["extra"]["archerysec"]
        self.upload("semgrepscan", original)
        finding = StaticScanResultsDb.objects.get(project=self.project)
        StaticScanResultsDb.objects.filter(pk=finding.pk).update(false_positive="Yes", vuln_status="Closed", is_active=False)
        native = copy.deepcopy(original)
        native["results"][0]["extra"]["match_based_id"] = "vendor-native-id"
        self.upload("semgrepscan", native)
        native["results"][0]["start"]["line"] = native["results"][0]["end"]["line"] = 90
        self.upload("semgrepscan", native)
        finding.refresh_from_db()
        self.assertEqual(StaticScanResultsDb.objects.filter(project=self.project).count(), 1)
        self.assertEqual((finding.false_positive, finding.vuln_status), ("Yes", "Closed"))
