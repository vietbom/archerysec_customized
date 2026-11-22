"""Behavioral checks for v2 identity, FP scope and transition from submitted code."""
import copy
from io import StringIO
import json
import uuid
from xml.etree import ElementTree

from django.test import SimpleTestCase, TestCase
from django.core.management import call_command
from django.urls import reverse

from dashboard.scans_data import scans_query
from projects.models import ProjectDb
from scanners.report_formats import gitleaks_report, semgrep_report, trivy_report, zap_report, ReportValidationError
from scanners.test_finding_lifecycle import FindingLifecycleTests, make_report
from staticscanners.models import StaticScanResultsDb
from user_management.models import Organization, UserProfile, UserRoles
from webscanners.models import WebScanResultsDb, WebScansDb


def parsed(scanner, report):
    if scanner == "zap_scan":
        return zap_report(ElementTree.fromstring(report))[0]
    parser = {"gitleaks": gitleaks_report, "semgrepscan": semgrep_report, "trivy": trivy_report}[scanner.split(":")[0]]
    return parser(report)


def changed_metadata(scanner, report):
    report = copy.deepcopy(report)
    if scanner == "gitleaks":
        report[0].update(Commit="new-commit", Fingerprint="new-commit:A.env:A:1", Message="New description", References=["https://example.test/new"])
    elif scanner == "semgrepscan":
        report["results"][0]["extra"].update(message="New description", severity="WARNING", metadata={"references": ["https://example.test/new"]})
        report["results"][0]["end"] = {"line": 4, "col": 200}
    elif scanner.startswith("trivy"):
        result = report["Results"][0]
        group = next(name for name in ("Vulnerabilities", "Secrets", "Misconfigurations") if result.get(name))
        result[group][0].update(Title="Updated title", Description="New description", Severity="CRITICAL", References=["https://example.test/new"])
        if group == "Vulnerabilities":
            result[group][0]["FixedVersion"] = "9"
            if result["Class"] == "os-pkgs":
                result["Target"] = "app:build999 (alpine 3.21)"
        elif group == "Misconfigurations":
            result[group][0].update(Message="New diagnostic", Resolution="New fix")
    else:
        report = report.replace("Initial description", "New description").replace("<riskcode>3", "<riskcode>2").replace("example.test/advisory", "example.test/new")
    return report


class StableIdentityParserTests(SimpleTestCase):
    def test_metadata_changes_are_not_identity_changes(self):
        for scanner in FindingLifecycleTests.scanners:
            with self.subTest(scanner=scanner):
                report = make_report(scanner, ["A"])
                old, new = parsed(scanner, report)[0], parsed(scanner, changed_metadata(scanner, report))[0]
                self.assertEqual(old.identity_hash, new.identity_hash)
                self.assertNotEqual(old.values, new.values)
                self.assertEqual(old.identity_payload["identity_version"], 2)

    def test_gitleaks_native_presence_and_commits_do_not_change_identity(self):
        report = make_report("gitleaks", ["A"])
        before = gitleaks_report(report)[0]
        del report[0]["Fingerprint"]
        report[0]["Commit"] = "different"
        self.assertEqual(before.identity_hash, gitleaks_report(report)[0].identity_hash)
        report[0]["Match"] = "new-secret-value"
        changed = gitleaks_report(report)[0]
        self.assertNotEqual(before.identity_hash, changed.identity_hash)
        self.assertNotIn("new-secret-value", json.dumps(changed.identity_payload))

    def test_semgrep_normalized_path_and_start_position(self):
        report = make_report("semgrepscan", ["A"])
        report["results"][0]["path"] = "src\\A.js"
        original = semgrep_report(report)[0]
        report["results"][0]["path"] = "./src/A.js"
        report["results"][0]["end"] = {"line": 100, "col": 200}
        self.assertEqual(original.identity_hash, semgrep_report(report)[0].identity_hash)
        report["results"][0]["start"]["line"] = 8
        self.assertNotEqual(original.identity_hash, semgrep_report(report)[0].identity_hash)

    def test_semgrep_native_ids_and_ce_placeholder(self):
        report = make_report("semgrepscan", ["A"])
        fallback = semgrep_report(report)[0].identity_hash
        report["results"][0]["extra"]["fingerprint"] = "requires login"
        self.assertEqual(semgrep_report(report)[0].identity_hash, fallback)
        report["results"][0]["extra"]["fingerprint"] = "match-123"
        native = semgrep_report(report)[0].identity_hash
        report["results"][0]["start"] = {"line": 999}
        self.assertEqual(semgrep_report(report)[0].identity_hash, native)

    def test_trivy_package_version_path_rule_and_secret_are_separate(self):
        report = make_report("trivy", ["A"])
        before = trivy_report(report)[0].identity_hash
        report["Results"][0]["Vulnerabilities"][0]["InstalledVersion"] = "1.1"
        self.assertNotEqual(before, trivy_report(report)[0].identity_hash)
        report["Results"][0]["Vulnerabilities"][0]["InstalledVersion"] = "1"
        report["Results"][0]["Vulnerabilities"][0]["PkgPath"] = "another/package"
        self.assertNotEqual(before, trivy_report(report)[0].identity_hash)
        for scanner, group, key in (("trivy:secret", "Secrets", "RuleID"), ("trivy:config", "Misconfigurations", "ID")):
            report = make_report(scanner, ["A"])
            before = trivy_report(report)[0].identity_hash
            report["Results"][0][group][0][key] = "B"
            self.assertNotEqual(before, trivy_report(report)[0].identity_hash)

    def test_zap_instances_split_and_order_evidence_do_not_change_identity(self):
        report = make_report("zap_scan", ["A"])
        root = ElementTree.fromstring(report)
        instances = root.find(".//instances")
        other = copy.deepcopy(instances[0])
        other.find("uri").text = "https://app.test/other"
        instances.append(other)
        before = zap_report(root)[0]
        self.assertEqual(len(before), 2)
        self.assertEqual(len({item.identity_hash for item in before}), 2)
        instances[:] = list(reversed(instances))
        for instance in instances:
            ElementTree.SubElement(instance, "evidence").text = "New observation"
        after = zap_report(root)[0]
        self.assertEqual({item.identity_hash for item in before}, {item.identity_hash for item in after})
        self.assertTrue(all(len(json.loads(item.values["instance"])) == 1 for item in after))

    def test_zap_method_parameter_and_normalized_origin(self):
        root = ElementTree.fromstring(make_report("zap_scan", ["A"]))
        before = zap_report(root)[0][0].identity_hash
        root.find("site").set("name", "https://APP.TEST:443/")
        root.find(".//uri").text = "https://APP.TEST:443/A#fragment"
        self.assertEqual(before, zap_report(root)[0][0].identity_hash)
        root.find(".//method").text = "POST"
        self.assertNotEqual(before, zap_report(root)[0][0].identity_hash)
        root.find(".//method").text = "GET"
        ElementTree.SubElement(root.find(".//instance"), "param").text = "password"
        self.assertNotEqual(before, zap_report(root)[0][0].identity_hash)

    def test_malformed_identity_inputs_are_validation_errors(self):
        cases = [("gitleaks", [{"RuleID": "A", "File": "a", "Fingerprint": {}}]),
                 ("semgrepscan", {"results": [{"check_id": "A", "path": "a"}]}),
                 ("semgrepscan", {"results": [{"check_id": "A", "path": "a", "start": {"line": "1"}}]}),
                 ("trivy", {"ArtifactType": "filesystem", "Results": [], "Errors": ["failed"]}),
                 ("zap_scan", make_report("zap_scan", ["A"]).replace("app.test", "app.test:invalid")),
                 ("zap_scan", make_report("zap_scan", ["A"]).replace("https://app.test", "http://["))]
        for scanner, report in cases:
            with self.subTest(scanner=scanner), self.assertRaises(ReportValidationError):
                parsed(scanner, report)


class StableIdentityLifecycleTests(TestCase):
    models = FindingLifecycleTests.models
    upload = FindingLifecycleTests.upload
    assert_totals = FindingLifecycleTests.assert_totals

    @classmethod
    def setUpTestData(cls):
        cls.org = Organization.objects.create(name="Stable identities")
        cls.user = UserProfile.objects.create(email="stable@example.test", name="Analyst",
            role=UserRoles.objects.create(role="Analyst"), organization=cls.org)

    def setUp(self):
        self.client.force_login(self.user)
        self.project = ProjectDb.objects.create(project_name="main", organization=self.org)

    def mark(self, finding, scanner, fp="Yes", status="Closed"):
        namespace = "webscanners" if scanner == "zap_scan" else "staticscanners"
        response = self.client.post(reverse(namespace + ":vuln_mark"), {
            "scan_id": finding.scan_id, "vuln_id": finding.vuln_id, "false": fp, "status": status, "note": "Verified by analyst"})
        self.assertEqual(response.status_code, 302)

    def test_fp_survives_metadata_updates_and_reopen_after_unmark_for_all_kinds(self):
        for scanner in FindingLifecycleTests.scanners:
            with self.subTest(scanner=scanner):
                self.project = ProjectDb.objects.create(project_name=scanner, organization=self.org)
                report = make_report(scanner, ["A"])
                first = self.upload(scanner, report)
                model, _ = self.models(scanner)
                finding = model.objects.get(project=self.project)
                original_id, created, original_hash = finding.vuln_id, finding.created_time, finding.dup_hash
                self.mark(finding, scanner)
                changed = changed_metadata(scanner, report)
                second = self.upload(scanner, changed)
                finding.refresh_from_db()
                self.assertEqual(model.objects.filter(project=self.project).count(), 1)
                self.assertEqual((finding.vuln_id, finding.created_time, finding.dup_hash), (original_id, created, original_hash))
                self.assertEqual((finding.false_positive, finding.vuln_status, finding.is_active), ("Yes", "Closed", False))
                self.assertEqual(finding.false_positive_hash, finding.identity_hash)
                self.assertEqual(finding.note, "Verified by analyst")
                self.assertEqual(scans_query.all_vuln_count_data(self.project.uu_id, "false"), 1)
                self.assertEqual(second.total_vul, 0)
                self.mark(finding, scanner, fp="No", status="Closed")
                self.upload(scanner, changed)
                finding.refresh_from_db()
                self.assertEqual((finding.vuln_status, finding.false_positive), ("Open", "No"))
                first.refresh_from_db()
                self.assertEqual(first.total_vul, 1)

    def test_zap_fp_does_not_suppress_another_url_method_or_parameter(self):
        report = make_report("zap_scan", ["A"])
        self.upload("zap_scan", report)
        finding = WebScanResultsDb.objects.get(project=self.project)
        self.mark(finding, "zap_scan")
        root = ElementTree.fromstring(report)
        instances = root.find(".//instances")
        for field, value in (("uri", "https://app.test/another"), ("method", "POST"), ("param", "password")):
            other = copy.deepcopy(instances[0])
            target = other.find(field)
            if target is None:
                target = ElementTree.SubElement(other, field)
            target.text = value
            instances.append(other)
        self.upload("zap_scan", ElementTree.tostring(root, encoding="unicode"))
        self.assertEqual(WebScanResultsDb.objects.filter(project=self.project).count(), 4)
        self.assertEqual(WebScanResultsDb.objects.filter(project=self.project, false_positive="Yes").count(), 1)
        self.assert_totals(WebScanResultsDb, 3, 0)

    def test_legacy_grouped_zap_fp_migrates_only_exact_observation(self):
        root = ElementTree.fromstring(make_report("zap_scan", ["A"]))
        instances = root.find(".//instances")
        second = copy.deepcopy(instances[0])
        second.find("uri").text = "https://app.test/other"
        instances.append(second)
        items, _ = zap_report(root)
        scan = WebScansDb.objects.create(scan_id=uuid.uuid4(), project=self.project, organization=self.org, scanner="Zap")
        old = WebScanResultsDb.objects.create(vuln_id=uuid.uuid4(), scan_id=scan.scan_id, project=self.project,
            organization=self.org, scanner="Zap", dup_hash=items[0].duplicate_hash, false_positive="Yes",
            vuln_status="Closed", is_active=False, note="Old review", identity_version=0)
        original_id = old.vuln_id
        self.upload("zap_scan", ElementTree.tostring(root, encoding="unicode"))
        old.refresh_from_db()
        self.assertEqual(old.vuln_id, original_id)
        self.assertEqual(old.identity_version, 2)
        self.assertEqual(WebScanResultsDb.objects.filter(project=self.project, false_positive="Yes").count(), 2)
        self.assertEqual(WebScanResultsDb.objects.filter(project=self.project).count(), 2)
        self.assertEqual(len(old.scan_links.all()), 2)

    def test_old_report_counters_preserve_observed_severity_after_auto_close(self):
        report = make_report("semgrepscan", ["A"])
        first = self.upload("semgrepscan", report)
        changed = changed_metadata("semgrepscan", report)
        self.upload("semgrepscan", changed)
        first.refresh_from_db()
        self.assertEqual((first.high_vul, first.medium_vul, first.total_vul), (1, 0, 1))
        self.upload("semgrepscan", make_report("semgrepscan", []))
        first.refresh_from_db()
        self.assertEqual(first.total_vul, 1)

    def test_partial_failure_does_not_write_identity_or_close_existing(self):
        report = make_report("semgrepscan", ["A"])
        self.upload("semgrepscan", report)
        original = StaticScanResultsDb.objects.get(project=self.project)
        self.upload("semgrepscan", {"results": [{"check_id": "B", "path": "broken.js"}]}, expected_success=False)
        original.refresh_from_db()
        self.assertEqual((original.identity_version, original.vuln_status), (2, "Open"))
        self.assertEqual(StaticScanResultsDb.objects.filter(project=self.project).count(), 1)

    def test_read_only_identity_audit_reports_legacy_fp(self):
        self.upload("gitleaks", make_report("gitleaks", ["A"]))
        finding = StaticScanResultsDb.objects.get(project=self.project)
        self.mark(finding, "gitleaks")
        StaticScanResultsDb.objects.filter(pk=finding.pk).update(identity_version=0, identity_hash="")
        output = StringIO()
        call_command("audit_scanner_identity", project=self.project.uu_id, stdout=output)
        audit = json.loads(output.getvalue())
        self.assertEqual((audit["read_only"], audit["legacy_findings"], audit["legacy_fp"]), (True, 1, 1))
        finding.refresh_from_db()
        self.assertEqual((finding.identity_version, finding.identity_hash, finding.false_positive), (0, "", "Yes"))
