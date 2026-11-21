"""API regressions for Semgrep 1.177 PartialParsing warnings and full snapshots."""
import json
from unittest.mock import patch

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from django.urls import reverse
from notifications.models import Notification

from archeryapi.models import OrgAPIKey
from dashboard.scans_data import scans_query
from projects.models import ProjectDb
from scanners.test_finding_lifecycle import make_report
from staticscanners.models import StaticScanResultsDb, StaticScansDb
from user_management.models import Organization, UserProfile, UserRoles


def partial_warning(path="app/views/dashboard.html"):
    return {"code": 3, "level": "warn", "type": ["PartialParsing", [
        {"path": path, "start": {"line": 1, "col": 1}, "end": {"line": 1, "col": 91}},
    ]], "path": path, "message": 'Syntax error: `{% extends "./layout.html" %}` was unexpected'}


class SemgrepPartialImportTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.org = Organization.objects.create(name="Partial Semgrep")
        cls.user = UserProfile.objects.create(email="partial@example.test", name="Analyst",
            role=UserRoles.objects.create(role="Analyst"), organization=cls.org)
        cls.key = OrgAPIKey.objects.create(api_key="partial-semgrep-test-key", organization=cls.org)

    def setUp(self):
        self.project = ProjectDb.objects.create(project_name="same branch", organization=self.org)

    def upload(self, report, status=200):
        with patch("scanners.scanner_parser.staticscanner_parser.semgrep_json_report_parser.email_sch_notify"):
            response = self.client.post(reverse("test_api_upload"), {
                "project_id": str(self.project.uu_id), "scanner": "semgrepscan",
                "scan_url": "semgrep-test-commit", "filename": SimpleUploadedFile(
                    "semgrep.json", json.dumps(report).encode(), content_type="application/json"),
            }, HTTP_X_API_KEY=self.key.api_key)
        self.assertEqual(response.status_code, status, response.content[:1000])
        return response

    def findings(self):
        return StaticScanResultsDb.objects.filter(project=self.project)

    def test_35_findings_and_10_partial_parsing_warnings_import_without_closing_absent(self):
        self.upload(make_report("semgrepscan", ["old-finding"]))
        report = make_report("semgrepscan", [str(i) for i in range(35)])
        report["version"] = "1.177.0"
        for i, item in enumerate(report["results"]):
            item.update(check_id="test.same-rule", path="/home/gitlab-runner/builds/demo/app.js",
                        start={"line": i + 1, "col": 1})
            item["extra"].update(fingerprint="requires login", lines="requires login")
        report["errors"] = [partial_warning("app/views/%s.html" % i) for i in range(10)]
        response = self.upload(report).json()
        self.assertFalse(response["report_complete"])
        self.assertFalse(response["auto_close_enabled"])
        self.assertEqual(len(response["warnings"]), 10)
        self.assertEqual(int(response["result"]["total_vul"]), 35)
        self.assertEqual(self.findings().count(), 36)
        self.assertEqual(self.findings().filter(vuln_status="Open").count(), 36)
        self.assertEqual(scans_query.all_vuln(self.project.uu_id, "total"), 36)
        scan = StaticScansDb.objects.get(scan_id=response["scan_id"])
        self.assertEqual(len(scan.import_warnings), 10)
        self.upload(report)
        self.assertEqual(self.findings().count(), 36)
        self.assertTrue(Notification.objects.filter(recipient=self.user, verb__contains="incomplete scan").exists())

        self.client.force_login(self.user)
        listing = self.client.get(reverse("staticscanners:list_scans"))
        self.assertContains(listing, "Incomplete scan")
        details = self.client.get(reverse("staticscanners:list_vuln"), {"scan_id": scan.scan_id})
        self.assertContains(details, "auto-close skipped")
        self.assertContains(details, "app/views/0.html")

    def test_empty_partial_report_does_not_close_then_complete_empty_closes(self):
        self.upload(make_report("semgrepscan", ["A", "B"]))
        report = {"results": [], "errors": [partial_warning()]}
        self.upload(report)
        self.assertEqual(self.findings().filter(vuln_status="Open").count(), 2)
        complete = self.upload({"results": [], "errors": []}).json()
        self.assertTrue(complete["report_complete"])
        self.assertTrue(complete["auto_close_enabled"])
        self.assertEqual(self.findings().filter(vuln_status="Closed").count(), 2)

    def test_partial_reopens_observed_findings_preserves_fp_and_complete_scan_reconciles(self):
        self.upload(make_report("semgrepscan", ["A", "B", "FP"]))
        self.findings().filter(title="FP").update(false_positive="Yes", vuln_status="Closed", is_active=False)
        self.upload(make_report("semgrepscan", ["A", "FP"]))
        self.assertEqual(self.findings().get(title="B").vuln_status, "Closed")
        partial = make_report("semgrepscan", ["B", "C", "FP"])
        partial["errors"] = [partial_warning()]
        self.upload(partial)
        self.assertEqual(self.findings().get(title="A").vuln_status, "Open")
        self.assertEqual(self.findings().get(title="B").vuln_status, "Open")
        fp = self.findings().get(title="FP")
        self.assertEqual((fp.false_positive, fp.vuln_status, fp.is_active), ("Yes", "Closed", False))
        self.upload(make_report("semgrepscan", ["B", "C", "FP"]))
        self.assertEqual(self.findings().get(title="A").vuln_status, "Closed")
        self.assertEqual(self.findings().count(), 4)

    def test_fatal_unknown_and_malformed_errors_roll_back_without_closing(self):
        self.upload(make_report("semgrepscan", ["A"]))
        cases = [[{"level": "error", "type": "ParseError"}],
                 [partial_warning(), {"level": "error", "type": "Timeout"}],
                 [{"level": "warn", "type": "UnknownWarning"}],
                 [{"level": "error", "type": ["PartialParsing", []]}],
                 [{}], "bad errors", {"level": "warn"}]
        for errors in cases:
            with self.subTest(errors=errors):
                report = make_report("semgrepscan", ["NEW"])
                report["errors"] = errors
                self.upload(report, status=400)
                self.assertEqual(self.findings().count(), 1)
                self.assertEqual(self.findings().get().vuln_status, "Open")
                self.assertEqual(StaticScansDb.objects.filter(project=self.project).count(), 1)
