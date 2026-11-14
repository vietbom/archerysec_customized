import uuid
from types import SimpleNamespace
from unittest.mock import patch
from xml.etree import ElementTree

from bs4 import BeautifulSoup
from django.contrib.auth.models import AnonymousUser
from django.test import Client, TestCase
from django.urls import reverse
from django.utils import timezone
from notifications.models import Notification
from notifications.signals import notify

from dashboard.scans_data import scans_query
from dashboard.views import trend_update
from projects.models import MonthDb, ProjectDb
from scanners.scanner_parser.staticscanner_parser import (
    gitleaks_json_report_parser as gitleaks,
    semgrep_json_report_parser as semgrep,
    trivy_json_report_parser as trivy,
)
from scanners.scanner_parser.web_scanner import zap_xml_parser as zap
from staticscanners.models import StaticScanResultsDb, StaticScansDb
from user_management.models import Organization, UserProfile, UserRoles
from utility.scan_notifications import scan_imported
from webscanners.models import WebScanResultsDb, WebScansDb


class DashboardRegressionTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.org = Organization.objects.create(name="Test organization")
        cls.other_org = Organization.objects.create(name="Other organization")
        cls.role = UserRoles.objects.create(role="Analyst")
        cls.user = UserProfile.objects.create(email="analyst@example.test", name="Analyst",
                                              role=cls.role, organization=cls.org)
        cls.other_user = UserProfile.objects.create(email="other@example.test", name="Other",
                                                    role=cls.role, organization=cls.other_org)
        cls.project = ProjectDb.objects.create(project_name="Application demo", organization=cls.org)

    def setUp(self):
        self.client.force_login(self.user)
        self.request = SimpleNamespace(user=self.user, META={})

    def new_scan(self, scanner, web=False, project=None):
        model = WebScansDb if web else StaticScansDb
        return model.objects.create(scan_id=uuid.uuid4(), scanner=scanner,
                                    project=project or self.project, organization=self.org)

    def mark(self, finding, false="Yes", status="Open"):
        namespace = "webscanners" if isinstance(finding, WebScanResultsDb) else "staticscanners"
        return self.client.post(reverse(namespace + ":vuln_mark"), {
            "scan_id": finding.scan_id, "vuln_id": finding.vuln_id,
            "false": false, "status": status, "note": "Reviewed by analyst",
        })

    def parsers(self):
        return [
            ("gitleaks", gitleaks, "gitleaks_report_json", [{"RuleID": "test-key", "File": "app.env", "StartLine": 2, "Fingerprint": "fixture:app.env:2"}], False),
            ("Semgrep", semgrep, "semgrep_report_json", {"results": [{"check_id": "test-rule", "path": "app.js", "end": {"line": 3}, "extra": {"message": "Unsafe call", "severity": "ERROR", "metadata": {}, "lines": "fixture"}}]}, False),
            ("Trivy", trivy, "trivy_report_json", {"ArtifactType": "container_image", "Results": [{"Target": "app:demo", "Class": "os-pkgs", "Type": "alpine", "Vulnerabilities": [{"VulnerabilityID": "CVE-TEST", "PkgName": "libtest", "InstalledVersion": "1", "FixedVersion": "2", "Title": "Test issue", "Description": "Fixture", "Severity": "CRITICAL", "References": []}]}]}, False),
            ("Trivy", trivy, "trivy_report_json", {"ArtifactType": "filesystem", "Results": [{"Target": "test.env", "Class": "secret", "Secrets": [{"Title": "Test secret", "Severity": "HIGH", "Category": "test", "StartLine": 1, "EndLine": 1, "Match": "fixture-value"}]}]}, False),
            ("Zap", zap, "xml_parser", ElementTree.fromstring('<OWASPZAPReport><site name="https://app.test"><alerts><alertitem><alert>Test alert</alert><name>Test alert</name><riskcode>3</riskcode><desc>Fixture</desc><solution>Fix it</solution><reference>Fixture</reference><instances><instance><uri>https://app.test/path</uri><method>GET</method></instance></instances></alertitem></alerts></site></OWASPZAPReport>'), True),
        ]

    def test_false_positive_survives_reimport_and_can_be_reopened(self):
        for scanner, module, function, report, web in self.parsers():
            with self.subTest(scanner=scanner, artifact=str(report)[:70]):
                project = ProjectDb.objects.create(project_name="Isolated parser test", organization=self.org)
                scan = self.new_scan(scanner, web, project)
                model = WebScanResultsDb if web else StaticScanResultsDb
                with patch.object(module, "email_sch_notify"):
                    getattr(module, function)(report, project.pk, scan.scan_id, self.request)
                finding = model.objects.get(project=project)
                created_time = finding.created_time
                self.assertEqual(self.mark(finding).status_code, 302)
                finding.refresh_from_db()
                self.assertEqual(finding.created_time, created_time)
                self.assertEqual((finding.false_positive, finding.vuln_status, finding.is_active), ("Yes", "Closed", False))
                self.assertEqual(scans_query.all_vuln_count_data(project.uu_id, "false"), 1)
                self.assertEqual(scans_query.all_vuln_count_data(project.uu_id, "Closed"), 0)
                project.refresh_from_db()
                self.assertEqual((project.total_false, project.total_vuln), (1, 0))
                scan.refresh_from_db()
                self.assertEqual((scan.total_vul, scan.critical_vul), (0, 0))
                next_scan = self.new_scan(scanner, web, project)
                with patch.object(module, "email_sch_notify"):
                    getattr(module, function)(report, project.pk, next_scan.scan_id, self.request)
                finding.refresh_from_db()
                self.assertEqual(model.objects.filter(project=project).count(), 1)
                self.assertEqual((finding.false_positive, finding.vuln_status), ("Yes", "Closed"))
                self.assertEqual(finding.scan_id, next_scan.scan_id)
                self.assertEqual(self.mark(finding, false="No").status_code, 302)
                finding.refresh_from_db()
                self.assertIsNone(finding.false_positive_hash)
                self.assertTrue(finding.is_active)
                project.refresh_from_db()
                self.assertEqual((project.total_false, project.total_vuln), (0, 1))
                next_scan.refresh_from_db()
                self.assertEqual(next_scan.total_vul, 1)
                if finding.severity == "Critical":
                    self.assertEqual(next_scan.critical_vul, 1)
                with patch.object(module, "email_sch_notify"):
                    getattr(module, function)(report, project.pk, next_scan.scan_id, self.request)
                finding.refresh_from_db()
                self.assertEqual((finding.false_positive, finding.vuln_status), ("No", "Open"))
                self.assertTrue(Notification.objects.filter(recipient=self.user, verb__contains="report imported").exists())

    def test_status_validation_and_organization_boundary(self):
        scan = self.new_scan("Semgrep")
        finding = StaticScanResultsDb.objects.create(project=self.project, scan_id=scan.scan_id,
                    vuln_id=uuid.uuid4(), scanner="Semgrep", organization=self.org,
                    severity="High", false_positive="No", vuln_status="Open")
        self.assertEqual(self.mark(finding, false="invalid").status_code, 400)
        self.client.force_login(self.other_user)
        self.assertEqual(self.mark(finding).status_code, 404)
        finding.refresh_from_db()
        self.assertEqual(finding.false_positive, "No")

    def test_dashboard_shows_false_positive_when_no_open_findings(self):
        scan = self.new_scan("Semgrep")
        finding = StaticScanResultsDb.objects.create(project=self.project, scan_id=scan.scan_id,
            vuln_id=uuid.uuid4(), title="Fixture & query?", scanner="Semgrep", organization=self.org,
            severity="High", false_positive="No", vuln_status="Open", vuln_duplicate="No", fileName="app.js")
        self.mark(finding)
        overview = self.client.get(reverse("dashboard:dashboard"))
        self.assertEqual(overview.status_code, 200)
        self.assertContains(overview, "False Positive")
        self.assertEqual(overview.context["false_count_project"]["total_false__sum"], 1)
        self.assertEqual(overview.context["total_count_project"]["total_vuln__sum"], 0)
        detail = self.client.get(reverse("dashboard:proj_data"), {"uu_id": self.project.uu_id})
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(detail.context["all_false_positive"], 1)
        self.assertContains(detail, 'role="tablist"')
        self.assertEqual(detail.context["tota_vuln"], 0)
        for scope, severity in (("none", "All_False_Positive"), (self.project.uu_id, "False")):
            listing = self.client.get(reverse("dashboard:all_high_vuln"), {"project_id": scope, "severity": severity})
            self.assertEqual(listing.status_code, 200)
            self.assertEqual(list(listing.context["sast_all_high"]), [finding])
        reopened = self.mark(finding, false="No")
        self.assertIn("scan_name=Fixture+%26+query%3F", reopened.url)

    def test_global_severity_links_and_month_snapshots_are_scoped(self):
        other_project = ProjectDb.objects.create(project_name="Other project", organization=self.other_org)
        for project, org in ((self.project, self.org), (other_project, self.other_org)):
            StaticScanResultsDb.objects.create(project=project, organization=org, scan_id=uuid.uuid4(),
                vuln_id=uuid.uuid4(), severity="Critical", false_positive="No", vuln_status="Open", vuln_duplicate="No")
        trend_update()
        self.assertEqual(MonthDb.objects.filter(project=self.project, month=timezone.now().month).get().critical, 1)
        result = self.client.get(reverse("dashboard:all_high_vuln"), {"project_id": "none", "severity": "Critical"})
        self.assertEqual(result.status_code, 200)
        self.assertEqual(list(result.context["sast_all_high"].values_list("project_id", flat=True)), [self.project.pk])

    def test_empty_dashboards_render_and_use_one_chart_library(self):
        response = self.client.get(reverse("dashboard:dashboard"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "js/Chart.min.js", count=1)
        selection = self.client.get(reverse("dashboard:project_dashboard"))
        self.assertContains(selection, "Select a project to view")
        self.assertEqual(self.client.get(reverse("dashboard:proj_data")).status_code, 302)
        self.assertEqual(self.client.get(reverse("dashboard:proj_data"), {"uu_id": "invalid"}).status_code, 400)
        self.client.force_login(self.other_user)
        self.assertEqual(self.client.get(reverse("dashboard:proj_data"), {"uu_id": self.project.uu_id}).status_code, 404)

    def test_api_import_notifies_only_analysts_in_its_organization(self):
        viewer_role = UserRoles.objects.create(role="Viewer")
        viewer = UserProfile.objects.create(email="viewer@example.test", name="Viewer",
                                            role=viewer_role, organization=self.org)
        scan_imported(SimpleNamespace(user=AnonymousUser()), self.project.pk, "Trivy", 0)
        self.assertEqual(Notification.objects.filter(recipient=self.user).count(), 1)
        self.assertEqual(Notification.objects.filter(recipient=self.other_user).count(), 0)
        self.assertEqual(Notification.objects.filter(recipient=viewer).count(), 0)

    def test_finding_modals_have_unique_row_targets(self):
        scan = self.new_scan("Semgrep")
        for _ in range(2):
            StaticScanResultsDb.objects.create(project=self.project, scan_id=scan.scan_id,
                vuln_id=uuid.uuid4(), title="Same rule", scanner="Semgrep", organization=self.org,
                severity="High", false_positive="No", vuln_status="Open")
        response = self.client.get(reverse("staticscanners:list_vuln_info"), {"scan_id": scan.scan_id, "scan_name": "Same rule"})
        self.assertEqual(response.status_code, 200)
        soup = BeautifulSoup(response.content, "html.parser")
        modals = soup.select('.modal[id^="commentModal-"]')
        self.assertEqual(len(modals), 2)
        self.assertEqual(len({modal['id'] for modal in modals}), 2)

    def test_notifications_are_recipient_scoped_and_post_only(self):
        notify.send(self.project, recipient=self.user, verb="Import completed")
        notify.send(self.project, recipient=self.other_user, verb="Private notification")
        feed = reverse("dashboard:notification_feed")
        payload = self.client.get(feed).json()
        self.assertEqual(payload["count"], 1)
        self.assertEqual(payload["results"][0]["verb"], "Import completed")
        other = Notification.objects.get(recipient=self.other_user)
        dismiss = reverse("webscanners:del_notify")
        self.assertEqual(self.client.get(dismiss).status_code, 405)
        self.client.post(dismiss, {"notify_id": other.pk})
        other.refresh_from_db()
        self.assertTrue(other.unread)
        csrf_client = Client(enforce_csrf_checks=True)
        csrf_client.force_login(self.user)
        self.assertEqual(csrf_client.post(dismiss, {"notify_id": payload["results"][0]["id"]}).status_code, 403)
        self.client.post(reverse("webscanners:del_all_notify"))
        self.assertEqual(self.client.get(feed).json()["count"], 0)
        other.refresh_from_db()
        self.assertTrue(other.unread)
        self.assertEqual(Notification.objects.count(), 2)
