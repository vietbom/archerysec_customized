import html
from importlib import import_module
from types import SimpleNamespace
from unittest.mock import patch

from bs4 import BeautifulSoup
from django.core.files.uploadedfile import SimpleUploadedFile
from django.apps import apps
from django.db import connection
from django.test import TestCase
from django.urls import reverse

from dashboard.scans_data import scans_query
from projects.models import ProjectDb
from user_management.models import Organization, UserProfile, UserRoles
from webscanners.models import WebScanFinding, WebScanResultsDb, WebScansDb


class ZapReimportTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.org = Organization.objects.create(name="ZAP reimport")
        role = UserRoles.objects.create(role="Analyst")
        cls.user = UserProfile.objects.create(email="zap@example.test", name="Analyst",
                                              role=role, organization=cls.org)
        cls.project = ProjectDb.objects.create(project_name="ZAP demo", organization=cls.org)

    def setUp(self):
        self.client.force_login(self.user)

    def upload(self, title="Test alert", risk="3"):
        report = ('<OWASPZAPReport><site name="https://app.test"><alerts><alertitem>'
                  '<alert>{0}</alert><name>{0}</name><riskcode>{1}</riskcode>'
                  '<desc>Test description</desc><solution>Fix it</solution>'
                  '<reference>https://example.test/advisory</reference>'
                  '<instances><instance><uri>https://app.test/path</uri><method>GET</method>'
                  '</instance></instances></alertitem></alerts></site></OWASPZAPReport>'
                  ).format(html.escape(title), risk)
        with patch("scanners.scanner_parser.web_scanner.zap_xml_parser.email_sch_notify"):
            response = self.client.post(reverse("report_upload:upload"), {
                "project_id": self.project.uu_id, "scanner": "zap_scan", "target": "https://app.test",
                "file": SimpleUploadedFile("zap.xml", report.encode(), content_type="application/xml"),
            })
        self.assertEqual(response.status_code, 302)
        return WebScansDb.objects.latest("pk")

    def listing(self, scan):
        response = self.client.get(reverse("webscanners:list_vuln"), {"scan_id": scan.scan_id})
        self.assertEqual(response.status_code, 200)
        return response

    def test_identical_upload_keeps_both_reports_without_doubling_dashboard(self):
        first = self.upload()
        second = self.upload()
        for scan in (first, second):
            with self.subTest(scan=scan.scan_id):
                response = self.listing(scan)
                self.assertEqual(len(response.context["all_vuln"]), 1)
                link = BeautifulSoup(response.content, "html.parser").select_one("#data_table tbody a")
                grouped = self.client.get(link["href"])
                self.assertEqual(len(grouped.context["vuln_data"]), 1)
                self.assertContains(grouped, "Test alert")
                finding = grouped.context["vuln_data"][0]
                with patch("webscanners.views.get_jira_projects", return_value=None):
                    detail = self.client.get(reverse("webscanners:scan_details"), {"vuln_id": finding.vuln_id})
                self.assertContains(detail, "Test description")
                self.assertContains(detail, "https://example.test/advisory")
        self.assertEqual(WebScanResultsDb.objects.count(), 1)
        self.assertEqual(scans_query.all_vuln_count_data(self.project.uu_id, "Open"), 1)

    def test_title_special_characters_reach_the_finding_group(self):
        scan = self.upload("Alert & query #1 + parameter?")
        response = self.listing(scan)
        link = BeautifulSoup(response.content, "html.parser").select_one("#data_table tbody a")
        grouped = self.client.get(link["href"])
        self.assertEqual(len(grouped.context["vuln_data"]), 1)

    def test_changed_report_only_shows_its_own_findings(self):
        first = self.upload("Old alert")
        second = self.upload("New alert")
        self.assertEqual(list(self.listing(first).context["all_vuln"].values_list("title", flat=True)), ["Old alert"])
        self.assertEqual(list(self.listing(second).context["all_vuln"].values_list("title", flat=True)), ["New alert"])
        self.assertEqual(scans_query.all_vuln_count_data(self.project.uu_id, "Open"), 1)

    def test_false_positive_preserved_and_editable_from_either_report(self):
        first = self.upload()
        finding = WebScanResultsDb.objects.get()
        response = self.client.post(reverse("webscanners:vuln_mark"), {
            "scan_id": first.scan_id, "vuln_id": finding.vuln_id,
            "false": "Yes", "status": "Open", "note": "Reviewed",
        })
        self.assertEqual(response.status_code, 302)
        second = self.upload()
        finding.refresh_from_db()
        self.assertEqual((finding.false_positive, finding.vuln_status), ("Yes", "Closed"))
        for scan in (first, second):
            self.assertEqual(len(self.listing(scan).context["all_vuln"]), 1)
            scan.refresh_from_db()
            self.assertEqual(scan.total_vul, 0)
        response = self.client.post(reverse("webscanners:vuln_mark"), {
            "scan_id": first.scan_id, "vuln_id": finding.vuln_id,
            "false": "No", "status": "Open", "note": "Restored",
        })
        self.assertEqual(response.status_code, 302)
        self.assertIn(str(first.scan_id), response.url)
        for scan in (first, second):
            scan.refresh_from_db()
            self.assertEqual(scan.total_vul, 1)
        self.assertEqual(scans_query.all_vuln_count_data(self.project.uu_id, "Open"), 1)

    def test_deleting_either_report_preserves_the_other_and_last_delete_cleans_up(self):
        for delete_latest in (True, False):
            with self.subTest(delete_latest=delete_latest):
                first = self.upload()
                second = self.upload()
                deleted, kept = (second, first) if delete_latest else (first, second)
                response = self.client.post(reverse("webscanners:scan_delete"), {"scan_id": deleted.scan_id})
                self.assertEqual(response.status_code, 302)
                self.assertEqual(len(self.listing(kept).context["all_vuln"]), 1)
                self.assertEqual(WebScanResultsDb.objects.count(), 1)
                self.assertEqual(WebScanResultsDb.objects.get().scan_id, kept.scan_id)
                self.client.post(reverse("webscanners:scan_delete"), {"scan_id": kept.scan_id})
                self.assertFalse(WebScanResultsDb.objects.exists())
                self.assertFalse(WebScanFinding.objects.exists())

    def test_report_is_scoped_to_organization(self):
        first = self.upload()
        second = self.upload()
        org = Organization.objects.create(name="Other org")
        other_user = UserProfile.objects.create(email="other-zap@example.test", name="Other",
                                                role=self.user.role, organization=org)
        self.client.force_login(other_user)
        for scan in (first, second):
            self.assertEqual(len(self.listing(scan).context["all_vuln"]), 0)
            grouped = self.client.get(reverse("webscanners:list_vuln_info"),
                                      {"scan_id": scan.scan_id, "scan_name": "Test alert"})
            self.assertEqual(len(grouped.context["vuln_data"]), 0)
            self.client.post(reverse("webscanners:scan_delete"), {"scan_id": scan.scan_id})
        self.assertEqual(WebScansDb.objects.count(), 2)

    def test_migration_backfills_known_links_without_guessing_empty_reports(self):
        first = self.upload()
        second = self.upload()
        WebScanFinding.objects.all().delete()
        migration = import_module("webscanners.migrations.0030_webscanfinding")
        migration.backfill_current_memberships(apps, SimpleNamespace(connection=connection))
        self.assertEqual(list(WebScanFinding.objects.values_list("scan_id", flat=True)), [second.pk])
        # The old association was already lost; the backfill must not invent it.
        self.assertEqual(len(self.listing(first).context["all_vuln"]), 0)

    def test_critical_findings_are_included_in_report_total(self):
        scan = self.upload(risk="4")
        self.assertEqual((scan.total_vul, scan.critical_vul), (1, 1))
