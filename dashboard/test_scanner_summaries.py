"""Cross-project dashboard accounting and scan health are separate concerns."""
import uuid

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from projects.models import ProjectDb
from staticscanners.models import StaticScanFinding, StaticScanResultsDb, StaticScansDb
from user_management.models import Organization, UserProfile, UserRoles
from webscanners.models import WebScanFinding, WebScanResultsDb, WebScansDb


class ScannerSummaryTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(name="Dashboard accounting")
        self.user = UserProfile.objects.create(email="counts@example.test", name="Analyst",
            role=UserRoles.objects.create(role="Analyst"), organization=self.org)
        self.client.force_login(self.user)
        self.a = ProjectDb.objects.create(project_name="develop", organization=self.org)
        self.b = ProjectDb.objects.create(project_name="master", organization=self.org)
        old = self.scan(self.a, "Semgrep")
        self.retained = self.finding(old, "High")
        warnings = [{"type": "PartialParsing", "level": "warn", "path": "views/%s.html" % i,
                     "message": "Template was only partly parsed"} for i in range(10)]
        self.partial = self.scan(self.a, "Semgrep", warnings)
        self.info = self.finding(self.partial, "Informational")
        trivy = self.scan(self.a, "Trivy")
        self.finding(trivy, "Critical")
        self.finding(trivy, "Medium", fp="Yes", status="Closed")
        self.finding(trivy, "Low", status="Closed")
        self.finding(trivy, "High", duplicate="Yes")
        self.finding(self.scan(self.a, "Zap"), "Medium")
        self.finding(self.scan(self.b, "Semgrep"), "Medium")
        self.finding(self.scan(self.b, "gitleaks"), "High")
        zap = self.scan(self.b, "Zap")
        self.finding(zap, "Low")
        self.finding(zap, "Information")
        other = Organization.objects.create(name="Other tenant")
        hidden = ProjectDb.objects.create(project_name="Private project", organization=other)
        self.finding(self.scan(hidden, "Semgrep", warnings * 2), "Critical")

    def scan(self, project, scanner, warnings=None):
        model = WebScansDb if scanner == "Zap" else StaticScansDb
        values = dict(project=project, organization=project.organization, scanner=scanner,
            scan_id=uuid.uuid4(), date_time=timezone.now(), total_vul=999)
        if model == StaticScansDb:
            values["import_warnings"] = warnings or []
        return model.objects.create(**values)

    def finding(self, scan, severity, status="Open", fp="No", duplicate="No"):
        web = isinstance(scan, WebScansDb)
        model, link = (WebScanResultsDb, WebScanFinding) if web else (StaticScanResultsDb, StaticScanFinding)
        finding = model.objects.create(project=scan.project, organization=scan.organization,
            scan_id=scan.scan_id, vuln_id=uuid.uuid4(), title="Fixture", scanner=scan.scanner,
            severity=severity, vuln_status=status, false_positive=fp, vuln_duplicate=duplicate)
        link.objects.create(scan=scan, finding=finding)
        return finding

    def test_totals_are_sum_of_projects_not_historical_reports_or_parser_warnings(self):
        overview = self.client.get(reverse("dashboard:dashboard"))
        self.assertEqual(overview.status_code, 200)
        self.assertEqual(overview.context["total_count_project"]["total_vuln__sum"], 8)
        self.assertEqual(overview.context["info_counts"]["total"], 2)
        self.assertEqual(overview.context["false_count_project"]["total_false__sum"], 1)
        self.assertEqual(overview.context["close_count_project"]["total_close__sum"], 1)
        self.assertNotContains(overview, "Private project")
        self.assertNotContains(overview, "Scan coverage needs attention")
        self.assertNotContains(overview, "Current findings by scanner")
        projects = []
        for project in (self.a, self.b):
            response = self.client.get(reverse("dashboard:proj_data"), {"uu_id": project.uu_id})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.context["tota_vuln"], 4)
            self.assertContains(response, "Current findings by scanner")
            self.assertNotContains(response, "Scan coverage")
            self.assertNotContains(response, "parser warnings")
            if project == self.a:
                self.assertEqual(response.context["scan_health"]["warning_count"], 10)
                self.assertEqual(response.context["scan_health"]["project_count"], 1)
                semgrep = next(row for row in response.context["scanner_summaries"] if row["key"] == "semgrep")
                self.assertEqual((semgrep["open"], semgrep["report_open"], semgrep["not_in_latest"]), (2, 1, 1))
            rows = response.context["scanner_summaries"]
            self.assertEqual(sum(row["open"] for row in rows), 4)
            for row in rows:
                self.assertEqual(row["open"], sum(row[key] for key in ("critical", "high", "medium", "low", "info")))
            projects.append(response.context["tota_vuln"])
        self.assertEqual(sum(projects), overview.context["total_count_project"]["total_vuln__sum"])

    def test_latest_complete_report_clears_health_without_erasing_historical_warnings(self):
        complete = self.scan(self.a, "Semgrep")
        for finding in (self.retained, self.info):
            StaticScanFinding.objects.create(scan=complete, finding=finding)
        response = self.client.get(reverse("dashboard:proj_data"), {"uu_id": self.a.uu_id})
        self.assertEqual(response.context["scan_health"]["warning_count"], 0)
        row = next(row for row in response.context["scanner_summaries"] if row["key"] == "semgrep")
        self.assertEqual((row["open"], row["report_open"], row["not_in_latest"]), (2, 2, 0))
        self.partial.refresh_from_db()
        self.assertEqual(len(self.partial.import_warnings), 10)

    def test_scanner_links_count_the_same_scoped_findings_as_summary(self):
        for scope, expected in (("none", 3), (str(self.a.uu_id), 2), (str(self.b.uu_id), 1)):
            response = self.client.get(reverse("dashboard:all_high_vuln"), {
                "project_id": scope, "scanner": "semgrep", "severity": "All"})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.context["sast_all_high"].count(), expected)
            self.assertEqual(response.context["web_all_high"].count(), 0)
        self.assertEqual(self.client.get(reverse("dashboard:all_high_vuln"), {"scanner": "invalid"}).status_code, 400)

    def test_legacy_finding_without_scan_is_counted_as_not_in_latest_report(self):
        StaticScanResultsDb.objects.create(project=self.b, organization=self.org,
            scan_id=uuid.uuid4(), vuln_id=uuid.uuid4(), scanner="Trivy", severity="High",
            vuln_status="Open", false_positive="No", vuln_duplicate="No")
        response = self.client.get(reverse("dashboard:proj_data"), {"uu_id": self.b.uu_id})
        row = next(row for row in response.context["scanner_summaries"] if row["key"] == "trivy")
        self.assertEqual((row["open"], row["report_open"], row["not_in_latest"], row["has_reports"]), (1, 0, 1, False))
        self.assertEqual(response.context["tota_vuln"], 5)
