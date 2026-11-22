"""Regression coverage for historical report totals versus current finding state."""
import copy

from django.test import TestCase
from django.urls import reverse

from scanners import test_finding_lifecycle as lifecycle

from staticscanners.models import StaticScanResultsDb
from utility.finding_status import refresh_scan_counts
from utility.scan_history import findings_for_scan


make_report = lifecycle.make_report


class ReportHistoryTests(TestCase):
    models = lifecycle.FindingLifecycleTests.models
    upload = lifecycle.FindingLifecycleTests.upload
    assert_totals = lifecycle.FindingLifecycleTests.assert_totals
    setUpTestData = classmethod(lifecycle.FindingLifecycleTests.setUpTestData.__func__)
    setUp = lifecycle.FindingLifecycleTests.setUp

    def test_trivy_491_then_215_preserves_first_report_and_current_dashboard(self):
        first_report = make_report("trivy", ["CVE-%04d" % i for i in range(491)])
        tiers = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        for index, item in enumerate(first_report["Results"][0]["Vulnerabilities"]):
            item["Severity"] = tiers[index % len(tiers)]
        first = self.upload("trivy", first_report)
        old_counts = (first.total_vul, first.critical_vul, first.high_vul, first.medium_vul, first.low_vul)
        old_ids = dict(StaticScanResultsDb.objects.filter(project=self.project).values_list("title", "vuln_id"))
        # 76 findings persist, 415 disappear, and 139 are newly observed.
        second_report = make_report("trivy", ["CVE-%04d" % i for i in list(range(76)) + list(range(491, 630))])
        second_report["Results"][0]["Target"] = "app:build2"
        second = self.upload("trivy", second_report)
        self.assertEqual(second.total_vul, 215)
        self.assert_totals(StaticScanResultsDb, 215, 415)
        first.refresh_from_db()
        self.assertEqual((first.total_vul, first.critical_vul, first.high_vul, first.medium_vul, first.low_vul), old_counts)
        self.assertEqual(first.total_vul, 491)
        self.assertEqual(first.finding_links.count(), 491)
        self.assertEqual(second.finding_links.count(), 215)
        self.assertEqual(StaticScanResultsDb.objects.filter(project=self.project).count(), 630)
        self.assertEqual(StaticScanResultsDb.objects.get(project=self.project, title="CVE-0000").vuln_id, old_ids["CVE-0000"])
        response = self.client.get(reverse("dashboard:proj_data"), {"uu_id": self.project.uu_id})
        self.assertEqual(response.context["tota_vuln"], 215)
        scans = {scan.pk: scan.total_vul for scan in response.context["static_scan"]}
        self.assertEqual(scans, {first.pk: 491, second.pk: 215})
        listing = self.client.get(reverse("staticscanners:list_vuln"), {"scan_id": first.scan_id})
        self.assertEqual(sum(row["finding_count"] for row in listing.context["all_vuln"]), 491)

    def test_close_reopen_and_metadata_changes_do_not_rewrite_report_counts(self):
        for scanner in ("gitleaks", "semgrepscan", "trivy", "zap_scan"):
            with self.subTest(scanner=scanner):
                from projects.models import ProjectDb
                self.project = ProjectDb.objects.create(project_name=scanner, organization=self.org)
                model, scan_model = self.models(scanner)
                original = make_report(scanner, ["A", "B"])
                first = self.upload(scanner, original)
                original_counts = (first.total_vul, first.high_vul, first.medium_vul)
                changed = copy.deepcopy(make_report(scanner, ["B", "C"]))
                if scanner == "semgrepscan":
                    changed["results"][0]["extra"]["severity"] = "WARNING"
                elif scanner == "trivy":
                    changed["Results"][0]["Vulnerabilities"][0]["Severity"] = "MEDIUM"
                elif scanner == "zap_scan":
                    changed = changed.replace("<riskcode>3", "<riskcode>2")
                second = self.upload(scanner, changed)
                self.assert_totals(model, 2, 1)
                empty = self.upload(scanner, make_report(scanner, []))
                self.assert_totals(model, 0, 3)
                self.assertEqual(empty.total_vul, 0)
                for scan, expected in ((first, original_counts), (second, (2, second.high_vul, second.medium_vul))):
                    refresh_scan_counts(model, scan_model, scan.scan_id, self.org)
                    scan.refresh_from_db()
                    self.assertEqual((scan.total_vul, scan.high_vul, scan.medium_vul), expected)
                self.assertEqual(findings_for_scan(model, first.scan_id, self.org).count(), 2)
                reopened = self.upload(scanner, make_report(scanner, ["A"]))
                self.assert_totals(model, 1, 2)
                self.assertEqual(reopened.total_vul, 1)
                first.refresh_from_db()
                self.assertEqual((first.total_vul, first.high_vul, first.medium_vul), original_counts)

    def test_same_finding_shows_current_status_from_every_linked_report(self):
        for scanner in ("gitleaks", "semgrepscan", "trivy", "zap_scan"):
            with self.subTest(scanner=scanner):
                from projects.models import ProjectDb
                self.project = ProjectDb.objects.create(project_name=scanner, organization=self.org)
                model, _ = self.models(scanner)
                first = self.upload(scanner, make_report(scanner, ["A"]))
                second = self.upload(scanner, make_report(scanner, ["A"]))
                finding = model.objects.get(project=self.project)
                original_id = finding.vuln_id
                absent = self.upload(scanner, make_report(scanner, []))
                finding.refresh_from_db()
                self.assertEqual(finding.vuln_status, "Closed")
                self.assertEqual(findings_for_scan(model, absent.scan_id, self.org).count(), 0)
                namespace = "webscanners" if scanner == "zap_scan" else "staticscanners"
                for scan in (first, second):
                    scan.refresh_from_db()
                    self.assertEqual(scan.total_vul, 1)
                    listing = self.client.get(reverse(namespace + ":list_vuln"), {"scan_id": scan.scan_id})
                    self.assertEqual(list(listing.context["all_vuln"].values_list("vuln_status", flat=True)), ["Closed"])
                    detail = self.client.get(reverse(namespace + ":list_vuln_info"),
                        {"scan_id": scan.scan_id, "scan_name": finding.title})
                    self.assertEqual([(row.vuln_id, row.vuln_status) for row in detail.context["vuln_data"]],
                                     [(original_id, "Closed")])
                self.upload(scanner, make_report(scanner, ["A"]))
                finding.refresh_from_db()
                self.assertEqual((finding.vuln_id, finding.vuln_status), (original_id, "Open"))
                for scan in (first, second):
                    detail = self.client.get(reverse(namespace + ":list_vuln_info"),
                        {"scan_id": scan.scan_id, "scan_name": finding.title})
                    self.assertEqual([(row.vuln_id, row.vuln_status) for row in detail.context["vuln_data"]],
                                     [(original_id, "Open")])
