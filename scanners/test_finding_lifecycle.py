"""Exercise real multipart uploads and current dashboard totals for four scanners."""
import copy
import html
import json
from unittest.mock import patch

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from django.urls import reverse

from dashboard.scans_data import scans_query
from projects.models import ProjectDb
from staticscanners.models import StaticScanResultsDb, StaticScansDb
from user_management.models import Organization, UserProfile, UserRoles
from webscanners.models import WebScanResultsDb, WebScansDb
from archeryapi.models import OrgAPIKey


def make_report(scanner, names):
    if scanner == "gitleaks":
        return [{"RuleID": name, "File": name + ".env", "StartLine": 1,
                 "Fingerprint": "commit:" + name + ".env:" + name + ":1"} for name in names]
    if scanner == "semgrepscan":
        return {"results": [{"check_id": name, "path": name + ".js", "start": {"line": 1, "col": 1},
                "end": {"line": 2, "col": 4}, "extra": {"message": name, "severity": "ERROR",
                    "metadata": {}, "lines": "eval(input)"}} for name in names], "errors": []}
    if scanner.startswith("trivy"):
        kind = scanner.partition(":")[2] or "image"
        if kind in ("image", "filesystem"):
            results = [{"Target": "app:build1" if kind == "image" else "package-lock.json",
                        "Class": "os-pkgs" if kind == "image" else "lang-pkgs",
                        "Type": "alpine" if kind == "image" else "npm",
                        "Vulnerabilities": [{"VulnerabilityID": name, "PkgName": "lib-" + name,
                            "InstalledVersion": "1", "FixedVersion": "2", "Title": name,
                            "Description": name, "Severity": "HIGH"} for name in names]}]
        elif kind == "secret":
            results = [{"Target": "app.env", "Class": "secret", "Secrets": [
                {"RuleID": name, "Title": name, "Category": "test", "Severity": "HIGH",
                 "StartLine": ord(name[0]), "EndLine": ord(name[0]), "Match": name} for name in names]}]
        else:
            results = [{"Target": "Dockerfile", "Class": "config", "Misconfigurations": [
                {"ID": name, "Title": name, "Description": name, "Message": name,
                 "Resolution": "Fix it", "References": [], "Severity": "HIGH", "CauseMetadata": {
                     "StartLine": 1, "EndLine": 1, "Code": {"Lines": []},
                     "Resource": name, "Provider": "docker"}} for name in names]}]
        return {"SchemaVersion": 2, "ArtifactType": "container_image" if kind == "image" else "filesystem",
                "ArtifactName": "app:build1" if kind == "image" else ".", "Results": results}
    return ('<OWASPZAPReport><site name="https://app.test"><alerts>' + ''.join(
        '<alertitem><pluginid>{0}</pluginid><alertRef>{0}</alertRef><alert>{0}</alert><name>{0}</name>'
        '<riskcode>3</riskcode><desc>Initial description</desc><solution>Fix it</solution>'
        '<reference>https://example.test/advisory</reference><instances><instance>'
        '<uri>https://app.test/{0}</uri><method>GET</method></instance></instances></alertitem>'
        .format(html.escape(name)) for name in names) + '</alerts></site></OWASPZAPReport>')


class FindingLifecycleTests(TestCase):
    scanners = ("gitleaks", "semgrepscan", "trivy", "trivy:filesystem", "trivy:secret", "trivy:config", "zap_scan")

    @classmethod
    def setUpTestData(cls):
        cls.org = Organization.objects.create(name="Lifecycle")
        role = UserRoles.objects.create(role="Analyst")
        cls.user = UserProfile.objects.create(email="lifecycle@example.test", name="Analyst",
                                              role=role, organization=cls.org)

    def setUp(self):
        self.client.force_login(self.user)
        self.project = ProjectDb.objects.create(project_name="main branch", organization=self.org)

    def models(self, scanner):
        return (WebScanResultsDb, WebScansDb) if scanner == "zap_scan" else (StaticScanResultsDb, StaticScansDb)

    def upload(self, scanner, report, expected_success=True):
        web = scanner == "zap_scan"
        module = {"gitleaks": "gitleaks_json_report_parser", "semgrepscan": "semgrep_json_report_parser",
                  "trivy": "trivy_json_report_parser"}.get(scanner.split(":")[0])
        module = "web_scanner.zap_xml_parser" if web else "staticscanner_parser." + module
        contents = report if web else json.dumps(report)
        with patch("scanners.scanner_parser." + module + ".email_sch_notify"):
            response = self.client.post(reverse("report_upload:upload"), {
                "project_id": self.project.uu_id, "scanner": scanner.split(":")[0], "target": "main",
                "file": SimpleUploadedFile("report.xml" if web else "report.json", contents.encode("utf-8")),
            })
        self.assertEqual(response.status_code, 302 if expected_success else 200)
        if expected_success:
            return self.models(scanner)[1].objects.filter(project=self.project).latest("pk")
        return response

    def assert_totals(self, model, opened, closed):
        findings = model.objects.filter(project=self.project)
        self.assertEqual(findings.filter(vuln_status="Open", false_positive="No").count(), opened)
        self.assertEqual(findings.filter(vuln_status="Closed", false_positive="No").count(), closed)
        self.assertEqual(scans_query.all_vuln_count_data(self.project.uu_id, "Open"), opened)
        self.assertEqual(scans_query.all_vuln(self.project.uu_id, "total"), opened)
        self.project.refresh_from_db()
        self.assertEqual((self.project.total_vuln, self.project.total_close), (opened, closed))

    def test_full_upload_open_close_reopen_and_empty_report_for_every_scanner(self):
        for scanner in self.scanners:
            with self.subTest(scanner=scanner):
                self.project = ProjectDb.objects.create(project_name=scanner, organization=self.org)
                model, scan_model = self.models(scanner)
                first = self.upload(scanner, make_report(scanner, ["A", "B"]))
                original_ids = set(model.objects.filter(project=self.project).values_list("vuln_id", flat=True))
                self.assert_totals(model, 2, 0)
                second = self.upload(scanner, make_report(scanner, ["B", "C", "C"]))
                self.assertEqual(model.objects.filter(project=self.project).count(), 3)
                self.assert_totals(model, 2, 1)
                second.refresh_from_db()
                self.assertEqual(second.total_vul, 2)
                self.upload(scanner, make_report(scanner, ["C"]))
                self.assert_totals(model, 1, 2)
                self.upload(scanner, make_report(scanner, ["A", "B", "C"]))
                self.assert_totals(model, 3, 0)
                self.assertTrue(original_ids.issubset(set(model.objects.filter(project=self.project).values_list("vuln_id", flat=True))))
                empty = self.upload(scanner, make_report(scanner, []))
                self.assert_totals(model, 0, 3)
                self.assertEqual(empty.total_vul, 0)
                self.upload(scanner, make_report(scanner, ["A", "B", "C"]))
                self.assert_totals(model, 3, 0)
                self.assertEqual(model.objects.filter(project=self.project).count(), 3)
                namespace = "webscanners" if scanner == "zap_scan" else "staticscanners"
                old = self.client.get(reverse(namespace + ":list_vuln"), {"scan_id": first.scan_id})
                self.assertEqual(len(old.context["all_vuln"]), 2)

    def test_original_fingerprint_fields_control_create_and_close(self):
        for scanner in ("gitleaks", "semgrepscan", "trivy", "zap_scan"):
            with self.subTest(scanner=scanner):
                self.project = ProjectDb.objects.create(project_name=scanner, organization=self.org)
                original = make_report(scanner, ["A"])
                self.upload(scanner, original)
                model, _ = self.models(scanner)
                finding = model.objects.get(project=self.project)
                identity, created_time = finding.vuln_id, finding.created_time
                changed = copy.deepcopy(original)
                if scanner == "gitleaks":
                    changed[0]["Message"] = "Updated commit message"
                elif scanner == "semgrepscan":
                    changed["results"][0]["extra"].update(message="Updated message", severity="WARNING", metadata={"references": ["https://example.test/new"]})
                elif scanner == "trivy":
                    changed["Results"][0]["Vulnerabilities"][0].update(Title="New title", FixedVersion="3", Severity="CRITICAL")
                else:
                    changed = changed.replace("Initial description", "Updated description").replace("<riskcode>3", "<riskcode>2").replace("https://example.test/advisory", "https://example.test/new")
                self.upload(scanner, changed)
                finding.refresh_from_db()
                self.assertEqual(finding.created_time, created_time)
                if scanner == "gitleaks":
                    # Commit message was never part of Gitleaks' original hash.
                    self.assertEqual(model.objects.filter(project=self.project).count(), 1)
                    self.assertEqual(model.objects.get(project=self.project).vuln_id, identity)
                    self.assert_totals(model, 1, 0)
                else:
                    self.assertEqual(model.objects.filter(project=self.project).count(), 2)
                    self.assertEqual(finding.vuln_status, "Closed")
                    self.assertNotEqual(model.objects.get(project=self.project, vuln_status="Open").vuln_id, identity)
                    self.assert_totals(model, 1, 1)
                    # Returning to the old payload reopens its original UUID.
                    self.upload(scanner, original)
                    finding.refresh_from_db()
                    self.assertEqual(finding.vuln_status, "Open")
                    self.assert_totals(model, 1, 1)

    def test_invalid_report_does_not_close_existing_findings(self):
        invalid = {"gitleaks": {}, "semgrepscan": {}, "trivy": {},
                   "zap_scan": '<unrelated><site name="https://app.test" /></unrelated>'}
        for scanner, report in invalid.items():
            with self.subTest(scanner=scanner):
                self.project = ProjectDb.objects.create(project_name=scanner, organization=self.org)
                self.upload(scanner, make_report(scanner, ["A"]))
                self.upload(scanner, report, expected_success=False)
                model, scan_model = self.models(scanner)
                self.assert_totals(model, 1, 0)
                self.assertEqual(scan_model.objects.filter(project=self.project).count(), 1)

    def test_semgrep_report_with_errors_does_not_auto_close_findings(self):
        self.upload("semgrepscan", make_report("semgrepscan", ["A"]))
        self.upload("semgrepscan", {"results": [], "errors": [{"type": "ParseError", "message": "Incomplete scan"}]}, expected_success=False)
        self.assert_totals(StaticScanResultsDb, 1, 0)

    def test_zap_upload_preserves_unicode(self):
        report = make_report("zap_scan", ["A"]).replace("Initial description", "Mô tả lỗ hổng")
        self.upload("zap_scan", report)
        self.assertEqual(WebScanResultsDb.objects.get(project=self.project).description, "Mô tả lỗ hổng")

    def test_semgrep_native_id_does_not_override_original_end_position_hash(self):
        report = make_report("semgrepscan", ["A"])
        report["results"][0]["extra"]["fingerprint"] = "stable-match-id"
        self.upload("semgrepscan", report)
        original = StaticScanResultsDb.objects.get(project=self.project)
        report["results"][0]["start"] = {"line": 100, "col": 10}
        report["results"][0]["end"] = {"line": 101, "col": 13}
        self.upload("semgrepscan", report)
        self.assertEqual(StaticScanResultsDb.objects.filter(project=self.project).count(), 2)
        original.refresh_from_db()
        self.assertEqual(original.vuln_status, "Closed")
        self.assertNotEqual(StaticScanResultsDb.objects.get(project=self.project, vuln_status="Open").vuln_id, original.vuln_id)
        self.assert_totals(StaticScanResultsDb, 1, 1)

    def test_existing_rows_match_dup_hash_with_or_without_the_retired_identity(self):
        for scanner in ("gitleaks", "semgrepscan", "trivy", "zap_scan"):
            for old_identity in ("", "a" * 64):
                with self.subTest(scanner=scanner, old_identity=bool(old_identity)):
                    self.project = ProjectDb.objects.create(project_name=scanner, organization=self.org)
                    report = make_report(scanner, ["A"])
                    first = self.upload(scanner, report)
                    model, _ = self.models(scanner)
                    finding = model.objects.get(project=self.project)
                    original_id, original_hash = finding.vuln_id, finding.dup_hash
                    # Simulate both pre-upgrade rows and rows produced by the
                    # intermediate stable-identity implementation. Missing history
                    # links must be remembered before moving the latest scan ID.
                    model.objects.filter(pk=finding.pk).update(identity_hash=old_identity,
                        false_positive="Yes", vuln_status="Closed", is_active=False,
                        note="Keep analyst review", jira_ticket="DEMO-1")
                    finding.scan_links.all().delete()
                    second = self.upload(scanner, report)
                    finding.refresh_from_db()
                    self.assertEqual(model.objects.filter(project=self.project).count(), 1)
                    self.assertEqual((finding.vuln_id, finding.dup_hash), (original_id, original_hash))
                    self.assertEqual((finding.false_positive, finding.vuln_status, finding.is_active), ("Yes", "Closed", False))
                    self.assertEqual((finding.note, finding.jira_ticket), ("Keep analyst review", "DEMO-1"))
                    self.assertEqual(set(finding.scan_links.values_list("scan__scan_id", flat=True)),
                                     {first.scan_id, second.scan_id})
                    self.assertEqual(second.total_vul, 0)
                    # Rollback of the identity policy never erases the old column.
                    self.assertEqual(finding.identity_hash, old_identity)

    def test_distinct_zap_instances_are_not_merged_by_site_and_rule(self):
        report = make_report("zap_scan", ["A"])
        alert = report[report.index("<alertitem>"):report.index("</alertitem>") + len("</alertitem>")]
        other = alert.replace("https://app.test/A", "https://app.test/another-path")
        report = report.replace("</alerts>", other + "</alerts>")
        first = self.upload("zap_scan", report)
        second = self.upload("zap_scan", report)
        self.assert_totals(WebScanResultsDb, 2, 0)
        self.assertEqual(WebScanResultsDb.objects.filter(project=self.project).count(), 2)
        self.assertEqual((first.total_vul, second.total_vul), (2, 2))
        self.assertTrue(all(len(json.loads(finding.instance)) == 1
                            for finding in WebScanResultsDb.objects.filter(project=self.project)))

    def test_other_project_and_other_scanner_are_not_closed(self):
        for scanner in ("gitleaks", "semgrepscan", "trivy", "zap_scan"):
            self.upload(scanner, make_report(scanner, ["A"]))
        first_project = self.project
        self.project = ProjectDb.objects.create(project_name="other branch", organization=self.org)
        self.upload("gitleaks", make_report("gitleaks", ["A"]))
        second_project = self.project
        self.project = first_project
        self.upload("gitleaks", [])
        self.assertEqual(StaticScanResultsDb.objects.filter(project=first_project, vuln_status="Open").count(), 2)
        self.assertEqual(WebScanResultsDb.objects.filter(project=first_project, vuln_status="Open").count(), 1)
        self.assertEqual(StaticScanResultsDb.objects.filter(project=second_project, vuln_status="Open").count(), 1)

    def test_late_invalid_item_rolls_back_whole_upload(self):
        for scanner in ("gitleaks", "semgrepscan", "trivy"):
            with self.subTest(scanner=scanner):
                self.project = ProjectDb.objects.create(project_name=scanner, organization=self.org)
                self.upload(scanner, make_report(scanner, ["A"]))
                broken = make_report(scanner, ["B"])
                if scanner == "gitleaks":
                    broken.append({"File": "broken.env"})
                elif scanner == "semgrepscan":
                    broken["results"].append({"path": "broken.js"})
                else:
                    broken["Results"][0]["Vulnerabilities"].append({"PkgName": "broken"})
                self.upload(scanner, broken, expected_success=False)
                model, scan_model = self.models(scanner)
                self.assert_totals(model, 1, 0)
                self.assertEqual(scan_model.objects.filter(project=self.project).count(), 1)

    def test_api_upload_and_lifecycle_for_four_scanners(self):
        self.client.logout()
        key = OrgAPIKey.objects.create(api_key="lifecycle-test-key", organization=self.org)
        for scanner in ("gitleaks", "semgrepscan", "trivy", "zap_scan"):
            with self.subTest(scanner=scanner):
                self.project = ProjectDb.objects.create(project_name=scanner, organization=self.org)
                model, _ = self.models(scanner)
                module = {"gitleaks": "staticscanner_parser.gitleaks_json_report_parser",
                          "semgrepscan": "staticscanner_parser.semgrep_json_report_parser",
                          "trivy": "staticscanner_parser.trivy_json_report_parser",
                          "zap_scan": "web_scanner.zap_xml_parser"}[scanner]
                for names, expected in ((["A", "B"], 2), (["B", "C"], 2), ([], 0), (["A"], 1)):
                    report = make_report(scanner, names)
                    contents = report if scanner == "zap_scan" else json.dumps(report)
                    with patch("scanners.scanner_parser." + module + ".email_sch_notify"):
                        response = self.client.post(reverse("test_api_upload"), {
                            "project_id": self.project.uu_id, "scanner": scanner, "scan_url": "build-id",
                            "filename": SimpleUploadedFile("report.xml" if scanner == "zap_scan" else "report.json", contents.encode()),
                        }, HTTP_X_API_KEY=key.api_key)
                    self.assertEqual(response.status_code, 200)
                    self.assertEqual(int(response.json()["result"]["total_vul"]), expected)
                    self.assertEqual(scans_query.all_vuln(self.project.uu_id, "total"), expected)
                self.assertEqual(model.objects.filter(project=self.project).count(), 3)

    def test_api_rejects_invalid_reports_and_other_organizations(self):
        key = OrgAPIKey.objects.create(api_key="invalid-report-test-key", organization=self.org)
        self.upload("gitleaks", make_report("gitleaks", ["A"]))
        self.client.logout()
        for scanner, contents in (("gitleaks", "{}"), ("semgrepscan", '{"results": [], "errors": [{}]}'),
                                  ("trivy", "{}"), ("zap_scan", "<broken>"), ("gitleaks", "not json")):
            response = self.client.post(reverse("test_api_upload"), {
                "project_id": self.project.uu_id, "scanner": scanner, "filename": contents,
            }, HTTP_X_API_KEY=key.api_key)
            self.assertEqual(response.status_code, 400)
        self.assert_totals(StaticScanResultsDb, 1, 0)
        self.assertEqual(StaticScansDb.objects.filter(project=self.project).count(), 1)
        other_org = Organization.objects.create(name="Other organization")
        key.organization = other_org
        key.save()
        response = self.client.post(reverse("test_api_upload"), {
            "project_id": self.project.uu_id, "scanner": "gitleaks", "filename": "[]",
        }, HTTP_X_API_KEY=key.api_key)
        self.assertEqual(response.status_code, 404)
        self.client.force_login(self.user)
        response = self.client.post(reverse("test_api_upload"), {
            "project_id": self.project.uu_id, "scanner": "gitleaks", "filename": "[]",
        }, HTTP_X_API_KEY=key.api_key)
        self.assertEqual(response.status_code, 403)

    def test_trivy_mixed_results_null_lists_and_multiple_secrets(self):
        report = make_report("trivy", ["A"])
        report["Results"] += make_report("trivy:filesystem", ["B"])["Results"]
        report["Results"] += make_report("trivy:secret", ["C", "D"])["Results"]
        report["Results"] += make_report("trivy:config", ["E"])["Results"]
        report["Results"].append({"Target": "empty", "Class": "lang-pkgs", "Vulnerabilities": None, "Secrets": None})
        self.upload("trivy", report)
        self.assert_totals(StaticScanResultsDb, 5, 0)

    def test_zap_multiple_sites_and_changed_instances(self):
        report = make_report("zap_scan", ["A"])
        other_site = report[report.index("<site "):report.index("</OWASPZAPReport>")].replace("app.test", "other.test")
        report = report.replace("</OWASPZAPReport>", other_site + "</OWASPZAPReport>")
        self.upload("zap_scan", report)
        self.assert_totals(WebScanResultsDb, 2, 0)
        self.assertEqual(set(WebScanResultsDb.objects.values_list("url", flat=True)), {"https://app.test", "https://other.test"})
        changed = report.replace("</instances>", "<instance><uri>https://app.test/extra</uri><method>POST</method></instance></instances>")
        self.upload("zap_scan", changed)
        self.assert_totals(WebScanResultsDb, 2, 2)
        self.assertEqual(WebScanResultsDb.objects.filter(project=self.project).count(), 4)
        opened = WebScanResultsDb.objects.filter(project=self.project, vuln_status="Open")
        self.assertTrue(all(len(json.loads(item.instance)) == 2 for item in opened))

    def test_false_positive_survives_absence_and_manual_closed_findings_reopen(self):
        for scanner in ("gitleaks", "semgrepscan", "trivy", "zap_scan"):
            with self.subTest(scanner=scanner):
                self.project = ProjectDb.objects.create(project_name=scanner, organization=self.org)
                self.upload(scanner, make_report(scanner, ["A"]))
                model, _ = self.models(scanner)
                finding = model.objects.get(project=self.project)
                namespace = "webscanners" if scanner == "zap_scan" else "staticscanners"
                self.client.post(reverse(namespace + ":vuln_mark"), {
                    "scan_id": finding.scan_id, "vuln_id": finding.vuln_id,
                    "false": "Yes", "status": "Open", "note": "Confirmed false alarm",
                })
                self.upload(scanner, make_report(scanner, []))
                self.upload(scanner, make_report(scanner, ["A"]))
                finding.refresh_from_db()
                self.assertEqual((finding.false_positive, finding.vuln_status), ("Yes", "Closed"))
                self.assertEqual(scans_query.all_vuln_count_data(self.project.uu_id, "false"), 1)
                self.assertEqual(scans_query.all_vuln(self.project.uu_id, "total"), 0)
                self.client.post(reverse(namespace + ":vuln_mark"), {
                    "scan_id": finding.scan_id, "vuln_id": finding.vuln_id,
                    "false": "No", "status": "Closed", "note": "Manually closed",
                })
                self.upload(scanner, make_report(scanner, ["A"]))
                finding.refresh_from_db()
                self.assertEqual((finding.false_positive, finding.vuln_status), ("No", "Open"))
                self.assertEqual(model.objects.filter(project=self.project).count(), 1)

    def test_suppressed_and_passing_results_are_not_open_findings(self):
        report = make_report("semgrepscan", ["A"])
        report["results"][0]["extra"]["is_ignored"] = True
        self.upload("semgrepscan", report)
        self.assert_totals(StaticScanResultsDb, 0, 0)
        report = make_report("trivy:config", ["A", "B"])
        report["Results"][0]["Misconfigurations"][0]["Status"] = "PASS"
        report["Results"][0]["Misconfigurations"][1]["Status"] = "EXCEPTION"
        self.upload("trivy", report)
        self.assert_totals(StaticScanResultsDb, 0, 0)

    def test_deleting_static_report_preserves_other_reports_and_triage(self):
        for scanner in ("gitleaks", "semgrepscan", "trivy"):
            with self.subTest(scanner=scanner):
                self.project = ProjectDb.objects.create(project_name=scanner, organization=self.org)
                first = self.upload(scanner, make_report(scanner, ["A"]))
                second = self.upload(scanner, make_report(scanner, ["A"]))
                finding = StaticScanResultsDb.objects.get(project=self.project)
                response = self.client.post(reverse("staticscanners:vuln_mark"), {
                    "scan_id": first.scan_id, "vuln_id": finding.vuln_id,
                    "false": "Yes", "status": "Open", "note": "From an older report",
                })
                self.assertEqual(response.status_code, 302)
                self.client.post(reverse("staticscanners:scan_delete"), {"scan_id": second.scan_id})
                finding.refresh_from_db()
                self.assertEqual(finding.scan_id, first.scan_id)
                self.assertEqual((finding.false_positive, finding.note), ("Yes", "From an older report"))
                old = self.client.get(reverse("staticscanners:list_vuln"), {"scan_id": first.scan_id})
                self.assertEqual(len(old.context["all_vuln"]), 1)
