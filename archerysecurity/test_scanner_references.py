import json
from types import SimpleNamespace
from unittest.mock import patch
import uuid
from xml.etree import ElementTree

from bs4 import BeautifulSoup
from django.test import TestCase
from django.urls import reverse

from projects.models import ProjectDb
from scanners.scanner_parser.staticscanner_parser import (
    gitleaks_json_report_parser as gitleaks,
    semgrep_json_report_parser as semgrep,
    trivy_json_report_parser as trivy,
)
from scanners.scanner_parser.web_scanner import zap_xml_parser as zap
from scanners.vuln_checker import build_fingerprint
from staticscanners.models import StaticScanResultsDb, StaticScansDb
from user_management.models import Organization, UserProfile, UserRoles
from webscanners.models import WebScanResultsDb, WebScansDb


class ScannerReferenceImportTests(TestCase):
    urls = ["https://example.test/advisory/CVE-TEST",
            "https://example.test/details?id=42&source=scan#details",
            "https://example.test/rule/test-rule",
            "https://example.test/shortlink/test-rule"]

    @classmethod
    def setUpTestData(cls):
        cls.org = Organization.objects.create(name="Reference imports")
        role = UserRoles.objects.create(role="Analyst")
        cls.user = UserProfile.objects.create(email="refs@example.test", name="Analyst",
                                              role=role, organization=cls.org)

    def setUp(self):
        self.project = ProjectDb.objects.create(project_name="Reference project", organization=self.org)
        self.request = SimpleNamespace(user=self.user, META={})
        self.client.force_login(self.user)

    def ingest(self, module, function, scanner, report, web=False):
        scan_model = WebScansDb if web else StaticScansDb
        scan = scan_model.objects.create(scan_id=uuid.uuid4(), scanner=scanner,
                                          project=self.project, organization=self.org)
        with patch.object(module, "email_sch_notify"):
            getattr(module, function)(report, self.project.pk, scan.scan_id, self.request)
        result_model = WebScanResultsDb if web else StaticScanResultsDb
        return result_model.objects.get(project=self.project, scanner=scanner)

    def assert_round_trip(self, module, function, scanner, report, expected, web=False):
        finding = self.ingest(module, function, scanner, report, web)
        field = "reference" if web else "references"
        namespace = "webscanners" if web else "staticscanners"
        self.assertEqual(json.loads(getattr(finding, field)), expected)
        identity = finding.vuln_id
        fingerprint = finding.dup_hash
        with patch(namespace + ".views.get_jira_projects", return_value=None):
            response = self.client.get(reverse(namespace + ":scan_details"), {"vuln_id": identity})
        self.assertEqual(response.status_code, 200)
        anchors = BeautifulSoup(response.content, "html.parser").select('.accordion a[target="_blank"]')
        self.assertEqual([item["href"] for item in anchors], expected)
        self.assertTrue(all("noopener" in item["rel"] for item in anchors))

        marked = self.client.post(reverse(namespace + ":vuln_mark"), {
            "vuln_id": identity, "scan_id": finding.scan_id,
            "false": "Yes", "status": "Open", "note": "Reviewed",
        })
        self.assertEqual(marked.status_code, 302)
        # Simulate an older imported row whose References field was never populated.
        type(finding).objects.filter(pk=finding.pk).update(**{field: "" if web else None})
        updated = self.ingest(module, function, scanner, report, web)
        self.assertEqual(updated.vuln_id, identity)
        self.assertEqual(updated.dup_hash, fingerprint)
        self.assertEqual((updated.false_positive, updated.vuln_status), ("Yes", "Closed"))
        self.assertEqual(json.loads(getattr(updated, field)), expected)

    def test_gitleaks_report_references_and_source_link(self):
        report = [{"RuleID": "test-rule", "File": "config.env", "StartLine": 1,
                   "Fingerprint": "test:config.env:1", "References": self.urls[:2] * 2,
                   "Link": self.urls[2], "Match": "https://secret.example.test/private"}]
        self.assert_round_trip(gitleaks, "gitleaks_report_json", "gitleaks", report, self.urls[:3])

    def test_gitleaks_without_reference_fields_does_not_invent_links(self):
        report = [{"RuleID": "test-rule", "File": "config.env", "StartLine": 1,
                   "Match": "https://secret.example.test/private"}]
        finding = self.ingest(gitleaks, "gitleaks_report_json", "gitleaks", report)
        self.assertEqual(json.loads(finding.references), [])

    def test_semgrep_metadata_references_and_rule_source(self):
        report = {"results": [{"check_id": "test-rule", "path": "app.js", "end": {"line": 2},
            "extra": {"message": "Fixture", "severity": "ERROR", "lines": "Fixture",
                      "references": self.urls[:1], "metadata": {
                          "references": self.urls[:2], "source": self.urls[2],
                          "source-rule-url": self.urls[1], "shortlink": self.urls[3]}}}]}
        self.assert_round_trip(semgrep, "semgrep_report_json", "Semgrep", report, self.urls)

    def test_semgrep_without_metadata_has_empty_references(self):
        report = {"results": [{"check_id": "test-rule", "path": "app.js", "start": {"line": 1, "col": 1},
                               "extra": {"metadata": None, "severity": "ERROR"}}]}
        finding = self.ingest(semgrep, "semgrep_report_json", "Semgrep", report)
        self.assertEqual(json.loads(finding.references), [])

    def test_trivy_vulnerability_secret_and_config_references(self):
        references = {"References": self.urls[:2] * 2, "PrimaryURL": self.urls[2]}
        reports = [
            {"ArtifactType": "container_image", "Results": [{"Target": "demo", "Class": "os-pkgs", "Type": "alpine",
                "Vulnerabilities": [{"VulnerabilityID": "CVE-TEST", "PkgName": "libtest", "InstalledVersion": "1",
                                      "FixedVersion": "2", "Title": "Fixture", "Description": "Fixture", "Severity": "HIGH", **references}]}]},
            {"ArtifactType": "filesystem", "Results": [{"Target": "config.env", "Class": "secret",
                "Secrets": [{"Title": "Fixture", "Severity": "HIGH", "Category": "test", "StartLine": 1, "EndLine": 1,
                             "Match": "Fixture", **references}]}]},
            {"ArtifactType": "filesystem", "Results": [{"Target": "Dockerfile", "Class": "config",
                "Misconfigurations": [{"Title": "Fixture", "Description": "Fixture", "Message": "Fixture", "Resolution": "Fix",
                    "Severity": "HIGH", "CauseMetadata": {"Code": [], "StartLine": 1, "EndLine": 1, "Resource": "app", "Provider": "docker"}, **references}]}]},
        ]
        for report in reports:
            with self.subTest(artifact=report["ArtifactType"], result_class=report["Results"][0]["Class"]):
                self.project = ProjectDb.objects.create(project_name="Trivy references", organization=self.org)
                self.assert_round_trip(trivy, "trivy_report_json", "Trivy", report, self.urls[:3])

    def test_zap_cdata_and_nested_html_references_keep_legacy_fingerprint(self):
        html = '<a href="%s">Advisory</a><p>%s</p>' % tuple(self.urls[:2])
        for reference_markup in ("<![CDATA[" + html + "]]>", html):
            with self.subTest(reference=reference_markup):
                self.project = ProjectDb.objects.create(project_name="ZAP references", organization=self.org)
                report = ElementTree.fromstring('<OWASPZAPReport><site name="https://app.test"><alerts><alertitem>'
                    '<alert>Test alert</alert><name>Test alert</name><riskcode>3</riskcode><desc>Fixture</desc>'
                    '<reference>' + reference_markup.replace('&source=', '&amp;source=') + '</reference>'
                    '</alertitem></alerts></site></OWASPZAPReport>')
                if reference_markup.startswith("<![CDATA["):
                    # A historical row stores the raw HTML in its identity hash.
                    legacy_raw = report.find('.//reference').text
                    WebScanResultsDb.objects.create(project=self.project, organization=self.org, scanner="Zap",
                        vuln_id=uuid.uuid4(), scan_id=uuid.uuid4(), title="Test alert", severity="High", url="https://app.test",
                        false_positive="Yes", vuln_status="Closed", vuln_duplicate="No", is_active=False, reference=legacy_raw,
                        dup_hash=build_fingerprint({"scanner": "Zap", "title": "Test alert", "severity": "High", "scan_url": "https://app.test",
                            "alert": "Test alert", "instance": [], "description": "Fixture", "reference": legacy_raw}))
                self.assert_round_trip(zap, "xml_parser", "Zap", report, self.urls[:2], web=True)
