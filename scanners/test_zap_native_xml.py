"""ZAP 2.17 traditional XML: target sites must not include insight metadata."""
import copy
import json
from unittest.mock import patch
from xml.etree import ElementTree

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from django.urls import reverse

from archeryapi.models import OrgAPIKey
from projects.models import ProjectDb
from scanners.report_formats import zap_report
from user_management.models import Organization, UserProfile, UserRoles
from webscanners.models import WebScanResultsDb, WebScansDb


def native_report():
    # Based on the user's two complete alert examples and ZAP's official
    # traditional-xml template. This is a regression fixture, not the full scan.
    return ElementTree.fromstring('''<OWASPZAPReport programName="ZAP" version="2.17.0"
        generated="Sat, 21 Nov 2026 14:33:28" created="2026-11-21T14:33:28.149280912Z">
      <site name="http://nodegoat-dev:4000" host="nodegoat-dev" port="4000" ssl="false">
        <alerts>
          <alertitem>
            <pluginid>10055</pluginid><alertRef>10055-13</alertRef>
            <alert>CSP: Failure to Define Directive with No Fallback</alert>
            <name>CSP: Failure to Define Directive with No Fallback</name>
            <riskcode>2</riskcode><confidence>3</confidence><riskdesc>Medium (High)</riskdesc>
            <desc><p>The Content Security Policy fails to define a directive.</p></desc>
            <instances/><count>5</count><systemic>true</systemic>
            <solution><p>Set the Content-Security-Policy header.</p></solution>
            <reference><p>https://www.w3.org/TR/CSP/</p><p>https://caniuse.com/#search=content+security+policy</p></reference>
            <cweid>693</cweid><wascid>15</wascid><sourceid>87</sourceid>
          </alertitem>
          <alertitem>
            <pluginid>10038</pluginid><alertRef>10038-1</alertRef>
            <alert>Content Security Policy (CSP) Header Not Set</alert>
            <name>Content Security Policy (CSP) Header Not Set</name><riskcode>2</riskcode>
            <desc><p>Content Security Policy is an added layer of security.</p></desc>
            <instances>
              <instance><uri>http://nodegoat-dev:4000</uri><nodeName>http://nodegoat-dev:4000</nodeName>
                <method>GET</method><param/><attack/><evidence/><otherinfo/></instance>
              <instance><uri>http://nodegoat-dev:4000/login</uri><nodeName>http://nodegoat-dev:4000/login</nodeName>
                <method>GET</method><param/><attack/><evidence/><otherinfo/></instance>
            </instances>
            <count>2</count><systemic>true</systemic>
            <reference><p>https://www.w3.org/TR/CSP/</p></reference>
          </alertitem>
        </alerts>
      </site>
      <insights><insight><level>INFO</level><reason>Test insight</reason>
        <site>http://nodegoat-dev:4000</site><key>test.insight</key>
        <description>Scan metadata</description><statistic>53</statistic>
      </insight></insights>
      <stoppingInsight><level>INFO</level><site>http://nodegoat-dev:4000</site>
        <key>test.stopping</key><description>Metadata only</description>
      </stoppingInsight>
    </OWASPZAPReport>''')


class ZapNativeXmlTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.org = Organization.objects.create(name="ZAP XML compatibility")
        cls.user = UserProfile.objects.create(email="zap-native@example.test", name="Analyst",
            role=UserRoles.objects.create(role="Analyst"), organization=cls.org)
        cls.key = OrgAPIKey.objects.create(api_key="zap-native-test-key", organization=cls.org)

    def setUp(self):
        self.project = ProjectDb.objects.create(project_name="NodeGoat develop", organization=self.org)

    def upload(self, root, status=200):
        with patch("scanners.scanner_parser.web_scanner.zap_xml_parser.email_sch_notify"):
            response = self.client.post(reverse("test_api_upload"), {
                "project_id": self.project.uu_id, "scanner": "zap_scan", "scan_url": "http://nodegoat-dev:4000",
                "filename": SimpleUploadedFile("zap-report-39-dev.xml", ElementTree.tostring(root),
                                               content_type="application/xml"),
            }, HTTP_X_API_KEY=self.key.api_key)
        self.assertEqual(response.status_code, status, response.content[:1000])
        return response

    def test_api_imports_named_target_despite_unnamed_insight_sites_and_keeps_history(self):
        root = native_report()
        first = self.upload(root).json()
        self.assertEqual(int(first["result"]["total_vul"]), 3)
        self.assertEqual(int(first["result"]["total_medium"]), 3)
        records = WebScanResultsDb.objects.filter(project=self.project)
        original_ids = set(records.values_list("vuln_id", flat=True))
        systemic = records.get(title="CSP: Failure to Define Directive with No Fallback")
        self.assertEqual(json.loads(systemic.instance), [])
        self.assertIn("<p>", systemic.description)
        self.assertIn("https://www.w3.org/TR/CSP/", systemic.reference)
        second = self.upload(root).json()
        self.assertEqual(set(records.values_list("vuln_id", flat=True)), original_ids)
        self.assertEqual(WebScansDb.objects.filter(project=self.project).count(), 2)
        self.client.force_login(self.user)
        for scan_id in (first["scan_id"], second["scan_id"]):
            listing = self.client.get(reverse("webscanners:list_vuln"), {"scan_id": scan_id})
            self.assertEqual(len(listing.context["all_vuln"]), 3)

    def test_legacy_hash_and_identity_are_unchanged_by_insight_metadata(self):
        root = native_report()
        plain = copy.deepcopy(root)
        plain.remove(plain.find("insights"))
        plain.remove(plain.find("stoppingInsight"))
        before = zap_report(plain)[0]
        after = zap_report(root)[0]
        self.assertEqual([(f.duplicate_hash, f.identity_hash) for f in before],
                         [(f.duplicate_hash, f.identity_hash) for f in after])

    def test_alert_tags_in_metadata_are_not_imported_as_findings(self):
        root = native_report()
        # Both the report and target can carry additional metadata in XML-plus.
        site = root.find("site")
        stats = ElementTree.SubElement(site, "statistics")
        nested_site = ElementTree.SubElement(stats, "site")
        ElementTree.SubElement(nested_site, "alertitem")
        findings, url = zap_report(root)
        self.assertEqual((len(findings), url), (3, "http://nodegoat-dev:4000"))

    def test_invalid_real_sites_roll_back_and_cannot_close_existing_findings(self):
        self.upload(native_report())
        for invalid in (
            '<OWASPZAPReport><insights><insight><site>http://nodegoat-dev:4000</site></insight></insights></OWASPZAPReport>',
            '<OWASPZAPReport><site host="nodegoat-dev"><alerts/></site></OWASPZAPReport>',
            '<OWASPZAPReport><site name="http://nodegoat-dev:4000"/></OWASPZAPReport>',
            '<OWASPZAPReport><site name="http://nodegoat-dev:4000"><alerts/></site><site><alerts/></site></OWASPZAPReport>',
        ):
            with self.subTest(xml=invalid):
                self.upload(ElementTree.fromstring(invalid), status=400)
                self.assertEqual(WebScansDb.objects.filter(project=self.project).count(), 1)
                self.assertEqual(WebScanResultsDb.objects.filter(project=self.project, vuln_status="Open").count(), 3)

    def test_empty_valid_target_closes_and_later_report_reopens_without_losing_fp(self):
        root = native_report()
        self.upload(root)
        records = WebScanResultsDb.objects.filter(project=self.project)
        fp = records.get(title="CSP: Failure to Define Directive with No Fallback")
        self.client.force_login(self.user)
        marked = self.client.post(reverse("webscanners:vuln_mark"), {
            "scan_id": fp.scan_id, "vuln_id": fp.vuln_id,
            "false": "Yes", "status": "Closed", "note": "Verified false alarm",
        })
        self.assertEqual(marked.status_code, 302)
        empty = native_report()
        empty.find("site/alerts").clear()
        self.upload(empty)
        self.assertEqual(records.filter(vuln_status="Open").count(), 0)
        result = self.upload(root).json()
        self.assertEqual(int(result["result"]["total_vul"]), 2)
        self.assertEqual(records.count(), 3)
        self.assertEqual(records.filter(vuln_status="Open").count(), 2)
        fp.refresh_from_db()
        self.assertEqual((fp.false_positive, fp.vuln_status, fp.note), ("Yes", "Closed", "Verified false alarm"))
