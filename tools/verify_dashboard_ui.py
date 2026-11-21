r"""Optional browser smoke test against an isolated, temporary test database.

Run: .venv\Scripts\python.exe tools\verify_dashboard_ui.py
Requires Playwright and an installed Chrome (or ARCHERY_BROWSER_EXECUTABLE).
"""
import json
import os
from pathlib import Path
import sys
import uuid
from urllib.parse import urlencode

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)
os.environ["DJANGO_SETTINGS_MODULE"] = "archerysecurity.settings.test_dashboard"

import django
django.setup()

from django.conf import settings
from django.contrib.staticfiles.handlers import StaticFilesHandler
from django.test import Client, LiveServerTestCase
from django.test.utils import setup_databases, setup_test_environment, teardown_databases
from notifications.models import Notification
from notifications.signals import notify
from playwright.sync_api import sync_playwright

from dashboard.test_regressions import DashboardRegressionTests
from dashboard.views import trend_update
from projects.models import ProjectDb
from staticscanners.models import StaticScanResultsDb, StaticScansDb
from utility.finding_status import refresh_scan_counts
from webscanners.models import WebScanResultsDb, WebScansDb

settings.STATICFILES_DIRS = [str(ROOT / "templates" / "static")]


class PreviewServer(LiveServerTestCase):
    static_handler = StaticFilesHandler


def main():
    setup_test_environment()
    database = setup_databases(verbosity=0, interactive=False)
    started = False
    try:
        PreviewServer.setUpClass()
        started = True
        DashboardRegressionTests.setUpTestData()
        fixture = DashboardRegressionTests
        for scanner, web in (("gitleaks", False), ("Semgrep", False), ("Trivy", False), ("Zap", True)):
            scan_model, result_model = (WebScansDb, WebScanResultsDb) if web else (StaticScansDb, StaticScanResultsDb)
            scan = scan_model.objects.create(scan_id=uuid.uuid4(), scanner=scanner, project=fixture.project,
                                             organization=fixture.org, scan_status="100", total_dup=0)
            if scanner == "Semgrep":
                scan.import_warnings = [{"type": "PartialParsing", "level": "warn", "path": "view.html", "message": "Template syntax"}] * 10
                scan.save(update_fields=("import_warnings",))
            severities = ("Critical", "High", "Medium", "Low")
            if scanner in ("Semgrep", "Zap"):
                severities += ("Informational",)
            for severity in severities:
                finding = result_model.objects.create(scan_id=scan.scan_id, vuln_id=uuid.uuid4(), scanner=scanner,
                    title=scanner + " sample finding", severity=severity, false_positive="No",
                    vuln_status="Open", vuln_duplicate="No", project=fixture.project, organization=fixture.org)
                if scanner == "Semgrep" and severity == "High":
                    triage_url = "/staticscanners/list_vuln_info/?" + urlencode({
                        "scan_id": scan.scan_id, "scan_name": finding.title})
                    triage_id = str(finding.vuln_id)
                if scanner == "Zap" and severity == "High":
                    finding.instance = json.dumps([{"uri": "https://app.test", "evidence": evidence} for evidence in (
                        "First observation", '<img src=x onerror="window.evidenceExecuted=true">', "Third observation")])
                    finding.save(update_fields=("instance",))
                    zap_detail_url = "/webscanners/scan_details/?vuln_id=" + str(finding.vuln_id)
            result_model.objects.create(scan_id=scan.scan_id, vuln_id=uuid.uuid4(), scanner=scanner,
                title="Reviewed false alarm", severity="High", false_positive="Yes", vuln_status="Closed",
                is_active=False, vuln_duplicate="No", project=fixture.project, organization=fixture.org)
            refresh_scan_counts(result_model, scan_model, scan.scan_id, fixture.org)
        second_project = ProjectDb.objects.create(project_name="Second project", organization=fixture.org)
        StaticScanResultsDb.objects.create(project=second_project, organization=fixture.org,
            scan_id=uuid.uuid4(), vuln_id=uuid.uuid4(), scanner="gitleaks", title="Second project finding",
            severity="Medium", false_positive="No", vuln_status="Open", vuln_duplicate="No")
        trend_update()
        notify.send(fixture.project, recipient=fixture.user, verb="Semgrep report imported: Application demo - 4 open findings")
        notify.send(fixture.project, recipient=fixture.other_user, verb="Other user's private notification")
        client = Client()
        client.force_login(fixture.user)
        output = ROOT / ".artifacts" / "dashboard-ui"
        output.mkdir(parents=True, exist_ok=True)
        errors = []
        failures = []
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(
                executable_path=os.environ.get("ARCHERY_BROWSER_EXECUTABLE", r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
                headless=True,
            )
            context = browser.new_context(viewport={"width": 1440, "height": 1000})
            context.add_cookies([{"name": settings.SESSION_COOKIE_NAME,
                "value": client.cookies[settings.SESSION_COOKIE_NAME].value,
                "url": PreviewServer.live_server_url}])
            page = context.new_page()
            page.on("pageerror", lambda error: (errors.append(str(error)), print("JS ERROR: " + str(error), flush=True)))
            page.on("requestfailed", lambda request: (failures.append(request.url + " " + str(request.failure)), print("REQUEST FAILED: " + request.url, flush=True)))
            page.goto(PreviewServer.live_server_url + "/dashboard/", wait_until="networkidle")
            page.screenshot(path=str(output / "latest-page.png"), full_page=True)
            page.locator('.preloader').wait_for(state='hidden', timeout=10000)
            page.screenshot(path=str(output / "overview-desktop.png"), full_page=True)
            assert page.locator('.dashboard-stat-card').count() == 8
            assert page.locator('.dashboard-stat-card--medium .dashboard-stat-value').inner_text() == '5'
            assert page.locator('.dashboard-stat-card--low .dashboard-stat-value').inner_text() == '4'
            assert page.locator('.dashboard-stat-card--info .dashboard-stat-value').inner_text() == '2'
            assert page.locator('#data_table th', has_text='Informational').count() == 1
            assert page.evaluate("pie.data.labels") == ['Critical', 'High', 'Medium', 'Low', 'Informational']
            assert page.evaluate("pie.data.datasets[0].data") == [4, 4, 5, 4, 2]
            assert page.locator('.dashboard-scan-quality').count() == 0
            assert page.locator('.dashboard-scanner-summary').count() == 0
            assert page.locator('.notification-count').inner_text() == "1"
            page.locator('#notification-toggle').click()
            page.locator('.notification-item').wait_for(state='visible')
            assert "Other user's" not in page.locator('.notification-items').inner_text()
            page.locator('.notification-clear-button').click()
            page.wait_for_function("document.querySelector('.notification-count').hidden")
            page.goto(PreviewServer.live_server_url + "/dashboard/proj_data/?uu_id=" + str(fixture.project.uu_id), wait_until="networkidle")
            page.locator('.preloader').wait_for(state='hidden')
            assert page.locator('.dashboard-stat-card').count() == 8
            assert page.locator('.dashboard-stat-card--info .dashboard-stat-value').inner_text() == '2'
            assert page.evaluate("ProChart.data.datasets[0].data") == [4, 4, 4, 4, 2]
            assert page.locator('.dashboard-scan-quality').count() == 0
            assert page.locator('.dashboard-scanner-summary').is_visible()
            assert page.locator('.scanner-summary-table th', has_text='Scan coverage').count() == 0
            assert page.locator('.scanner-summary-table tr[data-scanner="semgrep"] td').nth(6).inner_text() == '1'
            for tab in page.locator('.scan-tabs [role=tab]').all():
                tab.click()
                assert tab.get_attribute('aria-selected') == 'true'
                assert page.locator('#' + tab.get_attribute('aria-controls')).is_visible()
            page.locator('#tab-static').click()
            assert page.locator('#scan-static th', has_text='Informational').count() == 1
            page.screenshot(path=str(output / "project-desktop.png"), full_page=True)
            page.set_viewport_size({"width": 390, "height": 844})
            page.reload(wait_until="networkidle")
            page.locator('.preloader').wait_for(state='hidden')
            assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth"), "Project overflows mobile viewport"
            page.screenshot(path=str(output / "project-mobile.png"), full_page=True)
            page.goto(PreviewServer.live_server_url + "/dashboard/", wait_until="networkidle")
            page.locator('.preloader').wait_for(state='hidden')
            assert page.locator('.dashboard-stat-card--medium').is_visible()
            assert page.locator('.dashboard-stat-card--low').is_visible()
            assert page.locator('.dashboard-scan-quality').count() == 0
            assert page.locator('.dashboard-scanner-summary').count() == 0
            assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth"), "Overview overflows mobile viewport"
            page.screenshot(path=str(output / "overview-mobile.png"), full_page=True)
            # Exercise the actual modal/form flow on one of several same-title rows.
            page.set_viewport_size({"width": 1440, "height": 1000})
            page.goto(PreviewServer.live_server_url + zap_detail_url, wait_until="networkidle")
            page.locator('[data-target="#collapseTwo"]').click()
            assert page.locator('tbody[id^="instance-"]').inner_text().count('Evidence ') == 3
            assert page.evaluate('window.evidenceExecuted === undefined')
            assert page.locator('tbody[id^="instance-"] img').count() == 0
            page.screenshot(path=str(output / "zap-evidence.png"), full_page=True)
            page.goto(PreviewServer.live_server_url + triage_url, wait_until="networkidle")
            page.locator('[data-target="#commentModal-' + triage_id + '"]').click()
            modal = page.locator('#commentModal-' + triage_id)
            modal.locator('[name="note"]').fill('Browser verification')
            modal.get_by_role('button', name='Save Note').click()
            page.wait_for_load_state('networkidle')
            page.goto(PreviewServer.live_server_url + "/dashboard/proj_data/?uu_id=" + str(fixture.project.uu_id), wait_until="networkidle")
            assert page.locator('.dashboard-stat-card--muted .dashboard-stat-value').inner_text() == '5'
            page.goto(PreviewServer.live_server_url + triage_url, wait_until="networkidle")
            page.locator('[data-target="#commentNoModal-' + triage_id + '"]').click()
            page.locator('#commentNoModal-' + triage_id).get_by_role('button', name='Save Note').click()
            page.wait_for_load_state('networkidle')
            page.goto(PreviewServer.live_server_url + "/dashboard/proj_data/?uu_id=" + str(fixture.project.uu_id), wait_until="networkidle")
            assert page.locator('.dashboard-stat-card--muted .dashboard-stat-value').inner_text() == '4'
            browser.close()
        assert Notification.objects.filter(recipient=fixture.other_user, unread=True).count() == 1
        result = {"javascript_errors": errors, "failed_requests": failures, "screenshots": str(output)}
        (output / "browser-check.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(json.dumps(result, indent=2))
        if errors or failures:
            raise SystemExit(1)
    finally:
        if started:
            PreviewServer.tearDownClass()
        teardown_databases(database, verbosity=0)


if __name__ == "__main__":
    main()
