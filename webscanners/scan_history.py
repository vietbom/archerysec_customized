"""Web report history compatibility helpers."""
from utility import scan_history
from webscanners.models import WebScanResultsDb


def findings_for_scan(scan_id, organization):
    return scan_history.findings_for_scan(WebScanResultsDb, scan_id, organization)


def remember_finding_scan(finding, scan_id):
    return scan_history.remember_finding_scan(finding, scan_id)


def delete_scans(scan_ids, organization):
    return scan_history.delete_scans(WebScanResultsDb, scan_ids, organization)
