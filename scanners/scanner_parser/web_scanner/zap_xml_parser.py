# -*- coding: utf-8 -*-
#                    _
#     /\            | |
#    /  \   _ __ ___| |__   ___ _ __ _   _
#   / /\ \ | '__/ __| '_ \ / _ \ '__| | | |
#  / ____ \| | | (__| | | |  __/ |  | |_| |
# /_/    \_\_|  \___|_| |_|\___|_|   \__, |
#                                     __/ |
#                                    |___/
# Copyright (C) 2017 Anand Tiwari
#
# Email:   anandtiwarics@gmail.com
# Twitter: @anandtiwarics
#
# This file is part of ArcherySec Project.
from scanners.finding_lifecycle import import_findings
from scanners.report_formats import zap_report
from webscanners.models import WebScanResultsDb, WebScansDb
from utility.email_notify import email_sch_notify


def xml_parser(data, project_id, scan_id, request):
    """Import a validated native report as a complete project/branch snapshot."""
    findings, scan_url = zap_report(data)
    scan = import_findings(findings, WebScanResultsDb, WebScansDb,
                           project_id, scan_id, request, 'Zap', scan_url=scan_url)
    email_sch_notify(subject="Archery Tool Scan Status - Zap Report Uploaded",
                     message="Zap report imported. Open findings: %s" % scan.total_vul)
    return scan


parser_header_dict = {
    "zap_scan": {
        "displayName": "ZAP Scanner",
        "dbtype": "WebScans",
        "dbname": "Zap",
        "type": "XML",
        "parserFunction": xml_parser,
        "icon": "/static/tools/zap.png",
    }
}
