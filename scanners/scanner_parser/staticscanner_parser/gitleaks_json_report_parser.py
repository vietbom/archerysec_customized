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
from scanners.report_formats import gitleaks_report
from staticscanners.models import StaticScanResultsDb, StaticScansDb
from utility.email_notify import email_sch_notify


def gitleaks_report_json(data, project_id, scan_id, request):
    """Import a validated native report as a complete project/branch snapshot."""
    findings = gitleaks_report(data)
    scan = import_findings(findings, StaticScanResultsDb, StaticScansDb,
                           project_id, scan_id, request, 'gitleaks')
    email_sch_notify(subject="Archery Tool Scan Status - gitleaks Report Uploaded",
                     message="gitleaks report imported. Open findings: %s" % scan.total_vul)
    return scan


parser_header_dict = {
    "gitleaks": {
        "displayName": "Gitleaks Scanner",
        "dbtype": "StaticScans",
        "dbname": "gitleaks",
        "type": "JSON",
        "parserFunction": gitleaks_report_json,
        "icon": "/static/tools/gitleaks.png",
    }
}
