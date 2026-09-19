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

import hashlib
import json
import uuid
from datetime import datetime

from archeryapi.models import OrgAPIKey
from dashboard.views import trend_update
from scanners.vuln_checker import build_fingerprint, reconcile_scan_results
from staticscanners.models import StaticScanResultsDb, StaticScansDb
from utility.email_notify import email_sch_notify

vul_col = ""
Target = ""
PkgName = ""
InstalledVersion = ""
FixedVersion = ""
Title = ""
Description = ""
Severity = ""
References = ""


def semgrep_report_json(data, project_id, scan_id, request):
    """

    :param data:
    :param project_id:
    :param scan_id:
    :return:
    """
    date_time = datetime.now()
    vul_col = ""

    vuln = data["results"]

    api_key = request.META.get("HTTP_X_API_KEY")
    key_object = OrgAPIKey.objects.filter(api_key=api_key).first()
    if str(request.user) == 'AnonymousUser':
        organization = key_object.organization
    else:
        organization = request.user.organization

    for vuln_data in vuln:
        try:
            check_id = vuln_data["check_id"]
        except Exception:
            check_id = "Not Found"

        try:
            path = vuln_data["path"]
        except Exception:
            path = "Not Found"

        # try:
        #     start = vuln_data["start"]
        # except Exception:
        #     start = "Not Found"

        try:
            end = vuln_data["end"]
        except Exception:
            end = "Not Found"

        try:
            message = vuln_data["extra"]["message"]
        except Exception:
            message = "Not Found"

        try:
            metavars = vuln_data["extra"]["metavars"]
        except Exception:
            metavars = "Not Found"

        try:
            metadata = vuln_data["extra"]["metadata"]
        except Exception:
            metadata = "Not Found"

        try:
            severity = vuln_data["extra"]["severity"]
        except Exception:
            severity = "Not Found"

        try:
            lines = vuln_data["extra"]["lines"]
        except Exception:
            lines = "Not Found"

        if severity == "ERROR":
            severity = "High"
            vul_col = "danger"

        elif severity == "WARNING":
            severity = "Medium"
            vul_col = "warning"

        elif severity == "INFORMATION":
            severity = "Low"
            vul_col = "info"

        vul_id = uuid.uuid4()

        duplicate_hash = build_fingerprint(
            {
                "scanner": "Semgrep",
                "check_id": check_id,
                "severity": severity,
                "path": path,
                "message": message,
                "metadata": metadata,
                "end": end,
                "lines": lines,
            }
        )

        existing_record = StaticScanResultsDb.objects.filter(
            project_id=project_id,
            dup_hash=duplicate_hash,
            scanner="Semgrep",
            organization=organization,
        ).first()

        if existing_record is not None:
            existing_record.scan_id = scan_id
            existing_record.date_time = date_time
            existing_record.title = check_id
            existing_record.severity_color = vul_col
            existing_record.vuln_status = "Open"
            existing_record.is_active = True
            existing_record.dup_hash = duplicate_hash
            existing_record.vuln_duplicate = "No"
            existing_record.false_positive = "No"
            existing_record.fileName = path
            existing_record.severity = severity
            existing_record.description = (
                str(message)
                + "\n\n"
                + str(check_id)
                + "\n\n"
                + str(end)
                + "\n\n"
                + str(metavars)
                + "\n\n"
                + str(metadata)
                + "\n\n"
                + str(lines)
            )
            existing_record.scanner = "Semgrep"
            existing_record.organization = organization
            existing_record.save()
            continue

        match_dup = StaticScanResultsDb.objects.filter(
            project_id=project_id,
            dup_hash=duplicate_hash,
            scanner="Semgrep",
            organization=organization,
        ).values("dup_hash")
        lenth_match = len(match_dup)

        if lenth_match == 0:
            duplicate_vuln = "No"

            false_p = StaticScanResultsDb.objects.filter(
                false_positive_hash=duplicate_hash,
                organization=organization,
            )
            fp_lenth_match = len(false_p)

            if fp_lenth_match == 1:
                false_positive = "Yes"
            else:
                false_positive = "No"

            save_all = StaticScanResultsDb(
                vuln_id=vul_id,
                scan_id=scan_id,
                date_time=date_time,
                project_id=project_id,
                title=check_id,
                severity_color=vul_col,
                vuln_status="Open",
                dup_hash=duplicate_hash,
                vuln_duplicate=duplicate_vuln,
                false_positive=false_positive,
                fileName=path,
                severity=severity,
                description=str(message)
                + "\n\n"
                + str(check_id)
                + "\n\n"
                + str(end)
                + "\n\n"
                + str(metavars)
                + "\n\n"
                + str(metadata)
                + "\n\n"
                + str(lines),
                scanner="Semgrep",
                organization=organization,
            )
            save_all.save()

        else:
            duplicate_vuln = "Yes"

            save_all = StaticScanResultsDb(
                vuln_id=vul_id,
                scan_id=scan_id,
                date_time=date_time,
                project_id=project_id,
                title=check_id,
                severity_color=vul_col,
                vuln_status="Duplicate",
                dup_hash=duplicate_hash,
                vuln_duplicate=duplicate_vuln,
                false_positive="Duplicate",
                fileName=path,
                severity=severity,
                description=str(message)
                + "\n\n"
                + str(check_id)
                + "\n\n"
                + str(end)
                + "\n\n"
                + str(metavars)
                + "\n\n"
                + str(metadata)
                + "\n\n"
                + str(lines),
                scanner="Semgrep",
                organization=organization,
            )
            save_all.save()

    reconcile_scan_results(
        StaticScanResultsDb, project_id, scan_id, organization, "Semgrep"
    )

    all_findbugs_data = StaticScanResultsDb.objects.filter(
        scan_id=scan_id, false_positive="No", organization=organization
    )

    duplicate_count = StaticScanResultsDb.objects.filter(
        scan_id=scan_id, vuln_duplicate="Yes", organization=organization
    )

    total_vul = len(all_findbugs_data)
    total_critical = len(all_findbugs_data.filter(severity="Critical"))
    total_high = len(all_findbugs_data.filter(severity="High"))
    total_medium = len(all_findbugs_data.filter(severity="Medium"))
    total_low = len(all_findbugs_data.filter(severity="Low"))
    total_duplicate = len(duplicate_count.filter(vuln_duplicate="Yes"))

    StaticScansDb.objects.filter(
        scan_id=scan_id, organization=organization
    ).update(
        total_vul=total_vul,
        date_time=date_time,
        critical_vul=total_critical,
        high_vul=total_high,
        medium_vul=total_medium,
        low_vul=total_low,
        total_dup=total_duplicate,
        scanner="Semgrep",
        organization=organization,
    )
    trend_update()
    subject = "Archery Tool Scan Status - semgrep Report Uploaded"
    message = (
        "semgrep Scanner has completed the scan "
        "  %s <br> Total: %s <br>High: %s <br>"
        "Medium: %s <br>Low %s"
        % ("semgrep", total_vul, total_high, total_medium, total_low)
    )

    email_sch_notify(subject=subject, message=message)


parser_header_dict = {
    "semgrepscan": {
        "displayName": "Semgrep Scanner",
        "dbtype": "StaticScans",
        "dbname": "Semgrep",
        "type": "JSON",
        "parserFunction": semgrep_report_json,
        "icon": "/static/tools/semgrep.svg",
    }
}
