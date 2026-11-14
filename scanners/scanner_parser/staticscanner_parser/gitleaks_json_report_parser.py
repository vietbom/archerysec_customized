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
VulnerabilityID = ""
PkgName = ""
InstalledVersion = ""
FixedVersion = ""
Title = ""
Description = ""
Severity = ""
References = ""


def gitleaks_report_json(data, project_id, scan_id, request):
    """

    :param data:
    :param project_id:
    :param scan_id:
    :return:
    """
    date_time = datetime.now()

    api_key = request.META.get("HTTP_X_API_KEY")
    key_object = OrgAPIKey.objects.filter(api_key=api_key).first()
    if str(request.user) == 'AnonymousUser':
        organization = key_object.organization
    else:
        organization = request.user.organization

    for issues_data in data or []:
        rule_id = (
            issues_data.get("RuleID")
            or issues_data.get("rule")
            or issues_data.get("Rule")
            or "Gitleaks finding"
        )
        file = issues_data.get("File") or issues_data.get("file") or "Not Found"
        start_line = issues_data.get("StartLine") or issues_data.get("line")
        line_label = str(start_line) if start_line is not None else "unknown"
        name = "%s in %s:%s" % (rule_id, file, line_label)
        severity = "High"
        vul_col = "danger"

        def display_value(value):
            if value is None:
                return "Not Found"
            if isinstance(value, (list, tuple)):
                return ", ".join(str(item) for item in value)
            return str(value)

        description = "<br>".join(
            [
                "Rule: " + display_value(rule_id),
                "Match: " + display_value(
                    issues_data.get("Match") or issues_data.get("offender")
                ),
                "Commit: " + display_value(
                    issues_data.get("Commit") or issues_data.get("commit")
                ),
                "Repository: " + display_value(
                    issues_data.get("Repo") or issues_data.get("repo")
                ),
                "Message: " + display_value(
                    issues_data.get("Message")
                    or issues_data.get("commitMessage")
                ),
                "Author: " + display_value(issues_data.get("Author") or issues_data.get("author")),
                "Email: " + display_value(issues_data.get("Email") or issues_data.get("email")),
                "Date: " + display_value(issues_data.get("Date") or issues_data.get("date")),
                "Tags: " + display_value(issues_data.get("Tags") or issues_data.get("tags")),
            ]
        )

        vul_id = uuid.uuid4()

        report_fingerprint = issues_data.get("Fingerprint")
        if report_fingerprint:
            fingerprint_payload = {
                "scanner": "gitleaks",
                "report_fingerprint": report_fingerprint,
            }
        else:
            fingerprint_payload = {
                "scanner": "gitleaks",
                "rule": rule_id,
                "file": file,
                "start_line": start_line,
                "commit": issues_data.get("Commit") or issues_data.get("commit"),
            }
        duplicate_hash = build_fingerprint(fingerprint_payload)

        existing_record = StaticScanResultsDb.objects.filter(
            project_id=project_id,
            dup_hash=duplicate_hash,
            scanner="gitleaks",
            organization=organization,
        ).first()

        if existing_record is not None:
            is_false_positive = existing_record.false_positive == "Yes"
            existing_record.scan_id = scan_id
            existing_record.date_time = date_time
            existing_record.title = name
            existing_record.description = description
            existing_record.fileName = file
            existing_record.severity = severity
            existing_record.severity_color = vul_col
            existing_record.vuln_status = "Closed" if is_false_positive else "Open"
            existing_record.is_active = not is_false_positive
            existing_record.dup_hash = duplicate_hash
            existing_record.vuln_duplicate = "No"
            existing_record.false_positive = "Yes" if is_false_positive else "No"
            existing_record.scanner = "gitleaks"
            existing_record.organization = organization
            existing_record.save()
            continue

        false_p = StaticScanResultsDb.objects.filter(
            false_positive_hash=duplicate_hash,
            organization=organization,
        )
        false_positive = "Yes" if false_p.exists() else "No"

        save_all = StaticScanResultsDb(
            vuln_id=vul_id,
            date_time=date_time,
            scan_id=scan_id,
            project_id=project_id,
            title=name,
            description=description,
            fileName=file,
            severity=severity,
            severity_color=vul_col,
            vuln_status="Open",
            dup_hash=duplicate_hash,
            vuln_duplicate="No",
            false_positive=false_positive,
            scanner="gitleaks",
            organization=organization,
        )
        save_all.save()

    reconcile_scan_results(
        StaticScanResultsDb, project_id, scan_id, organization, "gitleaks"
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

    StaticScansDb.objects.filter(scan_id=scan_id).update(
        date_time=date_time,
        total_vul=total_vul,
        critical_vul=total_critical,
        high_vul=total_high,
        medium_vul=total_medium,
        low_vul=total_low,
        total_dup=total_duplicate,
        scanner="gitleaks",
        organization=organization,
    )
    trend_update()
    subject = "Archery Tool Scan Status - GitLab Dependency Report Uploaded"
    message = (
        "Gitleaks Scanner has completed the scan "
        "  %s <br> Total: %s <br>High: %s <br>"
        "Medium: %s <br>Low %s"
        % (Target, total_vul, total_high, total_medium, total_low)
    )

    email_sch_notify(subject=subject, message=message)


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
