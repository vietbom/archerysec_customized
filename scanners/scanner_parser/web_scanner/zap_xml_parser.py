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

import ast
import hashlib
import json
import re
import uuid
from datetime import datetime

from dashboard.views import trend_update
from scanners.vuln_checker import (
    build_fingerprint,
    check_false_positive,
    reconcile_scan_results,
)
from utility.email_notify import email_sch_notify
from webscanners.models import WebScanResultsDb, WebScansDb
from archeryapi.models import OrgAPIKey

vul_col = ""
title = ""
risk = ""
reference = ""
url = ""
solution = ""
instance = ""
alert = ""
desc = ""
riskcode = ""
vuln_id = ""
false_positive = ""
duplicate_hash = ""
duplicate_vuln = ""
scan_url = ""


def xml_parser(root, project_id, scan_id, request):
    """
    ZAP Proxy scanner xml report parser.
    :param root:
    :param project_id:
    :param scan_id:
    :return:
    """
    api_key = request.META.get("HTTP_X_API_KEY")
    key_object = OrgAPIKey.objects.filter(api_key=api_key).first()
    if str(request.user) == 'AnonymousUser':
        organization = key_object.organization
    else:
        organization = request.user.organization
    date_time = datetime.now()
    site = next(
        (element for element in root.iter("site") if element.get("name")),
        None,
    )
    if site is None:
        raise ValueError("ZAP report does not contain a named site element")
    scan_url = site.get("name")

    for alert_item in root.iter("alertitem"):
        alert_name = "NA"
        title = "NA"
        solution = "NA"
        reference = "NA"
        riskcode = "NA"
        desc = "NA"
        instances_data = []

        for element in alert_item:
            if element.tag == "alert":
                alert_name = element.text or "NA"
            elif element.tag == "name":
                title = element.text or "NA"
            elif element.tag == "solution":
                solution = element.text or "NA"
            elif element.tag == "reference":
                reference = element.text or "NA"
            elif element.tag == "riskcode":
                riskcode = element.text or "NA"
            elif element.tag == "desc":
                desc = element.text or "NA"
            elif element.tag == "instances":
                for instance_element in element:
                    instance_data = {}
                    for value_element in instance_element:
                        value = re.sub(r"<[^>]*>", " ", str(value_element.text))
                        instance_data[value_element.tag] = (
                            "NA" if value == "None" else value
                        )
                    instances_data.append(instance_data)

        severity_by_riskcode = {
            "4": ("Critical", "critical"),
            "3": ("High", "danger"),
            "2": ("Medium", "warning"),
            "1": ("Low", "info"),
        }
        risk, vul_col = severity_by_riskcode.get(riskcode, ("Low", "info"))
        duplicate_hash = build_fingerprint(
            {
                "scanner": "Zap",
                "title": title,
                "severity": risk,
                "scan_url": scan_url,
                "alert": alert_name,
                "instance": instances_data,
                "description": desc,
                "reference": reference,
            }
        )
        false_positive_hash = hashlib.sha256(
            (str(title) + str(scan_url) + str(risk)).encode("utf-8")
        ).hexdigest()
        existing_record = WebScanResultsDb.objects.filter(
            project_id=project_id,
            dup_hash=duplicate_hash,
            scanner="Zap",
            organization=organization,
        ).first()
        is_false_positive = WebScanResultsDb.objects.filter(
            project_id=project_id,
            scanner="Zap",
            organization=organization,
            false_positive_hash=false_positive_hash,
            false_positive="Yes",
        ).exists()
        if existing_record is not None:
            is_false_positive = (
                is_false_positive or existing_record.false_positive == "Yes"
            )
            existing_record.scan_id = scan_id
            existing_record.date_time = date_time
            existing_record.url = scan_url
            existing_record.title = title
            existing_record.solution = solution
            existing_record.instance = json.dumps(instances_data, ensure_ascii=False)
            existing_record.reference = reference
            existing_record.description = desc
            existing_record.severity = risk
            existing_record.severity_color = vul_col
            existing_record.false_positive = "Yes" if is_false_positive else "No"
            existing_record.false_positive_hash = (
                false_positive_hash
                if is_false_positive
                else existing_record.false_positive_hash
            )
            existing_record.vuln_status = "Closed" if is_false_positive else "Open"
            existing_record.is_active = not is_false_positive
            existing_record.vuln_duplicate = "No"
            existing_record.save()
            continue

        data_store = WebScanResultsDb(
            vuln_id=uuid.uuid4(),
            severity_color=vul_col,
            scan_id=scan_id,
            date_time=date_time,
            project_id=project_id,
            url=scan_url,
            title=title,
            solution=solution,
            instance=json.dumps(instances_data, ensure_ascii=False),
            reference=reference,
            description=desc,
            severity=risk,
            false_positive="Yes" if is_false_positive else "No",
            false_positive_hash=false_positive_hash if is_false_positive else None,
            jira_ticket="NA",
            vuln_status="Closed" if is_false_positive else "Open",
            dup_hash=duplicate_hash,
            vuln_duplicate="No",
            is_active=not is_false_positive,
            scanner="Zap",
            organization=organization,
        )
        data_store.save()

    reconcile_scan_results(WebScanResultsDb, project_id, scan_id, organization, "Zap")

    zap_all_vul = WebScanResultsDb.objects.filter(
        scan_id=scan_id, false_positive="No", organization=organization
    )

    duplicate_count = WebScanResultsDb.objects.filter(
        scan_id=scan_id, vuln_duplicate="Yes", organization=organization
    )

    total_critical = len(zap_all_vul.filter(severity="Critical"))
    total_high = len(zap_all_vul.filter(severity="High"))
    total_medium = len(zap_all_vul.filter(severity="Medium"))
    total_low = len(zap_all_vul.filter(severity="Low"))
    total_info = len(zap_all_vul.filter(severity="Informational"))
    total_duplicate = len(duplicate_count.filter(vuln_duplicate="Yes"))
    total_vul = total_high + total_medium + total_low + total_info

    WebScansDb.objects.filter(scan_id=scan_id).update(
        total_vul=total_vul,
        date_time=date_time,
        critical_vul=total_critical,
        high_vul=total_high,
        medium_vul=total_medium,
        low_vul=total_low,
        info_vul=total_info,
        total_dup=total_duplicate,
        scan_url=scan_url,
        organization=organization,
    )
    if total_vul == total_duplicate:
        WebScansDb.objects.filter(scan_id=scan_id).update(
            total_vul=total_vul,
            date_time=date_time,
            high_vul=total_high,
            medium_vul=total_medium,
            low_vul=total_low,
            total_dup=total_duplicate,
            organization=organization,
        )

    trend_update()

    subject = "Archery Tool Scan Status - ZAP Report Uploaded"
    message = (
        "ZAP Scanner has completed the scan "
        "  %s <br> Total: %s <br>High: %s <br>"
        "Medium: %s <br>Low %s"
        % (scan_url, total_vul, total_high, total_medium, total_low)
    )

    email_sch_notify(subject=subject, message=message)


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
