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
    global vul_col, risk, reference, url, solution, instance, alert, desc, riskcode, vuln_id, false_positive, duplicate_hash, duplicate_vuln, scan_url, title

    for child in root:
        d = child.attrib
        scan_url = d["name"]

    for alert in root.iter("alertitem"):
        inst = []
        for vuln in alert:
            vuln_id = uuid.uuid4()
            if vuln.tag == "alert":
                alert = vuln.text
                if alert is None:
                    alert = "NA"
            if vuln.tag == "name":
                title = vuln.text
                if title is None:
                    title = "NA"
            if vuln.tag == "solution":
                solution = vuln.text
                if solution is None:
                    solution = "NA"
            if vuln.tag == "reference":
                reference = vuln.text
                if reference is None:
                    reference = "NA"
            if vuln.tag == "riskcode":
                riskcode = vuln.text
                if riskcode is None:
                    riskcode = "NA"
            for instances in vuln:
                for ii in instances:
                    instance = {}
                    dd = re.sub(r"<[^>]*>", " ", str(ii.text))
                    if dd == "None":
                        dd = "NA"
                    instance[ii.tag] = dd
                    inst.append(instance)

            if vuln.tag == "desc":
                desc = vuln.text
                if desc is None:
                    desc = "NA"

            if riskcode == "4":
                vul_col = "critical"
                risk = "Critical"
            elif riskcode == "3":
                vul_col = "danger"
                risk = "High"
            elif riskcode == "2":
                vul_col = "warning"
                risk = "Medium"
            elif riskcode == "1":
                vul_col = "info"
                risk = "Low"
            else:
                vul_col = "info"
                risk = "Low"
        if title == "None":
            print(title)
        else:
            duplicate_hash = build_fingerprint(
                {
                    "scanner": "Zap",
                    "title": title,
                    "severity": risk,
                    "scan_url": scan_url,
                    "alert": alert,
                    "instance": inst,
                    "description": desc,
                    "reference": reference,
                }
            )
            match_dup = (
                WebScanResultsDb.objects.filter(
                    dup_hash=duplicate_hash, organization=organization
                )
                .values("dup_hash")
                .distinct()
            )
            lenth_match = len(match_dup)

            existing_record = WebScanResultsDb.objects.filter(
                project_id=project_id,
                dup_hash=duplicate_hash,
                organization=organization,
            ).first()

            if existing_record is not None:
                existing_record.scan_id = scan_id
                existing_record.date_time = date_time
                existing_record.url = scan_url
                existing_record.title = title
                existing_record.solution = solution
                existing_record.instance = inst
                existing_record.reference = reference
                existing_record.description = desc
                existing_record.severity = risk
                existing_record.severity_color = vul_col
                existing_record.false_positive = "No"
                existing_record.vuln_status = "Open"
                existing_record.is_active = True
                existing_record.dup_hash = duplicate_hash
                existing_record.vuln_duplicate = "No"
                existing_record.scanner = "Zap"
                existing_record.organization = organization
                existing_record.save()
                continue

            if lenth_match == 0:
                duplicate_vuln = "No"
                vuln_status = "Open"
            else:
                duplicate_vuln = "Yes"
                false_positive = "Duplicate"
                vuln_status = "Duplicate"

            data_store = WebScanResultsDb(
                vuln_id=vuln_id,
                severity_color=vul_col,
                scan_id=scan_id,
                date_time=date_time,
                project_id=project_id,
                url=scan_url,
                title=title,
                solution=solution,
                instance=inst,
                reference=reference,
                description=desc,
                severity=risk,
                false_positive=false_positive,
                jira_ticket="NA",
                vuln_status=vuln_status,
                dup_hash=duplicate_hash,
                vuln_duplicate=duplicate_vuln,
                scanner="Zap",
                organization=organization,
            )

            data_store.save()

            false_p = WebScanResultsDb.objects.filter(
                false_positive_hash=duplicate_hash,
                organization=organization,
            )
            fp_lenth_match = len(false_p)

            if fp_lenth_match == 1:
                false_positive = "Yes"
            else:
                false_positive = "No"

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
