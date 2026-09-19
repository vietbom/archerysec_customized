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


def _normalize_fingerprint_value(value):
    if isinstance(value, dict):
        return {
            str(key): _normalize_fingerprint_value(val)
            for key, val in sorted(value.items(), key=lambda item: str(item[0]))
        }
    if isinstance(value, (list, tuple)):
        return [_normalize_fingerprint_value(item) for item in value]
    if isinstance(value, set):
        return sorted(_normalize_fingerprint_value(item) for item in value)
    if value is None:
        return None
    if isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def build_fingerprint(payload):
    normalized = _normalize_fingerprint_value(payload)
    canonical = json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def reconcile_scan_results(model, project_id, scan_id, organization, scanner):
    current_hashes = set(
        model.objects.filter(
            project_id=project_id,
            scan_id=scan_id,
            scanner=scanner,
            organization=organization,
        )
        .exclude(dup_hash__isnull=True)
        .values_list("dup_hash", flat=True)
    )

    stale_results = model.objects.filter(
        project_id=project_id,
        scanner=scanner,
        organization=organization,
        vuln_status="Open",
        false_positive="No",
        vuln_duplicate="No",
    ).exclude(scan_id=scan_id)

    if current_hashes:
        stale_results = stale_results.exclude(dup_hash__in=current_hashes)

    stale_results.update(vuln_status="Closed", is_active=False)


def check_false_positive(title, severity, scan_url):
    return build_fingerprint({"title": title, "severity": severity, "scan_url": scan_url})
