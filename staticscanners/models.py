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

from __future__ import unicode_literals

from django.db import models
from django.utils import timezone

from user_management.models import Organization, UserProfile

# Create your models here.


class StaticScansDb(models.Model):
    class Meta:
        db_table = "staticscansdb"
        verbose_name_plural = "Static Scans Db"

    project_name = models.TextField(blank=True, null=True)
    scan_id = models.UUIDField(blank=True)
    rescan_id = models.TextField(blank=True, null=True)
    scan_date = models.TextField(blank=True)
    scan_status = models.TextField(blank=True)
    import_warnings = models.JSONField(default=list, blank=True)
    project = models.ForeignKey(
        "projects.ProjectDb", on_delete=models.CASCADE, null=True
    )
    total_vul = models.IntegerField(blank=True, null=True)
    critical_vul = models.IntegerField(blank=True, null=True)
    high_vul = models.IntegerField(blank=True, null=True)
    medium_vul = models.IntegerField(blank=True, null=True)
    low_vul = models.IntegerField(blank=True, null=True)
    info_vul = models.IntegerField(blank=True, null=True)
    date_time = models.DateTimeField(blank=True, null=True)
    rescan = models.TextField(blank=True, null=True)
    total_dup = models.TextField(blank=True, null=True)
    scanner = models.CharField(max_length=256, null=True)
    updated_time = models.DateTimeField(auto_now=True, blank=True, null=True)
    created_time = models.DateTimeField(
        auto_now=True,
        blank=True,
    )
    created_by = models.ForeignKey(
        UserProfile,
        on_delete=models.SET_NULL,
        null=True,
        related_name="static_scan_db_created",
    )
    updated_by = models.ForeignKey(
        UserProfile,
        related_name="static_scan_db_updated",
        on_delete=models.SET_NULL,
        null=True,
    )
    is_active = models.BooleanField(default=True)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, default=1)


class StaticScanResultsDb(models.Model):
    class Meta:
        db_table = "staticscanresultsdb"
        verbose_name_plural = "Static Scans Data"
        constraints = [models.UniqueConstraint(
            fields=("organization", "project", "scanner", "identity_hash"),
            condition=~models.Q(identity_hash=""), name="unique_static_finding_identity",
        )]

    scan_id = models.UUIDField(blank=True)
    rescan_id = models.TextField(blank=True, null=True)
    project = models.ForeignKey(
        "projects.ProjectDb", on_delete=models.CASCADE, null=True
    )
    date_time = models.DateTimeField(blank=True, null=True)
    vuln_id = models.UUIDField(blank=True)
    false_positive = models.TextField(null=True, blank=True)
    severity_color = models.TextField(blank=True)
    dup_hash = models.TextField(null=True, blank=True)
    identity_hash = models.CharField(max_length=64, blank=True, default="", db_index=True)
    identity_version = models.PositiveSmallIntegerField(default=0)
    vuln_duplicate = models.TextField(null=True, blank=True)
    false_positive_hash = models.TextField(null=True, blank=True)
    vuln_status = models.TextField(null=True, blank=True)
    jira_ticket = models.TextField(null=True, blank=True)
    title = models.TextField(blank=True, null=True)
    severity = models.TextField(blank=True, null=True)
    description = models.TextField(blank=True, null=True)
    references = models.TextField(blank=True, null=True)
    fileName = models.TextField(blank=True, null=True)
    filePath = models.TextField(blank=True, null=True)
    solution = models.TextField(blank=True)
    scanner = models.TextField(blank=True)
    note = models.TextField(null=True, blank=True)
    updated_time = models.DateTimeField(auto_now=True, blank=True, null=True)
    created_time = models.DateTimeField(
        auto_now=True,
        blank=True,
    )
    created_by = models.ForeignKey(
        UserProfile,
        on_delete=models.SET_NULL,
        null=True,
        related_name="static_scan_result_db_created",
    )
    updated_by = models.ForeignKey(
        UserProfile,
        related_name="static_scan_result_db_updated",
        on_delete=models.SET_NULL,
        null=True,
    )
    is_active = models.BooleanField(default=True)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, default=1)


class StaticScanFinding(models.Model):
    scan = models.ForeignKey(StaticScansDb, on_delete=models.CASCADE, related_name="finding_links")
    finding = models.ForeignKey(StaticScanResultsDb, on_delete=models.CASCADE, related_name="scan_links")
    observed_severity = models.CharField(max_length=32, blank=True, default="")

    class Meta:
        constraints = [models.UniqueConstraint(fields=("scan", "finding"), name="unique_static_scan_finding")]
