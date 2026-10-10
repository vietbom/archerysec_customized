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


class jirasetting(models.Model):
    setting_id = models.UUIDField(blank=True, null=True)
    jira_server = models.TextField(blank=True, null=True)
    jira_username = models.TextField(blank=True, null=True)
    jira_password = models.TextField(blank=True, null=True)
    jira_project_id = models.CharField(max_length=64, blank=True, null=True)
    jira_issue_type = models.CharField(max_length=64, default="Bug")
    created_time = models.DateTimeField(
        auto_now=True,
        blank=True,
    )
    created_by = models.ForeignKey(
        UserProfile,
        on_delete=models.SET_NULL,
        null=True,
        related_name="jira_ticket_db_created",
    )
    updated_by = models.ForeignKey(
        UserProfile,
        related_name="jira_ticket_db_updated",
        on_delete=models.SET_NULL,
        null=True,
    )
    is_active = models.BooleanField(default=True)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, default=1)


class JiraSyncJob(models.Model):
    STATUS_PENDING = "pending"
    STATUS_PROCESSING = "processing"
    STATUS_SUCCEEDED = "succeeded"
    STATUS_RETRY = "retry"
    STATUS_FAILED = "failed"

    STATUS_CHOICES = (
        (STATUS_PENDING, "Pending"),
        (STATUS_PROCESSING, "Processing"),
        (STATUS_SUCCEEDED, "Succeeded"),
        (STATUS_RETRY, "Retry"),
        (STATUS_FAILED, "Failed"),
    )

    finding_id = models.UUIDField()
    scan_id = models.UUIDField()
    project_id = models.IntegerField()
    scanner = models.CharField(max_length=64)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE)
    status = models.CharField(
        max_length=16, choices=STATUS_CHOICES, default=STATUS_PENDING
    )
    attempts = models.PositiveIntegerField(default=0)
    next_retry_at = models.DateTimeField(null=True, blank=True)
    last_error = models.TextField(blank=True, default="")
    created_time = models.DateTimeField(auto_now_add=True)
    updated_time = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=("finding_id", "scan_id", "scanner", "organization"),
                name="unique_jira_sync_finding_scan",
            )
        ]
