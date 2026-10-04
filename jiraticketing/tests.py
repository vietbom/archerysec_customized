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

import uuid
from unittest.mock import Mock, patch

from django.core import signing
from django.db import transaction
from django.test import TestCase

from jiraticketing.models import jirasetting
from jiraticketing.services import (JiraServiceError, process_scan_findings,
                                    schedule_scan_findings_processing)
from projects.models import ProjectDb
from webscanners.models import WebScanResultsDb


class JiraServicesTest(TestCase):
    fixtures = [
        "fixtures/default_user_roles.json",
        "fixtures/default_organization.json",
    ]

    def setUp(self):
        self.organization_id = 1
        self.project = ProjectDb.objects.create(
            project_name="jira-service-project", organization_id=self.organization_id
        )
        self.scan_id = uuid.uuid4()
        self.finding = WebScanResultsDb.objects.create(
            vuln_id=uuid.uuid4(),
            scan_id=self.scan_id,
            project=self.project,
            title="SQL Injection",
            description="SQLi description",
            severity="High",
            scanner="zap",
            organization_id=self.organization_id,
        )
        jirasetting.objects.create(
            jira_server="https://jira.example.com",
            jira_username=signing.dumps("jira-user"),
            jira_password=signing.dumps("jira-password"),
            organization_id=self.organization_id,
            is_active=True,
        )

    @patch("jiraticketing.services.JIRA")
    def test_process_scan_findings_creates_jira_ticket_once(self, jira_class):
        jira_client = jira_class.return_value
        jira_client.projects.return_value = []
        jira_issue = Mock()
        jira_issue.key = "SEC-123"
        jira_client.create_issue.return_value = jira_issue

        result = process_scan_findings(
            scan_id=self.scan_id,
            organization=self.organization_id,
            jira_project_id="10001",
        )

        self.finding.refresh_from_db()
        self.assertEqual(result["created"], 1)
        self.assertEqual(self.finding.jira_ticket, "SEC-123")
        jira_client.create_issue.assert_called_once()

    @patch("jiraticketing.services.JIRA")
    def test_process_scan_findings_reprocess_updates_without_duplicate(self, jira_class):
        jira_client = jira_class.return_value
        jira_client.projects.return_value = []
        jira_issue = Mock()
        jira_issue.key = "SEC-123"
        jira_client.create_issue.return_value = jira_issue

        process_scan_findings(
            scan_id=self.scan_id,
            organization=self.organization_id,
            jira_project_id="10001",
        )
        second_result = process_scan_findings(
            scan_id=self.scan_id,
            organization=self.organization_id,
            jira_project_id="10001",
        )

        self.assertEqual(jira_client.create_issue.call_count, 1)
        self.assertEqual(second_result["updated"], 1)
        jira_client.add_comment.assert_called_once()

    def test_schedule_scan_processing_contains_jira_failure(self):
        with patch(
            "jiraticketing.services.process_scan_findings",
            side_effect=JiraServiceError("jira unavailable"),
        ), patch(
            "jiraticketing.services.transaction.on_commit",
            side_effect=lambda callback: callback(),
        ):
            with self.assertLogs("jiraticketing.services", level="ERROR") as logs:
                schedule_scan_findings_processing(
                    scan_id=self.scan_id, organization=self.organization_id
                )
        self.assertIn("Jira processing failed", "\n".join(logs.output))

    def test_schedule_scan_processing_runs_on_commit(self):
        with patch("jiraticketing.services.process_scan_findings") as process_mock:
            with self.captureOnCommitCallbacks(execute=False) as callbacks:
                with transaction.atomic():
                    schedule_scan_findings_processing(
                        scan_id=self.scan_id, organization=self.organization_id
                    )
                    process_mock.assert_not_called()
            self.assertEqual(len(callbacks), 1)
            callbacks[0]()
            process_mock.assert_called_once()
