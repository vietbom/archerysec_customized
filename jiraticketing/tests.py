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
from django.test import TestCase
from django.utils import timezone

from projects.models import ProjectDb
from staticscanners.models import StaticScanResultsDb
from user_management.models import Organization

from jiraticketing.models import jirasetting
from jiraticketing.services import process_finding, process_scan_findings


class JiraFindingServiceTests(TestCase):
	fixtures = ["fixtures/default_organization.json"]

	def setUp(self):
		self.organization = Organization.objects.get(pk=1)
		self.project = ProjectDb.objects.create(
			project_name="Jira service test",
			organization=self.organization,
		)
		self.scan_id = uuid.uuid4()
		jirasetting.objects.create(
			setting_id=uuid.uuid4(),
			jira_server="https://jira.example.test",
			jira_username=signing.dumps("user@example.test"),
			jira_password=signing.dumps("test-token"),
			jira_project_id="10001",
			jira_issue_type="Bug",
			organization=self.organization,
		)
		self.finding = StaticScanResultsDb.objects.create(
			scan_id=self.scan_id,
			project=self.project,
			date_time=timezone.now(),
			vuln_id=uuid.uuid4(),
			title="Test finding",
			severity="High",
			description="A test vulnerability",
			fileName="src/app.py",
			scanner="Trivy",
			dup_hash="test-fingerprint",
			vuln_status="Open",
			false_positive="No",
			vuln_duplicate="No",
			organization=self.organization,
		)

	def test_rescan_comments_existing_ticket_without_creating_another(self):
		jira_client = Mock()
		jira_client.create_issue.return_value.key = "SEC-123"

		created = process_finding(self.finding, jira_client=jira_client)
		self.finding.refresh_from_db()
		self.assertEqual(created["status"], "created")
		self.assertEqual(self.finding.jira_ticket, "SEC-123")

		next_scan_id = uuid.uuid4()
		StaticScanResultsDb.objects.filter(pk=self.finding.pk).update(
			scan_id=next_scan_id
		)
		with patch(
			"jiraticketing.services.get_jira_client", return_value=jira_client
		):
			results = process_scan_findings(
				self.project.pk,
				next_scan_id,
				self.organization.pk,
				"Trivy",
			)

		self.assertEqual(results[0]["status"], "updated")
		jira_client.create_issue.assert_called_once()
		jira_client.add_comment.assert_called_once()

	def test_jira_failure_does_not_change_scan_finding(self):
		with patch(
			"jiraticketing.services.get_jira_client",
			side_effect=RuntimeError("Jira unavailable"),
		):
			results = process_scan_findings(
				self.project.pk,
				self.scan_id,
				self.organization.pk,
				"Trivy",
			)

		self.finding.refresh_from_db()
		self.assertEqual(results, [])
		self.assertEqual(self.finding.vuln_status, "Open")
		self.assertFalse(self.finding.jira_ticket)
