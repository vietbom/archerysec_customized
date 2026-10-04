from __future__ import unicode_literals

import logging

from django.core import signing
from django.db import transaction
from jira import JIRA

from cloudscanners.models import CloudScansResultsDb
from jiraticketing.models import jirasetting
from networkscanners.models import NetworkScanResultsDb
from staticscanners.models import StaticScanResultsDb
from webscanners.models import WebScanResultsDb

logger = logging.getLogger(__name__)


class JiraServiceError(Exception):
    """Service-level Jira processing error."""


SCANNER_RESULT_MODELS = {
    "web": WebScanResultsDb,
    "sast": StaticScanResultsDb,
    "network": NetworkScanResultsDb,
    "cloud": CloudScansResultsDb,
}

SUPPORTED_RESULT_MODELS = (
    WebScanResultsDb,
    StaticScanResultsDb,
    NetworkScanResultsDb,
    CloudScansResultsDb,
)


def _normalize_jira_ticket(ticket):
    if ticket is None:
        return None
    if hasattr(ticket, "key") and ticket.key:
        return str(ticket.key)
    ticket_value = str(ticket).strip()
    if ticket_value == "":
        return None
    return ticket_value


def get_result_model_for_scanner(scanner):
    return SCANNER_RESULT_MODELS.get((scanner or "").lower())


def _load_active_jira_setting(organization):
    setting = (
        jirasetting.objects.filter(organization=organization, is_active=True)
        .order_by("-created_time", "-id")
        .first()
    )
    if setting is None:
        raise JiraServiceError("Active Jira configuration not found for organization.")
    if not setting.jira_server:
        raise JiraServiceError("Jira server URL is not configured.")
    if not setting.jira_password:
        raise JiraServiceError("Jira credential is not configured.")
    return setting


def _decode_signed_value(value):
    if not value:
        return None
    try:
        return signing.loads(value)
    except Exception as exc:
        raise JiraServiceError("Jira configuration is invalid.") from exc


def get_jira_client(organization, validate_connection=True):
    setting = _load_active_jira_setting(organization)
    jira_username = _decode_signed_value(setting.jira_username)
    jira_password = _decode_signed_value(setting.jira_password)
    options = {"server": setting.jira_server}

    try:
        if jira_username:
            jira_client = JIRA(
                options,
                basic_auth=(jira_username, jira_password),
                max_retries=0,
                timeout=30,
            )
        else:
            jira_client = JIRA(
                options, token_auth=jira_password, max_retries=0, timeout=30
            )

        if validate_connection:
            jira_client.projects()
    except Exception as exc:
        logger.exception(
            "Unable to connect Jira for organization_id=%s",
            getattr(organization, "id", organization),
        )
        raise JiraServiceError(
            "Jira connection is unavailable for this organization."
        ) from exc

    return jira_client


def _build_finding_summary(finding):
    title = (getattr(finding, "title", "") or "").strip()
    if title:
        return title[:255]
    vuln_id = getattr(finding, "vuln_id", None)
    return "Finding {0}".format(vuln_id or finding.pk)


def _build_finding_description(finding):
    description_parts = []
    for label, field in (
        ("Title", "title"),
        ("Severity", "severity"),
        ("Description", "description"),
        ("Solution", "solution"),
        ("URL", "url"),
        ("IP", "ip"),
        ("Port", "port"),
        ("File", "filePath"),
        ("Resource", "resourceName"),
        ("Vuln ID", "vuln_id"),
    ):
        value = getattr(finding, field, None)
        if value is not None and str(value).strip() != "":
            description_parts.append("{0}: {1}".format(label, value))

    if not description_parts:
        return "Finding details are available in ArcherySec."
    return "\n".join(description_parts)


def _get_finding_fingerprint(finding):
    for field_name in ("dup_hash", "false_positive_hash", "vuln_id"):
        value = getattr(finding, field_name, None)
        if value is None:
            continue
        value = str(value).strip()
        if value != "":
            return field_name, value
    return None, None


def _get_existing_ticket_from_fingerprint(finding):
    field_name, fingerprint = _get_finding_fingerprint(finding)
    if field_name is None:
        return None

    result_filter = {
        "organization": finding.organization,
        field_name: getattr(finding, field_name),
    }

    existing_finding = (
        finding.__class__.objects.filter(**result_filter)
        .exclude(pk=finding.pk)
        .exclude(jira_ticket__isnull=True)
        .exclude(jira_ticket="")
        .order_by("-updated_time", "-created_time", "-id")
        .first()
    )
    if existing_finding is None:
        return None
    return _normalize_jira_ticket(existing_finding.jira_ticket)


def process_finding(
    finding,
    jira_client,
    jira_project_id=None,
    issue_type="Bug",
    summary=None,
    description=None,
    existing_ticket_comment=None,
):
    jira_ticket = _normalize_jira_ticket(getattr(finding, "jira_ticket", None))

    if jira_ticket:
        if existing_ticket_comment:
            try:
                jira_client.add_comment(jira_ticket, existing_ticket_comment)
            except Exception as exc:
                raise JiraServiceError("Failed to update existing Jira issue.") from exc
        return {"status": "updated", "ticket": jira_ticket}

    existing_ticket = _get_existing_ticket_from_fingerprint(finding)
    if existing_ticket:
        finding.jira_ticket = existing_ticket
        finding.save(update_fields=["jira_ticket"])
        if existing_ticket_comment:
            try:
                jira_client.add_comment(existing_ticket, existing_ticket_comment)
            except Exception as exc:
                raise JiraServiceError("Failed to update existing Jira issue.") from exc
        return {"status": "updated", "ticket": existing_ticket}

    if not jira_project_id:
        return {"status": "skipped", "reason": "missing_jira_project_id"}

    issue_dict = {
        "project": {"id": jira_project_id},
        "summary": summary or _build_finding_summary(finding),
        "description": description or _build_finding_description(finding),
        "issuetype": {"name": issue_type or "Bug"},
    }

    try:
        new_issue = jira_client.create_issue(fields=issue_dict)
    except Exception as exc:
        raise JiraServiceError("Failed to create Jira issue.") from exc
    issue_ticket = _normalize_jira_ticket(new_issue)
    if issue_ticket is None:
        raise JiraServiceError("Jira issue was created without a stable issue key.")

    finding.jira_ticket = issue_ticket
    finding.save(update_fields=["jira_ticket"])
    return {"status": "created", "ticket": issue_ticket}


def process_scan_findings(
    scan_id,
    organization,
    jira_project_id=None,
    issue_type="Bug",
    jira_client=None,
    existing_ticket_comment="Finding observed again in a later upload.",
):
    summary = {"created": 0, "updated": 0, "skipped": 0, "failed": 0, "total": 0}

    findings = []
    for model in SUPPORTED_RESULT_MODELS:
        # NOTE: Unsupported scanners are skipped here until a result model mapping exists.
        findings.extend(model.objects.filter(scan_id=scan_id, organization=organization))

    summary["total"] = len(findings)
    if summary["total"] == 0:
        return summary

    if jira_client is None:
        jira_client = get_jira_client(organization)

    for finding in findings:
        try:
            result = process_finding(
                finding=finding,
                jira_client=jira_client,
                jira_project_id=jira_project_id,
                issue_type=issue_type,
                existing_ticket_comment=existing_ticket_comment,
            )
            status = result.get("status", "failed")
            if status in summary:
                summary[status] += 1
            else:
                summary["failed"] += 1
        except Exception:
            summary["failed"] += 1
            logger.exception(
                "Failed Jira processing for finding_id=%s scan_id=%s",
                finding.pk,
                scan_id,
            )

    return summary


def schedule_scan_findings_processing(scan_id, organization, **kwargs):
    def _process_after_commit():
        try:
            process_scan_findings(scan_id=scan_id, organization=organization, **kwargs)
        except Exception:
            logger.exception("Jira processing failed for committed scan_id=%s", scan_id)

    transaction.on_commit(_process_after_commit)
