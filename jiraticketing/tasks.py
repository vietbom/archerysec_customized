import logging
from datetime import timedelta

from django.db import transaction
from django.utils import timezone

from jiraticketing.models import JiraSyncJob
from jiraticketing.services import find_scan_finding, process_finding

logger = logging.getLogger(__name__)

MAX_ATTEMPTS = 8


def process_jira_sync_job(job_id):
    try:
        with transaction.atomic():
            job = JiraSyncJob.objects.select_for_update().get(pk=job_id)
            if job.status in (JiraSyncJob.STATUS_SUCCEEDED, JiraSyncJob.STATUS_FAILED):
                return

            if job.status == JiraSyncJob.STATUS_PROCESSING:
                stale_at = timezone.now() - timedelta(minutes=15)
                if job.updated_time and job.updated_time > stale_at:
                    return

            job.status = JiraSyncJob.STATUS_PROCESSING
            job.attempts += 1
            job.save(update_fields=["status", "attempts", "updated_time"])

        finding = find_scan_finding(
            job.finding_id,
            job.scan_id,
            job.scanner,
            job.organization_id,
        )
        if finding is None:
            _mark_job(
                job_id,
                JiraSyncJob.STATUS_SUCCEEDED,
                "Finding no longer exists for this scan",
            )
            return

        result = process_finding(finding, scan_id=job.scan_id)
        if result["status"] in ("created", "updated"):
            _mark_job(job_id, JiraSyncJob.STATUS_SUCCEEDED, "")
            return

        _retry_or_fail(job_id, "Jira processing failed")
    except JiraSyncJob.DoesNotExist:
        logger.warning("Jira sync job %s no longer exists", job_id)
    except Exception:
        logger.exception("Unexpected Jira sync job failure for job=%s", job_id)
        _retry_or_fail(job_id, "Unexpected Jira sync worker failure")


def _mark_job(job_id, status, error):
    JiraSyncJob.objects.filter(pk=job_id).update(
        status=status,
        last_error=error,
        next_retry_at=None,
        updated_time=timezone.now(),
    )


def _retry_or_fail(job_id, error):
    job = JiraSyncJob.objects.filter(pk=job_id).first()
    if job is None:
        return

    if job.attempts >= MAX_ATTEMPTS:
        _mark_job(job_id, JiraSyncJob.STATUS_FAILED, error)
        return

    delay = min(3600, 2 ** min(job.attempts, 10))
    next_retry_at = timezone.now() + timedelta(seconds=delay)
    JiraSyncJob.objects.filter(pk=job_id).update(
        status=JiraSyncJob.STATUS_RETRY,
        last_error=error,
        next_retry_at=next_retry_at,
        updated_time=timezone.now(),
    )
