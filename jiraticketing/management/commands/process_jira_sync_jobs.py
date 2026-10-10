import time
from datetime import timedelta

from django.core.management.base import BaseCommand
from django.db.models import Q
from django.utils import timezone

from jiraticketing.models import JiraSyncJob
from jiraticketing.tasks import process_jira_sync_job


class Command(BaseCommand):
    help = "Process pending Jira synchronization jobs from the database outbox."

    def add_arguments(self, parser):
        parser.add_argument(
            "--poll-interval",
            type=int,
            default=5,
            help="Seconds to wait when no Jira jobs are available.",
        )

    def handle(self, *args, **options):
        poll_interval = max(1, options["poll_interval"])
        self.stdout.write("Jira sync worker started")
        while True:
            job = (
                JiraSyncJob.objects.filter(
                    Q(status=JiraSyncJob.STATUS_PENDING)
                    | Q(
                        status=JiraSyncJob.STATUS_RETRY,
                        next_retry_at__lte=timezone.now(),
                    )
                    | Q(
                        status=JiraSyncJob.STATUS_PROCESSING,
                        updated_time__lte=timezone.now() - timedelta(minutes=15),
                    )
                )
                .order_by("created_time")
                .first()
            )
            if job is None:
                time.sleep(poll_interval)
                continue

            process_jira_sync_job(job.pk)
