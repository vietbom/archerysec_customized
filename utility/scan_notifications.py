"""In-app import notifications; no dependency on email configuration."""
from django.contrib.auth import get_user_model
from django.db.models import Q
from notifications.signals import notify

from projects.models import ProjectDb


def scan_imported(request, project_id, scanner, total):
    project = ProjectDb.objects.get(pk=project_id)
    user = request.user
    if user.is_authenticated:
        recipients = [user]
    else:
        recipients = get_user_model().objects.filter(
            organization=project.organization, is_active=True,
        ).filter(Q(role__role__in=("Admin", "Analyst")) | Q(is_superuser=True))
    for recipient in recipients:
        notify.send(project, recipient=recipient,
                    verb="%s report imported: %s — %s open findings" % (
                        scanner, project.project_name, total))
