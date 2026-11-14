"""The signed-in user's notification inbox, available on every page."""
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import redirect
from django.views.decorators.http import require_GET, require_POST
from notifications.models import Notification


@login_required
@require_GET
def notification_feed(request):
    unread = Notification.objects.filter(recipient=request.user).unread()
    return JsonResponse({
        "count": unread.count(),
        "results": [{"id": item.pk, "verb": item.verb,
                     "timestamp": item.timestamp.isoformat()}
                    for item in unread.order_by("-timestamp")[:20]],
    })


@login_required
@require_POST
def dismiss_notification(request):
    notification_id = request.POST.get("notify_id", "")
    if not notification_id.isdigit():
        return JsonResponse({"error": "Invalid notification ID"}, status=400)
    Notification.objects.filter(recipient=request.user, pk=notification_id).mark_all_as_read()
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return JsonResponse({"ok": True})
    return redirect("dashboard:dashboard")


@login_required
@require_POST
def dismiss_all_notifications(request):
    Notification.objects.filter(recipient=request.user).unread().mark_all_as_read()
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return JsonResponse({"ok": True})
    return redirect("dashboard:dashboard")
