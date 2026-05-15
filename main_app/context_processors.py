from .models import Notification


def notification_count(request):
    count = 0
    if request.user.is_authenticated:
        try:
            count = Notification.objects.filter(
                recipient=request.user,
                is_read=False,
            ).count()
        except Exception:
            pass
    return {'unread_notification_count': count}
