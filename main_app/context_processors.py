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


def student_theme(request):
    """Expose the student's saved theme preference to every template."""
    theme = 'system'
    if request.user.is_authenticated and getattr(request.user, 'user_type', None) == '3':
        try:
            theme = request.user.student.theme
        except Exception:
            pass
    return {'student_theme': theme}
