from .models import Notification
from .messaging import unread_message_count


def notification_count(request):
    count = 0
    message_count = 0
    if request.user.is_authenticated:
        try:
            count = Notification.objects.filter(
                recipient=request.user,
                is_read=False,
            ).count()
        except Exception:
            pass
        try:
            message_count = unread_message_count(request.user)
        except Exception:
            pass
    return {"unread_notification_count": count, "unread_message_count": message_count}


def brand(request):
    """Expose the resolved Iceberg brand (BrandConfig) as ``brand`` to every template."""
    from .branding import get_brand, resolve_brand_key

    return {"brand": get_brand(resolve_brand_key(request))}


def student_theme(request):
    """Expose the student's saved theme preference to every template."""
    theme = "system"
    if request.user.is_authenticated and getattr(request.user, "user_type", None) == "3":
        try:
            theme = request.user.student.theme
        except Exception:
            pass
    return {"student_theme": theme}
