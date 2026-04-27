from .models import NotificationStudent, NotificationStaff


def notification_count(request):
    count = 0
    if request.user.is_authenticated:
        user_type = str(request.user.user_type)
        if user_type == '3':
            try:
                count = NotificationStudent.objects.filter(
                    student=request.user.student,
                    is_read=False,
                ).count()
            except Exception:
                pass
        elif user_type == '2':
            try:
                count = NotificationStaff.objects.filter(
                    staff=request.user.staff,
                    is_read=False,
                ).count()
            except Exception:
                pass
    return {'unread_notification_count': count}
