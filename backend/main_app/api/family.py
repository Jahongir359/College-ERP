"""Which student a student-or-parent request is about.

Students always get their own record. Parents pass ``?student=<id>`` for one
of their linked children (it may be left out when they have exactly one
child). Who may see which child is decided in ``branching.py``.
"""

from rest_framework import status
from rest_framework.response import Response

from .. import branching
from ..models import Student


def student_for_request(request):
    """Return ``(student, None)`` or ``(None, error_response)``."""
    user = request.user
    user_type = str(getattr(user, "user_type", ""))

    if user_type == "3":
        try:
            return user.student, None
        except Student.DoesNotExist:
            return None, Response(
                {"detail": "Student profile not found."}, status=status.HTTP_403_FORBIDDEN
            )

    if user_type == "4":
        children = branching.children_for_parent(user)
        raw = request.query_params.get("student", "").strip()
        if not raw:
            only = list(children[:2])
            if len(only) == 1:
                return only[0], None
            return None, Response(
                {"detail": "Pass ?student=<id> to choose a child."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if not raw.isdigit():
            return None, Response(
                {"detail": "student must be a number."}, status=status.HTTP_400_BAD_REQUEST
            )
        student = children.filter(pk=int(raw)).first()
        if student is None:
            return None, Response(
                {"detail": "Student not found."}, status=status.HTTP_404_NOT_FOUND
            )
        return student, None

    return None, Response({"detail": "Permission denied."}, status=status.HTTP_403_FORBIDDEN)
