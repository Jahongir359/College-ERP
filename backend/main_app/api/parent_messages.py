"""Teacher ↔ parent messages for Iceberg School (plan task P2.6).

One ``ChatThread`` (kind "parent") per student and teacher; every linked parent
of the student reads and writes in it. A parent writes to the homeroom and
subject teachers of their child's class; a teacher writes to the parents of a
student they teach. Admins may read their branches' threads but not write.
Who may do what is decided in ``branching.py``.

    GET  messages/parent/?student=      threads (parents: one child or all)
    POST messages/parent/               {student, teacher} → open or create
    GET  messages/parent/contacts/?student=   who the user can start a thread with
    GET  messages/parent/<id>/          messages (marks the thread read)
    POST messages/parent/<id>/          {message, attachment?}
"""

from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction
from django.utils import timezone
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .. import branching, messaging
from ..models import ChatMessage, ChatReadState, ChatThread, ClassSubject, Group, Staff, Student
from .family import student_for_request
from .serializers import _current_class

MAX_ATTACHMENT_BYTES = 10 * 1024 * 1024


def _is_student(user):
    return str(getattr(user, "user_type", "")) == "3"


def _subjects_of(teacher, student):
    """Names of the subjects ``teacher`` teaches in the student's active classes."""
    return sorted(
        ClassSubject.objects.filter(
            teacher=teacher,
            group__enrollment__student=student,
            group__enrollment__is_active=True,
            group__is_archived=False,
        )
        .values_list("subject__name", flat=True)
        .distinct()
    )


def _is_homeroom(teacher, student):
    return Group.objects.filter(
        kind=Group.KIND_CLASS,
        is_archived=False,
        teacher=teacher,
        enrollment__student=student,
        enrollment__is_active=True,
    ).exists()


def _person(user):
    return user.get_full_name() or user.email


def _teacher_dict(teacher, student):
    return {
        "id": teacher.pk,
        "name": _person(teacher.admin),
        "subjects": _subjects_of(teacher, student),
        "is_homeroom": _is_homeroom(teacher, student),
    }


def _student_dict(student):
    return {
        "id": student.pk,
        "name": _person(student.admin),
        "class": _current_class(student),
    }


def _thread_dict(request, thread):
    last = thread.messages.order_by("-created_at").first()
    return {
        "id": thread.pk,
        "student": _student_dict(thread.student),
        "teacher": _teacher_dict(thread.teacher, thread.student),
        "parents": [
            _person(user)
            for user in get_user_model().objects.filter(
                pk__in=branching.parent_user_ids_for_students([thread.student])
            )
        ],
        "can_post": branching.user_can_post_in_parent_thread(request.user, thread),
        "last_message": last.body[:120] if last else "",
        "last_message_time": last.created_at.isoformat() if last else None,
        "unread_count": messaging.unread_count_for_thread(request.user, thread),
    }


def _message_dict(request, m):
    return {
        "id": m.id,
        "message": m.body,
        "sender_name": _person(m.sender),
        "sender_role": {"2": "teacher", "4": "parent"}.get(str(m.sender.user_type), "admin"),
        "is_mine": m.sender_id == request.user.id,
        "created_at": m.created_at.isoformat(),
        "attachment_url": (request.build_absolute_uri(m.attachment.url) if m.attachment else None),
        "attachment_name": m.attachment_display_name,
        "attachment_is_image": m.attachment_is_image,
    }


def _visible_threads(user):
    return branching.filter_parent_threads_for_user(
        user,
        ChatThread.objects.select_related("student__admin", "teacher__admin"),
    )


def _student_param(request):
    """``(student or None, error)`` for an optional ``student`` in the query or
    body. A student the user may not see (another family's child) is a 404."""
    raw = str(request.query_params.get("student") or request.data.get("student") or "").strip()
    if not raw:
        return None, None
    if not raw.isdigit():
        return None, Response(
            {"detail": "student must be a number."}, status=status.HTTP_400_BAD_REQUEST
        )
    student = Student.objects.filter(pk=int(raw)).select_related("admin").first()
    if student is None or not branching.user_can_message_about_student(request.user, student):
        return None, Response({"detail": "Student not found."}, status=status.HTTP_404_NOT_FOUND)
    return student, None


class ParentThreadListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if _is_student(request.user):
            return Response({"detail": "Permission denied."}, status=status.HTTP_403_FORBIDDEN)
        student, err = _student_param(request)
        if err:
            return err
        threads = _visible_threads(request.user)
        if student is not None:
            threads = threads.filter(student=student)
        rows = [_thread_dict(request, t) for t in threads]
        rows.sort(key=lambda t: t["last_message_time"] or "", reverse=True)
        return Response({"threads": rows})

    def post(self, request):
        """Open the thread for {student, teacher}, creating it on first use.
        Teachers may leave ``teacher`` out (it is themself)."""
        user_type = str(request.user.user_type)
        if user_type not in ("2", "4"):
            return Response({"detail": "Permission denied."}, status=status.HTTP_403_FORBIDDEN)
        student, err = _student_param(request)
        if err:
            return err
        if student is None:
            return Response({"detail": "student is required."}, status=status.HTTP_400_BAD_REQUEST)

        if user_type == "2":
            teacher = request.user.staff
        else:
            raw = str(request.data.get("teacher") or "").strip()
            if not raw.isdigit():
                return Response(
                    {"detail": "teacher is required."}, status=status.HTTP_400_BAD_REQUEST
                )
            teacher = Staff.objects.filter(pk=int(raw)).first()
        if not branching.user_can_start_parent_thread(request.user, student, teacher):
            return Response(
                {"detail": "This teacher doesn't teach this student."},
                status=status.HTTP_403_FORBIDDEN,
            )
        if not student.parent_links.exists():
            return Response(
                {"detail": "This student has no linked parent."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            with transaction.atomic():
                thread, created = ChatThread.objects.get_or_create(
                    kind=ChatThread.KIND_PARENT, student=student, teacher=teacher
                )
        except IntegrityError:
            thread, created = (
                ChatThread.objects.get(
                    kind=ChatThread.KIND_PARENT, student=student, teacher=teacher
                ),
                False,
            )
        return Response(
            _thread_dict(request, thread),
            status=status.HTTP_201_CREATED if created else status.HTTP_200_OK,
        )


class ParentContactsView(APIView):
    """Parents: the teachers of a child. Teachers: their students who have a
    linked parent, with any thread already open."""

    permission_classes = [IsAuthenticated]

    def get(self, request):
        user_type = str(request.user.user_type)
        if user_type == "4":
            student, err = student_for_request(request)
            if err:
                return err
            teachers = branching.teachers_for_student(student).select_related("admin")
            rows = [_teacher_dict(t, student) for t in teachers]
            rows.sort(key=lambda r: (not r["is_homeroom"], r["name"]))
            return Response({"student": _student_dict(student), "teachers": rows})

        if user_type == "2":
            classes = branching.filter_classes_for_user(
                request.user, Group.objects.filter(is_archived=False)
            )
            students = (
                Student.objects.filter(
                    enrollment__group__in=classes.values("pk"),
                    enrollment__is_active=True,
                    parent_links__isnull=False,
                )
                .select_related("admin")
                .distinct()
                .order_by("admin__last_name", "admin__first_name")
            )
            open_threads = dict(_visible_threads(request.user).values_list("student_id", "id"))
            rows = [{**_student_dict(s), "thread_id": open_threads.get(s.pk)} for s in students]
            return Response({"students": rows})

        return Response({"detail": "Permission denied."}, status=status.HTTP_403_FORBIDDEN)


class ParentThreadDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def _thread(self, request, pk):
        if _is_student(request.user):
            return None, Response(
                {"detail": "Permission denied."}, status=status.HTTP_403_FORBIDDEN
            )
        thread = _visible_threads(request.user).filter(pk=pk).first()
        if thread is None:
            return None, Response({"detail": "Not found."}, status=status.HTTP_404_NOT_FOUND)
        return thread, None

    def get(self, request, pk):
        thread, err = self._thread(request, pk)
        if err:
            return err
        messages = [
            _message_dict(request, m)
            for m in thread.messages.select_related("sender").order_by("created_at")[:500]
        ]
        ChatReadState.objects.update_or_create(
            thread=thread, user=request.user, defaults={"last_read_at": timezone.now()}
        )
        return Response({"thread": _thread_dict(request, thread), "messages": messages})

    def post(self, request, pk):
        thread, err = self._thread(request, pk)
        if err:
            return err
        if not branching.user_can_post_in_parent_thread(request.user, thread):
            return Response(
                {"detail": "You can read this conversation but not write in it."},
                status=status.HTTP_403_FORBIDDEN,
            )
        body = str(request.data.get("message") or request.data.get("body") or "").strip()
        attachment = request.FILES.get("attachment")
        if not body and not attachment:
            return Response({"detail": "Message is required."}, status=status.HTTP_400_BAD_REQUEST)
        if attachment and attachment.size > MAX_ATTACHMENT_BYTES:
            return Response(
                {"detail": "Attachment too large (max 10 MB)."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        msg = ChatMessage.objects.create(
            thread=thread,
            sender=request.user,
            body=body[:4000],
            attachment=attachment,
            attachment_name=(attachment.name if attachment else ""),
        )
        thread.save(update_fields=["updated_at"])
        return Response(_message_dict(request, msg), status=status.HTTP_201_CREATED)
