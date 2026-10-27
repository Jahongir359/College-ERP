"""Admin API for Iceberg School data: subjects per class (plan task P1.3).

Who may see or change a class is decided in ``branching.py``: super admins
every class, branch admins the classes of their branches.
"""

from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .. import branching
from ..models import ClassSubject, Group, Staff, Subject
from .permissions import IsAdmin


def _class_subject_dict(cs):
    teacher = cs.teacher
    return {
        "id": cs.pk,
        "class_id": cs.group_id,
        "subject_id": cs.subject_id,
        "subject_name": cs.subject.name,
        "teacher_id": cs.teacher_id,
        "teacher_name": teacher.admin.get_full_name() if teacher else "",
        "weekly_hours": cs.weekly_hours,
    }


def _bad_request(detail):
    return Response(detail, status=status.HTTP_400_BAD_REQUEST)


def _not_found(what):
    return Response({"detail": f"{what} not found."}, status=status.HTTP_404_NOT_FOUND)


def _teacher_for(request, teacher_id):
    """(teacher or None, error_response). An empty id clears the teacher."""
    if teacher_id in (None, ""):
        return None, None
    staff = branching.filter_staff_for_user(request.user, Staff.objects.all())
    teacher = staff.filter(pk=teacher_id).select_related("admin").first()
    if teacher is None:
        return None, _not_found("Teacher")
    return teacher, None


def _save(cs):
    try:
        cs.full_clean()
        with transaction.atomic():
            cs.save()
    except ValidationError as exc:
        return _bad_request(exc.message_dict)
    except IntegrityError:
        return _bad_request({"subject": ["This class already has this subject."]})
    return None


class ClassSubjectListView(APIView):
    """GET/POST /api/v1/admin/classes/<pk>/subjects/"""

    permission_classes = [IsAuthenticated, IsAdmin]

    def _class(self, request, pk):
        classes = branching.filter_groups_for_user(
            request.user, Group.objects.filter(kind=Group.KIND_CLASS)
        )
        return classes.filter(pk=pk).first()

    def get(self, request, pk):
        group = self._class(request, pk)
        if group is None:
            return _not_found("Class")
        rows = group.class_subjects.select_related("subject", "teacher__admin")
        return Response([_class_subject_dict(cs) for cs in rows])

    def post(self, request, pk):
        group = self._class(request, pk)
        if group is None:
            return _not_found("Class")
        subject = Subject.objects.filter(pk=request.data.get("subject_id") or 0).first()
        if subject is None:
            return _not_found("Subject")
        teacher, err = _teacher_for(request, request.data.get("teacher_id"))
        if err:
            return err
        cs = ClassSubject(group=group, subject=subject, teacher=teacher)
        if "weekly_hours" in request.data:
            cs.weekly_hours = request.data["weekly_hours"]
        err = _save(cs)
        if err:
            return err
        return Response(_class_subject_dict(cs), status=status.HTTP_201_CREATED)


class ClassSubjectDetailView(APIView):
    """GET/PATCH/DELETE /api/v1/admin/class-subjects/<pk>/"""

    permission_classes = [IsAuthenticated, IsAdmin]

    def _get(self, request, pk):
        qs = branching.filter_class_subjects_for_user(
            request.user, ClassSubject.objects.select_related("group", "subject", "teacher__admin")
        )
        return qs.filter(pk=pk).first()

    def get(self, request, pk):
        cs = self._get(request, pk)
        if cs is None:
            return _not_found("Class subject")
        return Response(_class_subject_dict(cs))

    def patch(self, request, pk):
        cs = self._get(request, pk)
        if cs is None:
            return _not_found("Class subject")
        if "teacher_id" in request.data:
            teacher, err = _teacher_for(request, request.data["teacher_id"])
            if err:
                return err
            cs.teacher = teacher
        if "weekly_hours" in request.data:
            cs.weekly_hours = request.data["weekly_hours"]
        err = _save(cs)
        if err:
            return err
        return Response(_class_subject_dict(cs))

    def delete(self, request, pk):
        cs = self._get(request, pk)
        if cs is None:
            return _not_found("Class subject")
        cs.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
