"""API for Iceberg School data: subjects per class (plan task P1.3), bell
periods and the timetable (P2.1).

Who may see or change a class is decided in ``branching.py``: super admins
every class, branch admins the classes of their branches.
"""

from datetime import date, timedelta

from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.db.models import ProtectedError
from django.utils import timezone
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .. import branching
from ..models import (
    BellPeriod,
    Branch,
    ClassSubject,
    Group,
    Lesson,
    LessonClashError,
    Staff,
    Subject,
)
from .family import student_for_request
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


# ── Bell periods and timetable (P2.1) ────────────────────────────────────────


def _time(value):
    return value.strftime("%H:%M") if value else None


def _period_dict(period):
    return {
        "id": period.pk,
        "branch_id": period.branch_id,
        "number": period.number,
        "start_time": _time(period.start_time),
        "end_time": _time(period.end_time),
    }


def _lesson_dict(lesson):
    cs = lesson.class_subject
    teacher = cs.teacher
    return {
        "id": lesson.pk,
        "class_id": lesson.group_id,
        "class_name": lesson.group.name,
        "class_subject_id": cs.pk,
        "subject_id": cs.subject_id,
        "subject_name": cs.subject.name,
        "teacher_id": cs.teacher_id,
        "teacher_name": teacher.admin.get_full_name() if teacher else "",
        "weekday": lesson.weekday,
        "period": _period_dict(lesson.period),
        "room": lesson.effective_room,
        "valid_from": lesson.valid_from,
        "valid_to": lesson.valid_to,
    }


def _admin_lesson_dict(lesson):
    data = _lesson_dict(lesson)
    # Admins edit the lesson's own room; the class room is the fallback.
    data["room"] = lesson.room
    data["class_room"] = lesson.group.room
    return data


_LESSON_RELATED = ("group__session", "class_subject__subject", "class_subject__teacher__admin")


def _save_checked(obj, duplicate_message):
    """Validate field types first, then the model rules (so ``clean`` never sees
    a bad time or date string), then save. Returns an error response or None."""
    try:
        obj.clean_fields()
        obj.clean()
        obj.validate_constraints()
    except LessonClashError as exc:
        clashes = [
            {
                "kind": kind,
                "lesson_id": other.pk,
                "class_id": other.group_id,
                "class_name": other.group.name,
                "message": LessonClashError.message_for(kind, other),
            }
            for kind, other in exc.clashes
        ]
        return _bad_request({"detail": " ".join(exc.messages), "clashes": clashes})
    except ValidationError as exc:
        return _bad_request(exc.message_dict)
    try:
        with transaction.atomic():
            obj.save()
    except IntegrityError:
        return _bad_request({"detail": duplicate_message})
    return None


def _apply(obj, data, fields):
    for field in fields:
        if field in data:
            value = data[field]
            setattr(obj, field, None if value == "" and field.startswith("valid_") else value)


class BellPeriodListView(APIView):
    """GET/POST /api/v1/admin/bell-periods/ (GET takes ?branch=<id>)"""

    permission_classes = [IsAuthenticated, IsAdmin]

    def get(self, request):
        periods = branching.filter_bell_periods_for_user(request.user, BellPeriod.objects.all())
        branch_id = request.query_params.get("branch", "").strip()
        if branch_id:
            if not branch_id.isdigit():
                return _bad_request({"branch": ["Must be a number."]})
            periods = periods.filter(branch_id=int(branch_id))
        return Response([_period_dict(p) for p in periods])

    def post(self, request):
        branches = branching.filter_branches_for_user(request.user, Branch.objects.all())
        branch = branches.filter(pk=request.data.get("branch_id") or 0).first()
        if branch is None:
            return _not_found("Branch")
        period = BellPeriod(branch=branch)
        _apply(period, request.data, ("number", "start_time", "end_time"))
        err = _save_checked(period, "This branch already has a period with this number.")
        if err:
            return err
        period.refresh_from_db()
        return Response(_period_dict(period), status=status.HTTP_201_CREATED)


class BellPeriodDetailView(APIView):
    """GET/PATCH/DELETE /api/v1/admin/bell-periods/<pk>/"""

    permission_classes = [IsAuthenticated, IsAdmin]

    def _get(self, request, pk):
        periods = branching.filter_bell_periods_for_user(request.user, BellPeriod.objects.all())
        return periods.filter(pk=pk).first()

    def get(self, request, pk):
        period = self._get(request, pk)
        if period is None:
            return _not_found("Bell period")
        return Response(_period_dict(period))

    def patch(self, request, pk):
        period = self._get(request, pk)
        if period is None:
            return _not_found("Bell period")
        _apply(period, request.data, ("number", "start_time", "end_time"))
        err = _save_checked(period, "This branch already has a period with this number.")
        if err:
            return err
        period.refresh_from_db()
        return Response(_period_dict(period))

    def delete(self, request, pk):
        period = self._get(request, pk)
        if period is None:
            return _not_found("Bell period")
        try:
            period.delete()
        except ProtectedError:
            return _bad_request({"detail": "Lessons use this period. Move or delete them first."})
        return Response(status=status.HTTP_204_NO_CONTENT)


_LESSON_FIELDS = ("weekday", "room", "valid_from", "valid_to")


def _lesson_parts(request, group, data):
    """Resolve class_subject_id / period_id inside ``group``. (values, error_response)."""
    parts = {}
    if "class_subject_id" in data:
        cs = group.class_subjects.filter(pk=data.get("class_subject_id") or 0).first()
        if cs is None:
            return None, _not_found("Class subject")
        parts["class_subject"] = cs
    if "period_id" in data:
        periods = branching.filter_bell_periods_for_user(request.user, BellPeriod.objects.all())
        period = periods.filter(pk=data.get("period_id") or 0, branch_id=group.branch_id).first()
        if period is None:
            return None, _not_found("Bell period")
        parts["period"] = period
    return parts, None


class ClassLessonListView(APIView):
    """GET/POST /api/v1/admin/classes/<pk>/lessons/"""

    permission_classes = [IsAuthenticated, IsAdmin]

    def _class(self, request, pk):
        return (
            branching.filter_classes_for_user(request.user, Group.objects.all())
            .filter(pk=pk)
            .first()
        )

    def get(self, request, pk):
        group = self._class(request, pk)
        if group is None:
            return _not_found("Class")
        rows = group.lessons.select_related("period", *_LESSON_RELATED)
        return Response([_admin_lesson_dict(lesson) for lesson in rows])

    def post(self, request, pk):
        group = self._class(request, pk)
        if group is None:
            return _not_found("Class")
        for required in ("class_subject_id", "period_id", "weekday"):
            if request.data.get(required) in (None, ""):
                return _bad_request({required: ["This field is required."]})
        parts, err = _lesson_parts(request, group, request.data)
        if err:
            return err
        lesson = Lesson(group=group, **parts)
        _apply(lesson, request.data, _LESSON_FIELDS)
        err = _save_checked(lesson, "This lesson already exists.")
        if err:
            return err
        lesson.refresh_from_db()
        return Response(_admin_lesson_dict(lesson), status=status.HTTP_201_CREATED)


class LessonDetailView(APIView):
    """GET/PATCH/DELETE /api/v1/admin/lessons/<pk>/"""

    permission_classes = [IsAuthenticated, IsAdmin]

    def _get(self, request, pk):
        lessons = branching.filter_lessons_for_user(
            request.user, Lesson.objects.select_related("period", *_LESSON_RELATED)
        )
        return lessons.filter(pk=pk).first()

    def get(self, request, pk):
        lesson = self._get(request, pk)
        if lesson is None:
            return _not_found("Lesson")
        return Response(_admin_lesson_dict(lesson))

    def patch(self, request, pk):
        lesson = self._get(request, pk)
        if lesson is None:
            return _not_found("Lesson")
        parts, err = _lesson_parts(request, lesson.group, request.data)
        if err:
            return err
        for name, value in parts.items():
            setattr(lesson, name, value)
        _apply(lesson, request.data, _LESSON_FIELDS)
        err = _save_checked(lesson, "This lesson already exists.")
        if err:
            return err
        lesson.refresh_from_db()
        return Response(_admin_lesson_dict(lesson))

    def delete(self, request, pk):
        lesson = self._get(request, pk)
        if lesson is None:
            return _not_found("Lesson")
        lesson.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


def _class_brief(group):
    return {
        "id": group.pk,
        "name": group.name,
        "grade_level": group.grade_level,
        "letter": group.letter,
    }


def _int_param(request, name):
    """(int or None, error_response) for an optional numeric query parameter."""
    raw = request.query_params.get(name, "").strip()
    if not raw:
        return None, None
    if not raw.isdigit():
        return None, _bad_request({name: ["Must be a number."]})
    return int(raw), None


class TimetableView(APIView):
    """GET /api/v1/school/timetable/ — one week (Monday to Saturday) of lessons.

    ``?date=YYYY-MM-DD`` picks the week (default: this week). Students get
    their own class; parents pass ``?student=<id>`` (see family.py); teachers
    get the lessons they teach, or ``?class=<id>`` for a class they teach in or
    lead; admins pass ``?class=<id>``. Lessons outside their valid dates or the
    class's academic year are left out.
    """

    permission_classes = [IsAuthenticated]

    def get(self, request):
        raw_date = request.query_params.get("date", "").strip()
        if raw_date:
            try:
                day = date.fromisoformat(raw_date)
            except ValueError:
                return _bad_request({"date": ["Use the format YYYY-MM-DD."]})
        else:
            day = timezone.localdate()

        user = request.user
        user_type = str(getattr(user, "user_type", ""))
        classes = branching.filter_classes_for_user(user, Group.objects.all())
        lessons = branching.filter_lessons_for_user(user, Lesson.objects.all())
        group = None

        if user_type in ("3", "4"):
            student, err = student_for_request(request)
            if err:
                return err
            classes = classes.filter(enrollment__student=student, enrollment__is_active=True)
            lessons = lessons.filter(group__in=classes.values("pk"))
        else:
            class_id, err = _int_param(request, "class")
            if err:
                return err
            if class_id is not None:
                group = classes.filter(pk=class_id).first()
                if group is None:
                    return _not_found("Class")
                lessons = lessons.filter(group=group)
            elif user_type == "2":
                lessons = lessons.filter(class_subject__teacher__admin=user)
            elif user_type == "1":
                return _bad_request({"class": ["Pass ?class=<id>."]})
            else:
                return Response({"detail": "Permission denied."}, status=status.HTTP_403_FORBIDDEN)

        monday = day - timedelta(days=day.weekday())
        saturday = monday + timedelta(days=5)
        if user_type in ("3", "4"):
            # One class per academic year: name the one of this week, else the latest.
            by_year = classes.order_by("-session__start_year")
            group = (
                by_year.filter(
                    session__start_year__lte=saturday, session__end_year__gte=monday
                ).first()
                or by_year.first()
            )

        rows = list(lessons.select_related("period", *_LESSON_RELATED))
        days = []
        for offset in range(6):
            the_day = monday + timedelta(days=offset)
            todays = sorted(
                (lesson for lesson in rows if lesson.is_on(the_day)),
                key=lambda lesson: lesson.period.start_time,
            )
            days.append(
                {
                    "weekday": offset + 1,
                    "date": the_day,
                    "lessons": [_lesson_dict(lesson) for lesson in todays],
                }
            )

        return Response(
            {
                "date": day,
                "week_start": monday,
                "week_end": saturday,
                "class": _class_brief(group) if group else None,
                "days": days,
            }
        )
