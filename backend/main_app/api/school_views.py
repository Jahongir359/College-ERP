"""API for Iceberg School data: subjects per class (plan task P1.3), parents
with their children (P1.7), bell periods and the timetable (P2.1).

Who may see or change a class or parent is decided in ``branching.py``: super
admins everything, branch admins the classes and children of their branches.
Parent rules (one login per family, one primary contact) live in ``parents.py``.
"""

from datetime import date, timedelta

from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.db.models import ProtectedError, Q
from django.utils import timezone
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .. import branching, parents
from ..models import (
    BellPeriod,
    Branch,
    ClassSubject,
    Group,
    Lesson,
    LessonClashError,
    Parent,
    Staff,
    Subject,
)
from ..school_forms import ParentChildForm, ParentForm
from .family import student_for_request
from .serializers import _current_class
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


# ── Parents and their children (P1.7) ────────────────────────────────────────


def _form_errors(*forms):
    errors = {}
    for form in forms:
        errors.update({field: [str(e) for e in errs] for field, errs in form.errors.items()})
    return _bad_request(errors)


def _link_dict(link):
    student = link.student
    return {
        "student_id": student.pk,
        "name": student.admin.get_full_name(),
        "login_id": student.admin.login_id,
        "branch_name": student.branch.name if student.branch_id else None,
        "class": _current_class(student),
        "relation": link.relation,
        "is_primary": link.is_primary,
    }


def _parent_dict(request, parent):
    user = parent.admin
    links = list(parents.visible_links(request.user, parent))
    return {
        "id": parent.pk,
        "login_id": user.login_id,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "name": user.get_full_name(),
        "phone": parent.phone,
        "children": [_link_dict(link) for link in links],
        # Children in branches this admin can't see exist, but aren't listed.
        "has_other_children": parent.child_links.count() > len(links),
    }


def _visible_parent(request, pk):
    qs = branching.filter_parents_for_user(request.user, Parent.objects.select_related("admin"))
    return qs.filter(pk=pk).first()


def _link_payload(data, student_id=None):
    payload = {
        "student": student_id if student_id is not None else data.get("student_id"),
        "relation": data.get("relation") or "guardian",
    }
    if str(data.get("is_primary", "")).strip().lower() not in ("", "false", "0", "off", "none"):
        payload["is_primary"] = "on"
    return payload


class ParentListView(APIView):
    """GET/POST /api/v1/admin/parents/

    POST creates the parent login together with its first child:
    ``{first_name, last_name, phone, password, student_id, relation, is_primary}``.
    """

    permission_classes = [IsAuthenticated, IsAdmin]

    def get(self, request):
        qs = branching.filter_parents_for_user(request.user, Parent.objects.select_related("admin"))
        search = (request.query_params.get("search") or "").strip()
        if search:
            qs = qs.filter(
                Q(admin__first_name__icontains=search)
                | Q(admin__last_name__icontains=search)
                | Q(admin__login_id__icontains=search)
                | Q(phone__icontains=search)
            )
        qs = qs.order_by("admin__first_name", "admin__last_name")
        return Response([_parent_dict(request, p) for p in qs])

    def post(self, request):
        form = ParentForm(request.data, user=request.user)
        link_form = ParentChildForm(_link_payload(request.data), user=request.user)
        if not (form.is_valid() & link_form.is_valid()):
            return _form_errors(form, link_form)
        parent = parents.create_parent(
            first_name=form.cleaned_data["first_name"],
            last_name=form.cleaned_data["last_name"],
            phone=form.cleaned_data["phone"],
            password=form.cleaned_data["password"],
            student=link_form.cleaned_data["student"],
            relation=link_form.cleaned_data["relation"],
            is_primary=link_form.cleaned_data["is_primary"],
        )
        return Response(_parent_dict(request, parent), status=status.HTTP_201_CREATED)


class ParentDetailView(APIView):
    """GET/PATCH/DELETE /api/v1/admin/parents/<pk>/

    PATCH takes any of first_name, last_name, phone, password (a new password
    resets it). DELETE removes the login; it is refused while the parent also
    has children in a branch this admin can't see.
    """

    permission_classes = [IsAuthenticated, IsAdmin]

    def get(self, request, pk):
        parent = _visible_parent(request, pk)
        if parent is None:
            return _not_found("Parent")
        return Response(_parent_dict(request, parent))

    def patch(self, request, pk):
        parent = _visible_parent(request, pk)
        if parent is None:
            return _not_found("Parent")
        data = {
            "first_name": parent.admin.first_name,
            "last_name": parent.admin.last_name,
            "phone": parent.phone,
        }
        data.update({k: request.data[k] for k in (*data, "password") if k in request.data})
        form = ParentForm(data, user=request.user, instance=parent)
        if not form.is_valid():
            return _form_errors(form)
        parents.update_parent(parent, **form.cleaned_data)
        return Response(_parent_dict(request, parent))

    def delete(self, request, pk):
        parent = _visible_parent(request, pk)
        if parent is None:
            return _not_found("Parent")
        if parents.has_hidden_children(request.user, parent):
            return Response(
                {
                    "detail": "This parent also has children in another branch. "
                    "Remove your children from the parent instead."
                },
                status=status.HTTP_403_FORBIDDEN,
            )
        parent.admin.delete()  # the Parent profile and its links go with the login
        return Response(status=status.HTTP_204_NO_CONTENT)


class ParentChildListView(APIView):
    """POST /api/v1/admin/parents/<pk>/children/  ``{student_id, relation, is_primary}``"""

    permission_classes = [IsAuthenticated, IsAdmin]

    def post(self, request, pk):
        parent = _visible_parent(request, pk)
        if parent is None:
            return _not_found("Parent")
        return _link(request, parent)


class ParentLinkByLoginView(APIView):
    """POST /api/v1/admin/parents/link-by-login/
    ``{login_id, phone, student_id, relation, is_primary}``

    Links a child to a parent this admin can't see yet (for example a School
    parent whose younger child joins the Study Center), using the login ID the
    parent gives the office. One login per family (D4). The phone must match
    too, so a mistyped login ID can't hand a child's data to another family.
    """

    permission_classes = [IsAuthenticated, IsAdmin]

    def post(self, request):
        login_id = str(request.data.get("login_id") or "").strip()
        digits = parents.phone_digits(str(request.data.get("phone") or ""))
        parent = None
        if login_id and digits:
            parent = (
                Parent.objects.select_related("admin")
                .filter(admin__login_id__iexact=login_id)
                .first()
            )
        if parent is None or parents.phone_digits(parent.phone) != digits:
            return _not_found("Parent with this login ID and phone")
        return _link(request, parent)


def _link(request, parent):
    form = ParentChildForm(_link_payload(request.data), user=request.user)
    if not form.is_valid():
        return _form_errors(form)
    parents.link_child(parent, **form.cleaned_data)
    return Response(_parent_dict(request, parent), status=status.HTTP_201_CREATED)


class ParentChildDetailView(APIView):
    """PATCH/DELETE /api/v1/admin/parents/<pk>/children/<student_pk>/

    PATCH changes relation and/or is_primary; DELETE unlinks the child (the
    parent login stays).
    """

    permission_classes = [IsAuthenticated, IsAdmin]

    def _link(self, request, pk, student_pk):
        parent = _visible_parent(request, pk)
        if parent is None:
            return None
        return parents.visible_links(request.user, parent).filter(student_id=student_pk).first()

    def patch(self, request, pk, student_pk):
        link = self._link(request, pk, student_pk)
        if link is None:
            return _not_found("Child link")
        data = {"relation": link.relation, "is_primary": link.is_primary}
        data.update({k: request.data[k] for k in data if k in request.data})
        form = ParentChildForm(_link_payload(data, student_id=student_pk), user=request.user)
        if not form.is_valid():
            return _form_errors(form)
        parents.update_link(
            link, relation=form.cleaned_data["relation"], is_primary=form.cleaned_data["is_primary"]
        )
        return Response(_link_dict(link))

    def delete(self, request, pk, student_pk):
        link = self._link(request, pk, student_pk)
        if link is None:
            return _not_found("Child link")
        link.delete()
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
