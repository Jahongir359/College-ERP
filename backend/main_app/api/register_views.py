"""School daily register (plan task P2.2): ``school/register/<class>/<date>/``.

The homeroom teacher marks every pupil of a class present, late (with the
arrival time) or absent once a day, with an optional short note. Pupils start
as present, so the teacher only changes the few who aren't (design screens 12
and 13). Admins of the class's branch and its subject teachers can read the
register; only the homeroom teacher saves it. Pupils and parents don't see a
whole class's register (they read their own marks through ``attendance/``).
Access rules live in ``branching.py``.
"""

from datetime import date, datetime

from django.db import transaction
from django.utils import timezone
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .. import branching
from ..models import Attendance, AttendanceReport, Enrollment, Group, Staff
from ..school import REGISTER_STATUS_NAMES, REGISTER_STATUSES

NOTE_MAX = AttendanceReport._meta.get_field("note").max_length


def _bad_request(detail):
    return Response(detail, status=status.HTTP_400_BAD_REQUEST)


def _time(value):
    return value.strftime("%H:%M") if value else None


def _parse_time(raw):
    """``"08:12"`` → time, ``None``/``""`` → None; anything else raises ValueError."""
    if raw in (None, ""):
        return None
    return datetime.strptime(str(raw), "%H:%M").time()


def _initials(user):
    letters = (user.last_name[:1] + user.first_name[:1]).upper()
    return letters or user.email[:1].upper()


def _check_day(group, day):
    """An error message when ``day`` can't have a register for ``group``, else None."""
    if day > timezone.localdate():
        return "A register can't be taken for a future date."
    session = group.session
    if session and not session.start_year <= day <= session.end_year:
        return "This date is outside the class's academic year."
    return None


class RegisterView(APIView):
    """GET/POST /api/v1/school/register/<pk>/<YYYY-MM-DD>/

    GET returns every pupil of the class with their mark for the day: the saved
    one, or ``present`` when the register hasn't been taken yet. POST saves
    ``{"records": [{student_id, status, arrival_time?, note?}]}``; pupils left
    out are present. Saving again replaces the day's marks.
    """

    permission_classes = [IsAuthenticated]

    def _class(self, request, pk):
        group = Group.objects.select_related("session", "teacher__admin").filter(pk=pk).first()
        return group if branching.user_can_view_register(request.user, group) else None

    def _day(self, raw):
        try:
            return date.fromisoformat(raw), None
        except ValueError:
            return None, _bad_request({"date": ["Use the format YYYY-MM-DD."]})

    def _pupils(self, group):
        return (
            Enrollment.objects.filter(group=group, is_active=True)
            .select_related("student__admin")
            .order_by("student__admin__last_name", "student__admin__first_name")
        )

    def _payload(self, request, group, day):
        register = (
            Attendance.objects.filter(group=group, date=day)
            .select_related("taken_by__admin")
            .first()
        )
        saved = {}
        if register is not None:
            saved = {r.student_id: r for r in register.attendancereport_set.all()}
        rows, counts = [], dict.fromkeys(REGISTER_STATUSES, 0)
        for enrollment in self._pupils(group):
            student = enrollment.student
            report = saved.get(student.pk)
            mark = REGISTER_STATUS_NAMES[report.status] if report else "present"
            counts[mark] += 1
            rows.append(
                {
                    "student_id": student.pk,
                    "name": student.admin.get_full_name(),
                    "initials": _initials(student.admin),
                    "status": mark,
                    "arrival_time": _time(report.arrival_time) if report else None,
                    "note": report.note if report else "",
                    "saved": report is not None,
                }
            )
        homeroom = group.teacher
        taken_by = register.taken_by if register else None
        return {
            "class": {"id": group.pk, "name": group.name},
            "date": day,
            "homeroom_teacher": homeroom.admin.get_full_name() if homeroom else "",
            "taken": register is not None,
            "taken_at": register.updated_at if register else None,
            "taken_by": taken_by.admin.get_full_name() if taken_by else "",
            "can_edit": branching.user_can_take_register(request.user, group)
            and _check_day(group, day) is None,
            "counts": counts,
            "students": rows,
        }

    def get(self, request, pk, day):
        group = self._class(request, pk)
        if group is None:
            return Response({"detail": "Class not found."}, status=status.HTTP_404_NOT_FOUND)
        day, err = self._day(day)
        if err:
            return err
        return Response(self._payload(request, group, day))

    def post(self, request, pk, day):
        group = self._class(request, pk)
        if group is None:
            return Response({"detail": "Class not found."}, status=status.HTTP_404_NOT_FOUND)
        if not branching.user_can_take_register(request.user, group):
            return Response(
                {"detail": "Only the class's homeroom teacher can save the register."},
                status=status.HTTP_403_FORBIDDEN,
            )
        day, err = self._day(day)
        if err:
            return err
        problem = _check_day(group, day)
        if problem:
            return _bad_request({"date": [problem]})

        records = request.data.get("records", [])
        if not isinstance(records, list):
            return _bad_request({"records": ["Send a list of records."]})
        pupils = {e.student_id for e in self._pupils(group)}
        marks, errors = {}, {}
        for index, rec in enumerate(records):
            if not isinstance(rec, dict):
                errors[str(index)] = ["Each record must be an object."]
                continue
            try:
                student_id = int(rec.get("student_id"))
            except (TypeError, ValueError):
                errors[str(index)] = ["student_id must be a number."]
                continue
            if student_id not in pupils:
                errors[str(index)] = ["This pupil is not in the class."]
                continue
            mark = rec.get("status")
            if mark not in REGISTER_STATUSES:
                errors[str(index)] = ["status must be present, late or absent."]
                continue
            try:
                arrival = _parse_time(rec.get("arrival_time"))
            except ValueError:
                errors[str(index)] = ["arrival_time must look like 08:12."]
                continue
            note = str(rec.get("note") or "").strip()
            if len(note) > NOTE_MAX:
                errors[str(index)] = [f"note can have at most {NOTE_MAX} characters."]
                continue
            marks[student_id] = (
                REGISTER_STATUSES[mark],
                arrival if mark == "late" else None,
                note,
            )
        if errors:
            return _bad_request({"records": errors})

        teacher = Staff.objects.filter(admin=request.user).first()
        with transaction.atomic():
            register, _ = Attendance.objects.select_for_update().get_or_create(
                group=group, date=day
            )
            register.taken_by = teacher
            register.save(update_fields=["taken_by", "updated_at"])
            existing = {r.student_id: r for r in register.attendancereport_set.all()}
            to_create, to_update = [], []
            for student_id in pupils:
                code, arrival, note = marks.get(student_id, (AttendanceReport.PRESENT, None, ""))
                report = existing.get(student_id)
                if report is None:
                    to_create.append(
                        AttendanceReport(
                            attendance=register,
                            student_id=student_id,
                            status=code,
                            arrival_time=arrival,
                            note=note,
                        )
                    )
                else:
                    report.status, report.arrival_time, report.note = code, arrival, note
                    to_update.append(report)
            AttendanceReport.objects.bulk_create(to_create)
            AttendanceReport.objects.bulk_update(to_update, ["status", "arrival_time", "note"])
            # A pupil who left the class keeps no mark on a re-saved register.
            register.attendancereport_set.exclude(student_id__in=pupils).delete()

        return Response(self._payload(request, group, day))
