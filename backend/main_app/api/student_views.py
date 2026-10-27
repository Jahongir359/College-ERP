"""Student-only API endpoints added for the ICEBERG mobile app.

Everything here is scoped to ``request.user.student`` — a student can never
reach another student's data through these views. The attendance summary is
also open to parents for a linked child (``?student=<id>``, see family.py).
"""

import calendar
import datetime

from django.db.models import Q
from django.http import FileResponse, Http404
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from ..models import (
    AttendanceReport,
    Group,
    ResultFile,
    Student,
)
from .family import student_for_request
from .permissions import IsStudent, IsStudentOrParent


def _get_student(request):
    try:
        return request.user.student
    except Student.DoesNotExist:
        return None


# ---------------------------------------------------------------------------
# Attendance summary (Attendance Hub)
# ---------------------------------------------------------------------------


class StudentAttendanceSummaryView(APIView):
    """Calendar + trend payload for the Attendance Hub screen.

    GET /api/v1/student/attendance/summary/?month=YYYY-MM&group_id=N
    """

    permission_classes = [IsStudentOrParent]

    def get(self, request):
        from django.utils import timezone as tz

        student, error = student_for_request(request)
        if error is not None:
            return error

        today = tz.localdate()
        month_param = request.query_params.get("month", "")
        try:
            month_start = datetime.datetime.strptime(month_param, "%Y-%m").date()
        except ValueError:
            month_start = today.replace(day=1)
        month_end = month_start.replace(
            day=calendar.monthrange(month_start.year, month_start.month)[1]
        )

        reports = AttendanceReport.objects.filter(student=student).select_related(
            "attendance__group"
        )
        group_id = request.query_params.get("group_id")
        if group_id:
            reports = reports.filter(attendance__group_id=group_id)

        # ── Overall stats ────────────────────────────────────────────────
        all_reports = list(reports.values_list("attendance__date", "status"))
        total = len(all_reports)
        present = sum(1 for _, s in all_reports if s == AttendanceReport.PRESENT)
        late = sum(1 for _, s in all_reports if s == AttendanceReport.LATE)
        absent = sum(1 for _, s in all_reports if s == AttendanceReport.ABSENT)
        overall_rate = round((present + late) / total * 100, 1) if total else None
        present_pct = round(present / total * 100, 1) if total else None

        # ── Streak: consecutive most-recent class days the student showed up
        # (present or late keeps the streak; an absence breaks it). Multiple
        # groups on one date collapse to that date's worst status.
        by_date = {}
        for d, s in all_reports:
            if d not in by_date or s == AttendanceReport.ABSENT:
                by_date[d] = s
        streak = 0
        for d in sorted(by_date.keys(), reverse=True):
            if by_date[d] == AttendanceReport.ABSENT:
                break
            streak += 1

        # ── Month calendar ───────────────────────────────────────────────
        month_reports = [
            {
                "date": d.isoformat(),
                "status": s,
                "group_id": gid,
                "group_name": gname,
            }
            for d, s, gid, gname in reports.filter(
                attendance__date__gte=month_start, attendance__date__lte=month_end
            )
            .order_by("attendance__date")
            .values_list(
                "attendance__date", "status", "attendance__group_id", "attendance__group__name"
            )
        ]

        # ── 12-week trend ────────────────────────────────────────────────
        week_start = today - datetime.timedelta(days=today.weekday())  # Monday
        weekly = []
        for i in range(11, -1, -1):
            ws = week_start - datetime.timedelta(weeks=i)
            we = ws + datetime.timedelta(days=6)
            wk = [s for d, s in all_reports if ws <= d <= we]
            pct = (
                round(sum(1 for s in wk if s != AttendanceReport.ABSENT) / len(wk) * 100, 1)
                if wk
                else None
            )
            weekly.append({"start": ws.isoformat(), "pct": pct, "count": len(wk)})

        # ── Group filter options ─────────────────────────────────────────
        groups = [
            {"id": g.id, "name": g.name}
            for g in Group.objects.filter(
                enrollment__student=student, enrollment__is_active=True
            ).distinct()
        ]

        # Teacher emails for the "Email Teacher" quick action.
        teachers = [
            {
                "name": g.teacher.admin.get_full_name(),
                "email": g.teacher.admin.email,
                "group_name": g.name,
            }
            for g in Group.objects.filter(
                enrollment__student=student, enrollment__is_active=True, teacher__isnull=False
            )
            .select_related("teacher__admin")
            .distinct()
        ]

        return Response(
            {
                "overall_rate": overall_rate,
                "present_pct": present_pct,
                "present_count": present,
                "late_count": late,
                "absent_count": absent,
                "total_count": total,
                "streak_days": streak,
                "month": month_start.strftime("%Y-%m"),
                "days": month_reports,
                "weekly_trend": weekly,
                "groups": groups,
                "teachers": teachers,
            }
        )


# ---------------------------------------------------------------------------
# Result files
# ---------------------------------------------------------------------------


def _student_result_files(student):
    enrolled = Group.objects.filter(enrollment__student=student, enrollment__is_active=True)
    return (
        ResultFile.objects.filter(
            Q(student=student) | (Q(student__isnull=True) & Q(group__in=enrolled))
        )
        .select_related("group", "uploaded_by__admin")
        .order_by("-uploaded_at")
    )


class StudentResultFileListView(APIView):
    """GET /api/v1/result-files/ — downloadable result documents for the student."""

    permission_classes = [IsStudent]

    def get(self, request):
        student = _get_student(request)
        if student is None:
            return Response(
                {"detail": "Student profile not found."}, status=status.HTTP_403_FORBIDDEN
            )

        files = []
        for rf in _student_result_files(student):
            try:
                size = rf.file.size if rf.file else 0
            except (OSError, ValueError):
                size = 0
            files.append(
                {
                    "id": rf.id,
                    "title": rf.title,
                    "description": rf.description,
                    "group_id": rf.group_id,
                    "group_name": rf.group.name if rf.group else None,
                    "filename": rf.filename,
                    "size": size,
                    "uploaded_at": rf.uploaded_at.isoformat(),
                    "download_url": request.build_absolute_uri(
                        f"/api/v1/result-files/{rf.id}/download/"
                    ),
                }
            )
        return Response({"files": files})


class StudentResultFileDownloadView(APIView):
    """GET /api/v1/result-files/<pk>/download/ — authenticated file stream."""

    permission_classes = [IsStudent]

    def get(self, request, pk):
        student = _get_student(request)
        if student is None:
            return Response(
                {"detail": "Student profile not found."}, status=status.HTTP_403_FORBIDDEN
            )
        rf = _student_result_files(student).filter(pk=pk).first()
        if rf is None or not rf.file:
            raise Http404
        try:
            return FileResponse(rf.file.open("rb"), as_attachment=True, filename=rf.filename)
        except (OSError, ValueError):
            raise Http404


# ---------------------------------------------------------------------------
# App settings
# ---------------------------------------------------------------------------

SETTINGS_DEFAULTS = {
    "theme": "system",  # system | light | dark
    "accent": "ice",  # ice | cyan | blue | lime | purple | pink | orange
    "font_size": "medium",  # small | medium | large
    "language": "uz",  # uz | en | ru | ko  (Uzbek is the default)
    "notifications": {
        "assignments": True,
        "vocabulary": True,
        "payments": True,
        "announcements": True,
    },
}

_THEME_VALUES = {"system", "light", "dark"}
_ACCENT_VALUES = {"ice", "cyan", "blue", "lime", "purple", "pink", "orange"}
_FONT_VALUES = {"small", "medium", "large"}
_LANGUAGE_VALUES = {"uz", "en", "ru", "ko"}

# Student.theme uses "bright" where the app uses "light".
_THEME_TO_MODEL = {
    "light": Student.THEME_BRIGHT,
    "dark": Student.THEME_DARK,
    "system": Student.THEME_SYSTEM,
}
_THEME_FROM_MODEL = {
    Student.THEME_BRIGHT: "light",
    Student.THEME_DARK: "dark",
    Student.THEME_SYSTEM: "system",
}


class StudentSettingsView(APIView):
    """GET/PATCH /api/v1/student/settings/ — mobile app preferences."""

    permission_classes = [IsStudent]

    def _payload(self, student):
        stored = student.app_settings or {}
        merged = {**SETTINGS_DEFAULTS, **stored}
        merged["notifications"] = {
            **SETTINGS_DEFAULTS["notifications"],
            **(stored.get("notifications") or {}),
        }
        merged["theme"] = _THEME_FROM_MODEL.get(student.theme, "system")
        return merged

    def get(self, request):
        student = _get_student(request)
        if student is None:
            return Response(
                {"detail": "Student profile not found."}, status=status.HTTP_403_FORBIDDEN
            )
        return Response(self._payload(student))

    def patch(self, request):
        student = _get_student(request)
        if student is None:
            return Response(
                {"detail": "Student profile not found."}, status=status.HTTP_403_FORBIDDEN
            )

        data = request.data
        stored = dict(student.app_settings or {})
        errors = {}

        def _take(key, allowed):
            if key in data:
                value = str(data[key])
                if value not in allowed:
                    errors[key] = f"Must be one of: {', '.join(sorted(allowed))}."
                else:
                    stored[key] = value

        _take("theme", _THEME_VALUES)
        _take("accent", _ACCENT_VALUES)
        _take("font_size", _FONT_VALUES)
        _take("language", _LANGUAGE_VALUES)

        if "notifications" in data:
            incoming = data["notifications"]
            if not isinstance(incoming, dict):
                errors["notifications"] = "Must be an object of boolean flags."
            else:
                current = {
                    **SETTINGS_DEFAULTS["notifications"],
                    **(stored.get("notifications") or {}),
                }
                for k, v in incoming.items():
                    if k in SETTINGS_DEFAULTS["notifications"]:
                        current[k] = bool(v)
                stored["notifications"] = current

        if errors:
            return Response(errors, status=status.HTTP_400_BAD_REQUEST)

        update_fields = ["app_settings"]
        if "theme" in stored:
            student.theme = _THEME_TO_MODEL[stored["theme"]]
            update_fields.append("theme")
        student.app_settings = stored
        student.save(update_fields=update_fields)
        return Response(self._payload(student))
