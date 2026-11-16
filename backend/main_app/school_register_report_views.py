"""Admin web register report for Iceberg School (plan task P3.7, mockup 19).

Read-only (D15: homeroom teachers take the register in the app, P2.2). For a
date and an optional class: which classes took the register and when, the
present/late/absent counts and attendance rate per class, and the absent and
late pupils with arrival time and note, also as a CSV file. Which classes an
admin sees is decided in ``branching.py``.
"""

import csv
from datetime import date

from django.db.models import Count, Q
from django.http import HttpResponse
from django.shortcuts import render
from django.utils import timezone
from django.utils.translation import gettext as _
from django.utils.translation import pgettext

from . import branching
from .decorators import admin_only
from .models import Attendance, AttendanceReport, Group
from .school import register_summaries


def _day(raw):
    try:
        return date.fromisoformat(raw)
    except (TypeError, ValueError):
        return timezone.localdate()


def _rate(present, late, absent):
    """Share of pupils who came (present or late), in whole percent, or None."""
    total = present + late + absent
    return round(100 * (present + late) / total) if total else None


def _report(request, day):
    """The classes, totals and absent/late pupils for ``day`` (scoped to the user)."""
    in_year = branching.filter_classes_for_user(
        request.user,
        Group.objects.filter(
            is_archived=False, session__start_year__lte=day, session__end_year__gte=day
        ),
    )
    all_classes = list(in_year.order_by("grade_level", "letter", "branch__name"))
    group = None
    if request.GET.get("class", "").isdigit():
        group = next((c for c in all_classes if c.pk == int(request.GET["class"])), None)
    classes = in_year.filter(pk=group.pk) if group else in_year

    summary = register_summaries(classes, day)
    taken_at = dict(
        Attendance.objects.filter(group__in=classes.values("pk"), date=day).values_list(
            "group_id", "created_at"
        )
    )
    rows = []
    for c in (
        classes.select_related("teacher__admin", "branch")
        .annotate(pupils=Count("enrollment", filter=Q(enrollment__is_active=True), distinct=True))
        .order_by("grade_level", "letter", "branch__name")
    ):
        counts = summary.get(c.pk, {"taken": False, "present": 0, "late": 0, "absent": 0})
        at = taken_at.get(c.pk)
        rows.append(
            {
                "group": c,
                "teacher": c.teacher.admin.get_full_name() if c.teacher else "",
                "pupils": c.pupils,
                "taken_at": timezone.localtime(at) if at else None,
                **counts,
                "rate": _rate(counts["present"], counts["late"], counts["absent"])
                if counts["taken"]
                else None,
            }
        )

    present = sum(r["present"] for r in rows)
    late = sum(r["late"] for r in rows)
    absent = sum(r["absent"] for r in rows)
    pupils = (
        AttendanceReport.objects.filter(
            attendance__group__in=classes.values("pk"),
            attendance__date=day,
            status__in=[AttendanceReport.ABSENT, AttendanceReport.LATE],
        )
        .select_related("student__admin", "attendance__group")
        # Absent pupils first, then late ones by arrival time (mockup 19).
        .order_by(
            "status", "arrival_time", "attendance__group__grade_level", "student__admin__last_name"
        )
    )
    return {
        "day": day,
        "group": group,
        "all_classes": all_classes,
        "rows": rows,
        "show_branch": len({r["group"].branch_id for r in rows}) > 1,
        "taken_count": sum(1 for r in rows if r["taken"]),
        "present": present,
        "late": late,
        "absent": absent,
        "rate": _rate(present, late, absent),
        "pupils": list(pupils),
    }


@admin_only
def register_report(request):
    """Davomat hisoboti: the register of every class for one day."""
    report = _report(request, _day(request.GET.get("date")))
    if request.GET.get("export") == "csv":
        return _report_csv(report)
    report["page_title"] = _("Register report")
    report["is_today"] = report["day"] == timezone.localdate()
    return render(request, "hod_template/school/register_report.html", report)


# A cell starting with one of these is read as a formula by Excel and
# LibreOffice (CSV injection); a leading apostrophe makes it plain text.
_FORMULA_START = ("=", "+", "-", "@", "\t", "\r")


def _safe(value):
    if isinstance(value, str) and value.startswith(_FORMULA_START):
        return "'" + value
    return value


class _SafeWriter:
    """``csv.writer`` that neutralises formula-like text cells."""

    def __init__(self, response):
        self._writer = csv.writer(response)

    def writerow(self, row):
        self._writer.writerow([_safe(v) for v in row])


def _report_csv(report):
    day = report["day"]
    response = HttpResponse(content_type="text/csv; charset=utf-8")
    response["Content-Disposition"] = f'attachment; filename="register-{day:%Y-%m-%d}.csv"'
    response.write("﻿")  # so Excel reads Uzbek and Russian letters as UTF-8
    writer = _SafeWriter(response)
    writer.writerow(
        [
            _("Date"),
            _("Class"),
            _("Homeroom teacher"),
            _("Students"),
            _("Taken at"),
            _("Present"),
            _("Late"),
            _("Absent"),
            _("Attendance %"),
        ]
    )
    for r in report["rows"]:
        writer.writerow(
            [
                day.isoformat(),
                r["group"].name,
                r["teacher"],
                r["pupils"],
                f"{r['taken_at']:%H:%M}" if r["taken_at"] else _("Not taken"),
                r["present"] if r["taken"] else "",
                r["late"] if r["taken"] else "",
                r["absent"] if r["taken"] else "",
                r["rate"] if r["rate"] is not None else "",
            ]
        )
    writer.writerow([])
    writer.writerow(
        [_("Date"), _("Class"), _("Student"), _("Status"), _("Arrival time"), _("Note")]
    )
    for p in report["pupils"]:
        writer.writerow(
            [
                day.isoformat(),
                p.attendance.group.name,
                p.student.admin.get_full_name(),
                pgettext("one pupil", "Late")
                if p.status == AttendanceReport.LATE
                else pgettext("one pupil", "Absent"),
                f"{p.arrival_time:%H:%M}" if p.arrival_time else "",
                p.note,
            ]
        )
    return response
