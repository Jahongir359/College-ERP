"""Admin web pages for the Iceberg School timetable: bell times per branch and
the weekly timetable of a class (plan task P3.2, mockup 17).

Admins only (D15). The timetable is edited as one week grid and saved at once;
when a cell would double-book a teacher, room or class nothing is saved and the
clashing cells are shown in red. Changes take effect from a chosen date, so the
weeks before it keep the old timetable (``Lesson.valid_from``/``valid_to``).
"""

from datetime import date, timedelta

from django.contrib import messages
from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import ProtectedError, Q
from django.http import Http404
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.utils.dates import WEEKDAYS
from django.utils.translation import gettext as _
from django.views.decorators.http import require_POST

from . import branching
from .decorators import admin_only
from .models import BellPeriod, Branch, Group, Lesson, LessonClashError, Session, lesson_clashes
from .school_forms import BellPeriodForm

DAYS = [(number, WEEKDAYS[number - 1]) for number in range(1, 7)]  # Monday … Saturday


def _clash_message(kind, other):
    if kind == "teacher":
        return _("Teacher busy: %(class)s") % {"class": other.group.name}
    if kind == "room":
        return _("Room busy: %(class)s") % {"class": other.group.name}
    return _("The class already has a lesson at this time.")


# ── Bell times ──────────────────────────────────────────────────────────────


def _school_branches(request):
    return branching.filter_branches_for_user(
        request.user, Branch.objects.filter(brand=Branch.BRAND_SCHOOL)
    ).order_by("name")


def _periods(request):
    return branching.filter_bell_periods_for_user(request.user, BellPeriod.objects.all())


def _form_errors(request, form):
    for errors in form.errors.values():
        for error in errors:
            messages.error(request, error)


@admin_only
def bells(request):
    """Qoʻngʻiroqlar: the bell periods of each School branch the admin manages."""
    branches = []
    for branch in _school_branches(request):
        periods = _periods(request).filter(branch=branch)  # scoping-ok: narrows a scoped list
        branches.append(
            {
                "branch": branch,
                "periods": [
                    (p, BellPeriodForm(instance=p, branch=branch, prefix=f"p{p.pk}"))
                    for p in periods
                ],
                "add_form": BellPeriodForm(
                    branch=branch,
                    prefix=f"b{branch.pk}",
                    initial={"number": len(periods) + 1},
                ),
            }
        )
    return render(
        request,
        "hod_template/school/bells.html",
        {"page_title": _("Bell times"), "branches": branches},
    )


@admin_only
@require_POST
def bell_add(request, branch_pk):
    branch = get_object_or_404(_school_branches(request), pk=branch_pk)
    form = BellPeriodForm(request.POST, branch=branch, prefix=f"b{branch.pk}")
    if form.is_valid():
        period = form.save()
        messages.success(request, _("Period %(number)s saved.") % {"number": period.number})
    else:
        _form_errors(request, form)
    return redirect("school_bells")


@admin_only
@require_POST
def bell_edit(request, pk):
    period = get_object_or_404(_periods(request), pk=pk)
    form = BellPeriodForm(request.POST, instance=period, branch=period.branch, prefix=f"p{pk}")
    if form.is_valid():
        form.save()
        messages.success(request, _("Period %(number)s saved.") % {"number": period.number})
    else:
        _form_errors(request, form)
    return redirect("school_bells")


@admin_only
@require_POST
def bell_delete(request, pk):
    period = get_object_or_404(_periods(request), pk=pk)
    try:
        period.delete()
    except ProtectedError:
        messages.error(request, _("Lessons use this period. Move or delete them first."))
    else:
        messages.success(request, _("Period %(number)s deleted.") % {"number": period.number})
    return redirect("school_bells")


# ── Timetable ───────────────────────────────────────────────────────────────


def _parse_date(raw):
    try:
        return date.fromisoformat(raw)
    except (TypeError, ValueError):
        return None


def _default_start(group):
    """Today, kept inside the class's academic year."""
    today = timezone.localdate()
    session = group.session
    if session is None:
        return today
    return min(max(today, session.start_year), session.end_year)


def _lessons_on(group, day):
    """The class's lessons in force on ``day``, keyed by (weekday, period id)."""
    lessons = group.lessons.filter(
        Q(valid_from__isnull=True) | Q(valid_from__lte=day),
        Q(valid_to__isnull=True) | Q(valid_to__gte=day),
    ).select_related("period", "group", "class_subject__subject", "class_subject__teacher__admin")
    return {(lesson.weekday, lesson.period_id): lesson for lesson in lessons}


def _save_week(group, periods, current, chosen, start):
    """Apply the grid. ``chosen`` maps (weekday, period id) to a ClassSubject or None.

    Returns {cell: [messages]} for cells that clash; then nothing is saved.
    A lesson that already ran before ``start`` is ended the day before;
    one that starts on ``start`` (or a whole-year edit) is replaced.
    """
    session = group.session
    whole_year = session is None or start <= session.start_year
    errors = {}
    period_by_pk = {p.pk: p for p in periods}
    with transaction.atomic():
        changed = [
            cell
            for cell, cs in chosen.items()
            if (current[cell].class_subject_id if cell in current else None)
            != (cs.pk if cs else None)
        ]
        for cell in changed:
            old = current.get(cell)
            if old is None:
                continue
            if whole_year or (old.valid_from and old.valid_from >= start):
                old.delete()
            else:
                old.valid_to = start - timedelta(days=1)
                old.save(update_fields=["valid_to"])
        for cell in changed:
            cs = chosen[cell]
            if cs is None:
                continue
            old = current.get(cell)
            lesson = Lesson(
                group=group,
                class_subject=cs,
                weekday=cell[0],
                period=period_by_pk[cell[1]],
                room=old.room if old else "",
                valid_from=None if whole_year else start,
            )
            try:
                lesson.clean()
            except LessonClashError as exc:
                errors[cell] = [_clash_message(kind, other) for kind, other in exc.clashes]
                continue
            except ValidationError as exc:
                errors[cell] = exc.messages
                continue
            lesson.save()
        if errors:
            transaction.set_rollback(True)
    return errors


def _existing_clashes(current):
    """Clashes already in the saved timetable (e.g. after a teacher change)."""
    return {
        cell: [_clash_message(kind, other) for kind, other in lesson_clashes(lesson)]
        for cell, lesson in current.items()
        if lesson_clashes(lesson)
    }


@admin_only
def timetable(request):
    """Dars jadvali: the week grid of one class, edited and saved at once."""
    classes = branching.filter_classes_for_user(
        request.user, Group.objects.select_related("branch", "session")
    )
    year = Session.current()
    picker = classes.filter(session=year) if year else classes
    picker = picker.order_by("branch__name", "grade_level", "letter")
    group = None
    if request.GET.get("class", "").isdigit():
        group = classes.filter(pk=request.GET["class"]).first()
        if group is None:
            raise Http404
    group = group or picker.first()
    context = {"page_title": _("Timetable"), "picker": picker, "group": group, "days": DAYS}
    if group is None:
        return render(request, "hod_template/school/timetable.html", context)

    session = group.session
    start = _parse_date(request.POST.get("start") or request.GET.get("start"))
    start = start or _default_start(group)
    out_of_year = session and not session.start_year <= start <= session.end_year
    periods = list(
        branching.filter_bell_periods_for_user(request.user, BellPeriod.objects.all())
        .filter(branch_id=group.branch_id)  # scoping-ok: narrows a scoped list
        .order_by("start_time")
    )
    subjects = list(
        group.class_subjects.select_related("subject", "teacher__admin").order_by("subject__name")
    )
    by_pk = {str(cs.pk): cs for cs in subjects}
    current = _lessons_on(group, start)

    errors = {}
    if request.method == "POST":
        chosen = {}
        for weekday, _name in DAYS:
            for period in periods:
                raw = request.POST.get(f"cell-{weekday}-{period.pk}", "")
                chosen[(weekday, period.pk)] = by_pk.get(raw)
        if out_of_year:
            messages.error(request, _("The date must be inside the class's academic year."))
        else:
            errors = _save_week(group, periods, current, chosen, start)
            if not errors:
                messages.success(request, _("Timetable of %(name)s saved.") % {"name": group.name})
                return redirect(f"{request.path}?class={group.pk}&start={start.isoformat()}")
            messages.error(request, _("Nothing was saved: fix the red cells first."))
        selected = {cell: cs.pk if cs else None for cell, cs in chosen.items()}
    else:
        errors = _existing_clashes(current)
        selected = {cell: lesson.class_subject_id for cell, lesson in current.items()}

    rows = []
    for period in periods:
        cells = []
        for weekday, day_name in DAYS:
            cell = (weekday, period.pk)
            cells.append(
                {
                    "name": f"cell-{weekday}-{period.pk}",
                    "day": day_name,
                    "selected": selected.get(cell),
                    "lesson": current.get(cell),
                    "errors": errors.get(cell, []),
                }
            )
        rows.append({"period": period, "cells": cells})
    planned = {cs.pk: 0 for cs in subjects}
    for value in selected.values():
        if value in planned:
            planned[value] += 1
    context.update(
        {
            "rows": rows,
            "subjects": subjects,
            "hours": [(cs, planned[cs.pk]) for cs in subjects],
            "start": start,
            "whole_year": session is None or start <= session.start_year,
            "has_errors": bool(errors),
        }
    )
    return render(request, "hod_template/school/timetable.html", context)
