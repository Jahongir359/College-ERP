"""Admin web pages for Iceberg School: classes, their students and subjects, and
the academic year with its quarters (plan task P3.1, mockup 16).

Admins only (D15). Which classes an admin sees is decided in ``branching.py``;
academic years are shared by all branches, so only super admins change them.
"""

from django.contrib import messages
from django.db import IntegrityError, transaction
from django.db.models import Count, Q
from django.utils import timezone
from django.utils.dates import WEEKDAYS
from django.http import Http404
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.translation import gettext as _
from django.views.decorators.http import require_POST

from . import branching
from .decorators import admin_only, super_admin_only
from .models import (
    ClassSubject,
    Enrollment,
    Group,
    ParentChild,
    Session,
    Term,
    lesson_clashes,
)
from .school import register_summaries
from .school_forms import ClassForm, ClassStudentForm, ClassSubjectForm, TermForm


def _classes(request):
    return branching.filter_classes_for_user(
        request.user, Group.objects.select_related("branch", "session", "teacher__admin")
    )


def _class_or_404(request, pk):
    group = _classes(request).filter(pk=pk).first()
    if group is None:
        raise Http404
    return group


@admin_only
def classes(request):
    """Sinflar: the classes of the chosen academic year (current by default)."""
    years = Session.objects.order_by("-start_year")
    year = None
    if request.GET.get("year", "").isdigit():
        year = years.filter(pk=request.GET["year"]).first()
    year = year or Session.current() or years.first()
    rows = (
        _classes(request)
        .filter(session=year)
        .annotate(
            student_count=Count("enrollment", filter=Q(enrollment__is_active=True), distinct=True),
            subject_count=Count("class_subjects", distinct=True),
        )
        .order_by("branch__name", "grade_level", "letter")
    )
    active = Enrollment.objects.filter(is_active=True, group__in=rows)
    # Today's register per class (keldi / kech / yo'q), as on the register report.
    today = timezone.localdate()
    summary = register_summaries(rows, today)
    rows = list(rows)
    for row in rows:
        row.today = summary.get(row.pk, {"taken": False, "present": 0, "late": 0, "absent": 0})
    context = {
        "page_title": _("Classes"),
        "classes": rows,
        "years": years,
        "year": year,
        "show_branch": len({row.branch_id for row in rows}) > 1,
        "total_students": active.values("student_id").distinct().count(),
        "taken_today": sum(1 for row in rows if row.today["taken"]),
        "linked_students": ParentChild.objects.filter(student_id__in=active.values("student_id"))
        .values("student_id")
        .distinct()
        .count(),
    }
    return render(request, "hod_template/school/classes.html", context)


def _class_form(request, instance=None):
    form = ClassForm(request.POST or None, instance=instance, user=request.user)
    if request.method == "POST" and form.is_valid():
        group = form.save()
        messages.success(request, _("Class %(name)s saved.") % {"name": group.name})
        return redirect("school_class_detail", pk=group.pk)
    title = _("Edit class %(name)s") % {"name": instance.name} if instance else _("New class")
    return render(
        request,
        "hod_template/school/class_form.html",
        {"page_title": title, "form": form, "group": instance},
    )


@admin_only
def class_add(request):
    return _class_form(request)


@admin_only
def class_edit(request, pk):
    return _class_form(request, instance=_class_or_404(request, pk))


@admin_only
def class_detail(request, pk):
    group = _class_or_404(request, pk)
    enrollments = (
        Enrollment.objects.filter(group=group, is_active=True)
        .select_related("student__admin")
        .annotate(parent_count=Count("student__parent_links", distinct=True))
        .order_by("student__admin__last_name", "student__admin__first_name")
    )
    subjects = group.class_subjects.select_related("subject", "teacher__admin").order_by(
        "subject__name"
    )
    context = {
        "page_title": _("Class %(name)s") % {"name": group.name},
        "group": group,
        "enrollments": enrollments,
        "subjects": [
            (cs, ClassSubjectForm(instance=cs, user=request.user, group=group, prefix=f"cs{cs.pk}"))
            for cs in subjects
        ],
        "weekly_hours": sum(cs.weekly_hours for cs in subjects),
        "student_form": ClassStudentForm(user=request.user, group=group),
        "subject_form": ClassSubjectForm(user=request.user, group=group),
    }
    return render(request, "hod_template/school/class_detail.html", context)


def _form_errors(request, form):
    for errors in form.errors.values():
        for error in errors:
            messages.error(request, error)


@admin_only
@require_POST
def class_student_add(request, pk):
    group = _class_or_404(request, pk)
    form = ClassStudentForm(request.POST, user=request.user, group=group)
    if form.is_valid():
        student = form.cleaned_data["student"]
        enrollment, created = Enrollment.objects.get_or_create(
            student=student, group=group, defaults={"is_active": True}
        )
        if not created and not enrollment.is_active:
            enrollment.is_active = True
            enrollment.save(update_fields=["is_active"])
        messages.success(
            request,
            _("%(student)s added to %(name)s.")
            % {"student": student.admin.get_full_name(), "name": group.name},
        )
    else:
        _form_errors(request, form)
    return redirect("school_class_detail", pk=group.pk)


@admin_only
@require_POST
def class_student_remove(request, pk, student_pk):
    """Take a student out of the class. The enrollment is kept, inactive, for history."""
    group = _class_or_404(request, pk)
    enrollment = get_object_or_404(Enrollment, group=group, student_id=student_pk, is_active=True)
    enrollment.is_active = False
    enrollment.save(update_fields=["is_active"])
    messages.success(
        request,
        _("%(student)s removed from %(name)s.")
        % {"student": enrollment.student.admin.get_full_name(), "name": group.name},
    )
    return redirect("school_class_detail", pk=group.pk)


def _teacher_clashes(class_subject):
    """Lessons of ``class_subject`` (today or later) that its new teacher cannot take."""
    today = timezone.localdate()
    found = []
    for lesson in class_subject.lessons.filter(Q(valid_to__isnull=True) | Q(valid_to__gte=today)):
        lesson.class_subject = class_subject
        for kind, other in lesson_clashes(lesson):
            if kind == "teacher":
                found.append((lesson, other))
    return found


def _save_class_subject(request, form):
    if not form.is_valid():
        _form_errors(request, form)
        return
    if form.instance.pk and "teacher" in form.changed_data and form.instance.teacher_id:
        clashes = _teacher_clashes(form.instance)
        if clashes:
            for lesson, other in clashes:
                messages.error(
                    request,
                    _(
                        "%(teacher)s already teaches %(class)s at that time (%(day)s, period %(period)s)."
                    )
                    % {
                        "teacher": form.instance.teacher.admin.get_full_name(),
                        "class": other.group.name,
                        "day": WEEKDAYS[lesson.weekday - 1],
                        "period": lesson.period.number,
                    },
                )
            return
    try:
        with transaction.atomic():
            form.save()
    except IntegrityError:
        messages.error(request, _("This class already has this subject."))
        return
    messages.success(request, _("Subjects saved."))


@admin_only
@require_POST
def class_subject_add(request, pk):
    group = _class_or_404(request, pk)
    _save_class_subject(request, ClassSubjectForm(request.POST, user=request.user, group=group))
    return redirect("school_class_detail", pk=group.pk)


@admin_only
@require_POST
def class_subject_edit(request, pk, cs_pk):
    group = _class_or_404(request, pk)
    cs = get_object_or_404(ClassSubject, pk=cs_pk, group=group)
    form = ClassSubjectForm(
        request.POST, instance=cs, user=request.user, group=group, prefix=f"cs{cs.pk}"
    )
    _save_class_subject(request, form)
    return redirect("school_class_detail", pk=group.pk)


@admin_only
@require_POST
def class_subject_remove(request, pk, cs_pk):
    group = _class_or_404(request, pk)
    cs = get_object_or_404(ClassSubject, pk=cs_pk, group=group)
    cs.delete()
    messages.success(request, _("%(subject)s removed.") % {"subject": cs.subject.name})
    return redirect("school_class_detail", pk=group.pk)


# ── Academic years and quarters ─────────────────────────────────────────────


@admin_only
def school_years(request):
    """Oʻquv yili: every academic year with its quarters. Super admins can change them."""
    years = Session.objects.prefetch_related("terms").order_by("-start_year")
    current = Session.current()
    can_edit = branching.is_super_admin(request.user)
    context = {
        "page_title": _("Academic year"),
        "years": years,
        "current": current,
        "can_edit": can_edit,
        # One "add a quarter" form per year and one edit form per quarter (super admins).
        "add_forms": {year.pk: TermForm(session=year, prefix=f"y{year.pk}") for year in years}
        if can_edit
        else {},
        "edit_forms": {
            term.pk: TermForm(instance=term, session=year, prefix=f"t{term.pk}")
            for year in years
            for term in year.terms.all()
        }
        if can_edit
        else {},
    }
    return render(request, "hod_template/school/years.html", context)


@super_admin_only
@require_POST
def school_year_make_current(request, pk):
    year = get_object_or_404(Session, pk=pk)
    year.is_current = True
    year.save()
    messages.success(request, _("%(year)s is now the current academic year.") % {"year": year})
    return redirect("school_years")


@super_admin_only
@require_POST
def school_term_add(request, pk):
    year = get_object_or_404(Session, pk=pk)
    form = TermForm(request.POST, session=year, prefix=f"y{year.pk}")
    if form.is_valid():
        term = form.save()
        messages.success(request, _("%(term)s saved.") % {"term": term.name})
    else:
        _form_errors(request, form)
    return redirect("school_years")


@super_admin_only
@require_POST
def school_term_edit(request, term_pk):
    term = get_object_or_404(Term, pk=term_pk)
    form = TermForm(request.POST, instance=term, session=term.session, prefix=f"t{term.pk}")
    if form.is_valid():
        form.save()
        messages.success(request, _("%(term)s saved.") % {"term": term.name})
    else:
        _form_errors(request, form)
    return redirect("school_years")


@super_admin_only
@require_POST
def school_term_delete(request, term_pk):
    term = get_object_or_404(Term, pk=term_pk)
    term.delete()
    messages.success(request, _("%(term)s deleted.") % {"term": term.name})
    return redirect("school_years")
