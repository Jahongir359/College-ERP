"""School board: the School admin's home page on the web (plan task P3.8).

Admins only (D15). Everything on the page is limited to the School branches
and classes the admin can see, through ``branching.py``.
"""

from django.db.models import Q
from django.shortcuts import render
from django.utils import timezone
from django.utils.translation import gettext as _

from . import branching
from .decorators import admin_only
from .models import Branch, Enrollment, Group, ParentChild, Session, Staff
from .school import register_summaries


def _current_term(year, today):
    """The quarter ``today`` falls in, else the last one that started, else None."""
    terms = year.terms.order_by("start_date")
    term = terms.filter(start_date__lte=today, end_date__gte=today).first()
    if term is None:
        term = terms.filter(start_date__lte=today).last()
    return term


@admin_only
def school_board(request):
    user = request.user
    today = timezone.localdate()
    branches = branching.filter_branches_for_user(
        user, Branch.objects.filter(brand=Branch.BRAND_SCHOOL)
    ).order_by("name")
    year = Session.current()
    term = _current_term(year, today) if year else None

    classes = Group.objects.none()
    if year is not None:
        classes = (
            branching.filter_classes_for_user(user, Group.objects.select_related("teacher__admin"))
            .filter(session=year)
            .order_by("grade_level", "letter")
        )
    pupil_ids = (
        Enrollment.objects.filter(group__in=classes, is_active=True)
        .values_list("student_id", flat=True)
        .distinct()
    )
    links = branching.filter_parent_links_for_user(user, ParentChild.objects.all()).filter(
        student_id__in=pupil_ids
    )
    parent_ids = links.values_list("parent_id", flat=True).distinct()
    teachers = Staff.objects.filter(
        Q(group__in=classes) | Q(class_subjects__group__in=classes)
    ).distinct()

    summaries = register_summaries(classes, today) if year is not None else {}
    class_rows = [
        {"group": group, **summaries.get(group.pk, {"taken": False})} for group in classes
    ]
    not_taken = [row for row in class_rows if not row["taken"]]

    never_signed_in = (
        links.filter(parent__admin__last_login__isnull=True)
        .values_list("parent_id", flat=True)
        .distinct()
        .count()
    )

    context = {
        "page_title": _("School board"),
        "today": today,
        "has_school": branches.exists(),
        "show_branch": branches.count() > 1,
        "branches": branches,
        "year": year,
        "term": term,
        "counts": {
            "pupils": pupil_ids.count(),
            "classes": len(class_rows),
            "teachers": teachers.count(),
            "parents": parent_ids.count(),
        },
        "class_rows": class_rows,
        "taken_count": len(class_rows) - len(not_taken),
        "not_taken": not_taken,
        "pupils_without_parent": pupil_ids.count()
        - links.values_list("student_id", flat=True).distinct().count(),
        "parents_never_signed_in": never_signed_in,
    }
    return render(request, "hod_template/school/board.html", context)
