"""Creating parents and linking them to children (plan task P1.7).

The admin form (``school_forms.py``) and the admin API (``api/school_views.py``)
both call these helpers, so the rules live in one place. Who may see which
parent or child is decided in ``branching.py``.

Rules:
  * A parent is created together with their first child, so a branch admin can
    always see the parent they just made.
  * One login per family (D4): a phone number already used by another parent
    is refused; the office links the child to that parent instead.
  * A child has at most one primary contact; marking a link primary clears it
    on the child's other links.
"""

import re

from django.db import transaction

from . import branching
from .models import CustomUser, Parent, ParentChild, Student

LOGIN_PREFIX = "PR"


def phone_digits(phone):
    """Digits used to compare phones: the last 9 (an Uzbek number without +998)."""
    return re.sub(r"\D", "", phone or "")[-9:]


def parent_with_phone(phone, exclude_pk=None):
    """The parent already using this phone number (compared by digits), or None."""
    digits = phone_digits(phone)
    if len(digits) < 7:
        return None
    # Phones are stored as typed ("+998 90 111-22-33"), so compare digits in Python.
    candidates = Parent.objects.exclude(phone="")
    if exclude_pk is not None:
        candidates = candidates.exclude(pk=exclude_pk)
    for pk, phone in candidates.values_list("pk", "phone").iterator():
        if phone_digits(phone) == digits:
            return Parent.objects.select_related("admin").get(pk=pk)
    return None


def visible_links(user, parent):
    """The parent's child links this admin may see (children in their branches)."""
    students = branching.filter_students_for_user(user, Student.objects.all())
    return (
        parent.child_links.filter(student__in=students)
        .select_related("student__admin", "student__branch")
        .order_by("student__admin__first_name", "student__admin__last_name")
    )


def has_hidden_children(user, parent):
    """True when the parent also has children this admin can't see."""
    return parent.child_links.count() != visible_links(user, parent).count()


def _set_primary(link):
    if link.is_primary:
        ParentChild.objects.filter(student=link.student, is_primary=True).exclude(
            pk=link.pk
        ).update(is_primary=False)


def link_child(parent, student, relation, is_primary=False):
    """Link (or re-link) a child to a parent. Returns the ParentChild row."""
    with transaction.atomic():
        link, _ = ParentChild.objects.update_or_create(
            parent=parent,
            student=student,
            defaults={"relation": relation, "is_primary": is_primary},
        )
        _set_primary(link)
    return link


def update_link(link, relation=None, is_primary=None):
    with transaction.atomic():
        if relation is not None:
            link.relation = relation
        if is_primary is not None:
            link.is_primary = is_primary
        link.save()
        _set_primary(link)
    return link


@transaction.atomic
def create_parent(first_name, last_name, phone, password, student, relation, is_primary=False):
    """Create a parent login (user_type "4") linked to its first child."""
    from .hod_views import _generate_login_id

    login_id = _generate_login_id(LOGIN_PREFIX)
    user = CustomUser.objects.create_user(
        email=f"{login_id.lower()}@iceberg.internal",
        password=password,
        user_type="4",
        first_name=first_name,
        last_name=last_name,
        login_id=login_id,
    )
    parent = user.parent
    parent.phone = phone
    parent.save(update_fields=["phone"])
    link_child(parent, student, relation, is_primary)
    return parent


@transaction.atomic
def update_parent(parent, first_name=None, last_name=None, phone=None, password=None):
    user = parent.admin
    if first_name is not None:
        user.first_name = first_name
    if last_name is not None:
        user.last_name = last_name
    if password:
        user.set_password(password)
    user.save()
    if phone is not None:
        parent.phone = phone
        parent.save(update_fields=["phone"])
    return parent
