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
import secrets

from django.db import transaction

from . import branching
from .models import CustomUser, Parent, ParentChild, PasswordResetLog

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


def parent_by_login_and_phone(login_id, phone):
    """The parent with this login ID *and* phone (compared by digits), or None.

    Used to link a child to a parent of another branch (D4). Both must match, so
    a mistyped login ID can't hand a child's data to another family, and a
    mismatch tells the caller nothing about who exists.
    """
    login_id = (login_id or "").strip()
    digits = phone_digits(phone)
    if not login_id or not digits:
        return None
    parent = Parent.objects.select_related("admin").filter(admin__login_id__iexact=login_id).first()
    if parent is None or phone_digits(parent.phone) != digits:
        return None
    return parent


# No 0/O, 1/l/I: the office reads the password out or writes it on paper.
_PASSWORD_CHARS = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def temporary_password(length=10):
    """A random password for the office to hand to a parent after a reset."""
    return "".join(secrets.choice(_PASSWORD_CHARS) for _ in range(length))


def visible_links(user, parent):
    """The parent's child links this admin may see (children in their branches)."""
    return (
        branching.filter_parent_links_for_user(user, parent.child_links.all())
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
        must_change_password=True,  # the office chose it; the parent picks their own (PL.1)
    )
    parent = user.parent
    parent.phone = phone
    parent.save(update_fields=["phone"])
    link_child(parent, student, relation, is_primary)
    return parent


@transaction.atomic
def update_parent(
    parent, first_name=None, last_name=None, phone=None, password=None, by=None, method=None
):
    """Change a parent's details. A new ``password`` is one the office chose: the parent
    must change it after signing in (PL.1), and the reset is written to the audit log
    (``PasswordResetLog``, PL.2) with ``by`` (the admin) and ``method``."""
    user = parent.admin
    if first_name is not None:
        user.first_name = first_name
    if last_name is not None:
        user.last_name = last_name
    if password:
        user.set_password(password)
        user.must_change_password = True  # set by the office: temporary until changed (PL.1)
    user.save()
    if password:
        PasswordResetLog.objects.create(
            user=user, by=by, method=method or PasswordResetLog.METHOD_OFFICE
        )
    if phone is not None:
        parent.phone = phone
        parent.save(update_fields=["phone"])
    return parent
