"""Admin web pages for Iceberg School parents (plan task P3.3, mockups 18 and 18b),
and their printed login letters (PL.1, D14).

Admins only (D15). Which parents and children an admin sees is decided in
``branching.py``; the rules for creating parents and linking children (one login
per family, one main contact per child) live in ``parents.py`` and are shared
with the admin API of P1.7. CSV import is Release 2 (D16).
"""

import segno
from django.conf import settings
from django.contrib import messages
from django.db import transaction
from django.db.models import Count, Prefetch, Q
from django.http import Http404
from django.shortcuts import redirect, render
from django.urls import reverse
from django.utils import translation
from django.utils.cache import add_never_cache_headers
from django.utils.safestring import mark_safe
from django.utils.translation import gettext as _
from django.views.decorators.http import require_POST

from . import branching, parents
from .decorators import admin_only
from .models import Enrollment, Group, Parent, ParentChild, Session
from .school_forms import (
    ParentChildForm,
    ParentForm,
    ParentLinkByLoginForm,
    ParentLinkEditForm,
)


def _parents(request):
    return branching.filter_parents_for_user(request.user, Parent.objects.select_related("admin"))


def _parent_or_404(request, pk):
    parent = _parents(request).filter(pk=pk).first()
    if parent is None:
        raise Http404
    return parent


def _link_or_404(request, parent, student_pk):
    link = parents.visible_links(request.user, parent).filter(student_id=student_pk).first()
    if link is None:
        raise Http404
    return link


def _class_names(student_ids):
    """{student_id: class name} for active classes of the current academic year."""
    year = Session.current()
    if year is None:
        return {}
    rows = Enrollment.objects.filter(
        student_id__in=student_ids,
        is_active=True,
        group__kind=Group.KIND_CLASS,
        group__session=year,
    ).values_list("student_id", "group__name")
    return dict(rows)


def _form_errors(request, *forms):
    for form in forms:
        for errors in form.errors.values():
            for error in errors:
                messages.error(request, error)


@admin_only
def parent_list(request):
    """Ota-onalar: search, filter by class, and the "New parent" or "Link by login ID" panel."""
    classes = branching.filter_classes_for_user(
        request.user, Group.objects.filter(session=Session.current())
    ).order_by("grade_level", "letter", "branch__name")
    qs = _parents(request)
    search = request.GET.get("q", "").strip()
    if search:
        qs = qs.filter(
            Q(admin__first_name__icontains=search)
            | Q(admin__last_name__icontains=search)
            | Q(admin__login_id__icontains=search)
            | Q(phone__icontains=search)
        )
    group = None
    if request.GET.get("class", "").isdigit():
        group = classes.filter(pk=request.GET["class"]).first()
    if group is not None:
        qs = qs.filter(
            child_links__student__enrollment__group=group,
            child_links__student__enrollment__is_active=True,
        ).distinct()
    links = branching.filter_parent_links_for_user(
        request.user, ParentChild.objects.select_related("student__admin", "student__branch")
    ).order_by("student__admin__first_name")
    rows = list(
        qs.prefetch_related(
            Prefetch("child_links", queryset=links, to_attr="visible_links")
        ).order_by("admin__first_name", "admin__last_name")
    )
    class_of = _class_names([link.student_id for p in rows for link in p.visible_links])
    # All links, counted on their own: the branch filter above also narrows child_links,
    # so an annotation on that queryset would count only the visible ones.
    link_count = dict(
        ParentChild.objects.filter(parent__in=[p.pk for p in rows])
        .values("parent")
        .annotate(n=Count("pk"))
        .values_list("parent", "n")
    )
    for parent in rows:
        for link in parent.visible_links:
            link.class_name = class_of.get(link.student_id)
        parent.hidden_count = link_count.get(parent.pk, 0) - len(parent.visible_links)

    panel = "link" if request.GET.get("panel") == "link" else "new"
    form = ParentForm(user=request.user)
    child_form = ParentChildForm(user=request.user, prefix="child")
    link_form = ParentLinkByLoginForm(user=request.user, prefix="link")
    if request.method == "POST":
        if request.POST.get("action") == "link":
            panel = "link"
            link_form = ParentLinkByLoginForm(request.POST, user=request.user, prefix="link")
            if link_form.is_valid():
                data = link_form.cleaned_data
                parent = parents.parent_by_login_and_phone(data["login_id"], data["phone"])
                if parent is None:
                    # Same answer for a wrong login ID and a wrong phone: nothing leaks (D4).
                    messages.error(
                        request, _("Parent not found. Check the login ID and the phone number.")
                    )
                else:
                    parents.link_child(
                        parent, data["student"], data["relation"], data["is_primary"]
                    )
                    messages.success(
                        request,
                        _("%(child)s linked to parent %(login)s.")
                        % {
                            "child": data["student"].admin.get_full_name(),
                            "login": parent.admin.login_id,
                        },
                    )
                    return redirect("school_parent_detail", pk=parent.pk)
        else:
            form = ParentForm(request.POST, user=request.user)
            child_form = ParentChildForm(request.POST, user=request.user, prefix="child")
            if form.is_valid() & child_form.is_valid():
                parent = parents.create_parent(**form.cleaned_data, **child_form.cleaned_data)
                messages.success(
                    request,
                    _("Parent %(name)s created. Login ID: %(login)s.")
                    % {"name": parent.admin.get_full_name(), "login": parent.admin.login_id},
                )
                return redirect("school_parent_detail", pk=parent.pk)

    context = {
        "page_title": _("Parents"),
        "parents": rows,
        "classes": classes,
        "group": group,
        "search": search,
        "panel": panel,
        "form": form,
        "child_form": child_form,
        "link_form": link_form,
        # Letters for a class go only to parents who never signed in (see class_letters).
        "letters_waiting": sum(1 for p in rows if _letter_due(p.admin)) if group else 0,
    }
    return render(request, "hod_template/school/parents.html", context)


def _detail(request, parent, form=None, new_password=None):
    links = list(parents.visible_links(request.user, parent))
    class_of = _class_names([link.student_id for link in links])
    rows = []
    for link in links:
        link.class_name = class_of.get(link.student_id)
        edit = ParentLinkEditForm(
            initial={"relation": link.relation, "is_primary": link.is_primary},
            user=request.user,
            prefix=f"l{link.student_id}",
        )
        rows.append((link, edit))
    context = {
        "page_title": parent.admin.get_full_name(),
        "parent": parent,
        "form": form or ParentForm(user=request.user, instance=parent),
        "links": rows,
        "hidden_count": parent.child_links.count() - len(links),
        "child_form": ParentChildForm(user=request.user, prefix="child"),
        "link_form": ParentLinkByLoginForm(user=request.user, prefix="link"),
        "new_password": new_password,
    }
    return render(request, "hod_template/school/parent_detail.html", context)


@admin_only
def parent_detail(request, pk):
    """The parent page: details, children with relation and main contact, reset, delete."""
    parent = _parent_or_404(request, pk)
    form = None
    if request.method == "POST":
        form = ParentForm(request.POST, user=request.user, instance=parent)
        if form.is_valid():
            # The page has no password field: resetting has its own button.
            data = {k: v for k, v in form.cleaned_data.items() if k != "password"}
            parents.update_parent(parent, **data)
            messages.success(request, _("Saved."))
            return redirect("school_parent_detail", pk=parent.pk)
    return _detail(request, parent, form=form)


@admin_only
@require_POST
def parent_reset_password(request, pk):
    """Give the parent a new temporary password, shown once on this page (not stored in
    a message, so it never sits in the session or a cookie)."""
    parent = _parent_or_404(request, pk)
    password = parents.temporary_password()
    parents.update_parent(parent, password=password)
    return _detail(request, parent, new_password=password)


@admin_only
@require_POST
def parent_delete(request, pk):
    parent = _parent_or_404(request, pk)
    if parents.has_hidden_children(request.user, parent):
        messages.error(
            request,
            _(
                "This parent also has children in another branch, so the login can't be "
                "deleted. Unlink your children instead."
            ),
        )
        return redirect("school_parent_detail", pk=parent.pk)
    name = parent.admin.get_full_name()
    parent.admin.delete()  # the Parent profile and its links go with the login
    messages.success(request, _("Parent %(name)s deleted.") % {"name": name})
    return redirect("school_parents")


@admin_only
@require_POST
def parent_child_add(request, pk):
    parent = _parent_or_404(request, pk)
    form = ParentChildForm(request.POST, user=request.user, prefix="child")
    if form.is_valid():
        parents.link_child(parent, **form.cleaned_data)
        messages.success(
            request,
            _("%(child)s linked.") % {"child": form.cleaned_data["student"].admin.get_full_name()},
        )
    else:
        _form_errors(request, form)
    return redirect("school_parent_detail", pk=parent.pk)


@admin_only
@require_POST
def parent_child_edit(request, pk, student_pk):
    parent = _parent_or_404(request, pk)
    link = _link_or_404(request, parent, student_pk)
    form = ParentLinkEditForm(request.POST, user=request.user, prefix=f"l{student_pk}")
    if form.is_valid():
        parents.update_link(link, **form.cleaned_data)
        messages.success(request, _("Saved."))
    else:
        _form_errors(request, form)
    return redirect("school_parent_detail", pk=parent.pk)


@admin_only
@require_POST
def parent_child_remove(request, pk, student_pk):
    """Unlink a child. The parent login stays (it may have other children)."""
    parent = _parent_or_404(request, pk)
    link = _link_or_404(request, parent, student_pk)
    name = link.student.admin.get_full_name()
    link.delete()
    messages.success(request, _("%(child)s unlinked.") % {"child": name})
    if not _parents(request).filter(pk=parent.pk).exists():
        # The admin had no other child of this parent, so the parent is out of reach now.
        return redirect("school_parents")
    return redirect("school_parent_detail", pk=parent.pk)


# ── Login letters (PL.1, D14) ────────────────────────────────────────────────


def _download_url(request):
    """Where the letter's QR code points: the store links page (APP_DOWNLOAD_URL), or
    this site's /download/ page until the store listings exist (P5)."""
    return settings.APP_DOWNLOAD_URL or request.build_absolute_uri(reverse("download_page"))


def _letter_language(request):
    language = request.POST.get("language", "")
    return language if language in dict(settings.LANGUAGES) else translation.get_language()


def _letter_due(user):
    """A class letter goes only to a parent who has never signed in and still has a
    password the office set. Both are checked because the app's login did not record
    ``last_login`` before PL.1: a parent already using the app may have none, but their
    ``must_change_password`` is false (accounts made before PL.1, or they chose their own)."""
    return user.last_login is None and user.must_change_password


def _letters(request, parents_list):
    """Give each parent a new temporary password and render one printable letter each.

    Passwords are stored hashed, so a letter can only carry a fresh one: printing it
    replaces the old password, and the parent must change it after signing in.
    """
    url = _download_url(request)
    qr = mark_safe(segno.make(url, error="m").svg_inline(scale=4, dark="#1F1515"))
    # All passwords are replaced and the page rendered together, or nothing changes:
    # a failure half-way must not leave parents with passwords nobody printed.
    with transaction.atomic():
        letters = []
        for parent in parents_list:
            password = parents.temporary_password()
            parents.update_parent(parent, password=password)
            links = list(parents.visible_links(request.user, parent))
            class_of = _class_names([link.student_id for link in links])
            children = [
                (link.student.admin.get_full_name(), class_of.get(link.student_id))
                for link in links
            ]
            branch = next((link.student.branch for link in links if link.student.branch_id), None)
            letters.append(
                {"parent": parent, "password": password, "children": children, "branch": branch}
            )
        context = {
            "letters": letters,
            "qr": qr,
            "download_url": url,
            "web_url": request.build_absolute_uri("/app/"),
            "store_android": settings.APP_STORE_URL_ANDROID,
            "store_ios": settings.APP_STORE_URL_IOS,
            "back_url": request.POST.get("next") or reverse("school_parents"),
        }
        with translation.override(_letter_language(request)):
            response = render(request, "hod_template/school/parent_letters.html", context)
    add_never_cache_headers(response)  # the page shows passwords: don't keep it in a cache
    return response


@admin_only
@require_POST
def parent_letter(request, pk):
    """Print one parent's login letter (with a new temporary password)."""
    return _letters(request, [_parent_or_404(request, pk)])


@admin_only
@require_POST
def class_letters(request, class_pk):
    """Letters for a whole class, for the parent meeting (D14). Only parents who have
    never signed in and still have an office-set password get one (``_letter_due``), so a
    family already using the app keeps its password;
    for them the office prints a single letter from the parent page."""
    group = (
        branching.filter_classes_for_user(request.user, Group.objects.all())
        .filter(pk=class_pk)
        .first()
    )
    if group is None:
        raise Http404
    rows = (
        _parents(request)
        .filter(
            child_links__student__enrollment__group=group,
            child_links__student__enrollment__is_active=True,
            admin__last_login__isnull=True,
            admin__must_change_password=True,
        )
        .distinct()
        .order_by("admin__last_name", "admin__first_name")
    )
    if not rows:
        messages.info(
            request, _("Every parent in %(name)s has already signed in.") % {"name": group.name}
        )
        return redirect(f"{reverse('school_parents')}?class={group.pk}")
    return _letters(request, list(rows))
