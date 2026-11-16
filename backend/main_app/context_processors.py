from .models import Notification
from .messaging import unread_message_count


def notification_count(request):
    count = 0
    message_count = 0
    if request.user.is_authenticated:
        try:
            count = Notification.objects.filter(
                recipient=request.user,
                is_read=False,
            ).count()
        except Exception:
            pass
        try:
            message_count = unread_message_count(request.user)
        except Exception:
            pass
    return {"unread_notification_count": count, "unread_message_count": message_count}


def brand(request):
    """Expose the resolved Iceberg brand (BrandConfig) as ``brand`` to every template."""
    from .branding import get_brand, resolve_brand_key

    return {"brand": get_brand(resolve_brand_key(request))}


def student_theme(request):
    """Expose the student's saved theme preference to every template."""
    theme = "system"
    if request.user.is_authenticated and getattr(request.user, "user_type", None) == "3":
        try:
            theme = request.user.student.theme
        except Exception:
            pass
    return {"student_theme": theme}


def school_nav(request):
    """``show_school_nav``: the admin sidebar's "Maktab" section, only for admins
    who can see an Iceberg School branch (Study Center admins see no change).
    ``school_only_admin`` and ``admin_home_url``: the admin shell's menu and home
    link (P3.9)."""
    user = getattr(request, "user", None)
    if not (user and user.is_authenticated and str(user.user_type) == "1"):
        return {"show_school_nav": False, "school_only_admin": False}
    from . import branching
    from .models import Branch

    branches = branching.get_accessible_branches(user)
    from django.utils.functional import SimpleLazyObject

    show = branches.filter(brand=Branch.BRAND_SCHOOL).exists()
    # Lazy: only School-branded pages read it (base.html checks the brand
    # first), so Learning Center pages run no extra queries.
    period = SimpleLazyObject(school_period_label) if show else ""
    # P3.9: School-only admins get the short School menu and /maktab/ as home.
    # Only admins who see a School branch can be School-only, so Study Center
    # admins run no extra query.
    school_only = show and branching.is_school_only_admin(user)
    return {
        "show_school_nav": show,
        "school_period": period,
        "school_only_admin": school_only,
        "admin_home_url": branching.admin_home_url(user, school_only=school_only),
        # Lazy: read only by the Study Center topbar (School shows the period).
        "admin_branch_label": SimpleLazyObject(lambda: branching.admin_branch_label(user)),
    }


def school_period_label():
    """``"2026–2027 · 1-chorak"`` for the School navbar chip (mockup 16): the
    current academic year and the quarter today falls in (or the last one
    that started), in the active language. Empty when no academic year
    exists."""
    from django.utils import timezone
    from django.utils.translation import gettext as _

    from .models import Session

    year = Session.current()
    if year is None:
        return ""
    today = timezone.localdate()
    term = year.terms.filter(start_date__lte=today).order_by("-start_date").first()
    if term is None:
        return str(year)
    # The quarter by number in the page language ("1-chorak", "1-я четверть",
    # "Quarter 1"); the term's own name is a single free-text label, so it
    # would not follow the language (#75 review).
    name = _("Quarter %(number)s") % {"number": term.number}
    return f"{year} · {name}"
