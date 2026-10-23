"""Brand resolution — which Iceberg brand (Learning Center / School) a request sees.

Iceberg runs two institutions on this one ERP:

  * Learning Center ("center") — the existing brand, and the default everywhere.
  * School ("school")          — the maroon-crest brand, chosen per branch.

Brand affects presentation only (colours, logo, name, a few nouns). It never
grants or removes access to anything — that stays in branching.py.

While settings.SCHOOL_BRAND_ENABLED is False every request resolves to
"center", so the app looks exactly as it did before this module existed.
See docs/plans/ICEBERG_SCHOOL_BRAND_PLAN.md.
"""

import logging
from dataclasses import dataclass

from django.conf import settings

from .models import Branch

logger = logging.getLogger(__name__)

CENTER = Branch.BRAND_CENTER
SCHOOL = Branch.BRAND_SCHOOL

# Public School pages live under this prefix on the shared domain.
SCHOOL_PATH_PREFIX = "/school/"
# Remembers the brand an anonymous visitor came from (set by School pages).
BRAND_COOKIE = "iceberg_brand"
# Lets a super admin preview one brand (presentation only).
SESSION_KEY = "active_brand"


@dataclass(frozen=True)
class BrandConfig:
    key: str
    name: str
    short_name: str
    group_noun: str
    group_noun_plural: str
    level_noun: str
    logo_tile: str  # static path: square tile on login / navbar
    logo_on_dark: str  # static path: lockup for dark backgrounds
    logo_on_light: str  # static path: lockup for light backgrounds
    theme_color: str  # <meta name="theme-color">


BRANDS = {
    CENTER: BrandConfig(
        key=CENTER,
        # Matches the copy the templates already use — do not change for center.
        name="Iceberg Study Center",
        short_name="Learning Center",
        group_noun="Group",
        group_noun_plural="Groups",
        level_noun="Level",
        logo_tile="dist/img/logo.png",
        logo_on_dark="dist/img/iceberg-wordmark.png",
        logo_on_light="dist/img/logo.png",
        theme_color="#0C1F45",
    ),
    SCHOOL: BrandConfig(
        key=SCHOOL,
        name="Iceberg School",
        short_name="School",
        group_noun="Class",
        group_noun_plural="Classes",
        level_noun="Grade",
        logo_tile="dist/img/brand/school/crest-white.png",
        logo_on_dark="dist/img/brand/school/logo-h-white.png",
        logo_on_light="dist/img/brand/school/logo-h-maroon.png",
        theme_color="#4C0909",
    ),
}


def is_valid_brand(key):
    return key in BRANDS


def get_brand(key):
    """BrandConfig for ``key``; unknown or empty keys fall back to center."""
    return BRANDS.get(key) or BRANDS[CENTER]


def resolve_brand_key(request):
    """Return "center" or "school" for this request. Never raises.

    Order: feature flag → /school/ pages → signed-in user's branch →
    anonymous visitor's ?brand= / cookie → center.
    """
    if not getattr(settings, "SCHOOL_BRAND_ENABLED", False):
        return CENTER
    cached = getattr(request, "_iceberg_brand", None)
    if cached:
        return cached
    try:
        key = _resolve(request)
    except Exception:  # presentation must never break a page
        logger.exception("Brand resolution failed; falling back to center")
        key = CENTER
    if not is_valid_brand(key):
        key = CENTER
    try:
        request._iceberg_brand = key
    except AttributeError:
        pass
    return key


def brand_key_for_user(user):
    """Brand for ``user`` without a request (e.g. the API login response). Never raises."""
    if not getattr(settings, "SCHOOL_BRAND_ENABLED", False):
        return CENTER
    try:
        key = brand_for_user(user)
    except Exception:
        logger.exception("Brand resolution failed; falling back to center")
        return CENTER
    return key if is_valid_brand(key) else CENTER


def _resolve(request):
    path = getattr(request, "path", "") or ""
    if path.startswith(SCHOOL_PATH_PREFIX):
        return SCHOOL

    user = getattr(request, "user", None)
    if user is not None and getattr(user, "is_authenticated", False):
        return brand_for_user(user, getattr(request, "session", None))

    requested = request.GET.get("brand", "") if hasattr(request, "GET") else ""
    if is_valid_brand(requested):
        return requested
    cookie = request.COOKIES.get(BRAND_COOKIE, "") if hasattr(request, "COOKIES") else ""
    if is_valid_brand(cookie):
        return cookie
    return CENTER


def brand_for_user(user, session=None):
    """Brand for a signed-in user, from the branch they belong to."""
    user_type = str(getattr(user, "user_type", "") or "")

    if user_type == "3":
        branch = _profile_branch(user, "student")
        return branch.brand if branch else CENTER

    if user_type == "2":
        branch = _profile_branch(user, "staff")
        return branch.brand if branch else CENTER

    if user_type == "1":
        try:
            profile = user.admin
        except Exception:
            return CENTER
        if profile.is_super_admin:
            chosen = session.get(SESSION_KEY) if session is not None else None
            return chosen if is_valid_brand(chosen) else CENTER
        brands = set(profile.branches.values_list("brand", flat=True))
        # One brand across all managed branches → that brand; mixed or none → center.
        return brands.pop() if len(brands) == 1 else CENTER

    return CENTER


def _profile_branch(user, attr):
    try:
        profile = getattr(user, attr)
    except Exception:
        return None
    return profile.effective_branch
