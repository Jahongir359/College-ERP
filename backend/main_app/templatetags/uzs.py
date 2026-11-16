"""Currency formatting for UZS soʻm.

Usage: {% load uzs %}  ->  {{ invoice.amount|uzs }}  ->  "200 ming soʻm"

Round thousands/millions render the local "ming"/"million" words; other
amounts fall back to comma-grouped digits (e.g. "200,500 soʻm").
"""

from decimal import Decimal, InvalidOperation

from django import template
from django.utils.translation import gettext

from ..payments import format_uzs_number

register = template.Library()


_SOM = object()  # the default suffix: "soʻm" in the page language


@register.filter
def uzs(value, suffix=_SOM):
    """Format a number as UZS soʻm (e.g. "200 ming soʻm", "200,500 soʻm").

    The "ming"/"million" words and "soʻm" follow the page language.
    """
    if value is None or value == "":
        return "—"
    try:
        Decimal(value)
    except (InvalidOperation, TypeError, ValueError):
        return value
    number = format_uzs_number(value, localized=True)
    if suffix is _SOM:
        return gettext("%(amount)s soʻm") % {"amount": number}
    return f"{number} {suffix}".strip()


@register.filter
def uzs_plain(value):
    """UZS amount without the currency suffix (for tables)."""
    return uzs(value, suffix="")
