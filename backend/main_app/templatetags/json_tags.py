"""Safe embedding of pre-serialised JSON inside inline <script> blocks.

Usage: {% load json_tags %}  ->  var data = {{ some_json|js_json }};

Views pass ``json.dumps(...)`` strings. Rendering those with ``|safe`` lets a
value containing ``</script>`` close the script block and inject markup (e.g. a
student's self-edited name on the leaderboard). This filter escapes the
characters that matter in an HTML script context — the same set Django's
``json_script`` escapes — so the output is still valid JSON/JS but can never
break out of the surrounding <script>.
"""

from django import template
from django.utils.safestring import mark_safe

register = template.Library()

_JS_ESCAPES = {
    ord("<"): "\\u003C",
    ord(">"): "\\u003E",
    ord("&"): "\\u0026",
    ord(" "): "\\u2028",
    ord(" "): "\\u2029",
}


@register.filter(is_safe=True)
def js_json(value):
    """Escape an already-serialised JSON string for an inline <script>."""
    if value is None or value == "":
        return mark_safe("null")
    return mark_safe(str(value).translate(_JS_ESCAPES))
