"""The web language switch (plan task P3.0, decision D17).

POST /language/ with ``language`` (uz, ru or en) and ``next``. The choice is
saved on the signed-in user (``CustomUser.language``) and in a cookie, so the
sign-in page keeps it after logout. ``UserLanguageMiddleware`` applies it.
"""

from django.conf import settings
from django.http import HttpResponseRedirect
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.http import require_POST


def supported_language(code):
    code = (code or "").strip().lower()
    return code if code in {c for c, _ in settings.LANGUAGES} else ""


def set_language_cookie(response, language):
    response.set_cookie(
        settings.LANGUAGE_COOKIE_NAME,
        language,
        max_age=settings.LANGUAGE_COOKIE_AGE,
        samesite="Lax",
        secure=settings.SESSION_COOKIE_SECURE,
    )


def remember_cookie_language(request, user):
    """After sign-in: keep a language picked on the sign-in page if the user has none yet."""
    if user.language:
        return
    language = supported_language(request.COOKIES.get(settings.LANGUAGE_COOKIE_NAME))
    if language:
        user.language = language
        user.save(update_fields=["language"])


@require_POST
def set_language(request):
    language = supported_language(request.POST.get("language"))
    next_url = request.POST.get("next") or request.META.get("HTTP_REFERER") or "/"
    if not url_has_allowed_host_and_scheme(
        next_url, allowed_hosts={request.get_host()}, require_https=request.is_secure()
    ):
        next_url = "/"
    response = HttpResponseRedirect(next_url)
    if not language:
        return response
    user = request.user
    if user.is_authenticated and user.language != language:
        user.language = language
        user.save(update_fields=["language"])
    set_language_cookie(response, language)
    return response
