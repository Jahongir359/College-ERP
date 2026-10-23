import json
import logging
import re
import secrets

from django.conf import settings
from django.http import HttpResponse, JsonResponse, QueryDict
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from .models import RegistrationLead


logger = logging.getLogger(__name__)


TOKEN_FIELD_NAMES = {
    "token",
    "apitoken",
    "apikey",
    "registrationtoken",
    "registrationleadstoken",
    "registrationleadsapitoken",
}


def _normalize_key(key):
    return re.sub(r"[^a-z0-9]+", "", str(key).lower())


def _clean_value(value):
    if isinstance(value, (list, tuple)):
        value = next((item for item in value if str(item).strip()), "")
    if isinstance(value, dict):
        return ""
    if value is not None and str(value).strip():
        return str(value).strip()
    return ""


def _first_value(payload, *keys):
    normalized_payload = {_normalize_key(key): value for key, value in payload.items()}
    for key in keys:
        value = normalized_payload.get(_normalize_key(key))
        cleaned = _clean_value(value)
        if cleaned:
            return cleaned
    return ""


def _parse_payload(request):
    content_type = request.META.get("CONTENT_TYPE", "")
    body = request.body.strip()
    if "application/json" in content_type or body.startswith((b"{", b"[")):
        if not body:
            return {}
        return json.loads(body.decode("utf-8"))

    post_payload = {key: value for key, value in request.POST.items()}
    if post_payload or not body:
        return post_payload

    return {key: value for key, value in QueryDict(body.decode("utf-8")).items()}


def _request_token(request, payload):
    auth_header = request.META.get("HTTP_AUTHORIZATION", "").strip()
    if auth_header.lower().startswith("bearer "):
        return auth_header[7:].strip()
    if auth_header:
        return auth_header

    for header_name in ("HTTP_X_REGISTRATION_TOKEN", "HTTP_X_API_KEY"):
        header_value = request.META.get(header_name, "").strip()
        if header_value:
            return header_value

    return _first_value(
        payload,
        "registration_token",
        "registrationToken",
        "registration_leads_token",
        "registrationLeadsToken",
        "api_token",
        "apiToken",
        "api_key",
        "apiKey",
        "token",
    )


def _redacted_payload(payload):
    return {
        key: "[redacted]" if _normalize_key(key) in TOKEN_FIELD_NAMES else value
        for key, value in payload.items()
    }


def _remote_addr(request):
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
    if forwarded:
        return forwarded.split(",", 1)[0].strip()
    return request.META.get("REMOTE_ADDR", "")


@csrf_exempt
@require_http_methods(["POST", "OPTIONS"])
def registration_leads_receiver(request):
    if request.method == "OPTIONS":
        return HttpResponse(status=204)

    try:
        payload = _parse_payload(request)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return JsonResponse({"detail": "Invalid request payload."}, status=400)

    if not isinstance(payload, dict):
        return JsonResponse({"detail": "Payload must be an object."}, status=400)

    expected_token = getattr(settings, "REGISTRATION_LEADS_API_TOKEN", "").strip()
    if not expected_token and not settings.DEBUG:
        # Without a token anyone could create leads, so production refuses
        # them until REGISTRATION_LEADS_API_TOKEN is set (see checks.W002).
        logger.error("Registration lead rejected: REGISTRATION_LEADS_API_TOKEN is not configured.")
        return JsonResponse({"detail": "Lead intake is not configured."}, status=503)
    if expected_token and not secrets.compare_digest(
        _request_token(request, payload), expected_token
    ):
        return JsonResponse({"detail": "Unauthorized"}, status=401)

    first_name = _first_value(payload, "first_name", "firstName", "given_name", "firstname")
    last_name = _first_value(payload, "last_name", "lastName", "family_name", "lastname", "surname")
    full_name = _first_value(
        payload, "full_name", "fullName", "name", "student_name", "studentName"
    )
    if not full_name:
        full_name = " ".join(part for part in [first_name, last_name] if part).strip()

    phone = _first_value(
        payload,
        "phone",
        "phone_number",
        "phoneNumber",
        "student_phone",
        "contact_phone",
        "contact",
        "mobile",
        "mobile_number",
        "mobileNumber",
        "whatsapp",
        "whatsapp_number",
        "whatsappNumber",
        "telephone",
        "tel",
    )
    email = _first_value(payload, "email", "email_address", "emailAddress", "mail")
    parent_phone = _first_value(
        payload,
        "parent_phone",
        "parentPhone",
        "guardian_phone",
        "guardianPhone",
        "parent_contact",
        "parent_number",
        "parentNumber",
        "guardian_contact",
        "guardianContact",
        "guardian_number",
        "guardianNumber",
    )

    if not full_name:
        return JsonResponse({"detail": "full_name is required."}, status=400)
    if not phone:
        return JsonResponse({"detail": "phone is required."}, status=400)

    lead = RegistrationLead.objects.create(
        full_name=full_name,
        first_name=first_name,
        last_name=last_name,
        email=email,
        phone=phone,
        parent_phone=parent_phone,
        program=_first_value(
            payload,
            "program",
            "course",
            "course_name",
            "courseName",
            "selected_course",
            "selectedCourse",
            "interested_program",
            "interested_course",
            "interestedIn",
            "class",
        ),
        branch=_first_value(payload, "branch", "location", "preferred_branch", "campus", "center"),
        preferred_schedule=_first_value(
            payload,
            "preferred_schedule",
            "preferredSchedule",
            "schedule",
            "preferred_time",
            "preferredTime",
            "class_time",
            "classTime",
            "time",
        ),
        source=_first_value(
            payload,
            "source",
            "social_source",
            "socialSource",
            "lead_source",
            "leadSource",
            "platform",
            "site",
        )
        or "website",
        social_handle=_first_value(
            payload, "social_handle", "socialHandle", "instagram", "telegram", "username"
        ),
        campaign=_first_value(payload, "campaign", "ad_campaign", "adCampaign"),
        utm_source=_first_value(payload, "utm_source", "utmSource"),
        utm_medium=_first_value(payload, "utm_medium", "utmMedium"),
        utm_campaign=_first_value(payload, "utm_campaign", "utmCampaign"),
        referrer=_first_value(payload, "referrer", "referer", "page_url", "pageUrl", "url", "page"),
        message=_first_value(payload, "message", "notes", "comment", "comments", "question"),
        raw_payload=_redacted_payload(payload),
        remote_addr=_remote_addr(request),
        user_agent=request.META.get("HTTP_USER_AGENT", "")[:500],
    )
    logger.info("Registration lead received: id=%s source=%s", lead.pk, lead.source)
    return JsonResponse({"status": "ok", "lead_id": lead.pk}, status=201)
