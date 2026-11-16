"""Push notifications through FCM HTTP v1 (P2.8).

Credentials come only from env vars (see settings ``FCM_SERVICE_ACCOUNT_JSON``);
without them every call here is a no-op, so dev and tests never reach Google.

Callers use :func:`notify_users`. Sending happens after the DB transaction
commits, on one background worker thread, so a slow or failing FCM call never
breaks the request that created the notification.
"""

import json
import logging
import threading

import requests
from django.conf import settings
from django.db import connection, transaction
from django.db.models import Q
from django.utils import translation
from django.utils.translation import gettext_lazy as _

logger = logging.getLogger(__name__)

FCM_SCOPE = "https://www.googleapis.com/auth/firebase.messaging"
FCM_SEND_URL = "https://fcm.googleapis.com/v1/projects/{project_id}/messages:send"
SEND_TIMEOUT = 10
# FCM error codes that mean the token will never work again. Not
# INVALID_ARGUMENT: FCM also returns it for a bad payload, and one payload bug
# must not delete every recipient's device token. It is logged instead.
DEAD_TOKEN_ERRORS = {"UNREGISTERED", "SENDER_ID_MISMATCH"}

CATEGORY_TITLES = {
    "attendance": _("Attendance"),
    "result": _("New result"),
    "announcement": _("Announcement"),
    "homework": _("Homework"),
    "vocabulary": _("Vocabulary"),
    "payment": _("Payment"),
    "general": _("Notification"),
}

_credentials = None
_credentials_lock = threading.Lock()
_warned_off = False


def _service_account_info():
    global _warned_off
    raw = getattr(settings, "FCM_SERVICE_ACCOUNT_JSON", "")
    if not raw:
        if not _warned_off:
            _warned_off = True
            logger.warning("FCM_SERVICE_ACCOUNT_JSON is not set; push is off.")
        return None
    try:
        return json.loads(raw)
    except ValueError:
        logger.error("FCM_SERVICE_ACCOUNT_JSON is not valid JSON; push is off.")
        return None


def push_enabled():
    return _service_account_info() is not None


def _access_token():
    """OAuth2 token for FCM; google-auth caches it until shortly before expiry."""
    global _credentials
    from google.auth.transport.requests import Request
    from google.oauth2 import service_account

    with _credentials_lock:
        if _credentials is None:
            _credentials = service_account.Credentials.from_service_account_info(
                _service_account_info(), scopes=[FCM_SCOPE]
            )
        if not _credentials.valid:
            _credentials.refresh(Request())
        return _credentials.token


def _post(url, payload, access_token):
    return requests.post(
        url,
        json=payload,
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=SEND_TIMEOUT,
    )


def _is_dead_token(response):
    # Only FCM's own error codes count: a bare 404 (wrong URL, proxy) says
    # nothing about the token and must not delete it.
    try:
        details = response.json().get("error", {}).get("details", [])
    except ValueError:
        return False
    return any(isinstance(d, dict) and d.get("errorCode") in DEAD_TOKEN_ERRORS for d in details)


def send_messages(messages):
    """Send ``[(token, title, body, data), ...]``; delete tokens FCM rejects for good.

    Returns the number of messages FCM accepted.
    """
    from .models import DeviceToken

    info = _service_account_info()
    if not info or not messages:
        return 0
    try:
        access_token = _access_token()
    except Exception:
        logger.exception("Could not get an FCM access token.")
        return 0

    url = FCM_SEND_URL.format(project_id=info["project_id"])
    sent = 0
    dead = []
    for token, title, body, data in messages:
        payload = {
            "message": {
                "token": token,
                "notification": {"title": str(title), "body": str(body)},
                "data": {str(k): str(v) for k, v in (data or {}).items()},
                "android": {"priority": "high"},
            }
        }
        try:
            response = _post(url, payload, access_token)
        except requests.RequestException:
            logger.warning("FCM send failed (network).", exc_info=True)
            continue
        if response.status_code == 200:
            sent += 1
        elif _is_dead_token(response):
            dead.append(token)
        else:
            logger.warning("FCM send failed: %s %s", response.status_code, response.text[:300])
    if dead:
        DeviceToken.objects.filter(token__in=dead).delete()
    return sent


# Batches committed but not sent yet, and the one worker thread that sends
# them. Every committed transaction adds its batches here; a worker is started
# only when none is running, so a transaction that creates N notifications
# (e.g. monthly invoices) starts at most one thread, not N. The worker is a
# daemon, so batches still waiting when gunicorn restarts are lost: acceptable for push.
_pending = []
_pending_lock = threading.Lock()
_worker = None


def _take_pending():
    """All waiting batches, or ``None`` (and the worker slot freed) when empty."""
    global _worker
    with _pending_lock:
        if not _pending:
            _worker = None
            return None
        batches = _pending[:]
        _pending.clear()
        return batches


def _send_batches(batches):
    messages = []
    for users, title, body, data in batches:
        messages.extend(_build_messages(users, title, body, data))
    if messages:
        send_messages(messages)


def _work():
    try:
        while True:
            batches = _take_pending()
            if batches is None:
                return
            try:
                _send_batches(batches)
            except Exception:
                logger.exception("Push worker failed to send a batch.")
    finally:
        connection.close()


def _enqueue(batches):
    """Run after commit: hand ``batches`` to the worker, starting it if needed."""
    global _worker
    if getattr(settings, "FCM_SEND_INLINE", False):
        _send_batches(batches)
        return
    with _pending_lock:
        _pending.extend(batches)
        if _worker is not None and _worker.is_alive():
            return
        _worker = threading.Thread(target=_work, name="fcm-push", daemon=True)
        worker = _worker
    try:
        worker.start()
    except Exception:
        # No thread (e.g. the process is out of threads): free the slot so the
        # next commit tries again; the batches stay queued for it.
        with _pending_lock:
            if _worker is worker:
                _worker = None
        logger.exception("Could not start the push worker.")


def _build_messages(users, title, body, data):
    """Resolve device tokens now and render ``title``/``body`` in each user's language."""
    from .models import DeviceToken

    users = {u.pk: u for u in users if u is not None}
    if not users:
        return []
    messages = []
    tokens = DeviceToken.objects.filter(user_id__in=list(users)).values_list("user_id", "token")
    for user_id, token in tokens:
        user = users[user_id]
        with translation.override(user.language or settings.LANGUAGE_CODE):
            user_title = title(user) if callable(title) else str(title)
            user_body = body(user) if callable(body) else str(body)
        messages.append((token, user_title, user_body[:500], data))
    return messages


def _queue(batches):
    """After commit, send ``[(users, title, body, data), ...]`` through the worker.

    Each call registers its own cheap on-commit hook, so batches from a
    rolled-back savepoint are dropped with it; the sending itself is shared.
    """
    # robust: an error after commit is logged by Django instead of reaching the request.
    transaction.on_commit(lambda: _enqueue(batches), robust=True)


def notify_users(users, title, body, data=None):
    """Push ``title``/``body`` to every device of ``users`` once the transaction commits.

    ``title`` and ``body`` may be lazy translations (rendered in each user's
    language) or callables taking the user. ``data`` values are sent as strings.
    Does nothing when push is not configured.
    """
    if not push_enabled():
        return
    _queue([(list(users), title, body, data)])


def push_notifications(notifications):
    """Push in-app ``Notification`` rows to their recipients' devices."""
    if not push_enabled():
        return
    _queue(
        [
            (
                [n.recipient],
                CATEGORY_TITLES.get(n.category, CATEGORY_TITLES["general"]),
                n.message,
                {"type": "notification", "category": n.category, "id": n.pk or ""},
            )
            for n in notifications
        ]
    )


def _chat_members_q(group):
    q = Q(student__enrollment__group=group, student__enrollment__is_active=True)
    if group.teacher_id:
        q |= Q(staff__pk=group.teacher_id)
    return q


def _parent_thread_members_q(thread):
    from . import branching

    q = Q(pk__in=list(branching.parent_user_ids_for_students([thread.student_id])))
    if thread.teacher_id:
        q |= Q(staff__pk=thread.teacher_id)
    return q


def push_chat_message(message):
    """Push a new chat message to the other people in the thread.

    Group threads reach the teacher and the active pupils; teacher ↔ parent
    threads (P2.6, no group) reach the teacher and the pupil's linked parents.
    """
    if not push_enabled():
        return
    from .models import ChatThread, CustomUser

    thread = message.thread
    if thread.kind == ChatThread.KIND_PARENT:
        members = _parent_thread_members_q(thread)
        title = thread.student.admin.get_full_name() if thread.student_id else ""
        data = {"type": "parent_chat", "thread_id": thread.pk}
    else:
        members = _chat_members_q(thread.group)
        title = thread.group.name
        data = {"type": "chat", "group_id": thread.group_id}
    recipients = CustomUser.objects.filter(members).exclude(pk=message.sender_id).distinct()
    sender = message.sender.get_full_name() or message.sender.email
    preview = message.body or _("Sent an attachment")
    notify_users(recipients, title, lambda user: f"{sender}: {preview}", data)
