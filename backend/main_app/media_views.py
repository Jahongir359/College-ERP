"""Authorization-aware media serving.

Uploaded files live under MEDIA_ROOT and were previously served by an
unauthenticated ``django.views.static.serve`` catch-all, which let anyone who
knew (or guessed) a URL download private documents — most importantly the
student **result PDFs** under ``results/``.

This view keeps public assets (profile pictures, story images) freely
accessible — the Flutter app loads those with plain image requests that carry
no auth header — while gating the private prefixes behind login *and* an
object-level access check:

  * ``results/``          student result PDFs (mirrors the result-file API)
  * ``submissions/``      homework uploads (student, assignment teacher, admins)
  * ``chat_attachments/`` group chat files (members of that group's chat)

Login is accepted either as a web session or as a mobile-app JWT bearer token
(the app downloads submissions through its authenticated Dio client).

Note: when DigitalOcean Spaces is configured, files are served from the CDN
(``MEDIA_URL`` points there) and this view is bypassed. Making those objects
private requires switching the bucket ACL off ``public-read`` and issuing
signed URLs — tracked separately because it also affects how the app loads
public images.
"""

from django.core.files.storage import default_storage
from django.http import FileResponse, Http404
from django.views.static import serve as static_serve

from . import branching, messaging
from .models import ChatMessage, ChatThread, Enrollment, ResultFile, Submission


def _can_access_result_file(user, path):
    """Object-level check for a ``results/<...>`` media path, mirroring the
    access rules used by the authenticated result-file API."""
    if not user.is_authenticated:
        return False

    rf = ResultFile.objects.filter(file=path).select_related("group").first()
    if rf is None:
        # Unknown or orphaned result path — deny rather than leak.
        return False

    user_type = str(getattr(user, "user_type", "") or "")

    if user_type == "1":  # admin — branch scope (super admin sees all)
        if branching.is_super_admin(user):
            return True
        return rf.group_id is not None and branching.user_can_access_group(user, rf.group)

    if user_type == "2":  # teacher — uploaded it, or teaches the group
        staff = getattr(user, "staff", None)
        if staff is None:
            return False
        if rf.uploaded_by_id == staff.id:
            return True
        return rf.group_id is not None and rf.group.teacher_id == staff.id

    if user_type == "3":  # student — own personal file, or enrolled in the group
        student = getattr(user, "student", None)
        if student is None:
            return False
        if rf.student_id is not None:
            return rf.student_id == student.id
        return (
            rf.group_id is not None
            and Enrollment.objects.filter(
                student=student, group_id=rf.group_id, is_active=True
            ).exists()
        )

    return False


def _can_access_submission(user, path):
    sub = Submission.objects.filter(file=path).select_related("assignment__group").first()
    if sub is None:
        return False
    user_type = str(getattr(user, "user_type", "") or "")
    if user_type == "3":
        student = getattr(user, "student", None)
        return student is not None and sub.student_id == student.id
    if user_type == "2":
        staff = getattr(user, "staff", None)
        if staff is None:
            return False
        group = sub.assignment.group
        return sub.assignment.created_by_id == staff.id or (
            group is not None and group.teacher_id == staff.id
        )
    if user_type == "1":
        if branching.is_super_admin(user):
            return True
        return branching.user_can_access_group(user, sub.assignment.group)
    return False


def _can_access_chat_attachment(user, path):
    msg = ChatMessage.objects.filter(attachment=path).select_related("thread__group").first()
    if msg is None:
        return False
    if msg.thread.kind == ChatThread.KIND_PARENT:
        return branching.filter_parent_threads_for_user(
            user, ChatThread.objects.filter(pk=msg.thread_id)
        ).exists()
    return messaging.can_access_group(user, msg.thread.group)


# prefix → (object-level check, serve as download?)
_PROTECTED_PREFIXES = {
    "results/": (_can_access_result_file, True),
    "submissions/": (_can_access_submission, True),
    "chat_attachments/": (_can_access_chat_attachment, False),
}


def _request_user(request):
    """Session user, falling back to a mobile-app JWT bearer token."""
    if request.user.is_authenticated:
        return request.user
    from rest_framework.exceptions import AuthenticationFailed
    from rest_framework_simplejwt.authentication import JWTAuthentication

    try:
        result = JWTAuthentication().authenticate(request)
    except AuthenticationFailed:
        return None
    return result[0] if result else None


def protected_media(request, path):
    """Serve MEDIA_ROOT files, enforcing access control on private prefixes.

    Everything outside ``_PROTECTED_PREFIXES`` — profile pictures, story
    images — is served publicly so the mobile app's unauthenticated image
    loading keeps working.
    """
    for prefix, (can_access, as_attachment) in _PROTECTED_PREFIXES.items():
        if not path.startswith(prefix):
            continue
        user = _request_user(request)
        if user is None or not user.is_authenticated or not can_access(user, path):
            # 404 (not 403) so we don't confirm the file exists to a probe.
            raise Http404
        # Serve through the storage backend so it works for local and remote
        # (Spaces) storage alike.
        if not default_storage.exists(path):
            raise Http404
        return FileResponse(default_storage.open(path, "rb"), as_attachment=as_attachment)

    # Public assets — unchanged behaviour.
    from django.conf import settings

    return static_serve(request, path, document_root=settings.MEDIA_ROOT)
