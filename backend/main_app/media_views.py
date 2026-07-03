"""Authorization-aware media serving.

Uploaded files live under MEDIA_ROOT and were previously served by an
unauthenticated ``django.views.static.serve`` catch-all, which let anyone who
knew (or guessed) a URL download private documents — most importantly the
student **result PDFs** under ``results/``.

This view keeps public assets (profile pictures, story images) freely
accessible — the Flutter app loads those with plain image requests that carry
no auth header — while gating the sensitive ``results/`` prefix behind login
*and* an object-level access check that mirrors the API download endpoint
(`/api/v1/result-files/<id>/download/`). Result files in the mobile app are
fetched through that authenticated API, so gating the raw path breaks nothing.

Note: when DigitalOcean Spaces is configured, files are served from the CDN
(``MEDIA_URL`` points there) and this view is bypassed. Making those objects
private requires switching the bucket ACL off ``public-read`` and issuing
signed URLs — tracked separately because it also affects how the app loads
public images.
"""

from django.core.files.storage import default_storage
from django.http import FileResponse, Http404
from django.views.static import serve as static_serve

from . import branching
from .models import Enrollment, Group, ResultFile


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


def protected_media(request, path):
    """Serve MEDIA_ROOT files, enforcing access control on sensitive prefixes.

    Only ``results/`` is gated today (student grade documents). Everything else
    — profile pictures, story images — is served publicly, exactly as before,
    so the mobile app's unauthenticated image loading keeps working.
    """
    if path.startswith("results/"):
        if not _can_access_result_file(request.user, path):
            # 404 (not 403) so we don't confirm the file exists to a probe.
            raise Http404
        # Serve through the storage backend so it works for local and remote
        # (Spaces) storage alike.
        if not default_storage.exists(path):
            raise Http404
        return FileResponse(default_storage.open(path, "rb"), as_attachment=True)

    # Public assets — unchanged behaviour.
    from django.conf import settings

    return static_serve(request, path, document_root=settings.MEDIA_ROOT)
