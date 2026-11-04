import logging
import os
from urllib.parse import urlencode

import requests
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, get_user_model, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import PasswordResetView
from django.core.exceptions import PermissionDenied
from django.core.files.storage import default_storage
from django.db import DatabaseError
from django.db.models import Q
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render, reverse
from django.urls import reverse_lazy
from django.utils.translation import gettext as _
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import ensure_csrf_cookie

from .forms import AdminForm, StaffProfileForm, StudentProfileForm
from .language import remember_cookie_language
from .middleware import PARENT_HOME_URL
from .models import (
    Admin,
    Assignment,
    Attendance,
    AttendanceReport,
    Branch,
    Enrollment,
    Group,
    Parent,
    ResultFile,
    Staff,
    Student,
    StudentResult,
)

logger = logging.getLogger(__name__)


def _ensure_role_profile(user):
    """Best-effort role profile healing to avoid login-time crashes."""
    user_type = str(user.user_type)
    model_map = {
        "1": Admin,
        "2": Staff,
        "3": Student,
        "4": Parent,
    }
    profile_model = model_map.get(user_type)
    if profile_model is None:
        return

    try:
        if not profile_model.objects.filter(admin=user).exists():
            profile_model.objects.create(admin=user)
    except Exception:
        # Keep login flow alive; dashboard views will enforce access rules.
        logger.exception("Role profile healing failed for user pk=%s", user.pk)


def _redirect_authenticated_user(user):
    """Return the correct home redirect for an already-logged-in user."""
    user_type = str(user.user_type)
    if user_type == "1":
        return redirect(reverse("admin_home"))
    if user_type == "2":
        return redirect(reverse("staff_home"))
    if user_type == "3":
        return redirect(reverse("student_home"))
    if user_type == "4":
        return redirect(PARENT_HOME_URL)
    return None  # Unknown type — fall through to show login page


@never_cache
@ensure_csrf_cookie
def login_page(request):
    if request.user.is_authenticated:
        destination = _redirect_authenticated_user(request.user)
        if destination:
            return destination
    return render(
        request,
        "main_app/login.html",
        {
            "captcha_site_key": settings.CAPTCHA_SITE_KEY,
            "captcha_enabled": bool(settings.CAPTCHA_ENABLED and settings.CAPTCHA_SITE_KEY),
        },
    )


def _verify_captcha(request):
    if not settings.CAPTCHA_ENABLED:
        return True
    if not settings.CAPTCHA_SITE_KEY or not settings.CAPTCHA_SECRET_KEY:
        logger.error("CAPTCHA_ENABLED=True but CAPTCHA_SITE_KEY/CAPTCHA_SECRET_KEY are missing.")
        messages.error(
            request, _("Login verification is not configured. Contact the administrator.")
        )
        return False

    captcha_token = request.POST.get("g-recaptcha-response")
    if not captcha_token:
        messages.error(request, _("Please complete the captcha challenge."))
        return False

    try:
        response = requests.post(
            "https://www.google.com/recaptcha/api/siteverify",
            data={
                "secret": settings.CAPTCHA_SECRET_KEY,
                "response": captcha_token,
            },
            timeout=8,
        )
        response.raise_for_status()
        payload = response.json()
    except requests.RequestException:
        logger.exception("reCAPTCHA request failed.")
        messages.error(request, _("Captcha could not be verified. Try again."))
        return False
    except ValueError:
        logger.exception("reCAPTCHA returned non-JSON response.")
        messages.error(request, _("Captcha could not be verified. Try again."))
        return False

    if not payload.get("success"):
        messages.error(request, _("Invalid captcha. Try again."))
        return False
    return True


def doLogin(request, **kwargs):
    if request.method != "POST":
        return HttpResponse("<h4>Denied</h4>")

    # Identifier is either an email address (admin) or a login_id (staff/student).
    identifier = (request.POST.get("identifier") or "").strip()
    if not identifier:
        # Fallback: some browsers or old bookmarks may still post 'email'.
        identifier = (request.POST.get("email") or "").strip()
    password = request.POST.get("password") or ""

    if not identifier or not password:
        messages.error(request, _("Please enter both your ID/email and password."))
        return redirect(reverse("login_page"))

    if not _verify_captcha(request):
        return redirect(reverse("login_page"))

    try:
        user = authenticate(request, username=identifier, password=password)
    except PermissionDenied:
        # django-axes raises this once AXES_FAILURE_LIMIT is hit.
        logger.warning("Login locked out by axes for identifier=%s", identifier)
        messages.error(
            request,
            _("Too many failed login attempts. Please wait 15 minutes before trying again."),
        )
        return redirect(reverse("login_page"))
    except Exception:
        logger.exception(
            "authenticate() raised for identifier=%s — DB may be missing migrations", identifier
        )
        messages.error(
            request, _("Login is temporarily unavailable. Please try again in a moment.")
        )
        return redirect(reverse("login_page"))

    # NOTE: there is intentionally no "recovery email" re-seed here. The recovery
    # account is bootstrapped once on a fresh database (see apps.create_recovery_
    # admin_access) and is otherwise a normal super-admin account — its password
    # and email can be changed (or the account deleted) from the UI, and those
    # changes are permanent. Re-creating it on a failed login would resurrect
    # deleted/old credentials, which is exactly the bug we are avoiding.

    if user is None:
        UserModel = get_user_model()
        if "@" in identifier:
            exists = UserModel.objects.filter(email__iexact=identifier).exists()
            id_err_msg = _("Account not found.")
            pw_err_msg = _("Incorrect password.")
            id_qp = ""
        else:
            exists = UserModel.objects.filter(login_id__iexact=identifier).exists()
            id_err_msg = _("ID not found. Please check your ICEBERG login ID.")
            pw_err_msg = _("Incorrect password.")
            id_qp = identifier

        if not exists:
            messages.error(request, id_err_msg, extra_tags="id_error")
        else:
            messages.error(request, pw_err_msg, extra_tags="pw_error")
        url = reverse("login_page")
        if id_qp:
            url += "?" + urlencode({"id": id_qp})
        return redirect(url)

    try:
        login(request, user)
    except DatabaseError:
        logger.exception("Login failed due to session/database error for identifier=%s", identifier)
        messages.error(
            request, _("Login is temporarily unavailable. Please try again in a moment.")
        )
        return redirect(reverse("login_page"))
    except Exception:
        logger.exception("Unexpected login failure for identifier=%s", identifier)
        messages.error(request, _("Login failed due to a server issue. Please try again shortly."))
        return redirect(reverse("login_page"))

    # A language picked on the sign-in page becomes the user's own (P3.0).
    remember_cookie_language(request, user)

    # Ensure the role profile row exists (heals accounts created before signals).
    user_type = str(user.user_type)
    _ensure_role_profile(user)

    # Remember Me
    if request.POST.get("remember"):
        request.session.set_expiry(30 * 24 * 60 * 60)
    else:
        request.session.set_expiry(0)

    # Deterministic redirect — no catch-all else that silently misroutes users.
    if user_type == "1":
        return redirect(reverse("admin_home"))
    if user_type == "2":
        return redirect(reverse("staff_home"))
    if user_type == "3":
        return redirect(reverse("student_home"))
    if user_type == "4":
        return redirect(PARENT_HOME_URL)

    # Unknown user_type: log it, inform the user, and log them out safely.
    logger.error(
        "Login rejected: user pk=%s has unrecognised user_type=%r",
        user.pk,
        user.user_type,
    )
    logout(request)
    messages.error(
        request,
        _("Your account role is not configured correctly. Please contact the administrator."),
    )
    return redirect("/")


def logout_user(request):
    if request.method != "POST":
        # Ignore accidental GET hits on the logout URL — redirect to home.
        if request.user.is_authenticated:
            return _redirect_authenticated_user(request.user) or redirect(reverse("login_page"))
        return redirect(reverse("login_page"))

    if request.user is not None:
        logout(request)
    # The client-side inactivity timer posts ?inactive=1 so the login page can
    # explain why the user was signed out.
    if request.POST.get("inactive") or request.GET.get("inactive"):
        return redirect(f"{reverse('login_page')}?inactive=1")
    return redirect(reverse("login_page"))


def _settings_row(title, subtitle, icon, anim="icon-hover-pulse", href=None, kind="link", **extra):
    row = {
        "title": title,
        "subtitle": subtitle,
        "icon": icon,
        "anim": anim,
        "href": href or "#",
        "kind": kind,
    }
    row.update(extra)
    return row


def _reverse_row(title, subtitle, icon, url_name, anim="icon-hover-pulse", **extra):
    return _settings_row(title, subtitle, icon, anim=anim, href=reverse(url_name), **extra)


def _save_admin_profile(request, admin_profile, form):
    custom_user = admin_profile.admin
    password = form.cleaned_data.get("password") or None
    passport = request.FILES.get("profile_pic") or None

    if password is not None:
        custom_user.set_password(password)
    if passport is not None:
        custom_user.profile_pic = default_storage.save(passport.name, passport)

    custom_user.first_name = form.cleaned_data.get("first_name")
    custom_user.last_name = form.cleaned_data.get("last_name")
    email = form.cleaned_data.get("email")
    if email:
        custom_user.email = email
    gender = form.cleaned_data.get("gender")
    if gender:
        custom_user.gender = gender
    address = form.cleaned_data.get("address")
    if address is not None:
        custom_user.address = address
    dob = form.cleaned_data.get("date_of_birth")
    if dob is not None:
        custom_user.date_of_birth = dob
    custom_user.save()


def _save_staff_profile(staff, form):
    custom_user = staff.admin
    password = form.cleaned_data.get("password") or None
    if password:
        custom_user.set_password(password)
    custom_user.first_name = form.cleaned_data["first_name"]
    custom_user.last_name = form.cleaned_data["last_name"]
    custom_user.gender = form.cleaned_data.get("gender", "")
    dob = form.cleaned_data.get("date_of_birth")
    if dob is not None:
        custom_user.date_of_birth = dob
    custom_user.save()
    staff.phone = form.cleaned_data.get("phone", "")
    staff.specialization = form.cleaned_data.get("specialization", "")
    staff.save()


def _save_student_profile(student, form):
    custom_user = student.admin
    password = form.cleaned_data.get("password") or None
    if password:
        custom_user.set_password(password)
    custom_user.first_name = form.cleaned_data["first_name"]
    custom_user.last_name = form.cleaned_data["last_name"]
    custom_user.gender = form.cleaned_data.get("gender", "")
    dob = form.cleaned_data.get("date_of_birth")
    if dob is not None:
        custom_user.date_of_birth = dob
    custom_user.save()
    student.phone = form.cleaned_data.get("phone", "")
    student.save()


def _student_profile_context(user):
    student = get_object_or_404(
        Student.objects.select_related("admin", "course", "branch"),
        admin=user,
    )
    enrollments = list(
        Enrollment.objects.filter(student=student, is_active=True)
        .select_related("group", "group__course", "group__branch", "group__teacher__admin")
        .order_by("group__name")
    )
    groups = [e.group for e in enrollments if e.group_id]
    group_ids = [g.id for g in groups]
    total_attendance = AttendanceReport.objects.filter(student=student).count()
    attended = AttendanceReport.objects.filter(
        student=student, status__in=[AttendanceReport.PRESENT, AttendanceReport.LATE]
    ).count()
    attendance_label = "Not started"
    if total_attendance:
        attendance_label = f"{round((attended / total_attendance) * 100)}% present"

    assignment_count = Assignment.objects.filter(group_id__in=group_ids).count()
    result_count = StudentResult.objects.filter(student=student).count()
    file_count = (
        ResultFile.objects.filter(
            group_id__in=group_ids,
        )
        .filter(Q(student__isnull=True) | Q(student=student))
        .count()
    )
    group_names = ", ".join(g.name for g in groups[:2]) or "Not assigned"
    if len(groups) > 2:
        group_names += f" +{len(groups) - 2}"

    meta = [
        {"icon": "fa-id-badge", "text": user.login_id or "Student ID not set"},
        {"icon": "fa-book", "text": str(student.course) if student.course else "Course not set"},
        {"icon": "fa-layer-group", "text": group_names},
        {
            "icon": "fa-map-marker-alt",
            "text": str(student.effective_branch) if student.effective_branch else "Branch not set",
        },
    ]
    if student.level:
        meta.append({"icon": "fa-signal", "text": f"Level {student.level}"})

    stats = [
        {"label": "Attendance", "value": attendance_label, "icon": "fa-calendar-check"},
        {"label": "Assignments", "value": assignment_count, "icon": "fa-tasks"},
        {"label": "Results", "value": result_count + file_count, "icon": "fa-chart-line"},
    ]
    role_rows = [
        _reverse_row(
            "My Course",
            str(student.course) if student.course else "Course not set",
            "fa-book-open",
            "student_home",
            "icon-hover-folder",
        ),
        _reverse_row("My Group", group_names, "fa-users", "student_home", "icon-hover-pulse"),
        _reverse_row(
            "Attendance Summary",
            attendance_label,
            "fa-calendar-check",
            "student_view_attendance",
            "icon-hover-bounce",
        ),
        _reverse_row(
            "Results",
            "Exam scores and result files",
            "fa-chart-line",
            "student_view_result",
            "icon-hover-pulse",
        ),
        _reverse_row(
            "Assignments / Tasks",
            f"{assignment_count} assigned",
            "fa-tasks",
            "student_assignments",
            "icon-hover-wiggle",
        ),
        _reverse_row(
            "Vocabulary / Study Settings",
            "Daily vocabulary and practice",
            "fa-spell-check",
            "vocabulary_day_list",
            "icon-hover-bounce",
        ),
        _reverse_row(
            "Study Progress",
            "Learning progress and leaderboard",
            "fa-chart-line",
            "student_progress",
            "icon-hover-pulse",
        ),
        _reverse_row(
            "Library", "Issued books and resources", "fa-book", "view_books", "icon-hover-folder"
        ),
    ]
    return {
        "role_profile": student,
        "role_label": "Student",
        "role_icon": "fa-user-graduate",
        "form": StudentProfileForm(instance=student),
        "profile_meta": meta,
        "profile_stats": stats,
        "role_group_label": "My Studies",
        "role_rows": role_rows,
        "current_theme": student.theme,
        "theme_save_url": reverse("student_save_theme"),
    }


def _staff_profile_context(user):
    staff = get_object_or_404(
        Staff.objects.select_related("admin", "course", "branch"),
        admin=user,
    )
    groups = list(
        Group.objects.filter(teacher=staff, is_archived=False)
        .select_related("course", "branch")
        .order_by("name")
    )
    group_ids = [g.id for g in groups]
    total_students = (
        Enrollment.objects.filter(group_id__in=group_ids, is_active=True)
        .values("student")
        .distinct()
        .count()
    )
    total_attendance = Attendance.objects.filter(group_id__in=group_ids).count()
    assignment_count = Assignment.objects.filter(created_by=staff).count()
    group_names = ", ".join(g.name for g in groups[:2]) or "No active groups"
    if len(groups) > 2:
        group_names += f" +{len(groups) - 2}"

    meta = [
        {"icon": "fa-id-badge", "text": user.login_id or "Teacher ID not set"},
        {"icon": "fa-book", "text": str(staff.course) if staff.course else "Course not set"},
        {
            "icon": "fa-map-marker-alt",
            "text": str(staff.effective_branch) if staff.effective_branch else "Branch not set",
        },
    ]
    if staff.specialization:
        meta.append({"icon": "fa-star", "text": staff.specialization})

    stats = [
        {"label": "Groups", "value": len(groups), "icon": "fa-layer-group"},
        {"label": "Students", "value": total_students, "icon": "fa-user-graduate"},
        {"label": "Attendance Days", "value": total_attendance, "icon": "fa-calendar-check"},
    ]
    role_rows = [
        _reverse_row("My Groups", group_names, "fa-layer-group", "staff_home", "icon-hover-folder"),
        _reverse_row(
            "My Students",
            f"{total_students} active students",
            "fa-users",
            "staff_home",
            "icon-hover-pulse",
        ),
        _reverse_row(
            "Attendance Settings",
            "Take or update attendance",
            "fa-clipboard-check",
            "staff_take_attendance",
            "icon-hover-bounce",
        ),
        _reverse_row(
            "Result Upload Settings",
            "Add scores and upload files",
            "fa-file-upload",
            "staff_add_result",
            "icon-hover-pulse",
        ),
        _reverse_row(
            "Assignments / Vocabulary Settings",
            f"{assignment_count} assignments created",
            "fa-tasks",
            "staff_assignments",
            "icon-hover-wiggle",
        ),
        _reverse_row(
            "Daily Vocabulary",
            "Create and manage study days",
            "fa-spell-check",
            "staff_vocabulary_days",
            "icon-hover-bounce",
        ),
        _reverse_row(
            "Teaching Profile",
            "Specialization and contact details",
            "fa-chalkboard-teacher",
            "staff_home",
            "icon-hover-pulse",
        ),
    ]
    return {
        "role_profile": staff,
        "role_label": "Teacher",
        "role_icon": "fa-chalkboard-teacher",
        "form": StaffProfileForm(instance=staff),
        "profile_meta": meta,
        "profile_stats": stats,
        "role_group_label": "Teaching",
        "role_rows": role_rows,
        "current_theme": "system",
        "theme_save_url": "",
    }


def _admin_profile_context(user):
    admin_profile = get_object_or_404(
        Admin.objects.prefetch_related("branches"),
        admin=user,
    )
    try:
        from . import branching

        students_qs = branching.filter_students_for_user(user, Student.objects.all())
        staff_qs = branching.filter_staff_for_user(user, Staff.objects.all())
        groups_qs = branching.filter_groups_for_user(user, Group.objects.filter(is_archived=False))
        branches_qs = branching.filter_branches_for_user(user, Branch.objects.all())
    except Exception:
        logger.exception(
            "Profile hub admin branch scoping failed; falling back to unscoped counts."
        )
        students_qs = Student.objects.all()
        staff_qs = Staff.objects.all()
        groups_qs = Group.objects.filter(is_archived=False)
        branches_qs = Branch.objects.all()

    branch_names = ", ".join(admin_profile.branches.values_list("name", flat=True)[:2])
    if admin_profile.is_super_admin:
        branch_label = _("All branches")
    elif branch_names:
        extra = max(admin_profile.branches.count() - 2, 0)
        branch_label = branch_names + (f" +{extra}" if extra else "")
    else:
        branch_label = _("Branch not assigned")

    meta = [
        {"icon": "fa-envelope", "text": user.email or _("Email not set")},
        {
            "icon": "fa-shield-alt",
            "text": _("Super Admin") if admin_profile.is_super_admin else _("Branch Admin"),
        },
        {"icon": "fa-map-marker-alt", "text": branch_label},
    ]
    stats = [
        {"label": _("Students"), "value": students_qs.count(), "icon": "fa-user-graduate"},
        {"label": _("Teachers"), "value": staff_qs.count(), "icon": "fa-chalkboard-teacher"},
        {"label": _("Groups"), "value": groups_qs.count(), "icon": "fa-layer-group"},
        {"label": _("Branches"), "value": branches_qs.count(), "icon": "fa-building"},
    ]
    role_rows = [
        _reverse_row(
            _("Branch / Center Settings"),
            branch_label,
            "fa-building",
            "manage_branch",
            "icon-hover-folder",
        ),
        _reverse_row(
            _("User Management Shortcuts"),
            _("Teachers, students, and accounts"),
            "fa-users-cog",
            "manage_staff",
            "icon-hover-rotate",
        ),
        _reverse_row(
            _("Teacher Settings"),
            _("%(count)s teachers") % {"count": staff_qs.count()},
            "fa-chalkboard-teacher",
            "manage_staff",
            "icon-hover-pulse",
        ),
        _reverse_row(
            _("Student Settings"),
            _("%(count)s students") % {"count": students_qs.count()},
            "fa-user-graduate",
            "manage_student",
            "icon-hover-bounce",
        ),
        _reverse_row(
            _("Course / Group Settings"),
            _("Courses, groups, enrollments"),
            "fa-layer-group",
            "manage_group",
            "icon-hover-folder",
        ),
        _reverse_row(
            _("System Preferences"),
            _("Leaderboard rules and seasons"),
            "fa-sliders-h",
            "admin_leaderboard_settings",
            "icon-hover-rotate",
        ),
        _reverse_row(
            _("Reports / Dashboard Preferences"),
            _("Attendance and stories"),
            "fa-chart-line",
            "admin_view_attendance",
            "icon-hover-pulse",
        ),
    ]
    return {
        "role_profile": admin_profile,
        "role_label": _("Admin"),
        "role_icon": "fa-user-shield",
        "form": AdminForm(instance=admin_profile),
        "profile_meta": meta,
        "profile_stats": stats,
        "role_group_label": _("Administration"),
        "role_rows": role_rows,
        "current_theme": "system",
        "theme_save_url": "",
    }


@login_required
def profile_settings_hub(request):
    user_type = str(request.user.user_type)
    if user_type == "1":
        ctx = _admin_profile_context(request.user)
        profile = ctx["role_profile"]
        form = AdminForm(
            request.POST or None,
            request.FILES or None,
            instance=profile,
        )

        def save_fn():
            return _save_admin_profile(request, profile, form)
    elif user_type == "2":
        ctx = _staff_profile_context(request.user)
        profile = ctx["role_profile"]
        form = StaffProfileForm(instance=profile, data=request.POST or None)

        def save_fn():
            return _save_staff_profile(profile, form)
    elif user_type == "3":
        ctx = _student_profile_context(request.user)
        profile = ctx["role_profile"]
        form = StudentProfileForm(instance=profile, data=request.POST or None)

        def save_fn():
            return _save_student_profile(profile, form)
    else:
        messages.error(request, _("Your account role is not configured correctly."))
        logout(request)
        return redirect(reverse("login_page"))

    open_edit_panel = False
    if request.method == "POST":
        open_edit_panel = True
        if form.is_valid():
            try:
                save_fn()
                messages.success(request, _("Profile updated."))
                return redirect(reverse("profile_hub"))
            except Exception as exc:
                logger.exception("Profile hub update failed for user pk=%s", request.user.pk)
                messages.error(
                    request, _("Could not update your profile: %(error)s") % {"error": exc}
                )
        else:
            messages.error(request, _("Please fix the highlighted profile fields."))

    # One row per distinct destination — several earlier rows all opened the
    # same edit panel under different names.
    account_rows = [
        _settings_row(
            _("Personal Information"),
            _("Name, contact details, birthday, and profile basics"),
            "fa-user",
            kind="details",
            details_id="edit-profile",
            focus="#id_first_name",
        ),
        _settings_row(
            _("Change Profile Avatar"),
            _("Choose a profile sticker"),
            "fa-camera",
            anim="icon-hover-camera",
            kind="avatar",
        ),
        _settings_row(
            _("Change Password"),
            request.user.email or request.user.login_id or _("Account credentials"),
            "fa-key",
            anim="icon-hover-rotate",
            kind="details",
            details_id="edit-profile",
            focus="#id_password",
        ),
    ]

    preference_rows = [
        _settings_row(
            _("Theme / Appearance"),
            _("Dark, bright, or system mode"),
            "fa-palette",
            anim="icon-hover-rotate",
            kind="appearance",
        )
    ]
    if user_type == "2":
        preference_rows.extend(
            [
                _reverse_row(
                    _("Notifications"),
                    _("Announcements and alerts"),
                    "fa-bell",
                    "staff_view_notification",
                    "icon-hover-bell",
                ),
                _reverse_row(
                    _("Messages"),
                    _("Group chat and conversations"),
                    "fa-comments",
                    "messages",
                    "icon-hover-wiggle",
                ),
            ]
        )
    elif user_type == "3":
        preference_rows.extend(
            [
                _reverse_row(
                    _("Notifications"),
                    _("Announcements and alerts"),
                    "fa-bell",
                    "student_view_notification",
                    "icon-hover-bell",
                ),
                _reverse_row(
                    _("Messages"),
                    _("Group chat and conversations"),
                    "fa-comments",
                    "messages",
                    "icon-hover-wiggle",
                ),
            ]
        )
    else:
        preference_rows.append(
            _reverse_row(
                _("Messages"),
                _("Team and group conversations"),
                "fa-comments",
                "messages",
                "icon-hover-wiggle",
            )
        )

    support_rows = []
    if user_type == "1":
        support_rows = [
            _reverse_row(
                _("Help & Support"),
                _("Review student feedback"),
                "fa-circle-question",
                "student_feedback_message",
                "icon-hover-rotate",
            ),
            _reverse_row(
                _("Teacher Feedback"),
                _("Review teacher messages"),
                "fa-comment-dots",
                "staff_feedback_message",
                "icon-hover-wiggle",
            ),
            _reverse_row(
                _("Registration Leads"),
                _("Follow up with interested students"),
                "fa-user-clock",
                "manage_registration_leads",
                "icon-hover-pulse",
            ),
        ]
    elif user_type == "2":
        support_rows = [
            _reverse_row(
                _("Help & Feedback"),
                _("Contact admin"),
                "fa-circle-question",
                "staff_feedback",
                "icon-hover-rotate",
            ),
            _reverse_row(
                _("Apply for Leave"),
                _("Request time off"),
                "fa-plane-departure",
                "staff_apply_leave",
                "icon-hover-bounce",
            ),
        ]
    else:
        support_rows = [
            _reverse_row(
                _("Help & Feedback"),
                _("Contact your teacher or admin"),
                "fa-circle-question",
                "student_feedback",
                "icon-hover-rotate",
            ),
            _reverse_row(
                _("Apply for Leave"),
                _("Request time off"),
                "fa-plane-departure",
                "student_apply_leave",
                "icon-hover-bounce",
            ),
        ]
    support_rows.append(
        _settings_row(
            _("About Iceberg"),
            _("Central profile and settings hub for Iceberg"),
            "fa-info-circle",
            anim="icon-hover-rotate",
            kind="static",
        )
    )

    ctx.update(
        {
            "form": form,
            "page_title": _("My Profile / Settings"),
            "open_edit_panel": open_edit_panel,
            "dashboard_url": reverse(
                "admin_home"
                if user_type == "1"
                else "staff_home"
                if user_type == "2"
                else "student_home"
            ),
            "settings_groups": [
                {"label": _("Account"), "rows": account_rows},
                {"label": _("Preferences"), "rows": preference_rows},
                {"label": ctx["role_group_label"], "rows": ctx["role_rows"]},
                {"label": _("Support"), "rows": support_rows},
            ],
        }
    )
    return render(request, "main_app/profile_hub.html", ctx)


# ---------------------------------------------------------------------------
# Password reset — wraps Django's built-in view to prevent SMTP errors from
# becoming HTTP 500s.  Any exception during email dispatch is logged and the
# user is still sent to the "check your inbox" page (avoids email enumeration).
# ---------------------------------------------------------------------------


class SafePasswordResetView(PasswordResetView):
    template_name = "registration/password_reset_form.html"
    email_template_name = "registration/password_reset_email.html"
    subject_template_name = "registration/password_reset_subject.txt"
    success_url = reverse_lazy("password_reset_done")

    def form_valid(self, form):
        try:
            return super().form_valid(form)
        except Exception as exc:
            logger.error("Password reset email dispatch failed: %s", exc, exc_info=True)
            # Still redirect to "done" — do not leak whether the address exists
            # and do not expose a 500 to the user.
            return HttpResponseRedirect(self.success_url)


# ---------------------------------------------------------------------------
# Shared AJAX / utility views
# ---------------------------------------------------------------------------


@login_required
def get_attendance(request):
    group_id = request.POST.get("group")
    try:
        from .models import Group
        from . import branching

        group = get_object_or_404(Group, id=group_id)
        if not branching.user_can_access_group(request.user, group):
            return JsonResponse({"error": "Access denied."}, status=403)
        attendance_qs = Attendance.objects.filter(group=group).order_by("-date")
        attendance_list = [{"id": a.id, "attendance_date": str(a.date)} for a in attendance_qs]
        return JsonResponse(attendance_list, safe=False)
    except Exception:
        return JsonResponse({"error": "Unable to fetch attendance."}, status=400)


def health(request):
    """Lightweight health-check endpoint for DO load-balancer probes."""
    from django.db import connection

    try:
        connection.ensure_connection()
        db_ok = True
    except Exception:
        db_ok = False
    status = 200 if db_ok else 503
    return JsonResponse({"status": "ok" if db_ok else "db_unavailable", "db": db_ok}, status=status)


# ── Branded error handlers (registered in college_management_system/urls.py) ──


def _render_error(request, code, title, message, status):
    return render(
        request,
        "main_app/error.html",
        {"error_code": code, "error_title": title, "error_message": message},
        status=status,
    )


def page_not_found(request, exception):
    return _render_error(
        request,
        404,
        "We can't find that page",
        "The page you were looking for has moved or no longer exists. "
        "Head back to your dashboard to keep learning.",
        status=404,
    )


def server_error(request):
    return _render_error(
        request,
        500,
        "Something went wrong on our end",
        "An unexpected error occurred. The team has been notified — please try again in a moment.",
        status=500,
    )


def permission_denied(request, exception):
    return _render_error(
        request,
        403,
        "You don't have access to this page",
        "Your account doesn't have permission to view this section. "
        "Contact an administrator if you believe this is a mistake.",
        status=403,
    )


def bad_request(request, exception):
    return _render_error(
        request,
        400,
        "That request didn't look right",
        "The server couldn't process your request. Please refresh the page and try again.",
        status=400,
    )


@login_required
def save_avatar(request):
    """Save an emoji avatar sticker for any user type (student, staff, admin)."""
    if request.method != "POST":
        return JsonResponse({"status": "error"}, status=405)
    avatar = request.POST.get("avatar", "")
    valid = [str(i) for i in range(1, 25)] + [""]
    if avatar not in valid:
        return JsonResponse({"status": "error", "message": "Invalid avatar"}, status=400)
    request.user.avatar = avatar
    request.user.save(update_fields=["avatar"])
    return JsonResponse({"status": "ok", "avatar": avatar})


@login_required
def result_file_download(request, file_id):
    """
    Authenticated download proxy for ResultFile objects.

    Placed in views.py (not student_views / staff_views) so the role-based
    middleware never blocks it — both students and teachers reach this view.

    Access rules:
      student  — must be enrolled in the file's group; personal files only
                 visible to the addressed student.
      teacher  — can only download files they uploaded.
      admin    — unrestricted.

    For remote storage (S3 / Spaces) we redirect to the CDN URL.
    For local FileSystemStorage we stream the file directly and return a
    human-readable error page when the file is missing from disk (ephemeral
    container storage is the most common cause of this in production).
    """
    from django.http import FileResponse, Http404
    from .models import ResultFile, Student, Staff, Enrollment

    rf = get_object_or_404(ResultFile, id=file_id)
    user = request.user
    user_type = str(getattr(user, "user_type", ""))

    # ── Access control ───────────────────────────────────────────────────────
    if user_type == "3":  # Student
        student = get_object_or_404(Student, admin=user)
        enrolled_ids = list(
            Enrollment.objects.filter(student=student, is_active=True).values_list(
                "group_id", flat=True
            )
        )
        if rf.group_id not in enrolled_ids:
            raise Http404
        if rf.student_id and rf.student_id != student.id:
            raise Http404

    elif user_type == "2":  # Teacher
        staff = get_object_or_404(Staff, admin=user)
        if rf.uploaded_by_id != staff.id:
            raise Http404

    elif user_type == "1":  # Admin — can download any file
        pass

    else:
        raise Http404

    if not rf.file:
        raise Http404

    # ── Serve the file ───────────────────────────────────────────────────────
    try:
        file_path = rf.file.path  # raises NotImplementedError for S3
        if not os.path.exists(file_path):
            # File was on local (ephemeral) storage and has been lost.
            messages.error(
                request,
                "This file is no longer available on the server. "
                "The server may have been redeployed since the file was uploaded. "
                "Please contact your teacher to re-upload it.",
            )
            referer = request.META.get("HTTP_REFERER", "/")
            return redirect(referer)
        filename = rf.filename or rf.title
        return FileResponse(open(file_path, "rb"), as_attachment=True, filename=filename)

    except NotImplementedError:
        # Remote storage (S3 / DigitalOcean Spaces) — redirect to CDN URL.
        return redirect(rf.file.url)
