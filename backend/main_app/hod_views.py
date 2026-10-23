import json
import re
import logging
from datetime import timedelta, date as date_type
from django.contrib import messages
from django.core.files.storage import default_storage
from django.db import IntegrityError, OperationalError, ProgrammingError, models, transaction
from django.http import HttpResponse, JsonResponse
from django.views.decorators.http import require_POST
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone

from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError

from .decorators import admin_only, super_admin_only
from .forms import *
from .models import *
from . import branching


logger = logging.getLogger(__name__)

_ENGLISH_KEYWORDS = frozenset(
    [
        "ielts",
        "toefl",
        "sat",
        "english",
        "speaking",
        "grammar",
        "reading",
        "writing",
        "listening",
        "cambridge",
        "pronunciation",
        "conversation",
    ]
)


def _derive_is_english(name):
    name_lower = name.lower()
    return any(kw in name_lower for kw in _ENGLISH_KEYWORDS)


def _generate_login_id(prefix, date_of_birth=None):
    """Generate a unique login_id for a new student or teacher.

    Birthday-based format (preferred):
        {prefix}{MMDD}{NN}   e.g.  IC052401  →  ICEBERG · May 24 · #01
                                   TC021207  →  Teacher · Feb 12 · #07
        - MMDD : two-digit month + two-digit day of birth
        - NN   : 01–99 collision suffix (rolls forward for shared birthdays)

    Sequential fallback (only when DOB is missing):
        IC1000, IC1001 …  /  TC500, TC501 …

    The new format is always exactly 6 digits after the prefix, so it
    cannot collide with legacy IDs:
        - Old zero-padded:  IC00005       (5 digits)
        - Old sequential:   IC1000        (4 digits)
        - Old dashed:       STU-0001      (different prefix)
        - New birthday:     IC052401      (6 digits, MMDD + NN)
    """
    if date_of_birth is not None:
        mmdd = f"{date_of_birth.month:02d}{date_of_birth.day:02d}"
        base = f"{prefix}{mmdd}"
        existing = set(
            CustomUser.objects.filter(login_id__istartswith=base).values_list("login_id", flat=True)
        )
        existing_upper = {lid.upper() for lid in existing if lid}
        for n in range(1, 100):
            candidate = f"{base}{n:02d}"
            if candidate.upper() not in existing_upper:
                return candidate
        # 99 students born on the same day at the same centre is implausible,
        # but fall through to the sequential generator just in case.

    start = 1000 if prefix == "IC" else 500
    pat = re.compile(rf"^{re.escape(prefix)}(\d+)$")
    existing = CustomUser.objects.filter(login_id__regex=rf"^{re.escape(prefix)}\d").values_list(
        "login_id", flat=True
    )
    used = set()
    for lid in existing:
        m = pat.match(lid)
        if m:
            used.add(int(m.group(1)))
    n = start
    while n in used:
        n += 1
    return f"{prefix}{n}"


def _active_groups_for_enrollment():
    """
    Keep enrollment page usable even if deploy is running with an older schema.
    """
    base_qs = Group.objects.select_related("course", "teacher__admin")
    try:
        active_qs = base_qs.filter(is_archived=False)
        active_qs.exists()
        return active_qs, False
    except (OperationalError, ProgrammingError):
        logger.exception(
            "Group.is_archived is unavailable. Falling back to all groups; migrations are likely pending."
        )
        fallback_qs = base_qs.all()
        fallback_qs.exists()
        return fallback_qs, True


@admin_only
def admin_home(request):
    user = request.user
    today = timezone.localdate()
    week_start = today - timedelta(days=6)
    previous_week_start = today - timedelta(days=13)

    def pct_change(current, previous):
        if previous == 0:
            return 100 if current else 0
        return round(((current - previous) / previous) * 100)

    # Branch-scope every metric: super admin sees everything, branch admin
    # only their assigned branches.
    students_base = branching.filter_students_for_user(user, Student.objects.all())
    staff_base = branching.filter_staff_for_user(user, Staff.objects.all())
    groups_base = branching.filter_groups_for_user(user, Group.objects.filter(is_archived=False))

    total_staff = staff_base.count()
    total_students = students_base.count()
    total_course = Course.objects.all().count()
    active_course_count = Course.objects.filter(is_active=True).count()
    total_groups = groups_base.count()
    group_ids = list(groups_base.values_list("id", flat=True))

    new_students_7 = students_base.filter(admin__created_at__date__gte=week_start).count()
    new_students_previous = students_base.filter(
        admin__created_at__date__gte=previous_week_start,
        admin__created_at__date__lt=week_start,
    ).count()
    new_staff_7 = staff_base.filter(admin__created_at__date__gte=week_start).count()
    new_staff_previous = staff_base.filter(
        admin__created_at__date__gte=previous_week_start,
        admin__created_at__date__lt=week_start,
    ).count()
    new_groups_7 = groups_base.filter(created_at__date__gte=week_start).count()
    new_groups_previous = groups_base.filter(
        created_at__date__gte=previous_week_start,
        created_at__date__lt=week_start,
    ).count()
    new_courses_7 = Course.objects.filter(created_at__date__gte=week_start).count()
    new_courses_previous = Course.objects.filter(
        created_at__date__gte=previous_week_start,
        created_at__date__lt=week_start,
    ).count()

    today_attendance_qs = AttendanceReport.objects.filter(
        attendance__group_id__in=group_ids,
        attendance__date=today,
    )
    today_attendance_total = today_attendance_qs.count()
    today_attendance_present = today_attendance_qs.filter(
        status__in=[AttendanceReport.PRESENT, AttendanceReport.LATE]
    ).count()
    attendance_today_rate = (
        round((today_attendance_present / today_attendance_total) * 100)
        if today_attendance_total
        else 0
    )
    total_capacity = groups_base.aggregate(total=models.Sum("capacity"))["total"] or 0
    active_enrollments = Enrollment.objects.filter(
        group_id__in=group_ids,
        is_active=True,
    ).count()
    group_fill_pct = round((active_enrollments / total_capacity) * 100) if total_capacity else 0
    assignments_due_soon = Assignment.objects.filter(
        group_id__in=group_ids,
        due_date__gte=today,
        due_date__lte=today + timedelta(days=7),
    ).count()

    # Attendance chart: per active group
    active_groups = groups_base.select_related("course")
    group_label_list = [g.name[:12] for g in active_groups]
    group_attendance_list = [Attendance.objects.filter(group=g).count() for g in active_groups]

    # Students per program
    course_all = Course.objects.all()
    course_name_list = []
    student_count_list_in_course = []
    for course in course_all:
        course_name_list.append(course.name)
        student_count_list_in_course.append(students_base.filter(course_id=course.id).count())

    # Student attendance overview — 4 queries instead of O(3N+1)
    from django.db.models import Count

    students_qs = list(students_base.select_related("admin"))
    student_ids = [s.id for s in students_qs]

    present_map = dict(
        AttendanceReport.objects.filter(
            student_id__in=student_ids,
            status__in=[AttendanceReport.PRESENT, AttendanceReport.LATE],
        )
        .values("student_id")
        .annotate(c=Count("id"))
        .values_list("student_id", "c")
    )
    absent_map = dict(
        AttendanceReport.objects.filter(
            student_id__in=student_ids,
            status=AttendanceReport.ABSENT,
        )
        .values("student_id")
        .annotate(c=Count("id"))
        .values_list("student_id", "c")
    )
    leave_map = dict(
        LeaveReportStudent.objects.filter(
            student_id__in=student_ids,
            status=LeaveReportStudent.APPROVED,
        )
        .values("student_id")
        .annotate(c=Count("id"))
        .values_list("student_id", "c")
    )

    student_attendance_present_list = [present_map.get(s.id, 0) for s in students_qs]
    student_attendance_leave_list = [
        absent_map.get(s.id, 0) + leave_map.get(s.id, 0) for s in students_qs
    ]
    student_name_list = [s.admin.first_name for s in students_qs]

    # ── Monthly branch comparison (last 6 months) ──────────────────────────
    def _month_range(n=6):
        result = []
        ref = today
        for i in range(n - 1, -1, -1):
            m = ref.month - i
            y = ref.year
            while m <= 0:
                m += 12
                y -= 1
            first = date_type(y, m, 1)
            last = date_type(y + 1, 1, 1) if m == 12 else date_type(y, m + 1, 1)
            result.append((first, last, first.strftime("%b")))
        return result

    _months = _month_range(6)
    _month_labels = [r[2] for r in _months]

    accessible_branches = list(branching.get_accessible_branches(user).order_by("name")[:7])
    _BRANCH_COLORS = ["#06B6D4", "#0E3E94", "#10B981", "#F59E0B", "#EF4444", "#7C3AED", "#EC4899"]
    branch_lines = []
    for _bi, _branch in enumerate(accessible_branches):
        _att_rates, _avg_scores, _student_counts = [], [], []
        for _first, _last, _ in _months:
            _total_r = AttendanceReport.objects.filter(
                attendance__group__branch=_branch,
                attendance__date__gte=_first,
                attendance__date__lt=_last,
            ).count()
            _present_r = AttendanceReport.objects.filter(
                attendance__group__branch=_branch,
                attendance__date__gte=_first,
                attendance__date__lt=_last,
                status__in=[AttendanceReport.PRESENT, AttendanceReport.LATE],
            ).count()
            _att_rate = round(_present_r / _total_r * 100) if _total_r else 0

            _result_agg = StudentResult.objects.filter(
                group__branch=_branch,
                created_at__date__gte=_first,
                created_at__date__lt=_last,
            ).aggregate(avg=models.Avg(models.F("test") + models.F("exam")))
            _avg_score = round(_result_agg["avg"] or 0)

            _active_s = (
                Enrollment.objects.filter(
                    group__branch=_branch,
                    is_active=True,
                )
                .values("student")
                .distinct()
                .count()
            )

            # Composite health: 50% attendance, 35% results, 15% presence signal
            _presence = min(100, round((_active_s / max(total_students, 1)) * 100 * 3))
            _health = round(_att_rate * 0.50 + _avg_score * 0.35 + min(100, _presence) * 0.15)

            _att_rates.append(_att_rate)
            _avg_scores.append(_avg_score)
            _student_counts.append(_active_s)

        branch_lines.append(
            {
                "label": _branch.name,
                "health": [
                    round(
                        _att_rates[_i] * 0.50
                        + _avg_scores[_i] * 0.35
                        + min(100, round(_student_counts[_i] / max(total_students, 1) * 300)) * 0.15
                    )
                    for _i in range(6)
                ],
                "att": _att_rates,
                "scores": _avg_scores,
                "students": _student_counts,
                "color": _BRANCH_COLORS[_bi % len(_BRANCH_COLORS)],
            }
        )

    # Monthly totals (all branches) for admin-wide trend charts
    monthly_sessions_list = []
    monthly_att_rate_list = []
    monthly_enroll_list = []
    for _first, _last, _ in _months:
        _s = Attendance.objects.filter(
            group_id__in=group_ids, date__gte=_first, date__lt=_last
        ).count()
        _tr = AttendanceReport.objects.filter(
            attendance__group_id__in=group_ids,
            attendance__date__gte=_first,
            attendance__date__lt=_last,
        ).count()
        _pr = AttendanceReport.objects.filter(
            attendance__group_id__in=group_ids,
            attendance__date__gte=_first,
            attendance__date__lt=_last,
            status__in=[AttendanceReport.PRESENT, AttendanceReport.LATE],
        ).count()
        _new_s = students_base.filter(
            admin__created_at__date__gte=_first,
            admin__created_at__date__lt=_last,
        ).count()
        monthly_sessions_list.append(_s)
        monthly_att_rate_list.append(round(_pr / _tr * 100) if _tr else 0)
        monthly_enroll_list.append(_new_s)

    monthly_chart_json = json.dumps(
        {
            "labels": _month_labels,
            "sessions": monthly_sessions_list,
            "att_rate": monthly_att_rate_list,
            "new_students": monthly_enroll_list,
        }
    )
    branch_chart_json = json.dumps(
        {
            "labels": _month_labels,
            "lines": branch_lines,
        }
    )

    branch_names = list(branching.get_accessible_branches(user).values_list("name", flat=True))
    if branching.is_super_admin(user):
        lead_qs = RegistrationLead.objects.all()
    else:
        lead_qs = RegistrationLead.objects.filter(
            models.Q(assigned_to=user) | models.Q(branch__in=branch_names)
        )
    total_leads = lead_qs.count()
    new_leads_7 = lead_qs.filter(created_at__date__gte=week_start).count()
    new_leads_previous = lead_qs.filter(
        created_at__date__gte=previous_week_start,
        created_at__date__lt=week_start,
    ).count()
    recent_leads = lead_qs.order_by("-created_at")[:4]
    recent_students = students_base.select_related("admin", "course", "branch").order_by(
        "-admin__created_at"
    )[:5]
    teacher_activity = (
        staff_base.select_related("admin", "course", "branch")
        .annotate(
            active_groups_count=models.Count("group", filter=models.Q(group__is_archived=False))
        )
        .order_by("-admin__updated_at")[:5]
    )
    upcoming_classes = list(
        groups_base.select_related("course", "teacher__admin", "branch")
        .filter(start_date__gte=today)
        .order_by("start_date")[:5]
    )
    upcoming_title = "Upcoming Classes"
    if not upcoming_classes:
        upcoming_classes = list(
            groups_base.select_related("course", "teacher__admin", "branch").order_by(
                "-updated_at"
            )[:5]
        )
        upcoming_title = "Active Classes"

    today_attendance_groups = []
    for group in groups_base.select_related("course", "teacher__admin").order_by("name")[:5]:
        group_reports = AttendanceReport.objects.filter(
            attendance__group=group,
            attendance__date=today,
        )
        group_total = group_reports.count()
        group_present = group_reports.filter(
            status__in=[AttendanceReport.PRESENT, AttendanceReport.LATE]
        ).count()
        today_attendance_groups.append(
            {
                "group": group,
                "present": group_present,
                "total": group_total,
                "rate": round((group_present / group_total) * 100) if group_total else 0,
            }
        )

    recent_activity = []
    for student in recent_students[:3]:
        recent_activity.append(
            {
                "icon": "fa-user-plus",
                "title": f"{student.admin.get_full_name() or student.admin.email}",
                "meta": f"New student · {student.course or 'Course pending'}",
                "at": student.admin.created_at,
                "href": reverse("manage_student"),
            }
        )
    for assignment in (
        Assignment.objects.filter(group_id__in=group_ids)
        .select_related("group", "created_by__admin")
        .order_by("-created_at")[:2]
    ):
        recent_activity.append(
            {
                "icon": "fa-tasks",
                "title": assignment.title,
                "meta": f"Assignment · {assignment.group or 'No group'}",
                "at": assignment.created_at,
                "href": reverse("manage_group"),
            }
        )
    for message in (
        ChatMessage.objects.filter(thread__group_id__in=group_ids)
        .select_related("sender", "thread__group")
        .order_by("-created_at")[:2]
    ):
        recent_activity.append(
            {
                "icon": "fa-comments",
                "title": message.sender.get_full_name() or message.sender.email,
                "meta": f"Message in {message.thread.group.name}",
                "at": message.created_at,
                "href": reverse("messages"),
            }
        )
    recent_activity = sorted(recent_activity, key=lambda item: item["at"], reverse=True)[:6]

    metric_cards = [
        {
            "label": "Students",
            "value": total_students,
            "icon": "fa-user-graduate",
            "href": reverse("manage_student"),
            "trend": pct_change(new_students_7, new_students_previous),
            "trend_label": f"{new_students_7} new this week",
            "progress": min(100, max(8, group_fill_pct)),
            "tone": "cyan",
        },
        {
            "label": "Teachers",
            "value": total_staff,
            "icon": "fa-chalkboard-teacher",
            "href": reverse("manage_staff"),
            "trend": pct_change(new_staff_7, new_staff_previous),
            "trend_label": f"{new_staff_7} added this week",
            "progress": min(100, max(8, round((total_staff / max(total_groups, 1)) * 20))),
            "tone": "blue",
        },
        {
            "label": "Active Groups",
            "value": total_groups,
            "icon": "fa-layer-group",
            "href": reverse("manage_group"),
            "trend": pct_change(new_groups_7, new_groups_previous),
            "trend_label": f"{group_fill_pct}% capacity filled",
            "progress": min(100, group_fill_pct),
            "tone": "navy",
        },
        {
            "label": "Programs",
            "value": total_course,
            "icon": "fa-graduation-cap",
            "href": reverse("manage_course"),
            "trend": pct_change(new_courses_7, new_courses_previous),
            "trend_label": f"{new_courses_7} new this week",
            "progress": min(100, max(8, round((active_course_count / max(total_course, 1)) * 100))),
            "tone": "blue",
        },
        {
            "label": "Attendance Today",
            "value": f"{attendance_today_rate}%",
            "icon": "fa-clipboard-check",
            "href": reverse("admin_view_attendance"),
            "trend": attendance_today_rate,
            "trend_label": f"{today_attendance_present}/{today_attendance_total} present",
            "progress": attendance_today_rate,
            "tone": "ice",
        },
        {
            "label": "Registration Leads",
            "value": total_leads,
            "icon": "fa-user-clock",
            "href": reverse("manage_registration_leads"),
            "trend": pct_change(new_leads_7, new_leads_previous),
            "trend_label": f"{new_leads_7} new this week",
            "progress": min(100, max(8, round((new_leads_7 / max(total_leads, 1)) * 100))),
            "tone": "cyan",
        },
    ]

    context = {
        "page_title": "Administrative Dashboard",
        "total_students": total_students,
        "total_staff": total_staff,
        "total_course": total_course,
        "total_groups": total_groups,
        "total_leads": total_leads,
        "metric_cards": metric_cards,
        "new_students_7": new_students_7,
        "new_leads_7": new_leads_7,
        "attendance_today_rate": attendance_today_rate,
        "today_attendance_present": today_attendance_present,
        "today_attendance_total": today_attendance_total,
        "active_enrollments": active_enrollments,
        "total_capacity": total_capacity,
        "assignments_due_soon": assignments_due_soon,
        "recent_leads": recent_leads,
        "recent_students": recent_students,
        "teacher_activity": teacher_activity,
        "today_attendance_groups": today_attendance_groups,
        "upcoming_classes": upcoming_classes,
        "upcoming_title": upcoming_title,
        "recent_activity": recent_activity,
        "group_label_list": group_label_list,
        "group_attendance_list": group_attendance_list,
        "student_attendance_present_list": student_attendance_present_list,
        "student_attendance_leave_list": student_attendance_leave_list,
        "student_name_list": student_name_list,
        "student_count_list_in_course": student_count_list_in_course,
        "course_name_list": course_name_list,
        "monthly_chart_json": monthly_chart_json,
        "branch_chart_json": branch_chart_json,
    }
    return render(request, "hod_template/home_content.html", context)


@admin_only
def add_staff(request):
    form = StaffForm(request.POST or None, request.FILES or None, user=request.user)
    context = {"form": form, "page_title": "Add Teacher"}
    if request.method == "POST":
        if form.is_valid():
            first_name = form.cleaned_data.get("first_name")
            last_name = form.cleaned_data.get("last_name")
            address = form.cleaned_data.get("address")
            gender = form.cleaned_data.get("gender")
            password = form.cleaned_data.get("password")
            course = form.cleaned_data.get("course")
            date_of_birth = form.cleaned_data.get("date_of_birth")
            passport = request.FILES.get("profile_pic")
            try:
                passport_url = ""
                if passport:
                    passport_url = default_storage.save(passport.name, passport)
                login_id = _generate_login_id("TC", date_of_birth)
                email = f"{login_id.lower()}@iceberg.internal"
                user = CustomUser.objects.create_user(
                    email=email,
                    password=password,
                    user_type=2,
                    first_name=first_name,
                    last_name=last_name,
                    profile_pic=passport_url,
                    login_id=login_id,
                )
                user.gender = gender
                user.address = address
                user.date_of_birth = date_of_birth
                user.save()
                staff_obj = Staff.objects.get(admin=user)
                staff_obj.course = course
                staff_obj.branch = form.cleaned_data.get("branch")
                staff_obj.phone = form.cleaned_data.get("phone", "")
                staff_obj.specialization = form.cleaned_data.get("specialization", "")
                staff_obj.is_active = True
                staff_obj.save()
                messages.success(request, f"Teacher added successfully. Login ID: {login_id}")
                return redirect(reverse("add_staff"))

            except Exception as e:
                messages.error(request, "Could Not Add " + str(e))
        else:
            messages.error(request, "Please fulfil all requirements")

    return render(request, "hod_template/add_staff_template.html", context)


@admin_only
def add_student(request):
    student_form = AddStudentForm(request.POST or None, request.FILES or None, user=request.user)
    context = {"form": student_form, "page_title": "Add Student"}
    if request.method == "POST":
        if student_form.is_valid():
            first_name = student_form.cleaned_data.get("first_name")
            last_name = student_form.cleaned_data.get("last_name")
            address = student_form.cleaned_data.get("address")
            gender = student_form.cleaned_data.get("gender")
            password = student_form.cleaned_data.get("password")
            course = student_form.cleaned_data.get("course")
            group = student_form.cleaned_data.get("group")
            date_of_birth = student_form.cleaned_data.get("date_of_birth")
            passport = request.FILES.get("profile_pic")
            try:
                passport_url = ""
                if passport:
                    passport_url = default_storage.save(passport.name, passport)
                login_id = _generate_login_id("IC", date_of_birth)
                email = f"{login_id.lower()}@iceberg.internal"
                user = CustomUser.objects.create_user(
                    email=email,
                    password=password,
                    user_type=3,
                    first_name=first_name,
                    last_name=last_name,
                    profile_pic=passport_url,
                    login_id=login_id,
                )
                user.gender = gender
                user.address = address
                user.date_of_birth = date_of_birth
                user.save()
                student = user.student
                student.course = course
                # clean() defaults branch from the group when left blank.
                student.branch = student_form.cleaned_data.get("branch")
                student.phone = student_form.cleaned_data.get("phone", "")
                student.status = student_form.cleaned_data.get("status", Student.STATUS_ACTIVE)
                raw_level = student_form.cleaned_data.get("level", "")
                student.level = int(raw_level) if raw_level else None
                student.save()
                if group:
                    Enrollment.objects.get_or_create(
                        student=student, group=group, defaults={"is_active": True}
                    )
                    Notification.objects.create(
                        recipient=user,
                        category=Notification.GENERAL,
                        message=f"Welcome! You have been enrolled in {group.name}.",
                    )
                    messages.success(
                        request,
                        f"Student added and enrolled in '{group.name}'. Login ID: {login_id}",
                    )
                else:
                    messages.success(
                        request,
                        f"Student {first_name} {last_name} added. Login ID: {login_id}. Enroll them in a group from the Enrollments page.",
                    )
                return redirect(reverse("add_student"))
            except Exception as e:
                messages.error(request, "Could Not Add: " + str(e))
        else:
            messages.error(request, "Please fix the errors below.")
    return render(request, "hod_template/add_student_template.html", context)


@admin_only
def manage_registration_leads(request):
    base_qs = branching.filter_registration_leads_for_user(
        request.user, RegistrationLead.objects.all()
    )

    if request.method == "POST":
        lead = get_object_or_404(base_qs, id=request.POST.get("lead_id"))
        status = request.POST.get("status", lead.status)
        if status in dict(RegistrationLead.STATUS_CHOICES):
            lead.status = status
        lead.admin_notes = request.POST.get("admin_notes", "").strip()
        lead.save(update_fields=["status", "admin_notes", "updated_at"])
        messages.success(request, "Registration lead updated.")
        query_string = request.POST.get("next", "")
        return redirect(reverse("manage_registration_leads") + query_string)

    leads = base_qs
    status_filter = request.GET.get("status", "").strip()
    source_filter = request.GET.get("source", "").strip()
    branch_filter = request.GET.get("branch", "").strip()
    search = request.GET.get("q", "").strip()

    if status_filter:
        leads = leads.filter(status=status_filter)
    if source_filter:
        leads = leads.filter(source__iexact=source_filter)
    # RegistrationLead.branch is free text (pre-enrollment); this is a
    # best-effort contains match rather than a strict FK scope.
    if branch_filter:
        leads = leads.filter(branch__icontains=branch_filter)
    if search:
        leads = leads.filter(
            models.Q(full_name__icontains=search)
            | models.Q(first_name__icontains=search)
            | models.Q(last_name__icontains=search)
            | models.Q(phone__icontains=search)
            | models.Q(parent_phone__icontains=search)
            | models.Q(email__icontains=search)
            | models.Q(program__icontains=search)
            | models.Q(social_handle__icontains=search)
        )

    status_counts = {
        row["status"]: row["count"]
        for row in base_qs.values("status").annotate(count=models.Count("id"))
    }
    status_summary = [
        {"value": value, "label": label, "count": status_counts.get(value, 0)}
        for value, label in RegistrationLead.STATUS_CHOICES
    ]
    sources = (
        base_qs.exclude(source="").values_list("source", flat=True).distinct().order_by("source")
    )

    return render(
        request,
        "hod_template/manage_registration_leads.html",
        {
            "page_title": "Registration Leads",
            "leads": leads[:250],
            "status_choices": RegistrationLead.STATUS_CHOICES,
            "status_summary": status_summary,
            "sources": sources,
            "status_filter": status_filter,
            "source_filter": source_filter,
            "search": search,
        },
    )


@super_admin_only
def add_course(request):
    form = CourseForm(request.POST or None)
    context = {"form": form, "page_title": "Add Course"}
    if request.method == "POST":
        if form.is_valid():
            try:
                course = Course()
                course.name = form.cleaned_data.get("name")
                course.is_english = _derive_is_english(course.name)
                course.is_active = True
                course.monthly_fee = form.cleaned_data.get("monthly_fee")
                course.save()
                messages.success(request, "Program added successfully.")
                return redirect(reverse("add_course"))
            except Exception:
                messages.error(request, "Could Not Add")
        else:
            messages.error(request, "Could Not Add")
    return render(request, "hod_template/add_course_template.html", context)


@super_admin_only
def add_subject(request):
    form = SubjectForm(request.POST or None)
    context = {"form": form, "page_title": "Add Subject"}
    if request.method == "POST":
        if form.is_valid():
            name = form.cleaned_data.get("name")
            course = form.cleaned_data.get("course")
            staff = form.cleaned_data.get("staff")
            try:
                subject = Subject()
                subject.name = name
                subject.staff = staff
                subject.course = course
                subject.save()
                messages.success(request, "Successfully Added")
                return redirect(reverse("add_subject"))

            except Exception as e:
                messages.error(request, "Could Not Add " + str(e))
        else:
            messages.error(request, "Fill Form Properly")

    return render(request, "hod_template/add_subject_template.html", context)


@admin_only
def manage_staff(request):
    allowed = branching.filter_staff_for_user(request.user, Staff.objects.all())
    allStaff = (
        CustomUser.objects.filter(user_type=2, staff__in=allowed)
        .select_related("staff", "staff__course", "staff__branch")
        .distinct()
    )
    branch_id = request.GET.get("branch")
    if branch_id:
        allStaff = allStaff.filter(staff__branch_id=branch_id)
    context = {
        "allStaff": allStaff,
        "page_title": "Manage Teachers",
        "branches": branching.get_accessible_branches(request.user),
        "selected_branch": branch_id,
        "is_super_admin": branching.is_super_admin(request.user),
    }
    return render(request, "hod_template/manage_staff.html", context)


@admin_only
def manage_student(request):
    allowed = branching.filter_students_for_user(request.user, Student.objects.all())
    students = (
        CustomUser.objects.filter(user_type=3, student__in=allowed)
        .select_related("student", "student__course", "student__branch")
        .distinct()
    )
    branch_id = request.GET.get("branch")
    if branch_id:
        students = students.filter(student__branch_id=branch_id)
    context = {
        "students": students,
        "page_title": "Manage Students",
        "branches": branching.get_accessible_branches(request.user),
        "selected_branch": branch_id,
        "is_super_admin": branching.is_super_admin(request.user),
    }
    return render(request, "hod_template/manage_student.html", context)


@admin_only
def manage_course(request):
    courses = Course.objects.all()
    context = {"courses": courses, "page_title": "Manage Courses"}
    return render(request, "hod_template/manage_course.html", context)


@admin_only
def manage_subject(request):
    subjects = Subject.objects.all()
    context = {"subjects": subjects, "page_title": "Manage Subjects"}
    return render(request, "hod_template/manage_subject.html", context)


@admin_only
def edit_staff(request, staff_id):
    staff = get_object_or_404(Staff, id=staff_id)
    if not branching.filter_staff_for_user(
        request.user, Staff.objects.filter(id=staff_id)
    ).exists():
        messages.error(request, "You don't have access to this teacher's branch.")
        return redirect(reverse("manage_staff"))
    form = StaffEditForm(
        request.POST or None, request.FILES or None, instance=staff, user=request.user
    )
    context = {
        "form": form,
        "staff_id": staff_id,
        "login_id": staff.admin.login_id or "—",
        "page_title": "Edit Teacher",
    }
    if request.method == "POST":
        if form.is_valid():
            first_name = form.cleaned_data.get("first_name")
            last_name = form.cleaned_data.get("last_name")
            address = form.cleaned_data.get("address")
            gender = form.cleaned_data.get("gender")
            password = form.cleaned_data.get("password") or None
            course = form.cleaned_data.get("course")
            passport = request.FILES.get("profile_pic") or None
            try:
                user = CustomUser.objects.get(id=staff.admin.id)
                if password is not None:
                    user.set_password(password)
                if passport is not None:
                    user.profile_pic = default_storage.save(passport.name, passport)
                user.first_name = first_name
                user.last_name = last_name
                user.gender = gender
                user.address = address
                dob = form.cleaned_data.get("date_of_birth")
                if dob is not None:
                    user.date_of_birth = dob
                staff.course = course
                staff.branch = form.cleaned_data.get("branch")
                staff.phone = form.cleaned_data.get("phone", "")
                staff.specialization = form.cleaned_data.get("specialization", "")
                staff.is_active = True
                user.save()
                staff.save()
                messages.success(request, "Successfully Updated")
                return redirect(reverse("edit_staff", args=[staff_id]))
            except Exception as e:
                messages.error(request, "Could Not Update " + str(e))
        else:
            messages.error(request, "Please fill form properly")
    return render(request, "hod_template/edit_staff_template.html", context)


@admin_only
def edit_student(request, student_id):
    student = get_object_or_404(Student, id=student_id)
    if not branching.filter_students_for_user(
        request.user, Student.objects.filter(id=student_id)
    ).exists():
        messages.error(request, "You don't have access to this student's branch.")
        return redirect(reverse("manage_student"))
    form = StudentForm(request.POST or None, instance=student, user=request.user)
    context = {
        "form": form,
        "student_id": student_id,
        "login_id": student.admin.login_id or "—",
        "page_title": "Edit Student",
    }
    if request.method == "POST":
        if form.is_valid():
            first_name = form.cleaned_data.get("first_name")
            last_name = form.cleaned_data.get("last_name")
            address = form.cleaned_data.get("address")
            gender = form.cleaned_data.get("gender")
            password = form.cleaned_data.get("password") or None
            course = form.cleaned_data.get("course")
            passport = request.FILES.get("profile_pic") or None
            try:
                user = CustomUser.objects.get(id=student.admin.id)
                if passport is not None:
                    user.profile_pic = default_storage.save(passport.name, passport)
                if password is not None:
                    user.set_password(password)
                user.first_name = first_name
                user.last_name = last_name
                user.gender = gender
                user.address = address
                dob = form.cleaned_data.get("date_of_birth")
                if dob is not None:
                    user.date_of_birth = dob
                student.course = course
                student.branch = form.cleaned_data.get("branch")
                student.phone = form.cleaned_data.get("phone", "")
                student.status = form.cleaned_data.get("status", student.status)
                raw_level = form.cleaned_data.get("level", "")
                student.level = int(raw_level) if raw_level else None
                user.save()
                student.save()
                messages.success(request, "Successfully Updated")
                return redirect(reverse("edit_student", args=[student_id]))
            except Exception as e:
                messages.error(request, "Could Not Update " + str(e))
        else:
            messages.error(request, "Please Fill Form Properly!")
    return render(request, "hod_template/edit_student_template.html", context)


@super_admin_only
def edit_course(request, course_id):
    instance = get_object_or_404(Course, id=course_id)
    form = CourseForm(request.POST or None, instance=instance)
    context = {"form": form, "course_id": course_id, "page_title": "Edit Course"}
    if request.method == "POST":
        if form.is_valid():
            try:
                course = Course.objects.get(id=course_id)
                course.name = form.cleaned_data.get("name")
                course.is_english = _derive_is_english(course.name)
                course.monthly_fee = form.cleaned_data.get("monthly_fee")
                course.save()
                messages.success(request, "Program updated successfully.")
            except Exception:
                messages.error(request, "Could Not Update")
        else:
            messages.error(request, "Could Not Update")

    return render(request, "hod_template/edit_course_template.html", context)


@super_admin_only
def edit_subject(request, subject_id):
    instance = get_object_or_404(Subject, id=subject_id)
    form = SubjectForm(request.POST or None, instance=instance)
    context = {"form": form, "subject_id": subject_id, "page_title": "Edit Subject"}
    if request.method == "POST":
        if form.is_valid():
            name = form.cleaned_data.get("name")
            course = form.cleaned_data.get("course")
            staff = form.cleaned_data.get("staff")
            try:
                subject = Subject.objects.get(id=subject_id)
                subject.name = name
                subject.staff = staff
                subject.course = course
                subject.save()
                messages.success(request, "Successfully Updated")
                return redirect(reverse("edit_subject", args=[subject_id]))
            except Exception as e:
                messages.error(request, "Could Not Add " + str(e))
        else:
            messages.error(request, "Fill Form Properly")
    return render(request, "hod_template/edit_subject_template.html", context)


@super_admin_only
def add_session(request):
    form = SessionForm(request.POST or None)
    context = {"form": form, "page_title": "Add Session"}
    if request.method == "POST":
        if form.is_valid():
            try:
                form.save()
                messages.success(request, "Session Created")
                return redirect(reverse("add_session"))
            except Exception as e:
                messages.error(request, "Could Not Add " + str(e))
        else:
            messages.error(request, "Fill Form Properly ")
    return render(request, "hod_template/add_session_template.html", context)


@admin_only
def manage_session(request):
    sessions = Session.objects.all()
    context = {"sessions": sessions, "page_title": "Manage Sessions"}
    return render(request, "hod_template/manage_session.html", context)


@super_admin_only
def edit_session(request, session_id):
    instance = get_object_or_404(Session, id=session_id)
    form = SessionForm(request.POST or None, instance=instance)
    context = {"form": form, "session_id": session_id, "page_title": "Edit Session"}
    if request.method == "POST":
        if form.is_valid():
            try:
                form.save()
                messages.success(request, "Session Updated")
                return redirect(reverse("edit_session", args=[session_id]))
            except Exception as e:
                messages.error(request, "Session Could Not Be Updated " + str(e))
                return render(request, "hod_template/edit_session_template.html", context)
        else:
            messages.error(request, "Invalid Form Submitted ")
            return render(request, "hod_template/edit_session_template.html", context)

    else:
        return render(request, "hod_template/edit_session_template.html", context)


@admin_only
def check_email_availability(request):
    email = request.POST.get("email")
    try:
        user = CustomUser.objects.filter(email=email).exists()
        if user:
            return HttpResponse(True)
        return HttpResponse(False)
    except Exception as e:
        logger.exception("check_email_availability failed (%s)", e)
        return HttpResponse(False)


@admin_only
def student_feedback_message(request):
    allowed_students = branching.filter_students_for_user(request.user, Student.objects.all())
    if request.method != "POST":
        feedbacks = FeedbackStudent.objects.filter(student__in=allowed_students)
        context = {"feedbacks": feedbacks, "page_title": "Student Feedback Messages"}
        return render(request, "hod_template/student_feedback_template.html", context)
    else:
        feedback_id = request.POST.get("id")
        try:
            feedback = get_object_or_404(
                FeedbackStudent, id=feedback_id, student__in=allowed_students
            )
            reply = request.POST.get("reply")
            feedback.reply = reply
            feedback.save()
            return HttpResponse(True)
        except Exception as e:
            logger.exception("Failed to save feedback reply (%s)", e)
            return HttpResponse(False)


@admin_only
def staff_feedback_message(request):
    allowed_staff = branching.filter_staff_for_user(request.user, Staff.objects.all())
    if request.method != "POST":
        feedbacks = FeedbackStaff.objects.filter(staff__in=allowed_staff)
        context = {"feedbacks": feedbacks, "page_title": "Teacher Feedback"}
        return render(request, "hod_template/staff_feedback_template.html", context)
    else:
        feedback_id = request.POST.get("id")
        try:
            feedback = get_object_or_404(FeedbackStaff, id=feedback_id, staff__in=allowed_staff)
            reply = request.POST.get("reply")
            feedback.reply = reply
            feedback.save()
            return HttpResponse(True)
        except Exception as e:
            logger.exception("Failed to save feedback reply (%s)", e)
            return HttpResponse(False)


@admin_only
def view_staff_leave(request):
    allowed_staff = branching.filter_staff_for_user(request.user, Staff.objects.all())
    if request.method != "POST":
        allLeave = LeaveReportStaff.objects.filter(staff__in=allowed_staff)
        context = {"allLeave": allLeave, "page_title": "Teacher Leave Requests"}
        return render(request, "hod_template/staff_leave_view.html", context)
    else:
        id = request.POST.get("id")
        status = request.POST.get("status")
        if status == "1":
            status = 1
        else:
            status = -1
        try:
            leave = get_object_or_404(LeaveReportStaff, id=id, staff__in=allowed_staff)
            leave.status = status
            leave.save()
            return HttpResponse(True)
        except Exception as e:
            logger.exception("Failed to update leave status (%s)", e)
            return HttpResponse(False)


@admin_only
def view_student_leave(request):
    allowed_students = branching.filter_students_for_user(request.user, Student.objects.all())
    if request.method != "POST":
        allLeave = LeaveReportStudent.objects.filter(student__in=allowed_students)
        context = {"allLeave": allLeave, "page_title": "Leave Applications From Students"}
        return render(request, "hod_template/student_leave_view.html", context)
    else:
        id = request.POST.get("id")
        status = request.POST.get("status")
        if status == "1":
            status = 1
        else:
            status = -1
        try:
            leave = get_object_or_404(LeaveReportStudent, id=id, student__in=allowed_students)
            leave.status = status
            leave.save()
            return HttpResponse(True)
        except Exception as e:
            logger.exception("Failed to update leave status (%s)", e)
            return HttpResponse(False)


@admin_only
def admin_view_attendance(request):
    groups = branching.filter_groups_for_user(
        request.user,
        Group.objects.filter(is_archived=False).select_related("course", "teacher__admin"),
    )
    context = {
        "groups": groups,
        "page_title": "View Attendance",
    }
    return render(request, "hod_template/admin_view_attendance.html", context)


@admin_only
def get_admin_attendance(request):
    attendance_date_id = request.POST.get("attendance_date_id")
    group_id = request.POST.get("group")
    try:
        if attendance_date_id:
            attendance = get_object_or_404(
                Attendance.objects.select_related("group"), id=attendance_date_id
            )
            # Never let a branch admin read attendance from a group outside
            # their branch by posting a forged attendance_date_id.
            if not branching.user_can_access_group(request.user, attendance.group):
                return JsonResponse({"error": "Not allowed."}, status=403)
            reports = AttendanceReport.objects.filter(attendance=attendance).select_related(
                "student"
            )
            data = [{"status": r.status, "name": str(r.student)} for r in reports]
            return JsonResponse(data, safe=False)
        # Return list of attendance dates for a group
        group = get_object_or_404(Group, id=group_id)
        if not branching.user_can_access_group(request.user, group):
            return JsonResponse({"error": "Not allowed."}, status=403)
        dates = Attendance.objects.filter(group=group).order_by("-date")
        data = [{"id": a.id, "attendance_date": str(a.date)} for a in dates]
        return JsonResponse(data, safe=False)
    except Exception:
        return JsonResponse({"error": "Unable to fetch attendance."}, status=400)


@admin_only
def admin_view_profile(request):
    return redirect(reverse("profile_hub"))


@admin_only
def admin_notify_staff(request):
    return redirect(reverse("messages"))


@admin_only
def admin_notify_student(request):
    return redirect(reverse("messages"))


def _notify_user(recipient, message):
    """Create an in-app announcement for ``recipient``.

    The old code also POSTed to the legacy FCM ``/fcm/send`` endpoint, which
    Google shut down in 2024, so no push was ever delivered. Mobile push needs
    the FCM HTTP v1 API (service-account credentials) — tracked separately.
    """
    message = (message or "").strip()
    if not message:
        return HttpResponse("False", status=400)
    Notification.objects.create(
        recipient=recipient, category=Notification.ANNOUNCEMENT, message=message
    )
    return HttpResponse("True")


@admin_only
@require_POST
def send_student_notification(request):
    allowed = branching.filter_students_for_user(request.user, Student.objects.all())
    student = get_object_or_404(allowed, admin_id=request.POST.get("id"))
    return _notify_user(student.admin, request.POST.get("message"))


@admin_only
@require_POST
def send_staff_notification(request):
    allowed = branching.filter_staff_for_user(request.user, Staff.objects.all())
    staff = get_object_or_404(allowed, admin_id=request.POST.get("id"))
    return _notify_user(staff.admin, request.POST.get("message"))


@admin_only
@require_POST
def delete_staff(request, staff_id):
    staff_obj = get_object_or_404(Staff, id=staff_id)
    if not branching.filter_staff_for_user(
        request.user, Staff.objects.filter(id=staff_id)
    ).exists():
        messages.error(request, "You don't have permission to delete this teacher.")
        return redirect(reverse("manage_staff"))
    try:
        staff_obj.admin.delete()
        messages.success(request, "Staff deleted successfully!")
    except IntegrityError:
        messages.error(request, "Could not delete staff because related attendance data exists.")
    return redirect(reverse("manage_staff"))


@admin_only
@require_POST
def delete_student(request, student_id):
    student_obj = get_object_or_404(Student, id=student_id)
    if not branching.filter_students_for_user(
        request.user, Student.objects.filter(id=student_id)
    ).exists():
        messages.error(request, "You don't have permission to delete this student.")
        return redirect(reverse("manage_student"))
    student_user = student_obj.admin
    try:
        with transaction.atomic():
            # AttendanceReport keeps a DO_NOTHING FK to Student, so remove it manually.
            AttendanceReport.objects.filter(student=student_obj).delete()
            student_user.delete()
        messages.success(request, "Student deleted successfully!")
    except IntegrityError:
        messages.error(request, "Could not delete student because related records still exist.")
    return redirect(reverse("manage_student"))


@super_admin_only
@require_POST
def delete_course(request, course_id):
    course = get_object_or_404(Course, id=course_id)
    try:
        course.delete()
        messages.success(request, "Course deleted successfully!")
    except IntegrityError:
        messages.error(
            request,
            "Could not delete course because linked records still exist. Reassign linked students/staff and try again.",
        )
    except Exception:
        messages.error(
            request, "Could not delete course due to an unexpected error. Please try again."
        )
    return redirect(reverse("manage_course"))


@super_admin_only
@require_POST
def toggle_course_active(request, course_id):
    course = get_object_or_404(Course, id=course_id)
    course.is_active = not course.is_active
    course.save()
    state = "activated" if course.is_active else "deactivated"
    messages.success(request, f"Course '{course.name}' has been {state}.")
    return redirect(reverse("manage_course"))


@super_admin_only
@require_POST
def delete_subject(request, subject_id):
    subject = get_object_or_404(Subject, id=subject_id)
    try:
        subject.delete()
        messages.success(request, "Subject deleted successfully!")
    except IntegrityError:
        messages.error(
            request, "Could not delete subject because attendance records are linked to it."
        )
    return redirect(reverse("manage_subject"))


@super_admin_only
@require_POST
def delete_session(request, session_id):
    session = get_object_or_404(Session, id=session_id)
    try:
        session.delete()
        messages.success(request, "Session deleted successfully!")
    except Exception:
        messages.error(
            request,
            "There are students assigned to this session. Please move them to another session.",
        )
    return redirect(reverse("manage_session"))


@admin_only
def get_teachers_for_course(request):
    course_id = request.GET.get("course_id") or request.POST.get("course_id")
    try:
        teachers = (
            branching.filter_staff_for_user(request.user, Staff.objects.filter(course_id=course_id))
            .select_related("admin")
            .order_by("admin__last_name")
        )
        data = [{"id": t.id, "name": f"{t.admin.first_name} {t.admin.last_name}"} for t in teachers]
        return JsonResponse(data, safe=False)
    except Exception:
        return JsonResponse([], safe=False)


@admin_only
def get_groups_for_teacher(request):
    teacher_id = request.GET.get("teacher_id") or request.POST.get("teacher_id")
    course_id = request.GET.get("course_id") or request.POST.get("course_id")
    try:
        qs = branching.filter_groups_for_user(
            request.user,
            Group.objects.filter(is_archived=False).select_related("course", "teacher__admin"),
        )
        if teacher_id:
            qs = qs.filter(teacher_id=teacher_id)
        elif course_id:
            qs = qs.filter(course_id=course_id)
        qs = qs.order_by("name")
        data = [
            {
                "id": g.id,
                "name": (
                    g.name
                    + (f" · {g.course.name}" if g.course else "")
                    + (f" · {g.teacher}" if g.teacher else "")
                ),
            }
            for g in qs
        ]
        return JsonResponse(data, safe=False)
    except Exception:
        return JsonResponse([], safe=False)


# ── Admin account management ──────────────────────────────────────────────────


@admin_only
def add_admin(request):
    if not branching.is_super_admin(request.user):
        messages.error(request, "Only a super admin can add admin accounts.")
        return redirect(reverse("admin_home"))

    all_branches = Branch.objects.all().order_by("name")

    if request.method == "POST":
        first_name = request.POST.get("first_name", "").strip()
        last_name = request.POST.get("last_name", "").strip()
        email = request.POST.get("email", "").strip()
        password = request.POST.get("password", "")
        gender = request.POST.get("gender", "")
        address = request.POST.get("address", "").strip()
        branch_ids = request.POST.getlist("branches")

        errors = []
        if not first_name:
            errors.append("First name is required.")
        if not last_name:
            errors.append("Last name is required.")
        if not email:
            errors.append("Email address is required.")
        elif CustomUser.objects.filter(email__iexact=email).exists():
            errors.append("An account with this email already exists.")
        if not password:
            errors.append("Password is required.")
        else:
            try:
                validate_password(password)
            except ValidationError as exc:
                errors.extend(exc.messages)
        if not branch_ids:
            errors.append("Assign at least one branch to this admin.")

        if errors:
            for e in errors:
                messages.error(request, e)
            return render(
                request,
                "hod_template/add_admin_template.html",
                {
                    "all_branches": all_branches,
                    "page_title": "Add Admin",
                    "form_data": {
                        "first_name": first_name,
                        "last_name": last_name,
                        "email": email,
                        "gender": gender,
                        "address": address,
                    },
                    "selected_branch_ids": branch_ids,
                },
            )

        try:
            user = CustomUser.objects.create_user(
                email=email,
                password=password,
                user_type=1,
                first_name=first_name,
                last_name=last_name,
            )
            user.gender = gender
            user.address = address
            user.save()

            # Signal already created Admin with is_super_admin=True. Override it
            # to branch admin so we don't accidentally create a second super admin.
            admin_profile = user.admin
            admin_profile.is_super_admin = False
            admin_profile.save(update_fields=["is_super_admin"])
            selected_branches = Branch.objects.filter(id__in=branch_ids)
            admin_profile.branches.set(selected_branches)

            name = f"{first_name} {last_name}".strip()
            messages.success(
                request, f'Admin account "{name}" created. They can log in with their email.'
            )
            return redirect(reverse("manage_admin"))
        except Exception as exc:
            messages.error(request, f"Could not create admin — {exc}")

    return render(
        request,
        "hod_template/add_admin_template.html",
        {
            "all_branches": all_branches,
            "page_title": "Add Admin",
            "form_data": {},
            "selected_branch_ids": [],
        },
    )


@admin_only
def edit_admin(request, admin_id):
    """Super admins edit an existing admin's credentials (name, email,
    password) — including the recovery account. Changes are saved to that one
    account; nothing is duplicated."""
    if not branching.is_super_admin(request.user):
        messages.error(request, "Only a super admin can edit admin accounts.")
        return redirect(reverse("admin_home"))

    admin_profile = get_object_or_404(Admin.objects.select_related("admin"), id=admin_id)
    target = admin_profile.admin
    editing_self = target == request.user

    def _render(form_data):
        return render(
            request,
            "hod_template/edit_admin_template.html",
            {
                "page_title": "Edit Admin",
                "admin_profile": admin_profile,
                "editing_self": editing_self,
                "form_data": form_data,
            },
        )

    if request.method == "POST":
        first_name = request.POST.get("first_name", "").strip()
        last_name = request.POST.get("last_name", "").strip()
        email = request.POST.get("email", "").strip()
        password = request.POST.get("password", "")
        gender = request.POST.get("gender", "")
        address = request.POST.get("address", "").strip()

        errors = []
        if not first_name:
            errors.append("First name is required.")
        if not last_name:
            errors.append("Last name is required.")
        if not email:
            errors.append("Email address is required.")
        elif CustomUser.objects.filter(email__iexact=email).exclude(pk=target.pk).exists():
            errors.append("Another account already uses this email.")
        if password:
            try:
                validate_password(password, target)
            except ValidationError as exc:
                errors.extend(exc.messages)

        if errors:
            for e in errors:
                messages.error(request, e)
            return _render(
                {
                    "first_name": first_name,
                    "last_name": last_name,
                    "email": email,
                    "gender": gender,
                    "address": address,
                }
            )

        try:
            target.first_name = first_name
            target.last_name = last_name
            target.email = email
            target.gender = gender
            target.address = address
            if password:
                target.set_password(password)
            target.save()
            # Changing your own password rotates the session hash and would log
            # you out — keep the current session alive instead.
            if editing_self and password:
                update_session_auth_hash(request, target)
            name = target.get_full_name() or target.email
            if password and not editing_self:
                messages.success(
                    request,
                    f'Saved "{name}". They must sign in again with the new password.',
                )
            else:
                messages.success(request, f'Saved changes to "{name}".')
            return redirect(reverse("manage_admin"))
        except Exception as exc:
            messages.error(request, f"Could not save changes — {exc}")

    return _render(
        {
            "first_name": target.first_name,
            "last_name": target.last_name,
            "email": target.email,
            "gender": target.gender,
            "address": target.address,
        }
    )


@admin_only
def manage_admin(request):
    if not branching.is_super_admin(request.user):
        messages.error(request, "Only a super admin can manage admin accounts.")
        return redirect(reverse("admin_home"))

    try:
        current_admin_profile = Admin.objects.get(admin=request.user)
    except Admin.DoesNotExist:
        current_admin_profile = None

    admin_profiles = list(
        Admin.objects.select_related("admin")
        .prefetch_related("branches")
        .order_by("admin__first_name", "admin__last_name", "admin__email")
    )
    all_branches = Branch.objects.all().order_by("name")
    super_admin_count = sum(1 for ap in admin_profiles if ap.is_super_admin)

    for admin_profile in admin_profiles:
        assigned_branches = list(admin_profile.branches.all())
        admin_profile.assigned_branch_ids = {branch.id for branch in assigned_branches}
        admin_profile.assigned_branch_names = ", ".join(branch.name for branch in assigned_branches)
        admin_profile.is_current_user = (
            current_admin_profile is not None and admin_profile.id == current_admin_profile.id
        )
        admin_profile.is_recovery = branching.is_recovery_admin(admin_profile.admin)
        # The only protected case is the last remaining super admin — removing or
        # demoting it would lock everyone out. Otherwise any super admin can
        # change roles, edit credentials, and delete any account (incl. recovery).
        admin_profile.is_last_super = admin_profile.is_super_admin and super_admin_count <= 1
        admin_profile.superadmin_toggle_locked = admin_profile.is_last_super
        admin_profile.can_edit_credentials = True
        admin_profile.can_delete = (
            not admin_profile.is_current_user and not admin_profile.is_last_super
        )

    return render(
        request,
        "hod_template/manage_admin.html",
        {
            "admin_profiles": admin_profiles,
            "all_branches": all_branches,
            "page_title": "Manage Admins",
        },
    )


@admin_only
@require_POST
def delete_admin(request, admin_id):
    if not branching.is_super_admin(request.user):
        messages.error(request, "Only a super admin can delete admin accounts.")
        return redirect(reverse("manage_admin"))

    admin_profile = get_object_or_404(Admin, id=admin_id)

    if admin_profile.admin == request.user:
        messages.error(request, "You cannot delete your own admin account.")
        return redirect(reverse("manage_admin"))

    # The recovery account can be destroyed like any other admin. The only guard
    # is not wiping out the last super admin and locking everyone out — promote
    # another admin to super first.
    if admin_profile.is_super_admin and Admin.objects.filter(is_super_admin=True).count() <= 1:
        messages.error(
            request,
            "Cannot delete the only super admin — promote another admin to super first.",
        )
        return redirect(reverse("manage_admin"))

    name = admin_profile.admin.get_full_name() or admin_profile.admin.email
    try:
        admin_profile.admin.delete()
        messages.success(request, f'Admin account "{name}" deleted.')
    except Exception as exc:
        messages.error(request, f"Could not delete admin — {exc}")

    return redirect(reverse("manage_admin"))


# ── Branch CRUD ──────────────────────────────────────────────────────────────


@admin_only
def manage_branch(request):
    is_super_admin = branching.is_super_admin(request.user)
    branches = branching.filter_branches_for_user(request.user, Branch.objects.all())
    all_branches = Branch.objects.all().order_by("name")
    return render(
        request,
        "hod_template/manage_branch.html",
        {
            "branches": branches,
            "all_branches": all_branches,
            "page_title": "Manage Branches",
            "is_super_admin": is_super_admin,
        },
    )


@admin_only
def update_admin_branch_access(request, admin_id):
    if not branching.is_super_admin(request.user):
        messages.error(request, "Only a super admin can change admin branch access.")
        return redirect(reverse("manage_admin"))

    if request.method != "POST":
        return redirect(reverse("manage_admin"))

    admin_profile = get_object_or_404(
        Admin.objects.select_related("admin").prefetch_related("branches"), id=admin_id
    )
    make_super_admin = request.POST.get("is_super_admin") == "on"
    branch_ids = request.POST.getlist("branches")

    # Don't allow demoting the last super admin — that would leave nobody able
    # to manage admins/branches.
    if not make_super_admin and admin_profile.is_super_admin:
        other_super_exists = (
            Admin.objects.filter(is_super_admin=True).exclude(id=admin_profile.id).exists()
        )
        if not other_super_exists:
            messages.error(
                request,
                "Keep at least one super admin — promote another admin before demoting this one.",
            )
            return redirect(reverse("manage_admin"))

    if not make_super_admin and not branch_ids:
        messages.error(
            request,
            "Select at least one dedicated branch for a branch admin.",
        )
        return redirect(reverse("manage_admin"))

    selected_branches = Branch.objects.filter(id__in=branch_ids).order_by("name")
    if not make_super_admin and not selected_branches.exists():
        messages.error(request, "Select at least one valid branch for this admin.")
        return redirect(reverse("manage_admin"))

    admin_profile.is_super_admin = make_super_admin
    admin_profile.save(update_fields=["is_super_admin"])
    if make_super_admin:
        admin_profile.branches.clear()
        messages.success(
            request,
            f"{admin_profile.admin.get_full_name() or admin_profile.admin.email} now manages all branches.",
        )
    else:
        admin_profile.branches.set(selected_branches)
        branch_names = ", ".join(selected_branches.values_list("name", flat=True))
        messages.success(
            request,
            f"{admin_profile.admin.get_full_name() or admin_profile.admin.email} is assigned to {branch_names}.",
        )
    return redirect(reverse("manage_admin"))


@admin_only
def add_branch(request):
    # Only super admins create branches; branch admins manage within theirs.
    if not branching.is_super_admin(request.user):
        messages.error(request, "Only a super admin can create branches.")
        return redirect(reverse("manage_branch"))
    form = BranchForm(request.POST or None, can_set_brand=True)
    if request.method == "POST":
        if form.is_valid():
            form.save()
            messages.success(request, "Branch added successfully!")
            return redirect(reverse("manage_branch"))
    return render(
        request,
        "hod_template/add_branch.html",
        {
            "form": form,
            "page_title": "Add Branch",
        },
    )


@admin_only
def edit_branch(request, branch_id):
    branch = get_object_or_404(Branch, id=branch_id)
    if not branching.user_can_access_branch(request.user, branch):
        messages.error(request, "You don't have access to this branch.")
        return redirect(reverse("manage_branch"))
    form = BranchForm(
        request.POST or None,
        instance=branch,
        can_set_brand=branching.is_super_admin(request.user),
    )
    if request.method == "POST":
        if form.is_valid():
            form.save()
            messages.success(request, "Branch updated!")
            return redirect(reverse("manage_branch"))
    return render(
        request,
        "hod_template/add_branch.html",
        {
            "form": form,
            "page_title": "Edit Branch",
        },
    )


@admin_only
@require_POST
def delete_branch(request, branch_id):
    if not branching.is_super_admin(request.user):
        messages.error(request, "Only a super admin can delete branches.")
        return redirect(reverse("manage_branch"))
    if Branch.objects.count() <= 1:
        messages.error(request, "Cannot delete the only branch. Add another branch first.")
        return redirect(reverse("manage_branch"))
    branch = get_object_or_404(Branch, id=branch_id)
    branch_name = branch.name
    # Students/staff/groups use SET_NULL, so deleting a populated branch would
    # silently orphan them (invisible to every branch admin). Same rule as the
    # API's BranchDetailView.delete.
    if (
        Student.objects.filter(branch=branch).exists()
        or Staff.objects.filter(branch=branch).exists()
        or Group.objects.filter(branch=branch).exists()
    ):
        messages.error(
            request,
            f"Branch “{branch_name}” still has students, staff or groups. "
            "Move them to another branch first.",
        )
        return redirect(reverse("manage_branch"))
    try:
        branch.delete()
        messages.success(request, f"Branch “{branch_name}” deleted.")
    except Exception:
        logger.exception("delete_branch failed for branch_id=%s", branch_id)
        messages.error(request, "Could not delete branch due to an unexpected error.")
    return redirect(reverse("manage_branch"))


# ── Group CRUD ───────────────────────────────────────────────────────────────


@admin_only
def manage_group(request):
    from django.db.models import Count, Q

    groups = (
        branching.filter_groups_for_user(
            request.user, Group.objects.select_related("course", "teacher__admin", "branch")
        )
        .annotate(enrolled_count=Count("enrollment", filter=Q(enrollment__is_active=True)))
        .order_by("is_archived", "name")
    )
    branch_id = request.GET.get("branch")
    if branch_id:
        groups = groups.filter(branch_id=branch_id)
    return render(
        request,
        "hod_template/manage_group.html",
        {
            "groups": groups,
            "page_title": "Manage Groups",
            "branches": branching.get_accessible_branches(request.user),
            "selected_branch": branch_id,
            "is_super_admin": branching.is_super_admin(request.user),
        },
    )


@admin_only
def admin_group_detail(request, group_id):
    group = get_object_or_404(Group, id=group_id)
    if not branching.user_can_access_group(request.user, group):
        messages.error(request, "You don't have access to this group's branch.")
        return redirect(reverse("manage_group"))
    enrollments = (
        Enrollment.objects.filter(group=group, is_active=True)
        .select_related("student__admin", "student__course")
        .order_by("student__admin__last_name", "student__admin__first_name")
    )
    total_all = Enrollment.objects.filter(group=group).count()
    return render(
        request,
        "hod_template/group_detail.html",
        {
            "group": group,
            "enrollments": enrollments,
            "total_inactive": total_all - enrollments.count(),
            "page_title": f"{group.name} — Students",
        },
    )


def _notify_group_start_date(group):
    """Notify all enrolled active students that a group start date has been set/changed."""
    from .models import Enrollment, Notification

    if not group.start_date:
        return
    date_str = group.start_date.strftime("%B %d, %Y")
    enrollments = Enrollment.objects.filter(group=group, is_active=True).select_related(
        "student__admin"
    )
    notifs = []
    for e in enrollments:
        notifs.append(
            Notification(
                recipient=e.student.admin,
                category=Notification.GENERAL,
                message=f'Your group "{group.name}" will start on {date_str}.',
            )
        )
    if notifs:
        Notification.objects.bulk_create(notifs)


@admin_only
def add_group(request):
    form = GroupForm(request.POST or None, user=request.user)
    if request.method == "POST":
        if form.is_valid():
            group = form.save(commit=False)
            # Branch admins can only create groups in branches they manage.
            if not branching.user_can_access_branch(request.user, group.branch):
                messages.error(request, "You can only create groups in your own branches.")
                return render(
                    request,
                    "hod_template/add_group.html",
                    {"form": form, "page_title": "Add Group"},
                )
            group.save()
            _notify_group_start_date(group)
            messages.success(request, "Group created!")
            return redirect(reverse("manage_group"))
    return render(
        request,
        "hod_template/add_group.html",
        {
            "form": form,
            "page_title": "Add Group",
        },
    )


@admin_only
def edit_group(request, group_id):
    group = get_object_or_404(Group, id=group_id)
    if not branching.user_can_access_group(request.user, group):
        messages.error(request, "You don't have access to this group's branch.")
        return redirect(reverse("manage_group"))
    old_start_date = group.start_date
    form = GroupForm(request.POST or None, instance=group, user=request.user)
    if request.method == "POST":
        if form.is_valid():
            updated = form.save(commit=False)
            if not branching.user_can_access_branch(request.user, updated.branch):
                messages.error(request, "You can only assign groups to your own branches.")
                return render(
                    request,
                    "hod_template/add_group.html",
                    {"form": form, "page_title": "Edit Group"},
                )
            updated.save()
            if updated.start_date and updated.start_date != old_start_date:
                _notify_group_start_date(updated)
            messages.success(request, "Group updated!")
            return redirect(reverse("manage_group"))
    return render(
        request,
        "hod_template/add_group.html",
        {
            "form": form,
            "page_title": "Edit Group",
        },
    )


@admin_only
@require_POST
def delete_group(request, group_id):
    group = get_object_or_404(Group, id=group_id)
    if not branching.user_can_access_group(request.user, group):
        messages.error(request, "You don't have access to this group's branch.")
        return redirect(reverse("manage_group"))
    student_count = Enrollment.objects.filter(group=group).count()
    attendance_count = Attendance.objects.filter(group=group).count()
    result_count = StudentResult.objects.filter(group=group).count()

    if student_count or attendance_count or result_count:
        parts = []
        if student_count:
            parts.append(f"{student_count} enrollment(s)")
        if attendance_count:
            parts.append(f"{attendance_count} attendance record(s)")
        if result_count:
            parts.append(f"{result_count} result(s)")
        messages.warning(
            request,
            f'Cannot delete "{group.name}" — it has {", ".join(parts)}. '
            f"Archive it instead to hide it without losing data.",
        )
        return redirect(reverse("manage_group"))

    try:
        group.delete()
        messages.success(request, f'Group "{group.name}" deleted.')
    except Exception as e:
        messages.error(request, f"Could not delete group: {e}")
    return redirect(reverse("manage_group"))


@admin_only
@require_POST
def archive_group(request, group_id):
    group = get_object_or_404(Group, id=group_id)
    if not branching.user_can_access_group(request.user, group):
        messages.error(request, "You don't have access to this group's branch.")
        return redirect(reverse("manage_group"))
    group.is_archived = not group.is_archived
    group.save()
    action = "archived" if group.is_archived else "restored"
    messages.success(request, f'Group "{group.name}" {action}.')
    return redirect(reverse("manage_group"))


# ── Enrollment management ────────────────────────────────────────────────────


@admin_only
def manage_enrollment(request):
    group_id = request.GET.get("group")
    groups, schema_fallback = _active_groups_for_enrollment()
    groups = branching.filter_groups_for_user(request.user, groups)
    if schema_fallback:
        messages.warning(
            request,
            "Database schema looks outdated on this server. Showing all groups for now; run migrations to fully restore enrollment filtering.",
        )
    enrollments = branching.filter_enrollments_for_user(
        request.user,
        Enrollment.objects.select_related(
            "student__admin", "student__course", "group__course", "group__teacher__admin"
        ),
    ).order_by("group__name", "student__admin__last_name")
    if group_id:
        enrollments = enrollments.filter(group_id=group_id)
    return render(
        request,
        "hod_template/manage_enrollment.html",
        {
            "enrollments": enrollments,
            "groups": groups,
            "selected_group": group_id,
            "page_title": "Enrollments",
        },
    )


@admin_only
def add_enrollment(request):
    groups, schema_fallback = _active_groups_for_enrollment()
    groups = branching.filter_groups_for_user(request.user, groups)
    if schema_fallback:
        messages.warning(
            request,
            "Database schema looks outdated on this server. Showing all groups for now; run migrations to fully restore enrollment filtering.",
        )
    students = branching.filter_students_for_user(
        request.user, Student.objects.select_related("admin", "course")
    ).order_by("admin__last_name")

    if request.method == "POST":
        group_id = request.POST.get("group")
        student_id = request.POST.get("student")
        is_active = request.POST.get("is_active", "True") == "True"
        errors = {}
        if not group_id:
            errors["group"] = "Please select a group."
        if not student_id:
            errors["student"] = "Please select a student."
        if not errors:
            try:
                group = get_object_or_404(Group, id=group_id)
                student = get_object_or_404(Student, id=student_id)
                # Enforce branch access on both sides and reject cross-branch
                # enrollment (super admin may override a branch mismatch).
                if not branching.user_can_access_group(request.user, group) or not (
                    branching.filter_students_for_user(
                        request.user, Student.objects.filter(id=student.id)
                    ).exists()
                ):
                    errors["error"] = "You don't have access to that group or student."
                elif (
                    not branching.is_super_admin(request.user)
                    and group.branch_id
                    and student.branch_id
                    and group.branch_id != student.branch_id
                ):
                    errors["student"] = (
                        "This student belongs to a different branch than the selected group."
                    )
                else:
                    _, created = Enrollment.objects.get_or_create(
                        student=student, group=group, defaults={"is_active": is_active}
                    )
                    if created:
                        Notification.objects.create(
                            recipient=student.admin,
                            category=Notification.GENERAL,
                            message=f"You have been enrolled in {group.name}"
                            + (f" ({group.course.name})" if group.course else "")
                            + ".",
                        )
                        messages.success(request, f"{student} enrolled in {group.name}.")
                        return redirect(reverse("manage_enrollment"))
                    else:
                        errors["student"] = f"{student} is already enrolled in {group.name}."
            except (ValueError, TypeError):
                errors["error"] = "Invalid selection. Please choose valid group and student."
            except Exception as e:
                errors["error"] = f"Could not enroll: {e}"

        return render(
            request,
            "hod_template/add_enrollment.html",
            {
                "groups": groups,
                "students": students,
                "errors": errors,
                "posted": request.POST,
                "page_title": "Enroll Student",
            },
        )

    return render(
        request,
        "hod_template/add_enrollment.html",
        {
            "groups": groups,
            "students": students,
            "page_title": "Enroll Student",
        },
    )


@admin_only
def get_group_info(request):
    group_id = request.POST.get("group_id")
    group = get_object_or_404(Group, id=group_id)
    if not branching.user_can_access_group(request.user, group):
        return JsonResponse({"error": "Not allowed."}, status=403)
    enrolled_ids = list(Enrollment.objects.filter(group=group).values_list("student_id", flat=True))
    data = {
        "teacher": str(group.teacher) if group.teacher else "—",
        "program": group.course.name if group.course else "—",
        "schedule": group.schedule or "—",
        "enrolled_count": len(enrolled_ids),
        "capacity": group.capacity,
        "enrolled_ids": enrolled_ids,
    }
    return JsonResponse(data)


@admin_only
@require_POST
def delete_enrollment(request, enrollment_id):
    enrollment = get_object_or_404(Enrollment.objects.select_related("group"), id=enrollment_id)
    if not branching.user_can_access_group(request.user, enrollment.group):
        messages.error(request, "You don't have access to this enrollment's branch.")
        return redirect(reverse("manage_enrollment"))
    enrollment.delete()
    messages.success(request, "Enrollment removed.")
    return redirect(reverse("manage_enrollment"))


@admin_only
def manage_vocabulary_days(request):
    from django.db.models import Count

    accessible_groups = branching.filter_groups_for_user(request.user, Group.objects.all())
    days = (
        VocabularyDay.objects.filter(group__in=accessible_groups)
        .select_related("group", "created_by__admin")
        .prefetch_related("words", "completions")
        .annotate(
            word_count=Count("words", distinct=True),
            completion_count=Count("completions", distinct=True),
        )
        .order_by("-created_at")
    )
    return render(
        request,
        "hod_template/manage_vocabulary_days.html",
        {
            "days": days,
            "page_title": "Manage Vocabulary Days",
        },
    )


@admin_only
def manage_stories(request):
    from django.utils import timezone as tz

    stories = (
        DashboardStory.objects.select_related("created_by")
        .prefetch_related("target_groups")
        .order_by("-created_at")
    )
    # Branch admins see global stories (no target group), stories aimed at one
    # of their groups, or stories they authored. Super admins see everything.
    if not branching.is_super_admin(request.user):
        accessible_groups = branching.filter_groups_for_user(request.user, Group.objects.all())
        stories = stories.filter(
            models.Q(target_groups__in=accessible_groups)
            | models.Q(target_groups__isnull=True)
            | models.Q(created_by=request.user)
        ).distinct()
    return render(
        request,
        "hod_template/manage_stories.html",
        {
            "stories": stories,
            "now": tz.now(),
            "page_title": "Dashboard Stories",
        },
    )


_story_storage_ok = branching.story_storage_ok


_user_can_modify_story = branching.user_can_modify_story


def _story_form(user, *args, **kwargs):
    """DashboardStoryForm with target groups limited to the admin's branches."""
    form = DashboardStoryForm(*args, **kwargs)
    form.fields["target_groups"].queryset = branching.filter_groups_for_user(
        user, Group.objects.all()
    )
    return form


@admin_only
def add_story(request):
    if request.method == "POST":
        form = _story_form(request.user, request.POST, request.FILES)
        if form.is_valid():
            story = form.save(commit=False)
            story.created_by = request.user
            story.save()
            form.save_m2m()
            branching.scope_story_target_groups(request.user, story)
            messages.success(request, "Story published.")
            return redirect(reverse("manage_stories"))
    else:
        form = _story_form(request.user)
    return render(
        request,
        "hod_template/story_form.html",
        {
            "form": form,
            "page_title": "New Story",
            "action": "Add",
            "storage_ok": _story_storage_ok(),
        },
    )


@admin_only
def edit_story(request, story_id):
    story = get_object_or_404(DashboardStory, id=story_id)
    if not _user_can_modify_story(request.user, story):
        messages.error(request, "You don't have access to modify this story.")
        return redirect(reverse("manage_stories"))
    if request.method == "POST":
        form = _story_form(request.user, request.POST, request.FILES, instance=story)
        if form.is_valid():
            form.save()
            branching.scope_story_target_groups(request.user, story)
            messages.success(request, "Story updated.")
            return redirect(reverse("manage_stories"))
    else:
        form = _story_form(request.user, instance=story)
    return render(
        request,
        "hod_template/story_form.html",
        {
            "form": form,
            "story": story,
            "page_title": "Edit Story",
            "action": "Save",
            "storage_ok": _story_storage_ok(),
        },
    )


@admin_only
@require_POST
def delete_story(request, story_id):
    story = get_object_or_404(DashboardStory, id=story_id)
    if not _user_can_modify_story(request.user, story):
        messages.error(request, "You don't have access to delete this story.")
        return redirect(reverse("manage_stories"))
    story.delete()
    messages.success(request, "Story deleted.")
    return redirect(reverse("manage_stories"))


# ── Leaderboard Admin ────────────────────────────────────────────────────────


@super_admin_only
def admin_leaderboard_settings(request):
    """Admin form for tuning ranking weights and toggling metrics."""
    settings = LeaderboardSettings.get()
    form = LeaderboardSettingsForm(request.POST or None, instance=settings)
    if request.method == "POST":
        if form.is_valid():
            form.save()
            messages.success(request, "Leaderboard weights updated.")
            return redirect(reverse("admin_leaderboard_settings"))
    return render(
        request,
        "hod_template/admin_leaderboard_settings.html",
        {
            "form": form,
            "settings": settings,
            "page_title": "Leaderboard Settings",
        },
    )


@super_admin_only
def admin_manage_seasons(request):
    """List, create and end leaderboard seasons. Capture snapshots on demand."""
    if request.method == "POST":
        action = request.POST.get("action")
        if action == "create":
            form = LeaderboardSeasonForm(request.POST)
            if form.is_valid():
                form.save()
                messages.success(request, "Season created.")
            else:
                messages.error(request, "Could not create season — please check the fields.")
            return redirect(reverse("admin_manage_seasons"))
        if action == "end":
            season_id = request.POST.get("season_id")
            season = get_object_or_404(LeaderboardSeason, id=season_id)
            from django.utils import timezone as tz

            season.end_date = tz.now().date()
            season.is_active = False
            season.save()
            messages.success(request, f'Season "{season.name}" ended.')
            return redirect(reverse("admin_manage_seasons"))
        if action == "snapshot":
            season_id = request.POST.get("season_id")
            season = get_object_or_404(LeaderboardSeason, id=season_id)
            count = _capture_season_snapshot(season)
            messages.success(request, f'Captured {count} snapshots for "{season.name}".')
            return redirect(reverse("admin_manage_seasons"))
        if action == "delete":
            season_id = request.POST.get("season_id")
            season = get_object_or_404(LeaderboardSeason, id=season_id)
            name = season.name
            season.delete()
            messages.success(request, f'Season "{name}" deleted.')
            return redirect(reverse("admin_manage_seasons"))

    seasons = (
        LeaderboardSeason.objects.all()
        .annotate(snap_count=models.Count("snapshots"))
        .order_by("-is_active", "-start_date")
    )
    create_form = LeaderboardSeasonForm()
    return render(
        request,
        "hod_template/admin_manage_seasons.html",
        {
            "seasons": seasons,
            "create_form": create_form,
            "page_title": "Leaderboard Seasons",
        },
    )


def _capture_season_snapshot(season):
    """
    Freeze the current full-school 'all-time' ranking for the given season.
    Wipes previous snapshots for this season and writes a new set.
    """
    from .student_views import (
        _rank_score,
        _leaderboard_weights,
        _assign_badges,
    )
    from django.db import transaction

    weights = _leaderboard_weights()
    time_start = None  # Capture lifetime snapshot

    student_ids = list(
        Student.objects.filter(status=Student.STATUS_ACTIVE).values_list("id", flat=True)
    )
    if not student_ids:
        return 0

    enrolled_by_student = {}
    for e in Enrollment.objects.filter(student_id__in=student_ids, is_active=True).values(
        "student_id", "group_id"
    ):
        enrolled_by_student.setdefault(e["student_id"], []).append(e["group_id"])

    students = Student.objects.filter(id__in=student_ids).select_related("admin")
    rankings = []
    for s in students:
        m = _rank_score(s.id, time_start, weights, enrolled_by_student)
        rankings.append(
            {
                "student_id": s.id,
                "first": (s.admin.first_name or "").strip(),
                "name": s.admin.get_full_name() or s.admin.username,
                "avatar": s.admin.avatar or "",
                "metrics": m,
                "score": m["score"],
                "is_me": False,
            }
        )
    rankings.sort(key=lambda r: r["score"], reverse=True)
    for idx, r in enumerate(rankings):
        r["rank"] = idx + 1
    _assign_badges(rankings)

    with transaction.atomic():
        season.snapshots.all().delete()
        bulk = []
        for r in rankings:
            bulk.append(
                LeaderboardSnapshot(
                    season=season,
                    student_id=r["student_id"],
                    rank=r["rank"],
                    score=r["score"],
                    attendance_pct=r["metrics"]["attendance"],
                    homework_pct=r["metrics"]["homework"],
                    quizzes_pct=r["metrics"]["quizzes"],
                    results_pct=r["metrics"]["results"],
                    badge=r.get("badge", {}).get("label", "") if r.get("badge") else "",
                )
            )
        LeaderboardSnapshot.objects.bulk_create(bulk, batch_size=500)
    return len(rankings)
