"""Branch-first access control — the single source of truth for "what can
this user see?".

Iceberg is one organization with many branches. Access is scoped by branch:

  * Super admin  → every branch (all data).
  * Branch admin → only their assigned branches (Admin.branches).
  * Teacher      → only the groups they teach (and the students/attendance/
                   results inside those groups). Group ownership is the source
                   of truth, NOT Staff.branch, so legacy teachers with a null
                   branch keep working.
  * Student      → only their own record and their own enrolled groups.
  * Parent       → only their linked children (ParentChild), read-only.
  * Anyone else  → nothing (empty queryset), never "all".

Views, forms, messaging and the API all route through these helpers so the
rules live in exactly one place. Do not re-implement branch filtering inline.
"""

from django.db.models import Q

from .models import Admin, Branch, Enrollment, Group, Parent, Staff, Student


# ── Identity helpers ─────────────────────────────────────────────────────────


def _user_type(user):
    if not getattr(user, "is_authenticated", False):
        return None
    return str(getattr(user, "user_type", "") or "")


def get_admin_profile(user):
    """Return the Admin profile for an admin user, or None."""
    if _user_type(user) != "1":
        return None
    try:
        return user.admin
    except (Admin.DoesNotExist, AttributeError):
        return None


def _get_staff(user):
    if _user_type(user) != "2":
        return None
    try:
        return user.staff
    except (Staff.DoesNotExist, AttributeError):
        return None


def _get_student(user):
    if _user_type(user) != "3":
        return None
    try:
        return user.student
    except (Student.DoesNotExist, AttributeError):
        return None


def _get_parent(user):
    if _user_type(user) != "4":
        return None
    try:
        return user.parent
    except (Parent.DoesNotExist, AttributeError):
        return None


def children_for_parent(user):
    """Students linked to this parent user (empty for everyone else)."""
    parent = _get_parent(user)
    if parent is None:
        return Student.objects.none()
    return Student.objects.filter(parent_links__parent=parent).distinct()


def is_super_admin(user):
    """True only for an admin whose profile is flagged is_super_admin."""
    profile = get_admin_profile(user)
    return bool(profile and profile.is_super_admin)


def is_recovery_admin(user):
    """True for the permanent top-level recovery account.

    The Recovery Admin can never be demoted or deleted, and is the only admin
    allowed to promote other admins to super admin. It is identified by the
    Django superuser flag (set only on the seeded recovery account, see
    ``apps.create_recovery_admin_access``) or, as a fallback, the configured
    ``RECOVERY_ADMIN_EMAIL``.
    """
    if get_admin_profile(user) is None:
        return False
    if getattr(user, "is_superuser", False):
        return True
    import os

    recovery_email = (
        os.environ.get("RECOVERY_ADMIN_EMAIL", "iceberg.edu.center@gmail.com").strip().lower()
    )
    email = (getattr(user, "email", "") or "").strip().lower()
    return bool(email and email == recovery_email)


# ── Accessible branches ──────────────────────────────────────────────────────


def get_accessible_branches(user):
    """Return the Branch queryset this user is allowed to see."""
    profile = get_admin_profile(user)
    if profile is not None:
        if profile.is_super_admin:
            return Branch.objects.all()
        return profile.branches.all()

    staff = _get_staff(user)
    if staff is not None:
        return Branch.objects.filter(Q(group__teacher=staff) | Q(staff_members=staff)).distinct()

    student = _get_student(user)
    if student is not None:
        return Branch.objects.filter(
            Q(students=student) | Q(group__enrollment__student=student)
        ).distinct()

    parent = _get_parent(user)
    if parent is not None:
        children = children_for_parent(user)
        return Branch.objects.filter(
            Q(students__in=children) | Q(group__enrollment__student__in=children)
        ).distinct()

    return Branch.objects.none()


# ── Queryset filters ─────────────────────────────────────────────────────────


def filter_branches_for_user(user, queryset):
    if is_super_admin(user):
        return queryset
    profile = get_admin_profile(user)
    if profile is not None:
        return queryset.filter(id__in=profile.branches.values_list("id", flat=True))
    # Teachers/students don't manage branches.
    return queryset.filter(id__in=get_accessible_branches(user).values_list("id", flat=True))


def filter_students_for_user(user, queryset):
    """Filter a Student queryset by branch access."""
    if is_super_admin(user):
        return queryset

    profile = get_admin_profile(user)
    if profile is not None:
        ids = profile.branches.values_list("id", flat=True)
        # Students explicitly in the branch OR enrolled in one of its groups
        # (covers legacy students whose branch field is still null).
        return queryset.filter(
            Q(branch_id__in=ids) | Q(enrollment__group__branch_id__in=ids)
        ).distinct()

    staff = _get_staff(user)
    if staff is not None:
        return queryset.filter(
            enrollment__group__teacher=staff, enrollment__is_active=True
        ).distinct()

    student = _get_student(user)
    if student is not None:
        return queryset.filter(pk=student.pk)

    if _get_parent(user) is not None:
        return queryset.filter(pk__in=children_for_parent(user).values("pk"))

    return queryset.none()


def filter_staff_for_user(user, queryset):
    """Filter a Staff queryset by branch access."""
    if is_super_admin(user):
        return queryset

    profile = get_admin_profile(user)
    if profile is not None:
        ids = profile.branches.values_list("id", flat=True)
        # Teachers in the branch OR teaching a group in the branch.
        return queryset.filter(Q(branch_id__in=ids) | Q(group__branch_id__in=ids)).distinct()

    staff = _get_staff(user)
    if staff is not None:
        return queryset.filter(pk=staff.pk)

    return queryset.none()


def filter_groups_for_user(user, queryset):
    """Filter a Group queryset by branch access."""
    if is_super_admin(user):
        return queryset

    profile = get_admin_profile(user)
    if profile is not None:
        return queryset.filter(branch_id__in=profile.branches.values_list("id", flat=True))

    staff = _get_staff(user)
    if staff is not None:
        return queryset.filter(teacher=staff)

    student = _get_student(user)
    if student is not None:
        return queryset.filter(enrollment__student=student, enrollment__is_active=True).distinct()

    return queryset.none()


def filter_enrollments_for_user(user, queryset):
    """Filter an Enrollment queryset by branch access."""
    if is_super_admin(user):
        return queryset

    profile = get_admin_profile(user)
    if profile is not None:
        return queryset.filter(group__branch_id__in=profile.branches.values_list("id", flat=True))

    staff = _get_staff(user)
    if staff is not None:
        return queryset.filter(group__teacher=staff)

    student = _get_student(user)
    if student is not None:
        return queryset.filter(student=student)

    return queryset.none()


def filter_attendance_for_user(user, queryset):
    """Filter an Attendance queryset by branch access."""
    if is_super_admin(user):
        return queryset

    profile = get_admin_profile(user)
    if profile is not None:
        return queryset.filter(group__branch_id__in=profile.branches.values_list("id", flat=True))

    staff = _get_staff(user)
    if staff is not None:
        return queryset.filter(group__teacher=staff)

    student = _get_student(user)
    if student is not None:
        return queryset.filter(attendancereport__student=student).distinct()

    return queryset.none()


def filter_results_for_user(user, queryset):
    """Filter a StudentResult queryset by branch access."""
    if is_super_admin(user):
        return queryset

    profile = get_admin_profile(user)
    if profile is not None:
        return queryset.filter(group__branch_id__in=profile.branches.values_list("id", flat=True))

    staff = _get_staff(user)
    if staff is not None:
        return queryset.filter(group__teacher=staff)

    student = _get_student(user)
    if student is not None:
        return queryset.filter(student=student)

    if _get_parent(user) is not None:
        return queryset.filter(student__in=children_for_parent(user).values("pk"))

    return queryset.none()


def filter_parents_for_user(user, queryset):
    """Filter a Parent queryset: admins see parents of children in their branches.

    A parent with children in several branches is visible to each of those
    branches' admins (who still see only their own children, see parents.py).
    A parent sees themself. Teachers and students see no parents here.
    """
    if is_super_admin(user):
        return queryset

    if get_admin_profile(user) is not None:
        students = filter_students_for_user(user, Student.objects.all())
        return queryset.filter(child_links__student__in=students).distinct()

    parent = _get_parent(user)
    if parent is not None:
        return queryset.filter(pk=parent.pk)

    return queryset.none()


def filter_class_subjects_for_user(user, queryset):
    """Filter a ClassSubject queryset: admins by branch, teachers by class or subject."""
    if is_super_admin(user):
        return queryset

    profile = get_admin_profile(user)
    if profile is not None:
        return queryset.filter(group__branch_id__in=profile.branches.values_list("id", flat=True))

    staff = _get_staff(user)
    if staff is not None:
        return queryset.filter(Q(teacher=staff) | Q(group__teacher=staff)).distinct()

    student = _get_student(user)
    if student is not None:
        return queryset.filter(
            group__enrollment__student=student, group__enrollment__is_active=True
        )

    if _get_parent(user) is not None:
        return queryset.filter(
            group__enrollment__student__in=children_for_parent(user).values("pk"),
            group__enrollment__is_active=True,
        ).distinct()

    return queryset.none()


def filter_classes_for_user(user, queryset):
    """Filter a Group queryset to the school classes this user may see.

    Admins: classes in their branches. Teachers: classes where they are the
    homeroom teacher or teach a subject. Students: their own active class.
    Parents: their children's active classes.
    """
    queryset = queryset.filter(kind=Group.KIND_CLASS)
    if is_super_admin(user):
        return queryset

    profile = get_admin_profile(user)
    if profile is not None:
        return queryset.filter(branch_id__in=profile.branches.values_list("id", flat=True))

    staff = _get_staff(user)
    if staff is not None:
        return queryset.filter(Q(teacher=staff) | Q(class_subjects__teacher=staff)).distinct()

    student = _get_student(user)
    if student is not None:
        return queryset.filter(enrollment__student=student, enrollment__is_active=True).distinct()

    if _get_parent(user) is not None:
        return queryset.filter(
            enrollment__student__in=children_for_parent(user).values("pk"),
            enrollment__is_active=True,
        ).distinct()

    return queryset.none()


def filter_lessons_for_user(user, queryset):
    """Filter a Lesson queryset: the timetables of the classes the user may see."""
    if is_super_admin(user):
        return queryset
    classes = filter_classes_for_user(user, Group.objects.all())
    return queryset.filter(group__in=classes.values("pk"))


def filter_bell_periods_for_user(user, queryset):
    """Filter a BellPeriod queryset: admins see their branches' bell times only."""
    if is_super_admin(user):
        return queryset

    profile = get_admin_profile(user)
    if profile is not None:
        return queryset.filter(branch_id__in=profile.branches.values_list("id", flat=True))

    return queryset.none()


# ── Single-object access checks ──────────────────────────────────────────────


def filter_registration_leads_for_user(user, queryset):
    """Filter a RegistrationLead queryset by branch access.

    RegistrationLead.branch is a free-text field (pre-enrollment), so we do a
    case-insensitive name match against the admin's accessible branch names.
    Super admins see every lead; branch admins see leads whose branch text
    matches one of their branch names; everyone else sees nothing.
    """
    if is_super_admin(user):
        return queryset

    profile = get_admin_profile(user)
    if profile is not None:
        branch_names = list(profile.branches.values_list("name", flat=True))
        if not branch_names:
            return queryset.none()
        q = Q()
        for name in branch_names:
            q |= Q(branch__iexact=name)
        return queryset.filter(q)

    return queryset.none()


def user_can_access_branch(user, branch):
    if branch is None:
        return False
    if is_super_admin(user):
        return True
    branch_id = getattr(branch, "id", branch)
    return get_accessible_branches(user).filter(id=branch_id).exists()


def user_can_access_student(user, student):
    """True when this user may see this student's data.

    Admins: students in their branches; teachers: students in groups they
    teach; a student: themself; a parent: their linked children.
    """
    if student is None:
        return False
    student_id = getattr(student, "pk", student)
    return filter_students_for_user(user, Student.objects.filter(pk=student_id)).exists()


def user_can_access_group(user, group):
    if group is None:
        return False
    if is_super_admin(user):
        return True

    profile = get_admin_profile(user)
    if profile is not None:
        if group.branch_id is None:
            return False
        return profile.branches.filter(id=group.branch_id).exists()

    staff = _get_staff(user)
    if staff is not None:
        return group.teacher_id == staff.id

    student = _get_student(user)
    if student is not None:
        return Enrollment.objects.filter(student=student, group=group, is_active=True).exists()

    return False


# ── Dashboard stories ────────────────────────────────────────────────────────


def scope_story_target_groups(user, story):
    """Keep a story's audience inside what ``user`` may reach.

    A story with no target groups is shown to *every* student, so only super
    admins may publish one. For anyone else, targets are trimmed to their
    accessible groups, and an empty result falls back to all of their own
    active groups (a teacher's classes, a branch admin's branches) instead of
    silently becoming school-wide.
    """
    if is_super_admin(user):
        return
    allowed = filter_groups_for_user(user, Group.objects.all())
    kept = list(allowed.filter(id__in=story.target_groups.values_list("id", flat=True)))
    if not kept:
        kept = list(allowed.filter(is_archived=False))
    story.target_groups.set(kept)


def user_can_modify_story(user, story):
    """Branch admins may only edit/delete stories they authored or stories
    whose every target group lies within their accessible branches. Global
    stories (no target groups) belong to whoever authored them; other branch
    admins cannot touch them. Super admins can modify anything."""
    if is_super_admin(user):
        return True
    if story.created_by_id == user.id:
        return True
    target_ids = set(story.target_groups.values_list("id", flat=True))
    if not target_ids:
        return False
    accessible_ids = set(
        filter_groups_for_user(user, Group.objects.all()).values_list("id", flat=True)
    )
    return target_ids <= accessible_ids


# ── Deployment utilities ─────────────────────────────────────────────────────


def story_storage_ok():
    """True when a persistent remote storage backend (S3/Spaces) is configured."""
    import os

    return bool(os.environ.get("SPACES_KEY") and os.environ.get("SPACES_BUCKET"))
