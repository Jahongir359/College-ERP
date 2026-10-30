from rest_framework import serializers

from ..models import (
    Admin,
    CustomUser,
    Course,
    Branch,
    Group,
    Parent,
    Session,
    Student,
    Staff,
    Enrollment,
    Attendance,
    AttendanceReport,
    StudentResult,
    Assignment,
    Submission,
    Notification,
    LeaveReportStudent,
    LeaveReportStaff,
    FeedbackStudent,
    FeedbackStaff,
    Invoice,
    Payment,
    RegistrationLead,
    VocabularyDay,
    VocabularyDayWord,
    VocabularyDayCompletion,
    DashboardStory,
    LeaderboardSeason,
    LeaderboardSnapshot,
)


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------


class UserSerializer(serializers.ModelSerializer):
    profile_pic_url = serializers.SerializerMethodField()

    class Meta:
        model = CustomUser
        fields = [
            "id",
            "email",
            "login_id",
            "first_name",
            "last_name",
            "user_type",
            "gender",
            "date_of_birth",
            "profile_pic_url",
            "address",
        ]

    def get_profile_pic_url(self, obj):
        if not obj.profile_pic:
            return None
        request = self.context.get("request")
        if request:
            return request.build_absolute_uri(obj.profile_pic.url)
        return obj.profile_pic.url


# ---------------------------------------------------------------------------
# Profile (GET /me/)
# ---------------------------------------------------------------------------


class AdminRoleSerializer(serializers.ModelSerializer):
    branch_ids = serializers.SerializerMethodField()

    class Meta:
        model = Admin
        fields = ["is_super_admin", "branch_ids"]

    def get_branch_ids(self, obj):
        return list(obj.branches.values_list("id", flat=True))


class StaffRoleSerializer(serializers.ModelSerializer):
    course_id = serializers.IntegerField(source="course.id", read_only=True, allow_null=True)
    course_name = serializers.CharField(source="course.name", read_only=True, allow_null=True)

    class Meta:
        model = Staff
        fields = ["phone", "specialization", "course_id", "course_name", "is_active"]


class StudentRoleSerializer(serializers.ModelSerializer):
    course_id = serializers.IntegerField(source="course.id", read_only=True, allow_null=True)
    course_name = serializers.CharField(source="course.name", read_only=True, allow_null=True)
    branch_name = serializers.SerializerMethodField()
    group_names = serializers.SerializerMethodField()

    class Meta:
        model = Student
        fields = [
            "phone",
            "status",
            "course_id",
            "course_name",
            "branch_name",
            "level",
            "group_names",
        ]

    def get_branch_name(self, obj):
        branch = obj.effective_branch
        return branch.name if branch else None

    def get_group_names(self, obj):
        return list(obj.enrollment_set.filter(is_active=True).values_list("group__name", flat=True))


class MeSerializer(serializers.ModelSerializer):
    profile_pic_url = serializers.SerializerMethodField()
    role_profile = serializers.SerializerMethodField()
    # Iceberg brand the client should render ("center" or "school"); see branding.py.
    brand = serializers.SerializerMethodField()
    brand_name = serializers.SerializerMethodField()
    # "admin" | "teacher" | "student" | "parent"; children is filled for parents only.
    role = serializers.SerializerMethodField()
    children = serializers.SerializerMethodField()

    ROLE_NAMES = {"1": "admin", "2": "teacher", "3": "student", "4": "parent"}

    class Meta:
        model = CustomUser
        fields = [
            "id",
            "email",
            "login_id",
            "first_name",
            "last_name",
            "user_type",
            "gender",
            "date_of_birth",
            "profile_pic_url",
            "avatar",
            "address",
            "role_profile",
            "brand",
            "brand_name",
            "role",
            "children",
        ]
        read_only_fields = ["id", "email", "login_id", "user_type"]

    def get_role(self, obj):
        return self.ROLE_NAMES.get(str(obj.user_type))

    def get_children(self, obj):
        if str(obj.user_type) != "4":
            return []
        from ..branching import children_for_parent
        from ..branding import brand_key_for_student

        children = children_for_parent(obj).select_related("admin", "branch")
        return [
            {
                "id": child.pk,
                "name": child.admin.get_full_name(),
                "class": _current_class(child),
                "brand": brand_key_for_student(child),
            }
            for child in children.order_by("admin__first_name", "admin__last_name")
        ]

    def _brand_key(self, obj):
        from ..branding import brand_key_for_user, resolve_brand_key

        request = self.context.get("request")
        if request is not None and getattr(request, "user", None) == obj:
            return resolve_brand_key(request)
        # e.g. the login response, where request.user is still anonymous.
        return brand_key_for_user(obj)

    def get_brand(self, obj):
        return self._brand_key(obj)

    def get_brand_name(self, obj):
        from ..branding import get_brand

        return get_brand(self._brand_key(obj)).name

    def get_profile_pic_url(self, obj):
        if not obj.profile_pic:
            return None
        request = self.context.get("request")
        if request:
            return request.build_absolute_uri(obj.profile_pic.url)
        return obj.profile_pic.url

    def get_role_profile(self, obj):
        ctx = self.context
        user_type = str(obj.user_type)
        if user_type == "1":
            try:
                return AdminRoleSerializer(obj.admin, context=ctx).data
            except Exception:
                return {"is_super_admin": False, "branch_ids": []}
        if user_type == "2":
            try:
                return StaffRoleSerializer(obj.staff, context=ctx).data
            except Staff.DoesNotExist:
                return None
        if user_type == "3":
            try:
                return StudentRoleSerializer(obj.student, context=ctx).data
            except Student.DoesNotExist:
                return None
        if user_type == "4":
            try:
                return {"id": obj.parent.pk, "phone": obj.parent.phone}
            except Parent.DoesNotExist:
                return None
        return None


def _current_class(student):
    """The student's active school class, preferring the current year, or None."""
    enrollments = Enrollment.objects.filter(
        student=student, is_active=True, group__kind=Group.KIND_CLASS
    ).select_related("group")
    current = Session.current()
    enrollment = None
    if current is not None:
        enrollment = enrollments.filter(group__session=current).first()
    enrollment = enrollment or enrollments.order_by("-group__session__start_year").first()
    if enrollment is None:
        return None
    group = enrollment.group
    return {
        "id": group.pk,
        "name": group.name,
        "grade_level": group.grade_level,
        "letter": group.letter,
    }


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True, min_length=8)
    confirm_password = serializers.CharField(write_only=True)

    def validate_new_password(self, value):
        from django.contrib.auth.password_validation import validate_password

        request = self.context.get("request")
        validate_password(value, getattr(request, "user", None))
        return value

    def validate(self, attrs):
        if attrs["new_password"] != attrs["confirm_password"]:
            raise serializers.ValidationError({"confirm_password": "Passwords do not match."})
        return attrs


class FcmTokenSerializer(serializers.Serializer):
    token = serializers.CharField(max_length=512)
    platform = serializers.ChoiceField(
        choices=["android", "ios", "web"], required=False, allow_blank=True, default=""
    )


# ---------------------------------------------------------------------------
# Courses & Branches
# ---------------------------------------------------------------------------


class CourseSerializer(serializers.ModelSerializer):
    class Meta:
        model = Course
        fields = ["id", "name", "is_active"]


class BranchSerializer(serializers.ModelSerializer):
    class Meta:
        model = Branch
        fields = ["id", "name", "address", "brand"]


# ---------------------------------------------------------------------------
# Groups
# ---------------------------------------------------------------------------


class GroupSerializer(serializers.ModelSerializer):
    course_name = serializers.CharField(source="course.name", read_only=True)
    teacher_name = serializers.SerializerMethodField()
    branch_name = serializers.CharField(source="branch.name", read_only=True, allow_null=True)

    class Meta:
        model = Group
        fields = [
            "id",
            "name",
            "course",
            "course_name",
            "teacher",
            "teacher_name",
            "branch",
            "branch_name",
            "room",
            "schedule",
            "capacity",
            "is_archived",
        ]
        read_only_fields = ["course_name", "teacher_name", "branch_name"]

    def get_teacher_name(self, obj):
        if obj.teacher and obj.teacher.admin:
            u = obj.teacher.admin
            return f"{u.first_name} {u.last_name}".strip()
        return None


class StudentSummarySerializer(serializers.ModelSerializer):
    first_name = serializers.CharField(source="admin.first_name", read_only=True)
    last_name = serializers.CharField(source="admin.last_name", read_only=True)
    email = serializers.EmailField(source="admin.email", read_only=True)
    profile_pic_url = serializers.SerializerMethodField()

    class Meta:
        model = Student
        fields = ["id", "first_name", "last_name", "email", "phone", "status", "profile_pic_url"]

    def get_profile_pic_url(self, obj):
        if not obj.admin.profile_pic:
            return None
        request = self.context.get("request")
        if request:
            return request.build_absolute_uri(obj.admin.profile_pic.url)
        return obj.admin.profile_pic.url


class GroupDetailSerializer(GroupSerializer):
    enrolled_students = serializers.SerializerMethodField()
    enrolled_count = serializers.SerializerMethodField()

    class Meta(GroupSerializer.Meta):
        fields = GroupSerializer.Meta.fields + ["enrolled_students", "enrolled_count"]

    def get_enrolled_students(self, obj):
        enrollments = Enrollment.objects.filter(group=obj, is_active=True).select_related(
            "student__admin"
        )
        return StudentSummarySerializer(
            [e.student for e in enrollments],
            many=True,
            context=self.context,
        ).data

    def get_enrolled_count(self, obj):
        return Enrollment.objects.filter(group=obj, is_active=True).count()


# ---------------------------------------------------------------------------
# Attendance
# ---------------------------------------------------------------------------


class AttendanceReportItemSerializer(serializers.ModelSerializer):
    student_id = serializers.IntegerField(source="student.id", read_only=True)
    student_name = serializers.SerializerMethodField()

    class Meta:
        model = AttendanceReport
        fields = ["student_id", "student_name", "status"]

    def get_student_name(self, obj):
        u = obj.student.admin
        return f"{u.first_name} {u.last_name}".strip()


class AttendanceSerializer(serializers.ModelSerializer):
    group_name = serializers.CharField(source="group.name", read_only=True, allow_null=True)
    reports = AttendanceReportItemSerializer(
        source="attendancereport_set", many=True, read_only=True
    )

    class Meta:
        model = Attendance
        fields = ["id", "group", "group_name", "date", "reports"]


class AttendanceSaveSerializer(serializers.Serializer):
    group_id = serializers.IntegerField()
    date = serializers.DateField()
    records = serializers.ListField(
        child=serializers.DictField(),
        allow_empty=False,
    )

    def validate_group_id(self, value):
        if not Group.objects.filter(id=value).exists():
            raise serializers.ValidationError("Group not found.")
        return value

    def validate_records(self, records):
        for rec in records:
            if "student_id" not in rec or "status" not in rec:
                raise serializers.ValidationError("Each record must have student_id and status.")
            if int(rec["status"]) not in (0, 1, 2):
                raise serializers.ValidationError(
                    "Status must be 0 (Absent), 1 (Present), or 2 (Late)."
                )
        return records


# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------


class StudentResultSerializer(serializers.ModelSerializer):
    student_name = serializers.SerializerMethodField()
    group_name = serializers.CharField(source="group.name", read_only=True, allow_null=True)

    class Meta:
        model = StudentResult
        fields = [
            "id",
            "student",
            "student_name",
            "group",
            "group_name",
            "test",
            "exam",
            "comment",
            "updated_at",
        ]
        read_only_fields = ["student_name", "group_name", "updated_at"]

    def get_student_name(self, obj):
        u = obj.student.admin
        return f"{u.first_name} {u.last_name}".strip()


# ---------------------------------------------------------------------------
# Assignments & Submissions
# ---------------------------------------------------------------------------


class AssignmentSerializer(serializers.ModelSerializer):
    group_name = serializers.CharField(source="group.name", read_only=True, allow_null=True)
    subject_name = serializers.CharField(source="subject.name", read_only=True, allow_null=True)
    created_by_name = serializers.SerializerMethodField()
    status = serializers.SerializerMethodField()

    class Meta:
        model = Assignment
        fields = [
            "id",
            "title",
            "description",
            "group",
            "group_name",
            "subject_name",
            "due_date",
            "created_by_name",
            "created_at",
            "status",
        ]
        read_only_fields = ["group_name", "subject_name", "created_by_name", "created_at", "status"]

    def get_created_by_name(self, obj):
        u = obj.created_by.admin
        return f"{u.first_name} {u.last_name}".strip()

    def get_status(self, obj):
        """Student-facing status: submitted | graded | overdue | todo.

        The list view passes a ``submission_map`` (assignment_id → Submission)
        in context to avoid N+1 queries.
        """
        from django.utils import timezone as tz

        request = self.context.get("request")
        if not request or str(getattr(request.user, "user_type", "")) != "3":
            return None
        sub_map = self.context.get("submission_map")
        if sub_map is not None:
            sub = sub_map.get(obj.id)
        else:
            try:
                sub = Submission.objects.filter(
                    assignment=obj, student=request.user.student
                ).first()
            except Exception:
                sub = None
        if sub is not None:
            return "graded" if sub.grade is not None else "submitted"
        if obj.due_date and obj.due_date < tz.localdate():
            return "overdue"
        return "todo"


class SubmissionSerializer(serializers.ModelSerializer):
    file_url = serializers.SerializerMethodField()

    class Meta:
        model = Submission
        fields = ["id", "assignment", "file_url", "note", "submitted_at", "grade"]
        read_only_fields = ["submitted_at", "grade"]

    def get_file_url(self, obj):
        if not obj.file:
            return None
        request = self.context.get("request")
        if request:
            return request.build_absolute_uri(obj.file.url)
        return obj.file.url


class AssignmentDetailSerializer(AssignmentSerializer):
    my_submission = serializers.SerializerMethodField()

    class Meta(AssignmentSerializer.Meta):
        fields = AssignmentSerializer.Meta.fields + ["my_submission"]

    def get_my_submission(self, obj):
        request = self.context.get("request")
        if not request or str(request.user.user_type) != "3":
            return None
        try:
            sub = Submission.objects.get(assignment=obj, student=request.user.student)
            return SubmissionSerializer(sub, context=self.context).data
        except (Student.DoesNotExist, Submission.DoesNotExist):
            return None


class SubmitAssignmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Submission
        fields = ["file", "note"]


# ---------------------------------------------------------------------------
# Notifications
# ---------------------------------------------------------------------------


class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = ["id", "category", "message", "is_read", "created_at"]


# ---------------------------------------------------------------------------
# Admin helpers
# ---------------------------------------------------------------------------


class EnrollmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Enrollment
        fields = ["id", "student", "group", "enrolled_on", "is_active"]
        read_only_fields = ["enrolled_on"]


# ---------------------------------------------------------------------------
# Leave
# ---------------------------------------------------------------------------


class StudentLeaveSerializer(serializers.ModelSerializer):
    status_display = serializers.CharField(source="get_status_display", read_only=True)

    class Meta:
        model = LeaveReportStudent
        fields = ["id", "date", "message", "status", "status_display", "created_at", "updated_at"]
        read_only_fields = ["status", "status_display", "created_at", "updated_at"]


class StaffLeaveSerializer(serializers.ModelSerializer):
    status_display = serializers.CharField(source="get_status_display", read_only=True)

    class Meta:
        model = LeaveReportStaff
        fields = ["id", "date", "message", "status", "status_display", "created_at", "updated_at"]
        read_only_fields = ["status", "status_display", "created_at", "updated_at"]


class AdminStudentLeaveSerializer(serializers.ModelSerializer):
    """Admin view — includes student name."""

    status_display = serializers.CharField(source="get_status_display", read_only=True)
    student_id = serializers.IntegerField(source="student.id", read_only=True)
    student_name = serializers.SerializerMethodField()

    class Meta:
        model = LeaveReportStudent
        fields = [
            "id",
            "student_id",
            "student_name",
            "date",
            "message",
            "status",
            "status_display",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["student_id", "student_name", "created_at", "updated_at"]

    def get_student_name(self, obj):
        u = obj.student.admin
        return f"{u.first_name} {u.last_name}".strip()


class AdminStaffLeaveSerializer(serializers.ModelSerializer):
    """Admin view — includes staff name."""

    status_display = serializers.CharField(source="get_status_display", read_only=True)
    staff_id = serializers.IntegerField(source="staff.id", read_only=True)
    staff_name = serializers.SerializerMethodField()

    class Meta:
        model = LeaveReportStaff
        fields = [
            "id",
            "staff_id",
            "staff_name",
            "date",
            "message",
            "status",
            "status_display",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["staff_id", "staff_name", "created_at", "updated_at"]

    def get_staff_name(self, obj):
        u = obj.staff.admin
        return f"{u.first_name} {u.last_name}".strip()


# ---------------------------------------------------------------------------
# Feedback
# ---------------------------------------------------------------------------


class StudentFeedbackSerializer(serializers.ModelSerializer):
    has_reply = serializers.SerializerMethodField()

    class Meta:
        model = FeedbackStudent
        fields = ["id", "feedback", "reply", "has_reply", "created_at", "updated_at"]
        read_only_fields = ["reply", "has_reply", "created_at", "updated_at"]

    def get_has_reply(self, obj):
        return bool(obj.reply)


class StaffFeedbackSerializer(serializers.ModelSerializer):
    has_reply = serializers.SerializerMethodField()

    class Meta:
        model = FeedbackStaff
        fields = ["id", "feedback", "reply", "has_reply", "created_at", "updated_at"]
        read_only_fields = ["reply", "has_reply", "created_at", "updated_at"]

    def get_has_reply(self, obj):
        return bool(obj.reply)


class AdminStudentFeedbackSerializer(StudentFeedbackSerializer):
    student_id = serializers.IntegerField(source="student.id", read_only=True)
    student_name = serializers.SerializerMethodField()

    class Meta(StudentFeedbackSerializer.Meta):
        fields = [
            "id",
            "student_id",
            "student_name",
            "feedback",
            "reply",
            "has_reply",
            "created_at",
            "updated_at",
        ]

    def get_student_name(self, obj):
        u = obj.student.admin
        return f"{u.first_name} {u.last_name}".strip()


class AdminStaffFeedbackSerializer(StaffFeedbackSerializer):
    staff_id = serializers.IntegerField(source="staff.id", read_only=True)
    staff_name = serializers.SerializerMethodField()

    class Meta(StaffFeedbackSerializer.Meta):
        fields = [
            "id",
            "staff_id",
            "staff_name",
            "feedback",
            "reply",
            "has_reply",
            "created_at",
            "updated_at",
        ]

    def get_staff_name(self, obj):
        u = obj.staff.admin
        return f"{u.first_name} {u.last_name}".strip()


# ---------------------------------------------------------------------------
# Invoices & Payments
# ---------------------------------------------------------------------------


class PaymentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Payment
        fields = ["id", "amount", "method", "paid_on", "note", "created_at"]
        read_only_fields = ["created_at"]


class InvoiceSerializer(serializers.ModelSerializer):
    status_display = serializers.CharField(source="get_status_display", read_only=True)
    group_name = serializers.CharField(source="group.name", read_only=True, allow_null=True)
    payments = PaymentSerializer(many=True, read_only=True)
    amount_paid = serializers.SerializerMethodField()
    amount_due = serializers.SerializerMethodField()

    class Meta:
        model = Invoice
        fields = [
            "id",
            "group",
            "group_name",
            "period",
            "amount",
            "discount",
            "status",
            "status_display",
            "due_date",
            "note",
            "payments",
            "amount_paid",
            "amount_due",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "status_display",
            "group_name",
            "payments",
            "amount_paid",
            "amount_due",
            "created_at",
            "updated_at",
        ]

    def get_amount_paid(self, obj):
        return sum(p.amount for p in obj.payments.all())

    def get_amount_due(self, obj):
        paid = sum(p.amount for p in obj.payments.all())
        return max(0, obj.amount - obj.discount - paid)


# ---------------------------------------------------------------------------
# Registration Leads (admin)
# ---------------------------------------------------------------------------


class RegistrationLeadSerializer(serializers.ModelSerializer):
    class Meta:
        model = RegistrationLead
        fields = [
            "id",
            "full_name",
            "first_name",
            "last_name",
            "email",
            "phone",
            "parent_phone",
            "program",
            "branch",
            "preferred_schedule",
            "source",
            "social_handle",
            "message",
            "status",
            "admin_notes",
            "assigned_to",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["created_at", "updated_at"]


# ---------------------------------------------------------------------------
# Staff dashboard stats
# ---------------------------------------------------------------------------


class StaffStatsSerializer(serializers.Serializer):
    total_students = serializers.IntegerField()
    total_groups = serializers.IntegerField()
    total_sessions = serializers.IntegerField()
    pending_leave = serializers.IntegerField()


# ---------------------------------------------------------------------------
# Admin student / staff management
# ---------------------------------------------------------------------------


class _BranchScopedMixin:
    """Reject moving a record into a branch the requesting admin can't access."""

    def validate_branch(self, branch):
        from .. import branching

        request = self.context.get("request")
        user = getattr(request, "user", None)
        if branch is None:
            if user is not None and not branching.is_super_admin(user):
                raise serializers.ValidationError("branch is required.")
            return branch
        if user is None or not branching.user_can_access_branch(user, branch):
            raise serializers.ValidationError("You don't have access to that branch.")
        return branch


class AdminStudentSerializer(_BranchScopedMixin, serializers.ModelSerializer):
    """Full student record for admin CRUD."""

    first_name = serializers.CharField(source="admin.first_name")
    last_name = serializers.CharField(source="admin.last_name")
    email = serializers.EmailField(source="admin.email", read_only=True)
    login_id = serializers.CharField(source="admin.login_id", read_only=True)
    gender = serializers.CharField(source="admin.gender", read_only=True)
    date_of_birth = serializers.DateField(source="admin.date_of_birth", read_only=True)
    address = serializers.CharField(source="admin.address", read_only=True)
    profile_pic_url = serializers.SerializerMethodField()
    course_name = serializers.CharField(source="course.name", read_only=True, allow_null=True)
    branch_name = serializers.CharField(source="branch.name", read_only=True, allow_null=True)

    class Meta:
        model = Student
        fields = [
            "id",
            "first_name",
            "last_name",
            "email",
            "login_id",
            "gender",
            "date_of_birth",
            "address",
            "profile_pic_url",
            "phone",
            "status",
            "level",
            "theme",
            "course",
            "course_name",
            "branch",
            "branch_name",
        ]
        read_only_fields = [
            "email",
            "login_id",
            "gender",
            "date_of_birth",
            "address",
            "profile_pic_url",
            "course_name",
            "branch_name",
        ]

    def get_profile_pic_url(self, obj):
        if not obj.admin.profile_pic:
            return None
        request = self.context.get("request")
        return (
            request.build_absolute_uri(obj.admin.profile_pic.url)
            if request
            else obj.admin.profile_pic.url
        )

    def update(self, instance, validated_data):
        admin_data = validated_data.pop("admin", {})
        if admin_data:
            for attr, val in admin_data.items():
                setattr(instance.admin, attr, val)
            instance.admin.save()
        return super().update(instance, validated_data)


class AdminStaffSerializer(_BranchScopedMixin, serializers.ModelSerializer):
    """Full staff record for admin CRUD."""

    first_name = serializers.CharField(source="admin.first_name")
    last_name = serializers.CharField(source="admin.last_name")
    email = serializers.EmailField(source="admin.email", read_only=True)
    login_id = serializers.CharField(source="admin.login_id", read_only=True)
    gender = serializers.CharField(source="admin.gender", read_only=True)
    date_of_birth = serializers.DateField(source="admin.date_of_birth", read_only=True)
    profile_pic_url = serializers.SerializerMethodField()
    course_name = serializers.CharField(source="course.name", read_only=True, allow_null=True)
    branch_name = serializers.CharField(source="branch.name", read_only=True, allow_null=True)

    class Meta:
        model = Staff
        fields = [
            "id",
            "first_name",
            "last_name",
            "email",
            "login_id",
            "gender",
            "date_of_birth",
            "profile_pic_url",
            "phone",
            "specialization",
            "is_active",
            "course",
            "course_name",
            "branch",
            "branch_name",
        ]
        read_only_fields = [
            "email",
            "login_id",
            "gender",
            "date_of_birth",
            "profile_pic_url",
            "course_name",
            "branch_name",
        ]

    def get_profile_pic_url(self, obj):
        if not obj.admin.profile_pic:
            return None
        request = self.context.get("request")
        return (
            request.build_absolute_uri(obj.admin.profile_pic.url)
            if request
            else obj.admin.profile_pic.url
        )

    def update(self, instance, validated_data):
        admin_data = validated_data.pop("admin", {})
        if admin_data:
            for attr, val in admin_data.items():
                setattr(instance.admin, attr, val)
            instance.admin.save()
        return super().update(instance, validated_data)


# ---------------------------------------------------------------------------
# Vocabulary
# ---------------------------------------------------------------------------


class VocabularyWordSerializer(serializers.ModelSerializer):
    class Meta:
        model = VocabularyDayWord
        fields = ["id", "word", "meaning", "example_sentence", "pronunciation_note", "order"]


class VocabularyDaySerializer(serializers.ModelSerializer):
    words = VocabularyWordSerializer(many=True, read_only=True)
    word_count = serializers.ReadOnlyField()
    is_released = serializers.ReadOnlyField()
    is_completed = serializers.SerializerMethodField()
    group_name = serializers.CharField(source="group.name", read_only=True)

    class Meta:
        model = VocabularyDay
        fields = [
            "id",
            "day_number",
            "title",
            "level",
            "release_at",
            "word_count",
            "is_released",
            "is_completed",
            "group_name",
            "words",
        ]

    def get_is_completed(self, obj):
        request = self.context.get("request")
        if not request or not request.user.is_authenticated:
            return False
        try:
            student = request.user.student
        except Exception:
            return False
        return VocabularyDayCompletion.objects.filter(student=student, day=obj).exists()


# ---------------------------------------------------------------------------
# Leaderboard
# ---------------------------------------------------------------------------


class LeaderboardEntrySerializer(serializers.ModelSerializer):
    student_name = serializers.SerializerMethodField()
    avatar_url = serializers.SerializerMethodField()

    class Meta:
        model = LeaderboardSnapshot
        fields = [
            "rank",
            "score",
            "attendance_pct",
            "homework_pct",
            "quizzes_pct",
            "results_pct",
            "badge",
            "student_name",
            "avatar_url",
        ]

    def get_student_name(self, obj):
        u = obj.student.admin
        return f"{u.first_name} {u.last_name}".strip()

    def get_avatar_url(self, obj):
        user = obj.student.admin
        if not user.profile_pic:
            return None
        request = self.context.get("request")
        return request.build_absolute_uri(user.profile_pic.url) if request else user.profile_pic.url


class LeaderboardSeasonSerializer(serializers.ModelSerializer):
    entries = serializers.SerializerMethodField()

    class Meta:
        model = LeaderboardSeason
        fields = ["id", "name", "period", "start_date", "end_date", "is_active", "entries"]

    def get_entries(self, obj):
        snapshots = obj.snapshots.select_related("student__admin").order_by("rank")
        return LeaderboardEntrySerializer(snapshots, many=True, context=self.context).data


# ---------------------------------------------------------------------------
# Vocabulary Quiz
# ---------------------------------------------------------------------------


class QuizChoiceSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    word = serializers.CharField()


class QuizQuestionSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    meaning = serializers.CharField()
    example_sentence = serializers.CharField()
    correct_id = serializers.IntegerField()
    choices = QuizChoiceSerializer(many=True)


class VocabularyQuizSerializer(serializers.Serializer):
    day_number = serializers.IntegerField()
    title = serializers.CharField()
    questions = QuizQuestionSerializer(many=True)


# ---------------------------------------------------------------------------
# Stories
# ---------------------------------------------------------------------------


class StorySerializer(serializers.ModelSerializer):
    cover_image_url = serializers.SerializerMethodField()
    creator_name = serializers.SerializerMethodField()
    target_group_ids = serializers.SerializerMethodField()

    class Meta:
        model = DashboardStory
        fields = [
            "id",
            "title",
            "body",
            "story_type",
            "emoji",
            "bg_color",
            "cover_image_url",
            "expires_at",
            "created_at",
            "creator_name",
            "target_group_ids",
        ]

    def get_cover_image_url(self, obj):
        if not obj.has_valid_image:
            return None
        request = self.context.get("request")
        try:
            url = obj.image.url
            return request.build_absolute_uri(url) if request else url
        except (ValueError, AttributeError):
            return None

    def get_creator_name(self, obj):
        u = obj.created_by
        return f"{u.first_name} {u.last_name}".strip()

    def get_target_group_ids(self, obj):
        return list(obj.target_groups.values_list("id", flat=True))


# ---------------------------------------------------------------------------
# Staff Vocabulary Management
# ---------------------------------------------------------------------------


class VocabularyWordWriteSerializer(serializers.ModelSerializer):
    class Meta:
        model = VocabularyDayWord
        fields = ["id", "word", "meaning", "example_sentence", "pronunciation_note", "order"]


class StaffVocabularyDaySerializer(serializers.ModelSerializer):
    words = VocabularyWordSerializer(many=True, read_only=True)
    word_count = serializers.ReadOnlyField()
    is_released = serializers.ReadOnlyField()
    group_name = serializers.CharField(source="group.name", read_only=True, allow_null=True)
    completion_count = serializers.SerializerMethodField()

    class Meta:
        model = VocabularyDay
        fields = [
            "id",
            "day_number",
            "title",
            "group",
            "group_name",
            "level",
            "release_at",
            "release_scope",
            "notes",
            "word_count",
            "is_released",
            "completion_count",
            "words",
        ]

    def get_completion_count(self, obj):
        return obj.completions.count()
