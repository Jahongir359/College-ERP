import logging

from django.contrib.auth.hashers import make_password
from django.core.exceptions import ValidationError
from django.core.validators import MaxValueValidator, MinValueValidator
from django.contrib.auth.models import UserManager
from django.dispatch import receiver
from django.db.models.signals import post_save
from django.db import OperationalError, ProgrammingError, models
from django.db.models import Q
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
from django.utils.functional import lazy
from django.utils.translation import gettext, gettext_lazy
from datetime import datetime, timedelta


_LOAN_PERIOD_DAYS = 14
_OVERDUE_FINE_PER_DAY = 5  # ₹


def _default_loan_due_date():
    return timezone.now().date() + timedelta(days=_LOAN_PERIOD_DAYS)


def expiry():
    # Retained for historical migration compatibility (0001_initial.py references this)
    return datetime.today() + timedelta(days=14)


class CustomUserManager(UserManager):
    def _create_user(self, email, password, **extra_fields):
        email = self.normalize_email(email)
        user = CustomUser(email=email, **extra_fields)
        user.password = make_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", False)
        extra_fields.setdefault("is_superuser", False)
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)

        assert extra_fields["is_staff"]
        assert extra_fields["is_superuser"]
        return self._create_user(email, password, **extra_fields)


class Session(models.Model):
    """An academic year. School quarters hang off it as ``Term`` rows."""

    start_year = models.DateField()
    end_year = models.DateField()
    name = models.CharField(max_length=20, blank=True, default="", help_text="e.g. 2026–2027")
    # At most one session is marked current (DB constraint below); when none is
    # marked, the session whose dates contain today counts as current.
    is_current = models.BooleanField(default=False)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["is_current"],
                condition=Q(is_current=True),
                name="one_current_session",
            )
        ]

    def __str__(self):
        if self.name:
            return self.name
        return "From " + str(self.start_year) + " to " + str(self.end_year)

    def clean(self):
        if self.start_year and self.end_year and self.end_year <= self.start_year:
            raise ValidationError({"end_year": "The end date must be after the start date."})

    def validate_constraints(self, exclude=None):
        # save() un-marks the previous current session, so "one current
        # session" must not block marking a new one in forms and the API.
        exclude = set(exclude or ())
        exclude.add("is_current")
        super().validate_constraints(exclude=exclude)

    def save(self, *args, **kwargs):
        # Marking this session current un-marks the previous one.
        if self.is_current:
            Session.objects.filter(is_current=True).exclude(pk=self.pk).update(is_current=False)
        super().save(*args, **kwargs)

    @classmethod
    def current(cls):
        marked = cls.objects.filter(is_current=True).first()
        if marked:
            return marked
        today = timezone.localdate()
        return (
            cls.objects.filter(start_year__lte=today, end_year__gte=today)
            .order_by("-start_year")
            .first()
        )


class Term(models.Model):
    """A school quarter (chorak) inside an academic year."""

    session = models.ForeignKey(Session, on_delete=models.CASCADE, related_name="terms")
    number = models.PositiveSmallIntegerField(
        validators=[MinValueValidator(1), MaxValueValidator(4)]
    )
    name = models.CharField(max_length=40, blank=True, default="")
    start_date = models.DateField()
    end_date = models.DateField()

    class Meta:
        ordering = ["session", "number"]
        constraints = [
            models.UniqueConstraint(
                fields=["session", "number"], name="one_term_number_per_session"
            ),
            models.CheckConstraint(
                condition=Q(number__gte=1) & Q(number__lte=4), name="term_number_1_to_4"
            ),
        ]

    def __str__(self):
        return self.name or f"{self.session} · Q{self.number}"

    def clean(self):
        errors = {}
        if self.start_date and self.end_date and self.end_date <= self.start_date:
            errors["end_date"] = "The end date must be after the start date."
        if self.session_id and self.start_date and self.end_date:
            session = self.session
            if self.start_date < session.start_year or self.end_date > session.end_year:
                errors["start_date"] = "A quarter must fall inside its academic year."
            overlapping = (
                Term.objects.filter(session_id=self.session_id)
                .exclude(pk=self.pk)
                .filter(start_date__lte=self.end_date, end_date__gte=self.start_date)
            )
            if overlapping.exists():
                errors["start_date"] = "Quarters in one academic year must not overlap."
        if errors:
            raise ValidationError(errors)


class CustomUser(AbstractUser):
    # String keys so CharField comparisons are always consistent.
    # Integer keys (the original) caused `1 == '1'` → False in Python 3,
    # which broke login redirects and get_user_type_display().
    USER_TYPE = (("1", "HOD"), ("2", "Staff"), ("3", "Student"), ("4", "Parent"))
    GENDER = [("M", "Male"), ("F", "Female")]

    username = None  # Removed username, using email instead
    email = models.EmailField(unique=True)
    login_id = models.CharField(
        max_length=20,
        unique=True,
        null=True,
        blank=True,
        help_text="Unique ID for staff/student login. Leave blank for admin (uses email).",
    )
    user_type = models.CharField(default="1", choices=USER_TYPE, max_length=1)
    gender = models.CharField(max_length=1, choices=GENDER, blank=True, default="")
    date_of_birth = models.DateField(
        null=True,
        blank=True,
        help_text="Date of birth (YYYY-MM-DD). Used to generate the user's login ID.",
    )
    profile_pic = models.ImageField(blank=True, null=True)
    avatar = models.CharField(max_length=10, blank=True, default="")
    address = models.TextField(blank=True, default="")
    fcm_token = models.TextField(default="")  # For firebase notifications
    # Set when an admin gives the password (new parent, reset, login letter); the API then
    # allows only me/, change-password and logout until the user picks their own (PL.1).
    must_change_password = models.BooleanField(default=False)
    # Web language chosen with the header switch ("uz", "ru", "en"); blank = default (P3.0).
    language = models.CharField(max_length=5, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []
    objects = CustomUserManager()

    def __str__(self):
        return self.first_name + " " + self.last_name


class Admin(models.Model):
    admin = models.OneToOneField(CustomUser, on_delete=models.CASCADE)
    # Branch-first access control. Existing admins default to super admin so
    # nobody is locked out by the branch rollout (see migration 0033).
    is_super_admin = models.BooleanField(
        default=True,
        help_text="Super admins see every branch. Branch admins see only their assigned branches.",
    )
    branches = models.ManyToManyField(
        "Branch",
        blank=True,
        related_name="admins",
        help_text="Branches this admin manages. Ignored when is_super_admin is True.",
    )

    # Multiple super admins are allowed: the Recovery Admin can promote any
    # number of admins to super admin. The seeded Recovery Admin is the
    # permanent top-level account (see branching.is_recovery_admin) and is
    # protected from demotion/deletion at the view layer.

    def __str__(self):
        return f"{self.admin.first_name} {self.admin.last_name}".strip() or self.admin.email


class Course(models.Model):
    name = models.CharField(max_length=120)
    is_active = models.BooleanField(default=True)
    is_english = models.BooleanField(
        default=False,
        help_text="Mark as English program to enable level tracking and vocabulary features.",
    )
    monthly_fee = models.DecimalField(
        max_digits=12,
        decimal_places=0,
        null=True,
        blank=True,
        help_text="Default monthly tuition in UZS soʻm. Groups may override this.",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name


class Book(models.Model):
    name = models.CharField(max_length=200)
    author = models.CharField(max_length=200)
    isbn = models.PositiveIntegerField(unique=True)
    category = models.CharField(max_length=50)

    def __str__(self):
        return str(self.name) + " [" + str(self.isbn) + "]"


def _level_text(level):
    return gettext("Level %(level)s") % {"level": level}


# "Level 3" in the page language, worked out when it is shown (P3.0 / web audit M2).
_level_label = lazy(_level_text, str)


class Student(models.Model):
    STATUS_ACTIVE = "active"
    STATUS_INACTIVE = "inactive"
    STATUS_SUSPENDED = "suspended"
    STATUS_CHOICES = [
        (STATUS_ACTIVE, gettext_lazy("Active")),
        (STATUS_INACTIVE, gettext_lazy("Inactive")),
        (STATUS_SUSPENDED, gettext_lazy("Suspended")),
    ]

    LEVEL_CHOICES = [(i, _level_label(i)) for i in range(1, 7)]

    THEME_DARK = "dark"
    THEME_BRIGHT = "bright"
    THEME_SYSTEM = "system"
    THEME_CHOICES = [
        (THEME_DARK, "Dark"),
        (THEME_BRIGHT, "Bright"),
        (THEME_SYSTEM, "System Default"),
    ]

    admin = models.OneToOneField(CustomUser, on_delete=models.CASCADE)
    course = models.ForeignKey(Course, on_delete=models.SET_NULL, null=True, blank=False)
    branch = models.ForeignKey(
        "Branch",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="students",
    )
    phone = models.CharField(max_length=20, blank=True, default="")
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default=STATUS_ACTIVE)
    theme = models.CharField(max_length=10, choices=THEME_CHOICES, default=THEME_SYSTEM)
    app_settings = models.JSONField(
        default=dict,
        blank=True,
        help_text="Mobile app preferences (accent colour, font size, language, notification toggles).",
    )
    level = models.PositiveSmallIntegerField(
        choices=LEVEL_CHOICES,
        null=True,
        blank=True,
        help_text="English proficiency level (1–6). Only applies to English-program students.",
    )

    class Meta:
        indexes = [
            models.Index(fields=["branch", "status"]),
            models.Index(fields=["course", "status"]),
        ]

    def __str__(self):
        return self.admin.last_name + ", " + self.admin.first_name

    @property
    def level_display(self):
        return f"Level {self.level}" if self.level else "—"

    @property
    def is_english_student(self):
        return bool(self.course and self.course.is_english)

    @property
    def effective_branch(self):
        """Branch this student belongs to.

        Prefers the explicit branch; falls back to the branch of the first
        active enrollment group so legacy records (no branch set yet) still
        resolve sensibly. Returns None when nothing is known.
        """
        if self.branch_id:
            return self.branch
        enrollment = (
            self.enrollment_set.select_related("group__branch")
            .filter(is_active=True, group__branch__isnull=False)
            .first()
        )
        if enrollment and enrollment.group:
            return enrollment.group.branch
        return None


class Parent(models.Model):
    """A parent or guardian (user_type "4"). Sees only their linked children."""

    admin = models.OneToOneField(CustomUser, on_delete=models.CASCADE)
    phone = models.CharField(max_length=20, blank=True, default="")
    children = models.ManyToManyField(
        Student, through="ParentChild", related_name="parents", blank=True
    )

    def __str__(self):
        return f"{self.admin.first_name} {self.admin.last_name}".strip() or str(self.admin.login_id)


class ParentChild(models.Model):
    RELATION_MOTHER = "mother"
    RELATION_FATHER = "father"
    RELATION_GUARDIAN = "guardian"
    RELATION_CHOICES = [
        (RELATION_MOTHER, "Mother"),
        (RELATION_FATHER, "Father"),
        (RELATION_GUARDIAN, "Guardian"),
    ]

    parent = models.ForeignKey(Parent, on_delete=models.CASCADE, related_name="child_links")
    student = models.ForeignKey(Student, on_delete=models.CASCADE, related_name="parent_links")
    relation = models.CharField(max_length=10, choices=RELATION_CHOICES, default=RELATION_GUARDIAN)
    is_primary = models.BooleanField(
        default=False, help_text="Main contact for this child (gets messages first)."
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["parent", "student"], name="unique_parent_child"),
        ]

    def __str__(self):
        return f"{self.parent} → {self.student} ({self.relation})"


class Staff(models.Model):
    course = models.ForeignKey(Course, on_delete=models.SET_NULL, null=True, blank=False)
    admin = models.OneToOneField(CustomUser, on_delete=models.CASCADE)
    branch = models.ForeignKey(
        "Branch",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="staff_members",
    )
    phone = models.CharField(max_length=20, blank=True, default="")
    specialization = models.CharField(
        max_length=200,
        blank=True,
        default="",
        help_text="e.g. IELTS, Mathematics, Business English",
    )
    is_active = models.BooleanField(default=True)

    class Meta:
        indexes = [
            models.Index(fields=["branch", "is_active"]),
            models.Index(fields=["course", "is_active"]),
        ]

    def __str__(self):
        return self.admin.first_name + " " + self.admin.last_name

    @property
    def effective_branch(self):
        """Branch this teacher belongs to.

        Prefers the explicit branch; falls back to the branch of the first
        group they teach so legacy records still resolve. Returns None when
        nothing is known.
        """
        if self.branch_id:
            return self.branch
        group = (
            Group.objects.select_related("branch")
            .filter(teacher=self, branch__isnull=False)
            .first()
        )
        return group.branch if group else None


class Subject(models.Model):
    name = models.CharField(max_length=120)
    # School subjects have no single teacher: each class sets its own (ClassSubject).
    staff = models.ForeignKey(Staff, on_delete=models.CASCADE, null=True, blank=True)
    course = models.ForeignKey(Course, on_delete=models.CASCADE)
    updated_at = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=["course"]),
            models.Index(fields=["staff"]),
        ]

    def __str__(self):
        return self.name


class Attendance(models.Model):
    group = models.ForeignKey("Group", on_delete=models.CASCADE, null=True, blank=True)
    date = models.DateField()
    # School daily register (P2.2): the homeroom teacher who saved it last.
    taken_by = models.ForeignKey(
        "Staff", on_delete=models.SET_NULL, null=True, blank=True, related_name="registers_taken"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ("group", "date")

    def __str__(self):
        return f"{self.group.name} · {self.date}"


class AttendanceReport(models.Model):
    ABSENT = 0
    PRESENT = 1
    LATE = 2
    STATUS_CHOICES = ((ABSENT, "Absent"), (PRESENT, "Present"), (LATE, "Late"))

    # CASCADE matches every other student-owned table; DO_NOTHING left dangling
    # rows (or a hard IntegrityError) when a student was deleted.
    student = models.ForeignKey(Student, on_delete=models.CASCADE)
    attendance = models.ForeignKey(Attendance, on_delete=models.CASCADE)
    status = models.SmallIntegerField(default=ABSENT, choices=STATUS_CHOICES)
    # School daily register (P2.2): when a late pupil arrived, and a short note ("Kasal").
    arrival_time = models.TimeField(null=True, blank=True)
    note = models.CharField(max_length=200, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=["student"]),
            models.Index(fields=["attendance"]),
        ]
        # One attendance row per student per class/day. The UI rewrites cleanly,
        # but without this a race or bulk path could insert duplicate reports,
        # inflating present/absent counts and the leaderboard.
        constraints = [
            models.UniqueConstraint(
                fields=["attendance", "student"], name="uniq_attendance_student"
            ),
        ]


class LeaveReportStudent(models.Model):
    PENDING = 0
    APPROVED = 1
    REJECTED = -1
    LEAVE_STATUS = ((PENDING, "Pending"), (APPROVED, "Approved"), (REJECTED, "Rejected"))

    student = models.ForeignKey(Student, on_delete=models.CASCADE)
    date = models.DateField(null=True, blank=True)
    message = models.TextField()
    status = models.SmallIntegerField(default=PENDING, choices=LEAVE_STATUS)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class LeaveReportStaff(models.Model):
    PENDING = 0
    APPROVED = 1
    REJECTED = -1
    LEAVE_STATUS = ((PENDING, "Pending"), (APPROVED, "Approved"), (REJECTED, "Rejected"))

    staff = models.ForeignKey(Staff, on_delete=models.CASCADE)
    date = models.DateField(null=True, blank=True)
    message = models.TextField()
    status = models.SmallIntegerField(default=PENDING, choices=LEAVE_STATUS)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class FeedbackStudent(models.Model):
    student = models.ForeignKey(Student, on_delete=models.CASCADE)
    feedback = models.TextField()
    reply = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class FeedbackStaff(models.Model):
    staff = models.ForeignKey(Staff, on_delete=models.CASCADE)
    feedback = models.TextField()
    reply = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class NotificationQuerySet(models.QuerySet):
    def bulk_create(self, objs, *args, **kwargs):
        # bulk_create skips post_save, so push the new rows from here (P2.8).
        created = super().bulk_create(objs, *args, **kwargs)
        from .push import push_notifications

        try:
            push_notifications(created)
        except Exception:
            logging.getLogger("main_app.push").exception("Push for bulk notifications failed.")
        return created


class Notification(models.Model):
    ATTENDANCE = "attendance"
    RESULT = "result"
    ANNOUNCEMENT = "announcement"
    HOMEWORK = "homework"
    VOCABULARY = "vocabulary"
    PAYMENT = "payment"
    GENERAL = "general"
    CATEGORY_CHOICES = [
        (ATTENDANCE, "Attendance"),
        (RESULT, "Result"),
        (ANNOUNCEMENT, "Announcement"),
        (HOMEWORK, "Homework"),
        (VOCABULARY, "Vocabulary"),
        (PAYMENT, "Payment"),
        (GENERAL, "General"),
    ]

    recipient = models.ForeignKey(
        CustomUser, on_delete=models.CASCADE, related_name="notifications"
    )
    category = models.CharField(max_length=20, choices=CATEGORY_CHOICES, default=GENERAL)
    message = models.TextField()
    link = models.CharField(
        max_length=500, blank=True, default="", help_text="Optional URL the notification links to"
    )
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    objects = NotificationQuerySet.as_manager()

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["recipient", "is_read"]),
        ]

    def __str__(self):
        return f"[{self.category}] → {self.recipient.email}: {self.message[:50]}"


class DeviceToken(models.Model):
    """FCM registration token of one app install; a user can have several (P2.8)."""

    PLATFORM_ANDROID = "android"
    PLATFORM_IOS = "ios"
    PLATFORM_WEB = "web"
    PLATFORM_CHOICES = [
        (PLATFORM_ANDROID, "Android"),
        (PLATFORM_IOS, "iOS"),
        (PLATFORM_WEB, "Web"),
    ]

    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name="device_tokens")
    token = models.CharField(max_length=512, unique=True)
    platform = models.CharField(max_length=10, choices=PLATFORM_CHOICES, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-updated_at"]

    def __str__(self):
        return f"{self.user.email} [{self.platform or '?'}] {self.token[:12]}…"


class RegistrationLead(models.Model):
    STATUS_NEW = "new"
    STATUS_CONTACTED = "contacted"
    STATUS_CONVERTED = "converted"
    STATUS_REJECTED = "rejected"
    STATUS_CHOICES = [
        (STATUS_NEW, "New"),
        (STATUS_CONTACTED, "Contacted"),
        (STATUS_CONVERTED, "Converted"),
        (STATUS_REJECTED, "Rejected"),
    ]

    full_name = models.CharField(max_length=160, blank=True, default="")
    first_name = models.CharField(max_length=80, blank=True, default="")
    last_name = models.CharField(max_length=80, blank=True, default="")
    email = models.EmailField(blank=True, default="")
    phone = models.CharField(max_length=40, blank=True, default="")
    parent_phone = models.CharField(max_length=40, blank=True, default="")
    program = models.CharField(max_length=140, blank=True, default="")
    branch = models.CharField(max_length=140, blank=True, default="")
    preferred_schedule = models.CharField(max_length=160, blank=True, default="")
    source = models.CharField(max_length=80, blank=True, default="website")
    social_handle = models.CharField(max_length=120, blank=True, default="")
    campaign = models.CharField(max_length=160, blank=True, default="")
    utm_source = models.CharField(max_length=120, blank=True, default="")
    utm_medium = models.CharField(max_length=120, blank=True, default="")
    utm_campaign = models.CharField(max_length=160, blank=True, default="")
    referrer = models.CharField(max_length=500, blank=True, default="")
    message = models.TextField(blank=True, default="")
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_NEW)
    admin_notes = models.TextField(blank=True, default="")
    assigned_to = models.ForeignKey(
        CustomUser,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="assigned_registration_leads",
    )
    raw_payload = models.JSONField(blank=True, default=dict)
    remote_addr = models.CharField(max_length=80, blank=True, default="")
    user_agent = models.CharField(max_length=500, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["status", "created_at"]),
            models.Index(fields=["source", "created_at"]),
            models.Index(fields=["phone"]),
            models.Index(fields=["email"]),
        ]

    def __str__(self):
        return self.full_name or self.phone or self.email or f"Lead #{self.pk}"


class StudentResult(models.Model):
    # Grading scale: test is out of 40, exam out of 60 → total out of 100.
    TEST_MAX = 40
    EXAM_MAX = 60

    student = models.ForeignKey(Student, on_delete=models.CASCADE)
    group = models.ForeignKey("Group", on_delete=models.CASCADE, null=True, blank=True)
    test = models.FloatField(
        default=0,
        validators=[MinValueValidator(0), MaxValueValidator(TEST_MAX)],
    )
    exam = models.FloatField(
        default=0,
        validators=[MinValueValidator(0), MaxValueValidator(EXAM_MAX)],
    )
    comment = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ("student", "group")


@receiver(post_save, sender=CustomUser)
def create_user_profile(sender, instance, created, **kwargs):
    """Create the matching role-profile row on first save of a CustomUser.

    Previously this app had TWO post_save receivers (this one and a
    `save_user_profile` twin without the `created` guard) both calling
    get_or_create. The twin fired on every password change / profile
    edit, so every save round-tripped the DB once for the role table
    even though no new row was ever created. Audit fix #4.
    """
    if not created:
        return
    user_type = str(instance.user_type)
    if user_type == "1":
        Admin.objects.get_or_create(admin=instance)
    elif user_type == "2":
        Staff.objects.get_or_create(admin=instance)
    elif user_type == "3":
        Student.objects.get_or_create(admin=instance)
    elif user_type == "4":
        Parent.objects.get_or_create(admin=instance)


class Branch(models.Model):
    # Which Iceberg brand this branch's users see. Presentation only — access
    # is still decided by branching.py. See docs/plans/ICEBERG_SCHOOL_BRAND_PLAN.md.
    BRAND_CENTER = "center"
    BRAND_SCHOOL = "school"
    BRAND_CHOICES = [
        (BRAND_CENTER, "Iceberg Learning Center"),
        (BRAND_SCHOOL, "Iceberg School"),
    ]

    name = models.CharField(max_length=100)
    address = models.TextField(blank=True, default="")
    brand = models.CharField(
        max_length=20,
        choices=BRAND_CHOICES,
        default=BRAND_CENTER,
        help_text="Which Iceberg brand this branch's users see.",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

    class Meta:
        verbose_name_plural = "Branches"


class Group(models.Model):
    # A school class (7-B) is a Group with kind="class" so attendance, homework,
    # chat and invoices keep working (plan decision D5). Courses are unchanged.
    KIND_COURSE = "course"
    KIND_CLASS = "class"
    KIND_CHOICES = [(KIND_COURSE, "Course group"), (KIND_CLASS, "School class")]

    name = models.CharField(max_length=100)
    course = models.ForeignKey(Course, on_delete=models.CASCADE)
    teacher = models.ForeignKey(Staff, on_delete=models.SET_NULL, null=True, blank=True)
    branch = models.ForeignKey(Branch, on_delete=models.SET_NULL, null=True, blank=True)
    room = models.CharField(
        max_length=50, blank=True, default="", help_text="Classroom or room number, e.g. Room 3A"
    )
    schedule = models.CharField(
        max_length=200, blank=True, default="", help_text="e.g. Mon/Wed 10:00–12:00"
    )
    capacity = models.PositiveIntegerField(default=20)
    monthly_fee = models.DecimalField(
        max_digits=12,
        decimal_places=0,
        null=True,
        blank=True,
        help_text="Monthly tuition in UZS soʻm for this group. Leave blank to use the course fee.",
    )
    start_date = models.DateField(
        null=True, blank=True, help_text="The date when this group starts classes"
    )
    is_archived = models.BooleanField(default=False)
    kind = models.CharField(max_length=10, choices=KIND_CHOICES, default=KIND_COURSE)
    grade_level = models.PositiveSmallIntegerField(
        null=True,
        blank=True,
        validators=[MinValueValidator(1), MaxValueValidator(11)],
        help_text="School classes only: grade 1–11.",
    )
    letter = models.CharField(
        max_length=2, blank=True, default="", help_text="School classes only, e.g. B in 7-B."
    )
    session = models.ForeignKey(
        Session,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="classes",
        help_text="School classes only: the academic year.",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=["branch", "is_archived"]),
            models.Index(fields=["teacher", "is_archived"]),
        ]
        constraints = [
            models.CheckConstraint(
                condition=Q(kind="course")
                | (
                    Q(kind="class")
                    & Q(grade_level__isnull=False)
                    & Q(grade_level__gte=1)
                    & Q(grade_level__lte=11)
                ),
                name="class_grade_1_to_11",
            ),
        ]

    def __str__(self):
        return self.name

    @property
    def is_class(self):
        return self.kind == self.KIND_CLASS

    def clean(self):
        errors = {}
        if self.is_class:
            if self.grade_level is None or not 1 <= self.grade_level <= 11:
                errors["grade_level"] = "A school class needs a grade from 1 to 11."
            if not self.letter:
                errors["letter"] = "A school class needs a letter, e.g. B."
            if self.session_id is None:
                errors["session"] = "A school class needs an academic year."
            if self.branch_id and self.branch.brand != Branch.BRAND_SCHOOL:
                errors["branch"] = "School classes belong to an Iceberg School branch."
        elif self.grade_level is not None or self.letter or self.session_id:
            errors["kind"] = "Grade, letter and academic year are only for school classes."
        if errors:
            raise ValidationError(errors)

    @property
    def effective_monthly_fee(self):
        """Tuition for this group: explicit override, else the course default."""
        if self.monthly_fee is not None:
            return self.monthly_fee
        if self.course_id and self.course.monthly_fee is not None:
            return self.course.monthly_fee
        return None


class Enrollment(models.Model):
    student = models.ForeignKey(Student, on_delete=models.CASCADE)
    group = models.ForeignKey(Group, on_delete=models.CASCADE)
    enrolled_on = models.DateField(auto_now_add=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        unique_together = ("student", "group")
        indexes = [
            models.Index(fields=["student"]),
            models.Index(fields=["group"]),
            models.Index(fields=["group", "is_active"]),
            models.Index(fields=["student", "is_active"]),
        ]

    def __str__(self):
        return f"{self.student} → {self.group}"

    def clean(self):
        if self.is_active and self.student_id and self.group_id:
            other = class_enrollment_conflict(self.student_id, self.group, exclude_pk=self.pk)
            if other is not None:
                raise ValidationError(
                    {"group": f"This student is already in class {other.name} this academic year."}
                )


def class_enrollment_conflict(student_id, group, exclude_pk=None):
    """The other active class this student is in for ``group``'s academic year, if any.

    A student is in at most one active school class per academic year. Course
    groups never conflict.
    """
    if group is None or group.kind != Group.KIND_CLASS:
        return None
    qs = Enrollment.objects.filter(
        student_id=student_id,
        is_active=True,
        group__kind=Group.KIND_CLASS,
        group__session_id=group.session_id,
    ).exclude(group_id=group.pk)
    if exclude_pk is not None:
        qs = qs.exclude(pk=exclude_pk)
    match = qs.select_related("group").first()
    return match.group if match else None


class ClassSubject(models.Model):
    """A subject taught in one school class, by one teacher, so many hours a week."""

    group = models.ForeignKey(Group, on_delete=models.CASCADE, related_name="class_subjects")
    subject = models.ForeignKey(Subject, on_delete=models.PROTECT, related_name="class_subjects")
    teacher = models.ForeignKey(
        Staff,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="class_subjects",
    )
    weekly_hours = models.PositiveSmallIntegerField(
        default=1, validators=[MinValueValidator(1), MaxValueValidator(12)]
    )

    class Meta:
        ordering = ["group", "subject__name"]
        constraints = [
            models.UniqueConstraint(fields=["group", "subject"], name="unique_class_subject"),
        ]

    def __str__(self):
        return f"{self.group} · {self.subject}"

    def clean(self):
        errors = {}
        if self.group_id and not self.group.is_class:
            errors["group"] = "Subjects can only be added to a school class."
        elif self.group_id and self.subject_id and self.subject.course_id != self.group.course_id:
            errors["subject"] = "This subject belongs to another course than the class."
        if errors:
            raise ValidationError(errors)


class BellPeriod(models.Model):
    """One lesson slot of a school branch's day, e.g. period 2 from 08:55 to 09:40."""

    branch = models.ForeignKey(Branch, on_delete=models.CASCADE, related_name="bell_periods")
    number = models.PositiveSmallIntegerField(
        validators=[MinValueValidator(1), MaxValueValidator(12)]
    )
    start_time = models.TimeField()
    end_time = models.TimeField()

    class Meta:
        ordering = ["branch", "number"]
        constraints = [
            models.UniqueConstraint(
                fields=["branch", "number"], name="one_bell_period_number_per_branch"
            ),
            models.CheckConstraint(
                condition=Q(end_time__gt=models.F("start_time")),
                name="bell_period_ends_after_start",
            ),
        ]

    def __str__(self):
        return f"{self.number} ({self.start_time:%H:%M}–{self.end_time:%H:%M})"

    def clean(self):
        errors = {}
        if self.start_time and self.end_time and self.end_time <= self.start_time:
            errors["end_time"] = gettext_lazy("The end time must be after the start time.")
        if self.branch_id and self.branch.brand != Branch.BRAND_SCHOOL:
            errors["branch"] = gettext_lazy("Bell periods belong to an Iceberg School branch.")
        if not errors and self.branch_id and self.start_time and self.end_time:
            overlapping = (
                BellPeriod.objects.filter(branch_id=self.branch_id)
                .exclude(pk=self.pk)
                .filter(start_time__lt=self.end_time, end_time__gt=self.start_time)
            )
            if overlapping.exists():
                errors["start_time"] = gettext_lazy("Bell periods in one branch must not overlap.")
        if errors:
            raise ValidationError(errors)


class Lesson(models.Model):
    """One timetable slot: a class has a subject on a weekday in a bell period.

    ``valid_from``/``valid_to`` (both optional) limit the slot to part of the
    year, so a timetable change mid-year keeps the old weeks right. ``group``
    must be the class of ``class_subject``; it is stored for fast queries.
    """

    WEEKDAY_CHOICES = [
        (1, "Monday"),
        (2, "Tuesday"),
        (3, "Wednesday"),
        (4, "Thursday"),
        (5, "Friday"),
        (6, "Saturday"),
    ]

    group = models.ForeignKey(Group, on_delete=models.CASCADE, related_name="lessons")
    class_subject = models.ForeignKey(
        ClassSubject, on_delete=models.CASCADE, related_name="lessons"
    )
    weekday = models.PositiveSmallIntegerField(choices=WEEKDAY_CHOICES)
    period = models.ForeignKey(BellPeriod, on_delete=models.PROTECT, related_name="lessons")
    room = models.CharField(
        max_length=50, blank=True, default="", help_text="Leave blank to use the class's room."
    )
    valid_from = models.DateField(null=True, blank=True)
    valid_to = models.DateField(null=True, blank=True)

    class Meta:
        ordering = ["weekday", "period__start_time"]
        indexes = [
            models.Index(fields=["group", "weekday"]),
            models.Index(fields=["weekday", "period"]),
        ]
        constraints = [
            models.CheckConstraint(
                condition=Q(weekday__gte=1) & Q(weekday__lte=6), name="lesson_weekday_1_to_6"
            ),
        ]

    def __str__(self):
        return f"{self.group} · {self.get_weekday_display()} {self.period.number}"

    @property
    def effective_room(self):
        return self.room or self.group.room

    def is_on(self, day):
        """True when this lesson takes place on the date ``day``."""
        if day.isoweekday() != self.weekday:
            return False
        if self.valid_from and day < self.valid_from:
            return False
        if self.valid_to and day > self.valid_to:
            return False
        session = self.group.session
        if session and not session.start_year <= day <= session.end_year:
            return False
        return True

    def clean(self):
        errors = {}
        if self.group_id and not self.group.is_class:
            errors["group"] = "Lessons can only be added to a school class."
        if self.group_id and self.class_subject_id and self.class_subject.group_id != self.group_id:
            errors["class_subject"] = "This subject is not taught in this class."
        if self.group_id and self.period_id and self.period.branch_id != self.group.branch_id:
            errors["period"] = "This bell period belongs to another branch."
        if self.valid_from and self.valid_to and self.valid_to < self.valid_from:
            errors["valid_to"] = "The end date must not be before the start date."
        if errors:
            raise ValidationError(errors)
        if self.group_id and self.class_subject_id and self.period_id and self.weekday:
            clashes = lesson_clashes(self)
            if clashes:
                raise LessonClashError(clashes)


class LessonClashError(ValidationError):
    """A lesson would double-book its class, teacher or room.

    ``clashes`` keeps the details (kind and the other lesson) so screens can
    show where the conflict is; the messages say the same in words. They are
    non-field errors, so model forms (Django admin) show them too.
    """

    MESSAGES = {
        "class": "The class already has a lesson at this time.",
        "teacher": "The teacher already teaches {other} at this time.",
        "room": "The room is already used by {other} at this time.",
    }

    def __init__(self, clashes):
        self.clashes = clashes
        super().__init__([self.message_for(kind, other) for kind, other in clashes])

    @classmethod
    def message_for(cls, kind, other):
        return cls.MESSAGES[kind].format(other=other.group.name)


def lesson_clashes(lesson):
    """Other lessons that would be double-booked with ``lesson``.

    Returns a list of ``(kind, other_lesson)`` with kind ``"class"``,
    ``"teacher"`` or ``"room"``, at most one entry per kind. Lessons clash when
    they are on the same weekday, their bell times overlap (a teacher may work
    in several branches) and their valid dates overlap. Rooms are compared by
    name inside one branch.
    """
    period = lesson.period
    candidates = (
        Lesson.objects.filter(
            weekday=lesson.weekday,
            period__start_time__lt=period.end_time,
            period__end_time__gt=period.start_time,
        )
        .exclude(pk=lesson.pk)
        .select_related("group", "class_subject")
    )
    if lesson.valid_to:
        candidates = candidates.filter(
            Q(valid_from__isnull=True) | Q(valid_from__lte=lesson.valid_to)
        )
    if lesson.valid_from:
        candidates = candidates.filter(
            Q(valid_to__isnull=True) | Q(valid_to__gte=lesson.valid_from)
        )

    clashes = []
    other = candidates.filter(group_id=lesson.group_id).first()
    if other:
        clashes.append(("class", other))
    teacher_id = lesson.class_subject.teacher_id
    if teacher_id:
        other = candidates.filter(class_subject__teacher_id=teacher_id).first()
        if other:
            clashes.append(("teacher", other))
    room = lesson.effective_room.strip().lower()
    if room:
        for other in candidates.filter(group__branch_id=lesson.group.branch_id):
            if other.effective_room.strip().lower() == room:
                clashes.append(("room", other))
                break
    return clashes


class ChatThread(models.Model):
    """Persistent conversation: one per group, or one per student and teacher
    for the School teacher ↔ parent messages (kind "parent", plan P2.6). All
    linked parents of the student share the parent thread."""

    KIND_GROUP = "group"
    KIND_PARENT = "parent"
    KIND_CHOICES = [(KIND_GROUP, "Group chat"), (KIND_PARENT, "Teacher and parents")]

    group = models.OneToOneField(
        Group, on_delete=models.CASCADE, related_name="chat_thread", null=True, blank=True
    )
    kind = models.CharField(max_length=10, choices=KIND_CHOICES, default=KIND_GROUP)
    student = models.ForeignKey(
        Student,
        on_delete=models.CASCADE,
        related_name="parent_threads",
        null=True,
        blank=True,
    )
    teacher = models.ForeignKey(
        Staff,
        on_delete=models.CASCADE,
        related_name="parent_threads",
        null=True,
        blank=True,
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["group__name"]
        indexes = [
            models.Index(fields=["updated_at"]),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["student", "teacher"],
                condition=models.Q(kind="parent"),
                name="unique_parent_thread_per_student_teacher",
            ),
        ]

    def __str__(self):
        if self.kind == self.KIND_PARENT:
            return f"Parents chat - {self.student} / {self.teacher}"
        return f"Chat - {self.group.name if self.group_id else '-'}"


class ChatMessage(models.Model):
    IMAGE_EXTENSIONS = {"jpg", "jpeg", "png", "gif", "webp", "bmp"}

    thread = models.ForeignKey(ChatThread, on_delete=models.CASCADE, related_name="messages")
    sender = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name="chat_messages")
    body = models.TextField(blank=True, default="")
    attachment = models.FileField(upload_to="chat_attachments/%Y/%m/", blank=True, null=True)
    attachment_name = models.CharField(max_length=255, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["created_at"]
        indexes = [
            models.Index(fields=["thread", "created_at"]),
            models.Index(fields=["sender", "created_at"]),
        ]

    @property
    def attachment_is_image(self):
        if not self.attachment:
            return False
        ext = (self.attachment_name or self.attachment.name).rsplit(".", 1)[-1].lower()
        return ext in self.IMAGE_EXTENSIONS

    @property
    def attachment_display_name(self):
        return self.attachment_name or (
            self.attachment.name.rsplit("/", 1)[-1] if self.attachment else ""
        )

    def __str__(self):
        return f"{self.sender.email} -> {self.thread}: {self.body[:50]}"


class ChatReadState(models.Model):
    thread = models.ForeignKey(ChatThread, on_delete=models.CASCADE, related_name="read_states")
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name="chat_read_states")
    last_read_at = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ("thread", "user")
        indexes = [
            models.Index(fields=["user", "thread"]),
        ]

    def __str__(self):
        return f"{self.user.email} read {self.thread}"


@receiver(post_save, sender=Group)
def create_group_chat_thread(sender, instance, created, **kwargs):
    if created:
        try:
            ChatThread.objects.get_or_create(group=instance)
        except (OperationalError, ProgrammingError):
            pass


class Assignment(models.Model):
    title = models.CharField(max_length=200)
    description = models.TextField(blank=True, default="")
    subject = models.ForeignKey(Subject, on_delete=models.SET_NULL, null=True, blank=True)
    group = models.ForeignKey(Group, on_delete=models.SET_NULL, null=True, blank=True)
    due_date = models.DateField()
    created_by = models.ForeignKey(Staff, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.title


class Submission(models.Model):
    assignment = models.ForeignKey(Assignment, on_delete=models.CASCADE)
    student = models.ForeignKey(Student, on_delete=models.CASCADE)
    file = models.FileField(upload_to="submissions/", null=True, blank=True)
    note = models.TextField(blank=True, default="")
    submitted_at = models.DateTimeField(auto_now_add=True)
    grade = models.FloatField(null=True, blank=True)

    class Meta:
        unique_together = ("assignment", "student")

    def __str__(self):
        return f"{self.student} → {self.assignment}"


class ResultFile(models.Model):
    group = models.ForeignKey(Group, on_delete=models.CASCADE)
    student = models.ForeignKey(Student, on_delete=models.SET_NULL, null=True, blank=True)
    file = models.FileField(upload_to="results/")
    title = models.CharField(max_length=200)
    description = models.TextField(blank=True, default="")
    uploaded_by = models.ForeignKey(Staff, on_delete=models.CASCADE)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-uploaded_at"]

    def __str__(self):
        return self.title

    @property
    def filename(self):
        import os

        return os.path.basename(self.file.name) if self.file else ""


class PasswordResetCode(models.Model):
    """One-time 6-digit code for the custom password-recovery flow."""

    user = models.ForeignKey(
        CustomUser, on_delete=models.CASCADE, related_name="password_reset_codes"
    )
    code_hash = models.CharField(max_length=64)  # SHA-256 hex of the raw digit code
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used = models.BooleanField(default=False)
    attempts = models.PositiveSmallIntegerField(default=0)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["user", "used", "expires_at"]),
        ]

    def __str__(self):
        return f"Reset code for {self.user.email} ({'used' if self.used else 'active'})"


class Loan(models.Model):
    """A book lending transaction.

    Replaces the legacy IssuedBook table which stored student_id as a
    CharField (no referential integrity) and joined to Book via ISBN.
    Both ends are now real ForeignKeys; a partial unique constraint
    prevents the same book from being on loan to the same student twice
    simultaneously (returned_at IS NULL = active loan).
    """

    student = models.ForeignKey(Student, on_delete=models.PROTECT, related_name="loans")
    book = models.ForeignKey(Book, on_delete=models.PROTECT, related_name="loans")
    issued_on = models.DateField(default=timezone.localdate)
    due_on = models.DateField(default=_default_loan_due_date)
    returned_on = models.DateField(null=True, blank=True)
    fine_paid = models.BooleanField(default=False)

    class Meta:
        ordering = ["-issued_on"]
        indexes = [
            models.Index(fields=["student"]),
            models.Index(fields=["returned_on"]),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["student", "book"],
                condition=Q(returned_on__isnull=True),
                name="one_active_loan_per_student_book",
            ),
        ]

    def __str__(self):
        return f"{self.book.name} → {self.student} ({'open' if self.returned_on is None else 'returned'})"

    @property
    def is_active(self):
        return self.returned_on is None

    @property
    def is_overdue(self):
        if not self.is_active:
            return False
        return timezone.localdate() > self.due_on

    @property
    def days_overdue(self):
        if not self.is_active or not self.is_overdue:
            return 0
        return (timezone.localdate() - self.due_on).days

    @property
    def fine_amount(self):
        return self.days_overdue * _OVERDUE_FINE_PER_DAY


# ── Vocabulary ────────────────────────────────────────────────────────────────


class VocabularyDay(models.Model):
    """A teacher-curated vocabulary set for a group on a specific day number."""

    SCOPE_GROUP = "group"
    SCOPE_ALL = "all"
    SCOPE_CHOICES = [
        (SCOPE_GROUP, "Assigned group only"),
        (SCOPE_ALL, "All students"),
    ]

    group = models.ForeignKey("Group", on_delete=models.CASCADE, related_name="vocabulary_days")
    day_number = models.PositiveIntegerField(help_text="Day 1, Day 2, …")
    title = models.CharField(
        max_length=200, blank=True, default="", help_text='Optional title, e.g. "Describing People"'
    )
    level = models.PositiveSmallIntegerField(
        null=True,
        blank=True,
        help_text="Target level (1–6). Leave blank to inherit the group default.",
    )
    release_at = models.DateTimeField(
        help_text="Words become visible to students at this date/time.",
    )
    release_scope = models.CharField(
        max_length=10,
        choices=SCOPE_CHOICES,
        default=SCOPE_GROUP,
        help_text="Who can see this vocabulary day after it is released.",
    )
    notes = models.TextField(
        blank=True, default="", help_text="Private teaching notes (not shown to students)."
    )
    created_by = models.ForeignKey(
        "Staff", on_delete=models.CASCADE, related_name="vocabulary_days"
    )
    notified_students = models.ManyToManyField(
        "Student", blank=True, related_name="notified_vocab_days"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["day_number"]
        unique_together = ("group", "day_number")

    def __str__(self):
        return f"{self.group.name} — Day {self.day_number}"

    @property
    def is_released(self):
        return timezone.now() >= self.release_at

    @property
    def word_count(self):
        return self.words.count()

    def student_can_view(self, student):
        """Released, and either school-wide or the student is enrolled in the group."""
        if not self.is_released:
            return False
        if self.release_scope == self.SCOPE_ALL:
            return True
        return Enrollment.objects.filter(
            student=student, group_id=self.group_id, is_active=True
        ).exists()


class VocabularyDayWord(models.Model):
    """One vocabulary item inside a VocabularyDay."""

    day = models.ForeignKey(VocabularyDay, on_delete=models.CASCADE, related_name="words")
    word = models.CharField(max_length=200)
    meaning = models.TextField()
    example_sentence = models.TextField(blank=True, default="")
    pronunciation_note = models.CharField(
        max_length=300,
        blank=True,
        default="",
        help_text="IPA or phonetic hint, e.g. /ˈɛfərt/",
    )
    order = models.PositiveSmallIntegerField(default=0)

    class Meta:
        ordering = ["order", "id"]

    def __str__(self):
        return f"Day {self.day.day_number} — {self.word}"


class VocabularyDayCompletion(models.Model):
    """Records that a student finished reviewing a vocabulary day."""

    student = models.ForeignKey("Student", on_delete=models.CASCADE, related_name="day_completions")
    day = models.ForeignKey(VocabularyDay, on_delete=models.CASCADE, related_name="completions")
    completed_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("student", "day")

    def __str__(self):
        return f"{self.student} ✓ Day {self.day.day_number}"


class VocabularyQuizResult(models.Model):
    """Saves the outcome of one quiz session (tied to a VocabularyDay)."""

    student = models.ForeignKey("Student", on_delete=models.CASCADE, related_name="quiz_results")
    day = models.ForeignKey(
        VocabularyDay, on_delete=models.SET_NULL, null=True, blank=True, related_name="quiz_results"
    )
    score = models.FloatField(help_text="Percentage 0–100")
    correct = models.PositiveIntegerField(default=0)
    total = models.PositiveIntegerField(default=0)
    taken_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-taken_at"]

    def __str__(self):
        return f"{self.student} — {self.score:.0f}% ({self.taken_at.date()})"

    @staticmethod
    def score_submission(day, correct, total):
        """Validate client-reported quiz counts and return (correct, total, score).

        The quiz asks one question per word, so ``total`` must equal the day's
        word count and ``correct`` must lie in [0, total]. Without this a client
        could post correct=1000,total=1 and inflate the leaderboard. Raises
        ValueError on anything out of range.
        """
        correct = int(correct)
        total = int(total)
        if total <= 0 or total != day.words.count():
            raise ValueError("total must equal the number of quiz questions.")
        if not 0 <= correct <= total:
            raise ValueError("correct must be between 0 and total.")
        return correct, total, round(correct / total * 100, 1)


# ── Leaderboard configuration & history ─────────────────────────────────────


class LeaderboardSettings(models.Model):
    """
    Singleton row holding ranking weights and metric toggles.
    Use LeaderboardSettings.get() to read; admin form writes the same row.
    """

    attendance_weight = models.PositiveSmallIntegerField(default=25)
    homework_weight = models.PositiveSmallIntegerField(default=25)
    quizzes_weight = models.PositiveSmallIntegerField(default=25)
    results_weight = models.PositiveSmallIntegerField(default=25)
    enable_attendance = models.BooleanField(default=True)
    enable_homework = models.BooleanField(default=True)
    enable_quizzes = models.BooleanField(default=True)
    enable_results = models.BooleanField(default=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Leaderboard Settings"
        verbose_name_plural = "Leaderboard Settings"

    @classmethod
    def get(cls):
        obj, _ = cls.objects.get_or_create(pk=1)
        return obj

    def save(self, *args, **kwargs):
        self.pk = 1
        super().save(*args, **kwargs)

    def normalized_weights(self):
        """Return {metric: weight} for ENABLED metrics, normalized so values sum to 1."""
        raw = {}
        if self.enable_attendance:
            raw["attendance"] = self.attendance_weight
        if self.enable_homework:
            raw["homework"] = self.homework_weight
        if self.enable_quizzes:
            raw["quizzes"] = self.quizzes_weight
        if self.enable_results:
            raw["results"] = self.results_weight
        total = sum(raw.values())
        if total == 0:
            # Avoid divide-by-zero — fall back to equal weights across what's enabled
            n = len(raw) or 1
            return {k: 1 / n for k in raw}
        return {k: v / total for k, v in raw.items()}

    def __str__(self):
        return "Leaderboard Settings"


class LeaderboardSeason(models.Model):
    """A snapshot period — admin creates seasons, snapshots freeze the rankings."""

    PERIOD_WEEKLY = "weekly"
    PERIOD_MONTHLY = "monthly"
    PERIOD_CUSTOM = "custom"
    PERIOD_CHOICES = [
        (PERIOD_WEEKLY, "Weekly"),
        (PERIOD_MONTHLY, "Monthly"),
        (PERIOD_CUSTOM, "Custom"),
    ]
    name = models.CharField(max_length=120, help_text='e.g. "October 2026"')
    period = models.CharField(max_length=12, choices=PERIOD_CHOICES, default=PERIOD_MONTHLY)
    start_date = models.DateField()
    end_date = models.DateField(null=True, blank=True, help_text="Leave blank for ongoing season")
    is_active = models.BooleanField(
        default=True, help_text="Snapshots are only captured for active seasons"
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-start_date", "-id"]

    def __str__(self):
        return self.name


class LeaderboardSnapshot(models.Model):
    """One frozen row per student per season."""

    season = models.ForeignKey(
        LeaderboardSeason, on_delete=models.CASCADE, related_name="snapshots"
    )
    student = models.ForeignKey(
        "Student", on_delete=models.CASCADE, related_name="leaderboard_snapshots"
    )
    rank = models.PositiveIntegerField()
    score = models.FloatField()
    attendance_pct = models.FloatField(null=True, blank=True)
    homework_pct = models.FloatField(null=True, blank=True)
    quizzes_pct = models.FloatField(null=True, blank=True)
    results_pct = models.FloatField(null=True, blank=True)
    badge = models.CharField(max_length=60, blank=True, default="")
    captured_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("season", "student")
        ordering = ["season", "rank"]
        indexes = [
            models.Index(fields=["season", "rank"]),
            models.Index(fields=["student", "season"]),
        ]

    def __str__(self):
        return f"{self.season} · #{self.rank} {self.student} ({self.score:.1f}%)"


class DashboardStory(models.Model):
    """Short-form content cards shown in the horizontal stories strip on the student dashboard."""

    TYPE_ANNOUNCEMENT = "announcement"
    TYPE_VOCAB = "vocab"
    TYPE_EVENT = "event"
    TYPE_TIP = "tip"
    TYPE_CHALLENGE = "challenge"
    TYPE_UPDATE = "update"
    STORY_TYPES = [
        (TYPE_ANNOUNCEMENT, "Announcement"),
        (TYPE_VOCAB, "Vocabulary Tip"),
        (TYPE_EVENT, "Event"),
        (TYPE_TIP, "Study Tip"),
        (TYPE_CHALLENGE, "Challenge"),
        (TYPE_UPDATE, "Teacher Update"),
    ]

    title = models.CharField(max_length=120)
    body = models.TextField(blank=True)
    image = models.ImageField(upload_to="stories/", null=True, blank=True)
    story_type = models.CharField(max_length=20, choices=STORY_TYPES, default=TYPE_ANNOUNCEMENT)
    emoji = models.CharField(
        max_length=8, blank=True, default="📢", help_text="Emoji shown when no image is uploaded"
    )
    bg_color = models.CharField(
        max_length=7,
        blank=True,
        default="#0C1F45",
        help_text="Card background colour (hex) used when no image",
    )
    created_by = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name="stories")
    target_groups = models.ManyToManyField(
        "Group", blank=True, help_text="Leave empty to show to all students"
    )
    is_active = models.BooleanField(default=True)
    expires_at = models.DateTimeField(
        null=True, blank=True, help_text="Story is hidden after this date/time"
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return self.title

    @property
    def has_valid_image(self):
        """
        True if the image field is set AND the file is actually accessible.
        For local FileSystemStorage we check the disk; for S3-compatible
        backends (DigitalOcean Spaces) we trust the URL since HEAD-checking
        every page render would be too expensive.
        """
        if not self.image:
            return False
        try:
            # `.path` raises NotImplementedError on remote storage backends
            import os

            return os.path.exists(self.image.path)
        except (NotImplementedError, ValueError, AttributeError):
            # Remote backend — assume the file is there.
            return True

    @property
    def safe_image_url(self):
        """Return the image URL, or empty string if the file isn't accessible."""
        if not self.has_valid_image:
            return ""
        try:
            return self.image.url
        except (ValueError, AttributeError):
            return ""


# ── Payments (Uzbekistan tuition billing, amounts in UZS soʻm) ────────────────


class Invoice(models.Model):
    """A monthly tuition charge for one student.

    Anchored to Student (PROTECT, like Loan) rather than Enrollment so that
    moving a student between groups or removing an enrollment never destroys
    financial history. `group` is a soft reference kept for reporting.
    Amounts are UZS soʻm — whole numbers only (tiyin is unused in practice).
    """

    STATUS_DUE = "due"
    STATUS_PARTIAL = "partial"
    STATUS_PAID = "paid"
    STATUS_CANCELLED = "cancelled"
    STATUS_CHOICES = [
        (STATUS_DUE, gettext_lazy("Due")),
        (STATUS_PARTIAL, gettext_lazy("Partially paid")),
        (STATUS_PAID, gettext_lazy("Paid")),
        (STATUS_CANCELLED, gettext_lazy("Cancelled")),
    ]

    student = models.ForeignKey(Student, on_delete=models.PROTECT, related_name="invoices")
    group = models.ForeignKey(
        Group, on_delete=models.SET_NULL, null=True, blank=True, related_name="invoices"
    )
    period = models.DateField(help_text="First day of the month this invoice covers.")
    amount = models.DecimalField(max_digits=12, decimal_places=0)
    discount = models.DecimalField(
        max_digits=12,
        decimal_places=0,
        default=0,
        help_text="Discount in UZS soʻm subtracted from the amount.",
    )
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default=STATUS_DUE)
    due_date = models.DateField()
    note = models.TextField(blank=True, default="")
    created_by = models.ForeignKey(
        CustomUser,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="created_invoices",
    )
    last_reminded_on = models.DateField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-period", "-created_at"]
        indexes = [
            models.Index(fields=["student", "status"]),
            models.Index(fields=["group", "period"]),
            models.Index(fields=["status", "due_date"]),
        ]
        constraints = [
            # One generated invoice per student/group/month. NULL groups
            # (manual one-off invoices) are exempt by the condition.
            models.UniqueConstraint(
                fields=["student", "group", "period"],
                condition=Q(group__isnull=False),
                name="one_invoice_per_student_group_period",
            ),
            models.CheckConstraint(
                condition=Q(discount__gte=0) & Q(amount__gte=0),
                name="invoice_amounts_non_negative",
            ),
        ]

    def __str__(self):
        return (
            f"Invoice #{self.pk} {self.student} {self.period:%Y-%m} ({self.get_status_display()})"
        )

    @property
    def period_label(self):
        return self.period.strftime("%B %Y")

    @property
    def total_due(self):
        return self.amount - self.discount

    @property
    def paid_amount(self):
        # Sum in Python when payments were prefetched (list pages) so each
        # row doesn't issue its own aggregate query.
        if "payments" in getattr(self, "_prefetched_objects_cache", {}):
            return sum((p.amount for p in self.payments.all()), 0)
        return self.payments.aggregate(total=models.Sum("amount"))["total"] or 0

    @property
    def balance(self):
        return self.total_due - self.paid_amount

    @property
    def is_overdue(self):
        return (
            self.status in (self.STATUS_DUE, self.STATUS_PARTIAL)
            and timezone.localdate() > self.due_date
        )

    def refresh_status(self, save=True):
        """Recompute status from recorded payments. Cancelled is sticky."""
        if self.status == self.STATUS_CANCELLED:
            return self.status
        paid = self.paid_amount
        if paid >= self.total_due and self.total_due > 0:
            new_status = self.STATUS_PAID
        elif paid > 0:
            new_status = self.STATUS_PARTIAL
        else:
            new_status = self.STATUS_DUE
        if new_status != self.status:
            self.status = new_status
            if save:
                self.save(update_fields=["status", "updated_at"])
        return self.status


class Payment(models.Model):
    """Money received against an invoice (cash desk, card terminal, transfer…)."""

    METHOD_CASH = "cash"
    METHOD_CARD = "card"
    METHOD_TRANSFER = "transfer"
    METHOD_PAYME = "payme"
    METHOD_CLICK = "click"
    METHOD_UZUM = "uzum"
    METHOD_CHOICES = [
        (METHOD_CASH, "Cash"),
        (METHOD_CARD, "Card terminal"),
        (METHOD_TRANSFER, "Bank transfer"),
        (METHOD_PAYME, "Payme"),
        (METHOD_CLICK, "Click"),
        (METHOD_UZUM, "Uzum"),
    ]

    invoice = models.ForeignKey(Invoice, on_delete=models.PROTECT, related_name="payments")
    amount = models.DecimalField(max_digits=12, decimal_places=0)
    method = models.CharField(max_length=10, choices=METHOD_CHOICES, default=METHOD_CASH)
    received_by = models.ForeignKey(
        CustomUser,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="received_payments",
    )
    paid_on = models.DateField(default=timezone.localdate)
    note = models.CharField(max_length=300, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-paid_on", "-created_at"]
        indexes = [
            models.Index(fields=["invoice"]),
            models.Index(fields=["paid_on"]),
        ]
        constraints = [
            models.CheckConstraint(condition=Q(amount__gt=0), name="payment_amount_positive"),
        ]

    def __str__(self):
        return f"{self.receipt_no} {self.amount} soʻm ({self.get_method_display()})"

    @property
    def receipt_no(self):
        return f"PAY-{self.pk:06d}" if self.pk else "PAY-——"


class Mark(models.Model):
    """One gradebook mark (2–5) a subject teacher gives a pupil on a lesson date (plan P2.4).

    Same scale and per-date data as the state eMaktab journal (decision D18), so
    marks can be exported later. The quarter is not stored: it is the ``Term``
    of the class's academic year whose dates contain ``date``.
    """

    KIND_LESSON = "lesson"
    KIND_TEST = "test"
    KIND_EXAM = "exam"
    KIND_CHOICES = [(KIND_LESSON, "Lesson"), (KIND_TEST, "Test"), (KIND_EXAM, "Exam")]

    student = models.ForeignKey(Student, on_delete=models.CASCADE, related_name="marks")
    class_subject = models.ForeignKey(ClassSubject, on_delete=models.CASCADE, related_name="marks")
    date = models.DateField()
    value = models.PositiveSmallIntegerField(
        validators=[MinValueValidator(2), MaxValueValidator(5)]
    )
    kind = models.CharField(max_length=10, choices=KIND_CHOICES, default=KIND_LESSON)
    comment = models.CharField(max_length=200, blank=True, default="")
    given_by = models.ForeignKey(
        Staff, on_delete=models.SET_NULL, null=True, blank=True, related_name="marks_given"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["date", "pk"]
        indexes = [
            models.Index(fields=["student", "date"]),
            models.Index(fields=["class_subject", "date"]),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["student", "class_subject", "date", "kind"],
                name="one_mark_per_pupil_subject_date_kind",
            ),
            models.CheckConstraint(
                condition=Q(value__gte=2) & Q(value__lte=5), name="mark_value_2_to_5"
            ),
        ]

    def __str__(self):
        return f"{self.student} · {self.class_subject} · {self.date}: {self.value}"


class TermGrade(models.Model):
    """A pupil's quarter or year grade (2–5) in one class subject (plan P2.5, decision D3).

    ``term`` is the quarter; a row without a term is the year grade. ``value``
    null means "not graded". The teacher confirms the grade; the average of
    the marks is only a suggestion (``school.suggested_grade``).
    """

    student = models.ForeignKey(Student, on_delete=models.CASCADE, related_name="term_grades")
    class_subject = models.ForeignKey(
        ClassSubject, on_delete=models.CASCADE, related_name="term_grades"
    )
    term = models.ForeignKey(
        Term, on_delete=models.CASCADE, null=True, blank=True, related_name="grades"
    )
    value = models.PositiveSmallIntegerField(
        null=True, blank=True, validators=[MinValueValidator(2), MaxValueValidator(5)]
    )
    given_by = models.ForeignKey(
        CustomUser, on_delete=models.SET_NULL, null=True, blank=True, related_name="+"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [models.Index(fields=["student", "class_subject"])]
        constraints = [
            models.UniqueConstraint(
                fields=["student", "class_subject", "term"],
                condition=Q(term__isnull=False),
                name="one_term_grade_per_pupil_subject_term",
            ),
            models.UniqueConstraint(
                fields=["student", "class_subject"],
                condition=Q(term__isnull=True),
                name="one_year_grade_per_pupil_subject",
            ),
            models.CheckConstraint(
                condition=Q(value__isnull=True) | (Q(value__gte=2) & Q(value__lte=5)),
                name="term_grade_value_2_to_5",
            ),
        ]

    def __str__(self):
        period = self.term or "year"
        return f"{self.student} · {self.class_subject} · {period}: {self.value or '—'}"


# A push bug must never stop a notification or message from being saved.
@receiver(post_save, sender=Notification)
def push_new_notification(sender, instance, created, **kwargs):
    if created:
        from .push import push_notifications

        try:
            push_notifications([instance])
        except Exception:
            logging.getLogger("main_app.push").exception(
                "Push for notification %s failed.", instance.pk
            )


@receiver(post_save, sender=ChatMessage)
def push_new_chat_message(sender, instance, created, **kwargs):
    if created:
        from .push import push_chat_message

        try:
            push_chat_message(instance)
        except Exception:
            logging.getLogger("main_app.push").exception(
                "Push for chat message %s failed.", instance.pk
            )


class PasswordResetLog(models.Model):
    """Audit log: one row for every password reset of a parent (plan PL.2, D13).

    Written by ``parents.update_parent`` (office: web page, admin API, login letter)
    and by the SMS code reset. Read-only: admins see it on the parent page, scoped
    by ``branching.filter_password_resets_for_user``.
    """

    METHOD_OFFICE = "office"
    METHOD_API = "api"
    METHOD_LETTER = "letter"
    METHOD_SMS = "sms"
    METHOD_CHOICES = [
        (METHOD_OFFICE, gettext_lazy("Office")),
        (METHOD_API, gettext_lazy("Office (API)")),
        (METHOD_LETTER, gettext_lazy("Login letter")),
        (METHOD_SMS, gettext_lazy("SMS code (the parent)")),
    ]

    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name="password_resets")
    method = models.CharField(max_length=10, choices=METHOD_CHOICES)
    # The admin who reset it; empty for the parent's own SMS reset.
    by = models.ForeignKey(
        CustomUser,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="password_resets_done",
    )
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ["-created_at", "-pk"]

    def __str__(self):
        return f"{self.user} · {self.method} · {self.created_at:%Y-%m-%d %H:%M}"


class SmsResetCode(models.Model):
    """A one-time SMS code for a parent's own password reset (plan PL.2, D13).

    Only a hash of the code is stored. A code lives 10 minutes, works once and
    allows a few wrong tries (``parents_sms``). ``phone`` is the normalised number
    the code was sent to, used for the per-phone rate limit.
    """

    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name="sms_reset_codes")
    phone = models.CharField(max_length=20, db_index=True)
    code_hash = models.CharField(max_length=128)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    expires_at = models.DateTimeField()
    attempts = models.PositiveSmallIntegerField(default=0)
    used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at", "-pk"]

    def __str__(self):
        return f"{self.user} · {self.created_at:%Y-%m-%d %H:%M}"
