from django.contrib.auth.hashers import make_password
from django.core.validators import MaxValueValidator, MinValueValidator
from django.contrib.auth.models import UserManager
from django.dispatch import receiver
from django.db.models.signals import post_save
from django.db import OperationalError, ProgrammingError, models
from django.db.models import Q
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
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
    start_year = models.DateField()
    end_year = models.DateField()

    def __str__(self):
        return "From " + str(self.start_year) + " to " + str(self.end_year)


class CustomUser(AbstractUser):
    # String keys so CharField comparisons are always consistent.
    # Integer keys (the original) caused `1 == '1'` → False in Python 3,
    # which broke login redirects and get_user_type_display().
    USER_TYPE = (("1", "HOD"), ("2", "Staff"), ("3", "Student"))
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


class Student(models.Model):
    STATUS_ACTIVE = "active"
    STATUS_INACTIVE = "inactive"
    STATUS_SUSPENDED = "suspended"
    STATUS_CHOICES = [
        (STATUS_ACTIVE, "Active"),
        (STATUS_INACTIVE, "Inactive"),
        (STATUS_SUSPENDED, "Suspended"),
    ]

    LEVEL_CHOICES = [(i, f"Level {i}") for i in range(1, 7)]

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
    staff = models.ForeignKey(Staff, on_delete=models.CASCADE)
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

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["recipient", "is_read"]),
        ]

    def __str__(self):
        return f"[{self.category}] → {self.recipient.email}: {self.message[:50]}"


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


class Branch(models.Model):
    name = models.CharField(max_length=100)
    address = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

    class Meta:
        verbose_name_plural = "Branches"


class Group(models.Model):
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
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=["branch", "is_archived"]),
            models.Index(fields=["teacher", "is_archived"]),
        ]

    def __str__(self):
        return self.name

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


class ChatThread(models.Model):
    """Persistent group conversation for a class group."""

    group = models.OneToOneField(Group, on_delete=models.CASCADE, related_name="chat_thread")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["group__name"]
        indexes = [
            models.Index(fields=["updated_at"]),
        ]

    def __str__(self):
        return f"Chat - {self.group.name}"


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
        return f"{self.sender.email} -> {self.thread.group.name}: {self.body[:50]}"


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
        return f"{self.user.email} read {self.thread.group.name}"


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
        (STATUS_DUE, "Due"),
        (STATUS_PARTIAL, "Partially paid"),
        (STATUS_PAID, "Paid"),
        (STATUS_CANCELLED, "Cancelled"),
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
