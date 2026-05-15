from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import UserManager
from django.dispatch import receiver
from django.db.models.signals import post_save
from django.db import models
from django.db.models import Q
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
from datetime import datetime,timedelta


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
    USER_TYPE = (('1', "HOD"), ('2', "Staff"), ('3', "Student"))
    GENDER = [("M", "Male"), ("F", "Female")]

    username = None  # Removed username, using email instead
    email = models.EmailField(unique=True)
    user_type = models.CharField(default='1', choices=USER_TYPE, max_length=1)
    gender = models.CharField(max_length=1, choices=GENDER, blank=True, default='')
    profile_pic = models.ImageField(blank=True, null=True)
    address = models.TextField(blank=True, default='')
    fcm_token = models.TextField(default="")  # For firebase notifications
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []
    objects = CustomUserManager()

    def __str__(self):
        return  self.first_name + " " + self.last_name


class Admin(models.Model):
    admin = models.OneToOneField(CustomUser, on_delete=models.CASCADE)



class Course(models.Model):
    name = models.CharField(max_length=120)
    is_active = models.BooleanField(default=True)
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
        return str(self.name) + " ["+str(self.isbn)+']'


class Student(models.Model):
    STATUS_ACTIVE = 'active'
    STATUS_INACTIVE = 'inactive'
    STATUS_SUSPENDED = 'suspended'
    STATUS_CHOICES = [
        (STATUS_ACTIVE, 'Active'),
        (STATUS_INACTIVE, 'Inactive'),
        (STATUS_SUSPENDED, 'Suspended'),
    ]

    admin = models.OneToOneField(CustomUser, on_delete=models.CASCADE)
    course = models.ForeignKey(Course, on_delete=models.SET_NULL, null=True, blank=False)
    phone = models.CharField(max_length=20, blank=True, default='')
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default=STATUS_ACTIVE)

    def __str__(self):
        return self.admin.last_name + ", " + self.admin.first_name

class Staff(models.Model):
    course = models.ForeignKey(Course, on_delete=models.SET_NULL, null=True, blank=False)
    admin = models.OneToOneField(CustomUser, on_delete=models.CASCADE)
    phone = models.CharField(max_length=20, blank=True, default='')
    specialization = models.CharField(max_length=200, blank=True, default='',
                                      help_text="e.g. IELTS, Mathematics, Business English")
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return self.admin.first_name + " " + self.admin.last_name


class Subject(models.Model):
    name = models.CharField(max_length=120)
    staff = models.ForeignKey(Staff, on_delete=models.CASCADE)
    course = models.ForeignKey(Course, on_delete=models.CASCADE)
    updated_at = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=['course']),
            models.Index(fields=['staff']),
        ]

    def __str__(self):
        return self.name


class Attendance(models.Model):
    group = models.ForeignKey('Group', on_delete=models.CASCADE, null=True, blank=True)
    date = models.DateField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('group', 'date')

    def __str__(self):
        return f"{self.group.name} · {self.date}"


class AttendanceReport(models.Model):
    ABSENT = 0
    PRESENT = 1
    LATE = 2
    STATUS_CHOICES = ((ABSENT, 'Absent'), (PRESENT, 'Present'), (LATE, 'Late'))

    student = models.ForeignKey(Student, on_delete=models.DO_NOTHING)
    attendance = models.ForeignKey(Attendance, on_delete=models.CASCADE)
    status = models.SmallIntegerField(default=ABSENT, choices=STATUS_CHOICES)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=['student']),
            models.Index(fields=['attendance']),
        ]


class LeaveReportStudent(models.Model):
    PENDING = 0
    APPROVED = 1
    REJECTED = -1
    LEAVE_STATUS = ((PENDING, 'Pending'), (APPROVED, 'Approved'), (REJECTED, 'Rejected'))

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
    LEAVE_STATUS = ((PENDING, 'Pending'), (APPROVED, 'Approved'), (REJECTED, 'Rejected'))

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
    ATTENDANCE = 'attendance'
    RESULT = 'result'
    ANNOUNCEMENT = 'announcement'
    HOMEWORK = 'homework'
    GENERAL = 'general'
    CATEGORY_CHOICES = [
        (ATTENDANCE, 'Attendance'),
        (RESULT, 'Result'),
        (ANNOUNCEMENT, 'Announcement'),
        (HOMEWORK, 'Homework'),
        (GENERAL, 'General'),
    ]

    recipient = models.ForeignKey(CustomUser, on_delete=models.CASCADE,
                                  related_name='notifications')
    category = models.CharField(max_length=20, choices=CATEGORY_CHOICES, default=GENERAL)
    message = models.TextField()
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['recipient', 'is_read']),
        ]

    def __str__(self):
        return f"[{self.category}] → {self.recipient.email}: {self.message[:50]}"


class StudentResult(models.Model):
    student = models.ForeignKey(Student, on_delete=models.CASCADE)
    group = models.ForeignKey('Group', on_delete=models.CASCADE, null=True, blank=True)
    test = models.FloatField(default=0)
    exam = models.FloatField(default=0)
    comment = models.TextField(blank=True, default='')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('student', 'group')


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
    if user_type == '1':
        Admin.objects.get_or_create(admin=instance)
    elif user_type == '2':
        Staff.objects.get_or_create(admin=instance)
    elif user_type == '3':
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
    room = models.CharField(max_length=50, blank=True, default='',
                            help_text="Classroom or room number, e.g. Room 3A")
    schedule = models.CharField(max_length=200, blank=True, default='',
                                help_text="e.g. Mon/Wed 10:00–12:00")
    capacity = models.PositiveIntegerField(default=20)
    is_archived = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name


class Enrollment(models.Model):
    student = models.ForeignKey(Student, on_delete=models.CASCADE)
    group = models.ForeignKey(Group, on_delete=models.CASCADE)
    enrolled_on = models.DateField(auto_now_add=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        unique_together = ('student', 'group')
        indexes = [
            models.Index(fields=['student']),
            models.Index(fields=['group']),
        ]

    def __str__(self):
        return f"{self.student} → {self.group}"


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
    file = models.FileField(upload_to='submissions/', null=True, blank=True)
    note = models.TextField(blank=True, default="")
    submitted_at = models.DateTimeField(auto_now_add=True)
    grade = models.FloatField(null=True, blank=True)

    class Meta:
        unique_together = ('assignment', 'student')

    def __str__(self):
        return f"{self.student} → {self.assignment}"


class ResultFile(models.Model):
    group = models.ForeignKey(Group, on_delete=models.CASCADE)
    student = models.ForeignKey(Student, on_delete=models.SET_NULL, null=True, blank=True)
    file = models.FileField(upload_to='results/')
    title = models.CharField(max_length=200)
    description = models.TextField(blank=True, default="")
    uploaded_by = models.ForeignKey(Staff, on_delete=models.CASCADE)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-uploaded_at']

    def __str__(self):
        return self.title

    @property
    def filename(self):
        import os
        return os.path.basename(self.file.name) if self.file else ''


class PasswordResetCode(models.Model):
    """One-time 6-digit code for the custom password-recovery flow."""
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE,
                             related_name='password_reset_codes')
    code_hash = models.CharField(max_length=64)   # SHA-256 hex of the raw digit code
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used = models.BooleanField(default=False)
    attempts = models.PositiveSmallIntegerField(default=0)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'used', 'expires_at']),
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
    student = models.ForeignKey(Student, on_delete=models.PROTECT,
                                related_name='loans')
    book = models.ForeignKey(Book, on_delete=models.PROTECT,
                             related_name='loans')
    issued_on = models.DateField(default=timezone.localdate)
    due_on = models.DateField(default=_default_loan_due_date)
    returned_on = models.DateField(null=True, blank=True)
    fine_paid = models.BooleanField(default=False)

    class Meta:
        ordering = ['-issued_on']
        indexes = [
            models.Index(fields=['student']),
            models.Index(fields=['returned_on']),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=['student', 'book'],
                condition=Q(returned_on__isnull=True),
                name='one_active_loan_per_student_book',
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
