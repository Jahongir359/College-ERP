from datetime import date

from django import forms
from django.contrib.auth.password_validation import validate_password
from django.forms.widgets import DateInput, TextInput

from .models import *
from . import models
from . import branching


class GroupedNumberInput(forms.TextInput):
    """Whole-soʻm money input.

    Renders as a text field so admins can type ANY amount (no HTML5 step
    constraint — a number input with step="1000" only accepts 1, 1001, 2001…,
    which is why amounts appeared to "need to end in 1"). A small script groups
    the digits with commas as you type ("200,000"); the separators are stripped
    here on submit so the value parses cleanly.
    """

    def __init__(self, attrs=None):
        base = {"inputmode": "numeric", "data-money": "1", "autocomplete": "off"}
        if attrs:
            base.update(attrs)
        super().__init__(base)

    def value_from_datadict(self, data, files, name):
        value = super().value_from_datadict(data, files, name)
        if isinstance(value, str):
            for sep in (",", " ", " ", " ", "'"):
                value = value.replace(sep, "")
            value = value.strip()
        return value


class FormSettings(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super(FormSettings, self).__init__(*args, **kwargs)
        # Here make some changes such as:
        for field in self.visible_fields():
            field.field.widget.attrs["class"] = "form-control"


def _scope_branch_field(form, user, required=False):
    """Scope a form's ``branch`` field to the branches ``user`` may assign.

    Super admins keep the full branch list; branch admins see only their
    assigned branches and the field defaults to their branch when they manage
    exactly one. No-op when the form has no ``branch`` field.
    """
    if "branch" not in form.fields:
        return
    qs = Branch.objects.all().order_by("name")
    if user is not None:
        qs = branching.filter_branches_for_user(user, qs)
    field = form.fields["branch"]
    field.queryset = qs
    field.required = required
    field.empty_label = "— Select branch —"
    field.label = "Branch / Location"
    field.widget.attrs["class"] = "form-control"
    if user is not None and not field.initial and not branching.is_super_admin(user):
        first_two = list(qs[:2])
        if len(first_two) == 1:
            field.initial = first_two[0].pk


_MAX_PROFILE_PIC_BYTES = 5 * 1024 * 1024  # 5 MB

# Sanity bounds for date of birth: rejects obviously bad data without
# being strict about exact age (the centre accepts both kids and adults).
_DOB_MIN = date(1900, 1, 1)


def _validate_birthday(value):
    if value is None:
        return None
    today = date.today()
    if value > today:
        raise forms.ValidationError("Date of birth cannot be in the future.")
    if value < _DOB_MIN:
        raise forms.ValidationError("Please enter a valid date of birth.")
    return value


def _clean_new_password(password):
    """Run AUTH_PASSWORD_VALIDATORS on a non-blank new password.

    Blank means "keep the current password" on the edit/profile forms, so it
    passes through untouched; required-ness is enforced by the field itself.
    """
    if password:
        validate_password(password)
    return password


class CustomUserForm(FormSettings):
    gender = forms.ChoiceField(choices=[("M", "Male"), ("F", "Female")])
    first_name = forms.CharField(required=True)
    last_name = forms.CharField(required=True)
    date_of_birth = forms.DateField(
        required=True,
        label="Date of Birth",
        widget=forms.DateInput(
            attrs={
                "type": "date",
                "class": "form-control",
                "max": date.today().isoformat(),
            },
            format="%Y-%m-%d",
        ),
        input_formats=["%Y-%m-%d"],
        help_text="Format: YYYY-MM-DD. Used to generate the unique login ID.",
    )
    address = forms.CharField(
        widget=forms.TextInput(
            attrs={"placeholder": "e.g. Chilonzor 9, Tashkent", "class": "form-control"}
        )
    )
    password = forms.CharField(widget=forms.PasswordInput)
    profile_pic = forms.ImageField()

    def __init__(self, *args, **kwargs):
        super(CustomUserForm, self).__init__(*args, **kwargs)
        self.fields["profile_pic"].required = False
        # Pre-fill DOB when editing an existing user.
        instance = kwargs.get("instance")
        if instance is not None:
            user = getattr(instance, "admin", instance)
            if getattr(user, "date_of_birth", None):
                self.fields["date_of_birth"].initial = user.date_of_birth

    def clean_profile_pic(self):
        pic = self.cleaned_data.get("profile_pic")
        if pic and getattr(pic, "size", 0) > _MAX_PROFILE_PIC_BYTES:
            raise forms.ValidationError("Profile picture too large. Maximum size is 5 MB.")
        return pic

    def clean_date_of_birth(self):
        return _validate_birthday(self.cleaned_data.get("date_of_birth"))

    def clean_password(self):
        return _clean_new_password(self.cleaned_data.get("password"))

    class Meta:
        model = CustomUser
        fields = [
            "first_name",
            "last_name",
            "gender",
            "date_of_birth",
            "password",
            "profile_pic",
            "address",
        ]


class StudentForm(CustomUserForm):
    phone = forms.CharField(
        max_length=20,
        required=False,
        label="Phone Number",
        widget=forms.TextInput(attrs={"placeholder": "+998 90 123 45 67", "class": "form-control"}),
    )
    status = forms.ChoiceField(
        choices=Student.STATUS_CHOICES,
        initial=Student.STATUS_ACTIVE,
        label="Status",
    )
    level = forms.ChoiceField(
        choices=[("", "— No level assigned —")] + Student.LEVEL_CHOICES,
        required=False,
        label="English Level",
    )

    def __init__(self, *args, **kwargs):
        user = kwargs.pop("user", None)
        super(StudentForm, self).__init__(*args, **kwargs)
        self.fields["status"].widget.attrs["class"] = "form-control"
        self.fields["level"].widget.attrs["class"] = "form-control"
        # On edit, DOB is optional — existing accounts may not have one yet.
        self.fields["date_of_birth"].required = False
        instance = kwargs.get("instance")
        if instance:
            self.fields["phone"].initial = instance.phone
            self.fields["status"].initial = instance.status
            self.fields["level"].initial = instance.level if instance.level else ""
            if instance.branch_id:
                self.fields["branch"].initial = instance.branch_id
        _scope_branch_field(self, user)

    class Meta(CustomUserForm.Meta):
        model = Student
        fields = CustomUserForm.Meta.fields + ["course", "branch", "phone", "status", "level"]


class AddStudentForm(CustomUserForm):
    course = forms.ModelChoiceField(
        queryset=Course.objects.all(),
        empty_label="— Select a Program —",
        label="Program",
    )
    group = forms.ModelChoiceField(
        queryset=Group.objects.none(),
        empty_label="— Select a Class Group (optional) —",
        label="Assign to Class Group",
        required=False,
    )
    phone = forms.CharField(
        max_length=20,
        required=False,
        label="Phone Number",
        widget=forms.TextInput(attrs={"placeholder": "+998 90 123 45 67"}),
    )
    status = forms.ChoiceField(
        choices=Student.STATUS_CHOICES,
        initial=Student.STATUS_ACTIVE,
        label="Status",
    )
    level = forms.ChoiceField(
        choices=[("", "— No level assigned —")] + Student.LEVEL_CHOICES,
        required=False,
        label="English Level",
    )

    def __init__(self, *args, **kwargs):
        user = kwargs.pop("user", None)
        super().__init__(*args, **kwargs)
        self.fields["course"].widget.attrs["class"] = "form-control"
        self.fields["group"].widget.attrs["class"] = "form-control"
        self.fields["phone"].widget.attrs["class"] = "form-control"
        self.fields["status"].widget.attrs["class"] = "form-control"
        self.fields["level"].widget.attrs["class"] = "form-control"
        # DOB is required on add — the login_id is derived from it.
        self.fields["date_of_birth"].required = True
        # Group choices are scoped to the admin's accessible branches so a
        # branch admin can't enrol into another branch's group.
        group_qs = Group.objects.filter(is_archived=False)
        if user is not None:
            group_qs = branching.filter_groups_for_user(user, group_qs)
        if self.data.get("group"):
            self.fields["group"].queryset = group_qs
        _scope_branch_field(self, user)

    def clean(self):
        cleaned_data = super().clean()
        course = cleaned_data.get("course")
        group = cleaned_data.get("group")
        branch = cleaned_data.get("branch")
        if group and course and group.course_id != course.id:
            self.add_error(
                "group", "The selected class group does not belong to the chosen program."
            )
        # Keep student branch coherent with the chosen group's branch.
        if group and group.branch_id:
            if not branch:
                cleaned_data["branch"] = group.branch
            elif branch.id != group.branch_id:
                self.add_error("branch", "Selected group does not belong to the selected branch.")
        return cleaned_data

    class Meta(CustomUserForm.Meta):
        model = Student
        fields = CustomUserForm.Meta.fields + [
            "course",
            "branch",
            "group",
            "phone",
            "status",
            "level",
        ]


class AdminForm(CustomUserForm):
    email = forms.EmailField(required=False, label="Email")

    def __init__(self, *args, **kwargs):
        super(AdminForm, self).__init__(*args, **kwargs)
        self.fields["password"].required = False
        self.fields["profile_pic"].required = False
        self.fields["gender"].required = False
        self.fields["address"].required = False
        # Admins don't need a DOB — they log in by email, not a generated ID.
        self.fields["date_of_birth"].required = False
        if kwargs.get("instance"):
            self.fields["email"].initial = kwargs["instance"].admin.email

    class Meta(CustomUserForm.Meta):
        model = Admin
        fields = [
            "first_name",
            "last_name",
            "email",
            "gender",
            "date_of_birth",
            "password",
            "profile_pic",
            "address",
        ]


PREDEFINED_SUBJECTS = [
    "General English",
    "Pre-IELTS",
    "IELTS Academic",
    "IELTS General Training",
    "IELTS 7+ Band",
    "TOEFL iBT Preparation",
    "SAT English",
    "Business English",
    "Academic English",
    "Speaking & Communication",
    "Grammar & Vocabulary",
    "Reading & Writing",
    "Listening & Note-taking",
    "Conversation Club",
    "English for Kids",
    "English for Beginners",
    "Cambridge B2 (FCE)",
    "Cambridge C1 (CAE)",
    "Pronunciation Training",
    "IELTS Speaking",
    "IELTS Writing",
    "IELTS Reading",
    "IELTS Listening",
    "Mathematics",
    "Physics",
    "Chemistry",
    "Computer Science",
]


class StaffForm(CustomUserForm):
    phone = forms.CharField(
        max_length=20,
        required=False,
        label="Phone Number",
        widget=forms.TextInput(attrs={"placeholder": "+998 90 123 45 67", "class": "form-control"}),
    )
    specialization = forms.CharField(
        max_length=200,
        required=False,
        label="Specialization",
        widget=forms.TextInput(
            attrs={
                "class": "form-control",
                "placeholder": "e.g. IELTS, Mathematics, Business English",
            }
        ),
    )

    def __init__(self, *args, **kwargs):
        user = kwargs.pop("user", None)
        super(StaffForm, self).__init__(*args, **kwargs)
        instance = kwargs.get("instance")
        if instance and getattr(instance, "branch_id", None):
            self.fields["branch"].initial = instance.branch_id
        _scope_branch_field(self, user)

    class Meta(CustomUserForm.Meta):
        model = Staff
        fields = CustomUserForm.Meta.fields + ["course", "branch", "phone", "specialization"]


class CourseForm(forms.Form):
    name = forms.ChoiceField(
        choices=[("", "— Select a subject —")] + [(s, s) for s in PREDEFINED_SUBJECTS],
        label="Subject / Program",
        widget=forms.Select(attrs={"class": "form-control"}),
    )
    monthly_fee = forms.DecimalField(
        required=False,
        min_value=0,
        decimal_places=0,
        max_digits=12,
        label="Monthly fee (UZS soʻm)",
        help_text="Default tuition per month. Groups may override it.",
        widget=GroupedNumberInput(attrs={"class": "form-control", "placeholder": "e.g. 600,000"}),
    )

    def __init__(self, *args, instance=None, **kwargs):
        initial = kwargs.get("initial", {})
        if instance and instance.name and not initial.get("name"):
            initial["name"] = instance.name
        if instance and instance.monthly_fee is not None and "monthly_fee" not in initial:
            initial["monthly_fee"] = instance.monthly_fee
        kwargs["initial"] = initial
        super().__init__(*args, **kwargs)
        # If editing a course whose name isn't in the predefined list, add it
        if instance and instance.name:
            existing = [c[0] for c in self.fields["name"].choices]
            if instance.name not in existing:
                self.fields["name"].choices.append((instance.name, instance.name))


class SubjectForm(FormSettings):
    def __init__(self, *args, **kwargs):
        super(SubjectForm, self).__init__(*args, **kwargs)

    class Meta:
        model = Subject
        fields = ["name", "staff", "course"]


class SessionForm(FormSettings):
    def __init__(self, *args, **kwargs):
        super(SessionForm, self).__init__(*args, **kwargs)

    class Meta:
        model = Session
        fields = "__all__"
        widgets = {
            "start_year": DateInput(attrs={"type": "date"}),
            "end_year": DateInput(attrs={"type": "date"}),
        }


class LeaveReportStaffForm(FormSettings):
    def __init__(self, *args, **kwargs):
        super(LeaveReportStaffForm, self).__init__(*args, **kwargs)

    class Meta:
        model = LeaveReportStaff
        fields = ["date", "message"]
        widgets = {
            "date": DateInput(attrs={"type": "date"}),
        }


class FeedbackStaffForm(FormSettings):
    def __init__(self, *args, **kwargs):
        super(FeedbackStaffForm, self).__init__(*args, **kwargs)

    class Meta:
        model = FeedbackStaff
        fields = ["feedback"]


class LeaveReportStudentForm(FormSettings):
    def __init__(self, *args, **kwargs):
        super(LeaveReportStudentForm, self).__init__(*args, **kwargs)

    class Meta:
        model = LeaveReportStudent
        fields = ["date", "message"]
        widgets = {
            "date": DateInput(attrs={"type": "date"}),
        }


class FeedbackStudentForm(FormSettings):
    def __init__(self, *args, **kwargs):
        super(FeedbackStudentForm, self).__init__(*args, **kwargs)

    class Meta:
        model = FeedbackStudent
        fields = ["feedback"]


class StudentEditForm(CustomUserForm):
    def __init__(self, *args, **kwargs):
        user = kwargs.pop("user", None)
        super(StudentEditForm, self).__init__(*args, **kwargs)
        self.fields["date_of_birth"].required = False
        instance = kwargs.get("instance")
        if instance and getattr(instance, "branch_id", None):
            self.fields["branch"].initial = instance.branch_id
        _scope_branch_field(self, user)

    class Meta(CustomUserForm.Meta):
        model = Student
        fields = CustomUserForm.Meta.fields + ["branch"]


class StaffEditForm(CustomUserForm):
    def __init__(self, *args, **kwargs):
        user = kwargs.pop("user", None)
        super(StaffEditForm, self).__init__(*args, **kwargs)
        self.fields["date_of_birth"].required = False
        instance = kwargs.get("instance")
        if instance and getattr(instance, "branch_id", None):
            self.fields["branch"].initial = instance.branch_id
        _scope_branch_field(self, user)

    class Meta(CustomUserForm.Meta):
        model = Staff
        fields = CustomUserForm.Meta.fields + ["course", "branch", "phone", "specialization"]


def _dob_widget():
    return forms.DateInput(
        attrs={"class": "form-control", "type": "date", "max": date.today().isoformat()},
        format="%Y-%m-%d",
    )


class StudentProfileForm(forms.Form):
    """Lean form for student self-service profile editing (no email, no profile_pic)."""

    first_name = forms.CharField(
        required=True, label="First Name", widget=forms.TextInput(attrs={"class": "form-control"})
    )
    last_name = forms.CharField(
        required=True, label="Last Name", widget=forms.TextInput(attrs={"class": "form-control"})
    )
    gender = forms.ChoiceField(
        choices=[("", "—"), ("M", "Male"), ("F", "Female")],
        required=False,
        label="Gender",
        widget=forms.Select(attrs={"class": "form-control"}),
    )
    date_of_birth = forms.DateField(
        required=False, label="Date of Birth", widget=_dob_widget(), input_formats=["%Y-%m-%d"]
    )
    phone = forms.CharField(
        max_length=20,
        required=False,
        label="Phone Number",
        widget=forms.TextInput(attrs={"class": "form-control", "placeholder": "+998 90 123 45 67"}),
    )
    password = forms.CharField(
        required=False,
        label="New Password",
        widget=forms.PasswordInput(
            attrs={"class": "form-control", "placeholder": "Leave blank to keep current password"}
        ),
    )

    def __init__(self, instance=None, data=None, **kwargs):
        super().__init__(data=data, **kwargs)
        if instance:
            self.fields["first_name"].initial = instance.admin.first_name
            self.fields["last_name"].initial = instance.admin.last_name
            self.fields["gender"].initial = instance.admin.gender
            self.fields["date_of_birth"].initial = instance.admin.date_of_birth
            self.fields["phone"].initial = instance.phone

    def clean_password(self):
        return _clean_new_password(self.cleaned_data.get("password"))

    def clean_date_of_birth(self):
        return _validate_birthday(self.cleaned_data.get("date_of_birth"))


class StaffProfileForm(forms.Form):
    """Lean form for staff self-service profile editing (no email, no profile_pic)."""

    first_name = forms.CharField(
        required=True, label="First Name", widget=forms.TextInput(attrs={"class": "form-control"})
    )
    last_name = forms.CharField(
        required=True, label="Last Name", widget=forms.TextInput(attrs={"class": "form-control"})
    )
    gender = forms.ChoiceField(
        choices=[("", "—"), ("M", "Male"), ("F", "Female")],
        required=False,
        label="Gender",
        widget=forms.Select(attrs={"class": "form-control"}),
    )
    date_of_birth = forms.DateField(
        required=False, label="Date of Birth", widget=_dob_widget(), input_formats=["%Y-%m-%d"]
    )
    phone = forms.CharField(
        max_length=20,
        required=False,
        label="Phone Number",
        widget=forms.TextInput(attrs={"class": "form-control", "placeholder": "+998 90 123 45 67"}),
    )
    specialization = forms.CharField(
        max_length=200,
        required=False,
        label="Specialization",
        widget=forms.TextInput(
            attrs={
                "class": "form-control",
                "placeholder": "e.g. IELTS, Mathematics, Business English",
            }
        ),
    )
    password = forms.CharField(
        required=False,
        label="New Password",
        widget=forms.PasswordInput(
            attrs={"class": "form-control", "placeholder": "Leave blank to keep current password"}
        ),
    )

    def __init__(self, instance=None, data=None, **kwargs):
        super().__init__(data=data, **kwargs)
        if instance:
            self.fields["first_name"].initial = instance.admin.first_name
            self.fields["last_name"].initial = instance.admin.last_name
            self.fields["gender"].initial = instance.admin.gender
            self.fields["date_of_birth"].initial = instance.admin.date_of_birth
            self.fields["phone"].initial = instance.phone
            self.fields["specialization"].initial = instance.specialization

    def clean_password(self):
        return _clean_new_password(self.cleaned_data.get("password"))

    def clean_date_of_birth(self):
        return _validate_birthday(self.cleaned_data.get("date_of_birth"))


class EditResultForm(FormSettings):
    def __init__(self, *args, **kwargs):
        super(EditResultForm, self).__init__(*args, **kwargs)

    class Meta:
        model = StudentResult
        fields = ["group", "student", "test", "exam"]


# issue book


class BranchForm(FormSettings):
    def __init__(self, *args, **kwargs):
        # Only super admins may switch a branch between Learning Center and School.
        can_set_brand = kwargs.pop("can_set_brand", False)
        super().__init__(*args, **kwargs)
        self.fields["brand"].label = "Brand"
        if not can_set_brand:
            self.fields["brand"].disabled = True

    class Meta:
        model = Branch
        fields = ["name", "address", "brand"]
        widgets = {
            "address": forms.TextInput(
                attrs={"placeholder": "e.g. Chilonzor 9, Tashkent", "class": "form-control"}
            ),
        }


class GroupForm(FormSettings):
    def __init__(self, *args, **kwargs):
        user = kwargs.pop("user", None)
        super().__init__(*args, **kwargs)
        # Branch admins may only create/edit groups in their own branches.
        # Teacher/course dropdowns keep their existing AJAX-driven behaviour.
        _scope_branch_field(self, user, required=False)

    class Meta:
        model = Group
        fields = [
            "name",
            "course",
            "teacher",
            "branch",
            "room",
            "schedule",
            "capacity",
            "monthly_fee",
            "start_date",
        ]
        labels = {
            "course": "Program",
            "teacher": "Teacher",
            "branch": "Branch / Location",
            "room": "Room / Classroom",
            "schedule": "Schedule",
            "capacity": "Capacity (max students)",
            "monthly_fee": "Monthly fee (UZS soʻm)",
            "start_date": "Starting Date",
        }
        widgets = {
            "start_date": forms.DateInput(attrs={"type": "date", "class": "form-control"}),
            "monthly_fee": GroupedNumberInput(
                attrs={"class": "form-control", "placeholder": "Blank = course fee"}
            ),
        }


class EnrollmentForm(FormSettings):
    STATUS_CHOICES = [(True, "Active"), (False, "Inactive")]
    is_active = forms.TypedChoiceField(
        choices=STATUS_CHOICES,
        coerce=lambda x: x == "True" or x is True,
        label="Enrollment Status",
        initial=True,
    )

    def __init__(self, *args, **kwargs):
        user = kwargs.pop("user", None)
        super().__init__(*args, **kwargs)
        if user is not None:
            self.fields["group"].queryset = branching.filter_groups_for_user(
                user, Group.objects.filter(is_archived=False)
            )
            self.fields["student"].queryset = branching.filter_students_for_user(
                user, Student.objects.all()
            )

    def clean(self):
        cleaned = super().clean()
        group = cleaned.get("group")
        student = cleaned.get("student")
        # Don't allow enrolling a student into a group from a different branch.
        if group and student and group.branch_id and student.branch_id:
            if group.branch_id != student.branch_id:
                self.add_error(
                    "group",
                    "This student belongs to a different branch than the selected group.",
                )
        return cleaned

    class Meta:
        model = Enrollment
        fields = ["group", "student", "is_active"]


class AssignmentForm(FormSettings):
    class Meta:
        model = Assignment
        fields = ["title", "description", "group", "due_date"]
        widgets = {
            "due_date": DateInput(attrs={"type": "date"}),
        }


class SubmissionForm(FormSettings):
    class Meta:
        model = Submission
        fields = ["file", "note"]


class BookForm(forms.ModelForm):
    class Meta:
        model = models.Book
        fields = ["name", "author", "isbn", "category"]
        labels = {"name": "Book Title", "isbn": "ISBN"}
        widgets = {
            "name": TextInput(attrs={"class": "form-control", "placeholder": "Book title"}),
            "author": TextInput(attrs={"class": "form-control", "placeholder": "Author name"}),
            "isbn": TextInput(attrs={"class": "form-control", "placeholder": "ISBN number"}),
            "category": TextInput(attrs={"class": "form-control", "placeholder": "e.g. Science"}),
        }


class IssueBookForm(forms.Form):
    """Form for creating a new Loan (book lending).

    Field names match the new Loan model (book, student) rather than the
    legacy isbn2/name2 — the view reads cleaned_data, no more bypassing
    the form via request.POST.
    """

    book = forms.ModelChoiceField(
        queryset=models.Book.objects.all(),
        empty_label="Select book…",
        label="Book",
        widget=forms.Select(attrs={"class": "form-control"}),
    )
    student = forms.ModelChoiceField(
        queryset=models.Student.objects.all(),
        empty_label="Select student…",
        label="Student",
        widget=forms.Select(attrs={"class": "form-control"}),
    )

    def clean(self):
        cleaned = super().clean()
        book = cleaned.get("book")
        student = cleaned.get("student")
        if book and student:
            existing = models.Loan.objects.filter(
                book=book,
                student=student,
                returned_on__isnull=True,
            ).exists()
            if existing:
                raise forms.ValidationError(
                    "This student already has an active loan for this book."
                )
        return cleaned


class VocabularyDayForm(forms.ModelForm):
    class Meta:
        model = VocabularyDay
        fields = ["group", "day_number", "title", "level", "release_scope", "notes"]
        widgets = {
            "day_number": forms.NumberInput(
                attrs={
                    "class": "form-control",
                    "min": "1",
                    "max": "365",
                    "placeholder": "1",
                }
            ),
            "title": forms.TextInput(
                attrs={
                    "class": "form-control",
                    "placeholder": "e.g. Describing People",
                }
            ),
            "level": forms.Select(attrs={"class": "form-control"}),
            "release_scope": forms.RadioSelect(attrs={"class": "scope-radio"}),
            "notes": forms.Textarea(
                attrs={
                    "class": "form-control",
                    "rows": 2,
                    "placeholder": "Private teacher notes (not shown to students)",
                }
            ),
            "group": forms.Select(attrs={"class": "form-control"}),
        }

    LEVEL_CHOICES = [("", "— Inherit from group —")] + [(i, f"Level {i}") for i in range(1, 7)]

    def __init__(self, *args, **kwargs):
        staff = kwargs.pop("staff", None)
        super().__init__(*args, **kwargs)
        self.fields["title"].required = False
        self.fields["level"].required = False
        self.fields["level"].widget.choices = self.LEVEL_CHOICES
        self.fields["notes"].required = False
        if staff:
            self.fields["group"].queryset = Group.objects.filter(teacher=staff, is_archived=False)
        else:
            self.fields["group"].queryset = Group.objects.filter(is_archived=False)


class DashboardStoryForm(FormSettings):
    class Meta:
        model = DashboardStory
        fields = [
            "title",
            "body",
            "image",
            "story_type",
            "emoji",
            "bg_color",
            "target_groups",
            "is_active",
            "expires_at",
        ]
        widgets = {
            "title": forms.TextInput(attrs={"class": "form-control", "placeholder": "Story title"}),
            "body": forms.Textarea(
                attrs={"class": "form-control", "rows": 3, "placeholder": "Short description…"}
            ),
            "story_type": forms.Select(attrs={"class": "form-control"}),
            "emoji": forms.TextInput(
                attrs={"class": "form-control", "placeholder": "📢", "maxlength": 8}
            ),
            "bg_color": forms.TextInput(attrs={"class": "form-control"}),
            "target_groups": forms.CheckboxSelectMultiple(),
            "is_active": forms.CheckboxInput(),
            "expires_at": forms.DateTimeInput(
                attrs={"class": "form-control", "type": "datetime-local"}
            ),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Prevent FormSettings from stamping form-control onto checkbox widgets
        for name in ("target_groups", "is_active"):
            if name in self.fields:
                self.fields[name].widget.attrs.pop("class", None)
        # Initialise datetime-local input from existing value (converted to local time)
        if self.instance and self.instance.pk and self.instance.expires_at:
            from django.utils import timezone as _tz

            local_dt = _tz.localtime(self.instance.expires_at)
            self.initial["expires_at"] = local_dt.strftime("%Y-%m-%dT%H:%M")


class LeaderboardSettingsForm(FormSettings):
    class Meta:
        model = LeaderboardSettings
        fields = [
            "attendance_weight",
            "homework_weight",
            "quizzes_weight",
            "results_weight",
            "enable_attendance",
            "enable_homework",
            "enable_quizzes",
            "enable_results",
        ]
        widgets = {
            "attendance_weight": forms.NumberInput(
                attrs={"class": "form-control", "min": 0, "max": 100}
            ),
            "homework_weight": forms.NumberInput(
                attrs={"class": "form-control", "min": 0, "max": 100}
            ),
            "quizzes_weight": forms.NumberInput(
                attrs={"class": "form-control", "min": 0, "max": 100}
            ),
            "results_weight": forms.NumberInput(
                attrs={"class": "form-control", "min": 0, "max": 100}
            ),
            "enable_attendance": forms.CheckboxInput(),
            "enable_homework": forms.CheckboxInput(),
            "enable_quizzes": forms.CheckboxInput(),
            "enable_results": forms.CheckboxInput(),
        }


class LeaderboardSeasonForm(FormSettings):
    class Meta:
        model = LeaderboardSeason
        fields = ["name", "period", "start_date", "end_date", "is_active"]
        widgets = {
            "name": forms.TextInput(
                attrs={"class": "form-control", "placeholder": "e.g. October 2026"}
            ),
            "period": forms.Select(attrs={"class": "form-control"}),
            "start_date": forms.DateInput(attrs={"class": "form-control", "type": "date"}),
            "end_date": forms.DateInput(attrs={"class": "form-control", "type": "date"}),
            "is_active": forms.CheckboxInput(),
        }


# ── Payments ──────────────────────────────────────────────────────────────────


class GenerateInvoicesForm(forms.Form):
    """Monthly tuition invoice generation for all active enrollments."""

    month = forms.CharField(
        label="Billing month",
        widget=forms.TextInput(attrs={"type": "month", "class": "form-control"}),
        help_text="Invoices are created for every active enrollment in this month.",
    )
    branch = forms.ModelChoiceField(
        queryset=Branch.objects.none(),
        required=False,
        label="Branch / Location",
        empty_label="All my branches",
        widget=forms.Select(attrs={"class": "form-control"}),
    )
    due_date = forms.DateField(
        label="Payment due date",
        widget=forms.DateInput(attrs={"type": "date", "class": "form-control"}),
    )

    def __init__(self, *args, user=None, **kwargs):
        super().__init__(*args, **kwargs)
        qs = Branch.objects.all().order_by("name")
        if user is not None:
            qs = branching.filter_branches_for_user(user, qs)
        self.fields["branch"].queryset = qs

    def clean_month(self):
        raw = self.cleaned_data["month"]
        try:
            year, month = raw.split("-")
            return date(int(year), int(month), 1)
        except (ValueError, AttributeError):
            raise forms.ValidationError("Pick a month in the YYYY-MM format.")


class RecordPaymentForm(FormSettings):
    class Meta:
        model = Payment
        fields = ["amount", "method", "paid_on", "note"]
        labels = {
            "amount": "Amount (UZS soʻm)",
            "method": "Payment method",
            "paid_on": "Payment date",
            "note": "Note (optional)",
        }
        widgets = {
            "amount": GroupedNumberInput(
                attrs={"class": "form-control", "placeholder": "e.g. 200,000"}
            ),
            "paid_on": forms.DateInput(attrs={"type": "date", "class": "form-control"}),
            "note": forms.TextInput(
                attrs={"class": "form-control", "placeholder": "e.g. receipt #, payer name"}
            ),
        }

    def __init__(self, *args, invoice=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.invoice = invoice
        if invoice is not None and not self.initial.get("amount") and not self.data:
            self.initial["amount"] = invoice.balance

    def clean_amount(self):
        amount = self.cleaned_data["amount"]
        if amount <= 0:
            raise forms.ValidationError("Amount must be greater than zero.")
        if self.invoice is not None and amount > self.invoice.balance:
            raise forms.ValidationError(
                f"Amount exceeds the remaining balance ({self.invoice.balance:,.0f} soʻm)."
            )
        return amount


class ManualInvoiceForm(FormSettings):
    """One-off invoice for a single student (extra charge, materials, etc.)."""

    month = forms.CharField(
        label="Billing month",
        widget=forms.TextInput(attrs={"type": "month", "class": "form-control"}),
    )

    class Meta:
        model = Invoice
        fields = ["student", "amount", "discount", "due_date", "note"]
        labels = {
            "amount": "Amount (UZS soʻm)",
            "discount": "Discount (UZS soʻm)",
            "due_date": "Payment due date",
            "note": "Note (optional)",
        }
        widgets = {
            "amount": GroupedNumberInput(
                attrs={"class": "form-control", "placeholder": "e.g. 600,000"}
            ),
            "discount": GroupedNumberInput(attrs={"class": "form-control", "placeholder": "0"}),
            "due_date": forms.DateInput(attrs={"type": "date", "class": "form-control"}),
            "note": forms.TextInput(
                attrs={"class": "form-control", "placeholder": "e.g. course books, exam fee"}
            ),
        }

    def __init__(self, *args, user=None, **kwargs):
        super().__init__(*args, **kwargs)
        qs = Student.objects.select_related("admin").order_by("admin__last_name")
        if user is not None:
            qs = branching.filter_students_for_user(user, qs)
        self.fields["student"].queryset = qs

    def clean_month(self):
        raw = self.cleaned_data["month"]
        try:
            year, month = raw.split("-")
            return date(int(year), int(month), 1)
        except (ValueError, AttributeError):
            raise forms.ValidationError("Pick a month in the YYYY-MM format.")

    def clean(self):
        cleaned = super().clean()
        amount = cleaned.get("amount")
        discount = cleaned.get("discount") or 0
        if amount is not None and discount > amount:
            self.add_error("discount", "Discount cannot exceed the invoice amount.")
        return cleaned
