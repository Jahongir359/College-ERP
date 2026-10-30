"""Admin forms for Iceberg School data: parents and their children (P1.7), and
classes, their students and subjects, and quarters (P3.1), and bell times (P3.2).

The admin API validates through the parent forms, and the admin pages render
all of them. Labels and messages use gettext (translated in P3.0's catalogs).
"""

from django import forms
from django.contrib.auth.password_validation import validate_password
from django.utils.translation import gettext_lazy as _

from . import branching
from .models import (
    BellPeriod,
    Branch,
    ClassSubject,
    Course,
    Enrollment,
    Group,
    Parent,
    ParentChild,
    Session,
    Staff,
    Student,
    Subject,
    Term,
    class_enrollment_conflict,
)
from .parents import parent_with_phone


class _AdminForm(forms.Form):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.visible_fields():
            if not isinstance(field.field.widget, forms.CheckboxInput):
                field.field.widget.attrs["class"] = "form-control"


class ParentForm(_AdminForm):
    """Create a parent (``instance=None``) or edit one. On edit a blank password keeps it."""

    first_name = forms.CharField(label=_("First name"), max_length=150)
    last_name = forms.CharField(label=_("Last name"), max_length=150, required=False)
    phone = forms.CharField(
        label=_("Phone number"),
        max_length=20,
        widget=forms.TextInput(attrs={"placeholder": "+998 90 123 45 67"}),
    )
    password = forms.CharField(
        label=_("Password"),
        widget=forms.PasswordInput(render_value=False),
        required=False,
        strip=False,
    )

    def __init__(self, *args, user=None, instance=None, **kwargs):
        self.user = user
        self.instance = instance
        if instance is not None and "initial" not in kwargs:
            kwargs["initial"] = {
                "first_name": instance.admin.first_name,
                "last_name": instance.admin.last_name,
                "phone": instance.phone,
            }
        super().__init__(*args, **kwargs)
        if instance is None:
            self.fields["password"].required = True
        else:
            self.fields["password"].help_text = _("Leave blank to keep the current password.")

    def clean_phone(self):
        phone = self.cleaned_data["phone"].strip()
        existing = parent_with_phone(phone, exclude_pk=getattr(self.instance, "pk", None))
        if existing is not None:
            visible = branching.filter_parents_for_user(self.user, Parent.objects.all())
            if visible.filter(pk=existing.pk).exists():
                raise forms.ValidationError(
                    _(
                        "Parent %(login)s already uses this phone number. Link the child to "
                        "that parent instead."
                    ),
                    params={"login": existing.admin.login_id},
                    code="duplicate_phone",
                )
            raise forms.ValidationError(
                _(
                    "A parent with this phone number already has a login. Ask the parent for "
                    "their login ID and link the child to it."
                ),
                code="duplicate_phone",
            )
        return phone

    def clean_password(self):
        password = self.cleaned_data.get("password", "")
        if password:
            validate_password(password)
        return password


class ParentChildForm(_AdminForm):
    """Link a child to a parent. Only children in the admin's branches can be picked."""

    student = forms.ModelChoiceField(label=_("Child"), queryset=Student.objects.none())
    relation = forms.ChoiceField(
        label=_("Relation"),
        choices=[
            (ParentChild.RELATION_MOTHER, _("Mother")),
            (ParentChild.RELATION_FATHER, _("Father")),
            (ParentChild.RELATION_GUARDIAN, _("Guardian")),
        ],
        initial=ParentChild.RELATION_GUARDIAN,
    )
    is_primary = forms.BooleanField(
        label=_("Main contact for this child"),
        required=False,
    )

    def __init__(self, *args, user=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["student"].queryset = branching.filter_students_for_user(
            user, Student.objects.select_related("admin").order_by("admin__first_name")
        )


class ParentLinkEditForm(ParentChildForm):
    """Change the relation and main contact of a child already linked (no child picker)."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        del self.fields["student"]


class ParentLinkByLoginForm(ParentChildForm):
    """Link a child to a parent of another branch: login ID and phone must both match (D4)."""

    login_id = forms.CharField(
        label=_("Login ID"), max_length=30, widget=forms.TextInput(attrs={"placeholder": "PR500"})
    )
    phone = forms.CharField(
        label=_("Phone number"),
        max_length=20,
        widget=forms.TextInput(attrs={"placeholder": "+998 90 123 45 67"}),
    )

    field_order = ["login_id", "phone", "student", "relation", "is_primary"]


# ── Classes (P3.1) ───────────────────────────────────────────────────────────


def _staff_choices(user):
    return branching.filter_staff_for_user(
        user, Staff.objects.select_related("admin").order_by("admin__first_name")
    )


class _TeacherChoiceField(forms.ModelChoiceField):
    def label_from_instance(self, obj):
        return obj.admin.get_full_name() or obj.admin.email


class ClassForm(forms.ModelForm):
    """Create or edit a school class (a ``Group`` with kind "class"). The name is grade-letter."""

    teacher = _TeacherChoiceField(
        label=_("Homeroom teacher"), queryset=Staff.objects.none(), required=False
    )

    class Meta:
        model = Group
        fields = [
            "branch",
            "session",
            "grade_level",
            "letter",
            "teacher",
            "course",
            "room",
            "capacity",
            "monthly_fee",
        ]
        labels = {
            "branch": _("Branch"),
            "session": _("Academic year"),
            "grade_level": _("Grade"),
            "letter": _("Letter"),
            "course": _("Subject list (course)"),
            "room": _("Classroom"),
            "capacity": _("Places"),
            "monthly_fee": _("Monthly fee (soʻm)"),
        }
        help_texts = {
            "letter": _("For 7-B type B."),
            "course": _("The course whose subjects this class studies."),
            "monthly_fee": _("Leave blank to use the course fee."),
        }

    def __init__(self, *args, user=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.user = user
        self.fields["branch"].queryset = branching.filter_branches_for_user(
            user, Branch.objects.filter(brand=Branch.BRAND_SCHOOL).order_by("name")
        )
        self.fields["branch"].required = True
        self.fields["branch"].empty_label = None
        self.fields["session"].queryset = Session.objects.order_by("-start_year")
        self.fields["session"].required = True
        self.fields["session"].empty_label = None
        self.fields["grade_level"].required = True
        self.fields["grade_level"].widget = forms.Select(
            choices=[(n, str(n)) for n in range(1, 12)]
        )
        self.fields["letter"].required = True
        self.fields["teacher"].queryset = _staff_choices(user)
        self.fields["course"].queryset = Course.objects.filter(is_active=True).order_by("name")
        if self.instance.pk is None:
            from .school import school_course

            current = Session.current()
            if current is not None:
                self.initial.setdefault("session", current.pk)
            self.initial.setdefault("course", school_course().pk)
        for field in self.visible_fields():
            field.field.widget.attrs["class"] = "form-control"

    def clean_letter(self):
        return self.cleaned_data["letter"].strip().upper()

    def clean(self):
        cleaned = super().clean()
        branch, session = cleaned.get("branch"), cleaned.get("session")
        grade, letter = cleaned.get("grade_level"), cleaned.get("letter")
        if branch and session and grade and letter:
            twin = (
                Group.objects.filter(  # scoping-ok: uniqueness check inside a chosen branch
                    kind=Group.KIND_CLASS, branch=branch, session=session, grade_level=grade
                )
                .filter(letter__iexact=letter)
                .exclude(pk=self.instance.pk)
            )
            if twin.exists():
                raise forms.ValidationError(
                    _("Class %(name)s already exists in this branch for this year."),
                    params={"name": f"{grade}-{letter}"},
                    code="duplicate_class",
                )
        return cleaned

    def _post_clean(self):
        # Fill the fields Group.clean() checks before the model validates.
        self.instance.kind = Group.KIND_CLASS
        grade, letter = self.cleaned_data.get("grade_level"), self.cleaned_data.get("letter")
        if grade and letter:
            self.instance.name = f"{grade}-{letter}"
        super()._post_clean()


class ClassStudentForm(_AdminForm):
    """Add a student to a class: students of the class's branch without a class this year."""

    student = forms.ModelChoiceField(label=_("Student"), queryset=Student.objects.none())

    def __init__(self, *args, user=None, group=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.group = group
        students = branching.filter_students_for_user(user, Student.objects.all())
        in_a_class = Enrollment.objects.filter(
            is_active=True, group__kind=Group.KIND_CLASS, group__session_id=group.session_id
        ).values("student_id")
        self.fields["student"].queryset = (
            students.filter(branch_id=group.branch_id)  # scoping-ok: narrows a scoped list
            .exclude(pk__in=in_a_class)
            .select_related("admin")
            .order_by("admin__first_name", "admin__last_name")
        )
        self.fields["student"].label_from_instance = lambda s: (
            f"{s.admin.get_full_name()} ({s.admin.login_id or s.admin.email})"
        )

    def clean_student(self):
        student = self.cleaned_data["student"]
        other = class_enrollment_conflict(student.pk, self.group)
        if other is not None:
            raise forms.ValidationError(
                _("This student is already in class %(name)s this academic year."),
                params={"name": other.name},
            )
        return student


class ClassSubjectForm(forms.ModelForm):
    """Add a subject to a class, or change its teacher and weekly hours."""

    teacher = _TeacherChoiceField(label=_("Teacher"), queryset=Staff.objects.none(), required=False)

    class Meta:
        model = ClassSubject
        fields = ["subject", "teacher", "weekly_hours"]
        labels = {"subject": _("Subject"), "weekly_hours": _("Hours a week")}

    def __init__(self, *args, user=None, group=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.instance.group = group
        taken = group.class_subjects.exclude(pk=self.instance.pk).values("subject_id")
        self.fields["subject"].queryset = (
            Subject.objects.filter(course_id=group.course_id).exclude(pk__in=taken).order_by("name")
        )
        if self.instance.pk:
            self.fields["subject"].disabled = True
        self.fields["teacher"].queryset = _staff_choices(user)
        for field in self.visible_fields():
            field.field.widget.attrs["class"] = "form-control"


class TermForm(forms.ModelForm):
    """A quarter (chorak) of an academic year."""

    class Meta:
        model = Term
        fields = ["number", "name", "start_date", "end_date"]
        labels = {
            "number": _("Quarter"),
            "name": _("Name"),
            "start_date": _("First day"),
            "end_date": _("Last day"),
        }
        widgets = {
            "number": forms.Select(choices=[(n, str(n)) for n in range(1, 5)]),
            "start_date": forms.DateInput(attrs={"type": "date"}, format="%Y-%m-%d"),
            "end_date": forms.DateInput(attrs={"type": "date"}, format="%Y-%m-%d"),
        }

    def __init__(self, *args, session=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.instance.session = session
        for field in self.visible_fields():
            field.field.widget.attrs["class"] = "form-control"

    def clean(self):
        cleaned = super().clean()
        number = cleaned.get("number")
        if number and (
            Term.objects.filter(session=self.instance.session, number=number)
            .exclude(pk=self.instance.pk)
            .exists()
        ):
            self.add_error("number", _("This year already has this quarter."))
        if number and not cleaned.get("name"):
            cleaned["name"] = f"{number}-chorak"
            self.instance.name = cleaned["name"]
        return cleaned


class BellPeriodForm(forms.ModelForm):
    """One bell period (dars vaqti) of a school branch. Overlaps are checked by the model."""

    class Meta:
        model = BellPeriod
        fields = ["number", "start_time", "end_time"]
        labels = {"number": _("Period"), "start_time": _("Starts"), "end_time": _("Ends")}
        widgets = {
            "number": forms.Select(choices=[(n, str(n)) for n in range(1, 13)]),
            "start_time": forms.TimeInput(attrs={"type": "time"}, format="%H:%M"),
            "end_time": forms.TimeInput(attrs={"type": "time"}, format="%H:%M"),
        }

    def __init__(self, *args, branch=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.instance.branch = branch
        for field in self.visible_fields():
            field.field.widget.attrs["class"] = "form-control"

    def clean_number(self):
        number = self.cleaned_data["number"]
        taken = BellPeriod.objects.filter(  # scoping-ok: uniqueness check inside a chosen branch
            branch=self.instance.branch, number=number
        ).exclude(pk=self.instance.pk)
        if taken.exists():
            raise forms.ValidationError(
                _("This branch already has period %(number)s."), params={"number": number}
            )
        return number
