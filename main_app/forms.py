from django import forms
from django.forms.widgets import DateInput, TextInput

from .models import *
from . import models


class FormSettings(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super(FormSettings, self).__init__(*args, **kwargs)
        # Here make some changes such as:
        for field in self.visible_fields():
            field.field.widget.attrs['class'] = 'form-control'


_MAX_PROFILE_PIC_BYTES = 5 * 1024 * 1024  # 5 MB


class CustomUserForm(FormSettings):
    gender = forms.ChoiceField(choices=[('M', 'Male'), ('F', 'Female')])
    first_name = forms.CharField(required=True)
    last_name = forms.CharField(required=True)
    address = forms.CharField(widget=forms.Textarea)
    password = forms.CharField(widget=forms.PasswordInput)
    profile_pic = forms.ImageField()

    def __init__(self, *args, **kwargs):
        super(CustomUserForm, self).__init__(*args, **kwargs)
        self.fields['profile_pic'].required = False

    def clean_profile_pic(self):
        pic = self.cleaned_data.get('profile_pic')
        if pic and getattr(pic, 'size', 0) > _MAX_PROFILE_PIC_BYTES:
            raise forms.ValidationError("Profile picture too large. Maximum size is 5 MB.")
        return pic

        if kwargs.get('instance'):
            instance = kwargs.get('instance').admin.__dict__
            self.fields['password'].required = False
            for field in CustomUserForm.Meta.fields:
                if field in self.fields:
                    self.fields[field].initial = instance.get(field)
            if self.instance.pk is not None:
                self.fields['password'].widget.attrs['placeholder'] = "Fill this only if you wish to update password"

    class Meta:
        model = CustomUser
        fields = ['first_name', 'last_name', 'gender', 'password', 'profile_pic', 'address']


class StudentForm(CustomUserForm):
    phone = forms.CharField(
        max_length=20, required=False, label="Phone Number",
        widget=forms.TextInput(attrs={'placeholder': '+998 90 123 45 67', 'class': 'form-control'}),
    )
    status = forms.ChoiceField(
        choices=Student.STATUS_CHOICES,
        initial=Student.STATUS_ACTIVE,
        label="Status",
    )
    level = forms.ChoiceField(
        choices=[('', '— No level assigned —')] + Student.LEVEL_CHOICES,
        required=False,
        label="English Level",
    )

    def __init__(self, *args, **kwargs):
        super(StudentForm, self).__init__(*args, **kwargs)
        self.fields['status'].widget.attrs['class'] = 'form-control'
        self.fields['level'].widget.attrs['class'] = 'form-control'
        instance = kwargs.get('instance')
        if instance:
            self.fields['phone'].initial = instance.phone
            self.fields['status'].initial = instance.status
            self.fields['level'].initial = instance.level if instance.level else ''

    class Meta(CustomUserForm.Meta):
        model = Student
        fields = CustomUserForm.Meta.fields + ['course', 'phone', 'status', 'level']


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
        max_length=20, required=False, label="Phone Number",
        widget=forms.TextInput(attrs={'placeholder': '+998 90 123 45 67'}),
    )
    status = forms.ChoiceField(
        choices=Student.STATUS_CHOICES,
        initial=Student.STATUS_ACTIVE,
        label="Status",
    )
    level = forms.ChoiceField(
        choices=[('', '— No level assigned —')] + Student.LEVEL_CHOICES,
        required=False,
        label="English Level",
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['course'].widget.attrs['class'] = 'form-control'
        self.fields['group'].widget.attrs['class'] = 'form-control'
        self.fields['phone'].widget.attrs['class'] = 'form-control'
        self.fields['status'].widget.attrs['class'] = 'form-control'
        self.fields['level'].widget.attrs['class'] = 'form-control'
        if self.data.get('group'):
            self.fields['group'].queryset = Group.objects.filter(is_archived=False)

    def clean(self):
        cleaned_data = super().clean()
        course = cleaned_data.get('course')
        group = cleaned_data.get('group')
        if group and course and group.course_id != course.id:
            self.add_error('group', 'The selected class group does not belong to the chosen program.')
        return cleaned_data

    class Meta(CustomUserForm.Meta):
        model = Student
        fields = CustomUserForm.Meta.fields + ['course', 'group', 'phone', 'status', 'level']


class AdminForm(CustomUserForm):
    email = forms.EmailField(required=False, label='Email')

    def __init__(self, *args, **kwargs):
        super(AdminForm, self).__init__(*args, **kwargs)
        self.fields['password'].required = False
        self.fields['profile_pic'].required = False
        self.fields['gender'].required = False
        self.fields['address'].required = False
        if kwargs.get('instance'):
            self.fields['email'].initial = kwargs['instance'].admin.email

    class Meta(CustomUserForm.Meta):
        model = Admin
        fields = ['first_name', 'last_name', 'email', 'gender', 'password', 'profile_pic', 'address']


PREDEFINED_SUBJECTS = [
    'General English',
    'Pre-IELTS',
    'IELTS Academic',
    'IELTS General Training',
    'IELTS 7+ Band',
    'TOEFL iBT Preparation',
    'SAT English',
    'Business English',
    'Academic English',
    'Speaking & Communication',
    'Grammar & Vocabulary',
    'Reading & Writing',
    'Listening & Note-taking',
    'Conversation Club',
    'English for Kids',
    'English for Beginners',
    'Cambridge B2 (FCE)',
    'Cambridge C1 (CAE)',
    'Pronunciation Training',
    'IELTS Speaking',
    'IELTS Writing',
    'IELTS Reading',
    'IELTS Listening',
    'Mathematics',
    'Physics',
    'Chemistry',
    'Computer Science',
]


class StaffForm(CustomUserForm):
    def __init__(self, *args, **kwargs):
        super(StaffForm, self).__init__(*args, **kwargs)

    class Meta(CustomUserForm.Meta):
        model = Staff
        fields = CustomUserForm.Meta.fields + ['course', 'phone', 'specialization']


class CourseForm(forms.Form):
    name = forms.ChoiceField(
        choices=[('', '— Select a subject —')] + [(s, s) for s in PREDEFINED_SUBJECTS],
        label='Subject / Program',
        widget=forms.Select(attrs={'class': 'form-control'}),
    )

    def __init__(self, *args, instance=None, **kwargs):
        initial = kwargs.get('initial', {})
        if instance and instance.name and not initial.get('name'):
            initial['name'] = instance.name
        kwargs['initial'] = initial
        super().__init__(*args, **kwargs)
        # If editing a course whose name isn't in the predefined list, add it
        if instance and instance.name:
            existing = [c[0] for c in self.fields['name'].choices]
            if instance.name not in existing:
                self.fields['name'].choices.append((instance.name, instance.name))


class SubjectForm(FormSettings):

    def __init__(self, *args, **kwargs):
        super(SubjectForm, self).__init__(*args, **kwargs)

    class Meta:
        model = Subject
        fields = ['name', 'staff', 'course']


class SessionForm(FormSettings):
    def __init__(self, *args, **kwargs):
        super(SessionForm, self).__init__(*args, **kwargs)

    class Meta:
        model = Session
        fields = '__all__'
        widgets = {
            'start_year': DateInput(attrs={'type': 'date'}),
            'end_year': DateInput(attrs={'type': 'date'}),
        }


class LeaveReportStaffForm(FormSettings):
    def __init__(self, *args, **kwargs):
        super(LeaveReportStaffForm, self).__init__(*args, **kwargs)

    class Meta:
        model = LeaveReportStaff
        fields = ['date', 'message']
        widgets = {
            'date': DateInput(attrs={'type': 'date'}),
        }


class FeedbackStaffForm(FormSettings):

    def __init__(self, *args, **kwargs):
        super(FeedbackStaffForm, self).__init__(*args, **kwargs)

    class Meta:
        model = FeedbackStaff
        fields = ['feedback']


class LeaveReportStudentForm(FormSettings):
    def __init__(self, *args, **kwargs):
        super(LeaveReportStudentForm, self).__init__(*args, **kwargs)

    class Meta:
        model = LeaveReportStudent
        fields = ['date', 'message']
        widgets = {
            'date': DateInput(attrs={'type': 'date'}),
        }


class FeedbackStudentForm(FormSettings):

    def __init__(self, *args, **kwargs):
        super(FeedbackStudentForm, self).__init__(*args, **kwargs)

    class Meta:
        model = FeedbackStudent
        fields = ['feedback']


class StudentEditForm(CustomUserForm):
    def __init__(self, *args, **kwargs):
        super(StudentEditForm, self).__init__(*args, **kwargs)

    class Meta(CustomUserForm.Meta):
        model = Student
        fields = CustomUserForm.Meta.fields 


class StaffEditForm(CustomUserForm):
    def __init__(self, *args, **kwargs):
        super(StaffEditForm, self).__init__(*args, **kwargs)

    class Meta(CustomUserForm.Meta):
        model = Staff
        fields = CustomUserForm.Meta.fields + ['course', 'phone', 'specialization']


class StudentProfileForm(forms.Form):
    """Lean form for student self-service profile editing (no email, no profile_pic)."""
    first_name = forms.CharField(required=True, label='First Name',
        widget=forms.TextInput(attrs={'class': 'form-control'}))
    last_name = forms.CharField(required=True, label='Last Name',
        widget=forms.TextInput(attrs={'class': 'form-control'}))
    gender = forms.ChoiceField(
        choices=[('', '—'), ('M', 'Male'), ('F', 'Female')],
        required=False, label='Gender',
        widget=forms.Select(attrs={'class': 'form-control'}))
    phone = forms.CharField(max_length=20, required=False, label='Phone Number',
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': '+998 90 123 45 67'}))
    password = forms.CharField(required=False, label='New Password',
        widget=forms.PasswordInput(attrs={'class': 'form-control',
            'placeholder': 'Leave blank to keep current password'}))

    def __init__(self, instance=None, data=None, **kwargs):
        super().__init__(data=data, **kwargs)
        if instance:
            self.fields['first_name'].initial = instance.admin.first_name
            self.fields['last_name'].initial = instance.admin.last_name
            self.fields['gender'].initial = instance.admin.gender
            self.fields['phone'].initial = instance.phone


class StaffProfileForm(forms.Form):
    """Lean form for staff self-service profile editing (no email, no profile_pic)."""
    first_name = forms.CharField(required=True, label='First Name',
        widget=forms.TextInput(attrs={'class': 'form-control'}))
    last_name = forms.CharField(required=True, label='Last Name',
        widget=forms.TextInput(attrs={'class': 'form-control'}))
    gender = forms.ChoiceField(
        choices=[('', '—'), ('M', 'Male'), ('F', 'Female')],
        required=False, label='Gender',
        widget=forms.Select(attrs={'class': 'form-control'}))
    phone = forms.CharField(max_length=20, required=False, label='Phone Number',
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': '+998 90 123 45 67'}))
    specialization = forms.CharField(max_length=200, required=False, label='Specialization',
        widget=forms.TextInput(attrs={'class': 'form-control',
            'placeholder': 'e.g. IELTS, Mathematics, Business English'}))
    password = forms.CharField(required=False, label='New Password',
        widget=forms.PasswordInput(attrs={'class': 'form-control',
            'placeholder': 'Leave blank to keep current password'}))

    def __init__(self, instance=None, data=None, **kwargs):
        super().__init__(data=data, **kwargs)
        if instance:
            self.fields['first_name'].initial = instance.admin.first_name
            self.fields['last_name'].initial = instance.admin.last_name
            self.fields['gender'].initial = instance.admin.gender
            self.fields['phone'].initial = instance.phone
            self.fields['specialization'].initial = instance.specialization


class EditResultForm(FormSettings):
    def __init__(self, *args, **kwargs):
        super(EditResultForm, self).__init__(*args, **kwargs)

    class Meta:
        model = StudentResult
        fields = ['group', 'student', 'test', 'exam']

#todos
# class TodoForm(forms.ModelForm):
#     class Meta:
#         model=Todo
#         fields=["title","is_finished"]

#issue book

class BranchForm(FormSettings):
    class Meta:
        model = Branch
        fields = ['name', 'address']


class GroupForm(FormSettings):
    class Meta:
        model = Group
        fields = ['name', 'course', 'teacher', 'branch', 'room', 'schedule', 'capacity', 'start_date']
        labels = {
            'course': 'Program',
            'teacher': 'Teacher',
            'branch': 'Branch / Location',
            'room': 'Room / Classroom',
            'schedule': 'Schedule',
            'capacity': 'Capacity (max students)',
            'start_date': 'Starting Date',
        }
        widgets = {
            'start_date': forms.DateInput(attrs={'type': 'date', 'class': 'form-control'}),
        }


class EnrollmentForm(FormSettings):
    STATUS_CHOICES = [(True, 'Active'), (False, 'Inactive')]
    is_active = forms.TypedChoiceField(
        choices=STATUS_CHOICES,
        coerce=lambda x: x == 'True' or x is True,
        label="Enrollment Status",
        initial=True,
    )

    class Meta:
        model = Enrollment
        fields = ['group', 'student', 'is_active']


class AssignmentForm(FormSettings):
    class Meta:
        model = Assignment
        fields = ['title', 'description', 'group', 'due_date']
        widgets = {
            'due_date': DateInput(attrs={'type': 'date'}),
        }


class SubmissionForm(FormSettings):
    class Meta:
        model = Submission
        fields = ['file', 'note']


class BookForm(forms.ModelForm):
    class Meta:
        model = models.Book
        fields = ['name', 'author', 'isbn', 'category']
        widgets = {
            'name':     TextInput(attrs={'class': 'form-control', 'placeholder': 'Book title'}),
            'author':   TextInput(attrs={'class': 'form-control', 'placeholder': 'Author name'}),
            'isbn':     TextInput(attrs={'class': 'form-control', 'placeholder': 'ISBN number'}),
            'category': TextInput(attrs={'class': 'form-control', 'placeholder': 'e.g. Science'}),
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
        widget=forms.Select(attrs={'class': 'form-control'}),
    )
    student = forms.ModelChoiceField(
        queryset=models.Student.objects.all(),
        empty_label="Select student…",
        label="Student",
        widget=forms.Select(attrs={'class': 'form-control'}),
    )

    def clean(self):
        cleaned = super().clean()
        book = cleaned.get('book')
        student = cleaned.get('student')
        if book and student:
            existing = models.Loan.objects.filter(
                book=book, student=student, returned_on__isnull=True,
            ).exists()
            if existing:
                raise forms.ValidationError(
                    "This student already has an active loan for this book."
                )
        return cleaned


class VocabularyDayForm(forms.ModelForm):
    class Meta:
        model = VocabularyDay
        fields = ['group', 'day_number', 'title', 'level', 'release_scope', 'notes']
        widgets = {
            'day_number': forms.NumberInput(attrs={
                'class': 'form-control', 'min': '1', 'max': '365', 'placeholder': '1',
            }),
            'title': forms.TextInput(attrs={
                'class': 'form-control', 'placeholder': 'e.g. Describing People',
            }),
            'level': forms.Select(attrs={'class': 'form-control'}),
            'release_scope': forms.RadioSelect(attrs={'class': 'scope-radio'}),
            'notes': forms.Textarea(attrs={
                'class': 'form-control', 'rows': 2,
                'placeholder': 'Private teacher notes (not shown to students)',
            }),
            'group': forms.Select(attrs={'class': 'form-control'}),
        }

    LEVEL_CHOICES = [('', '— Inherit from group —')] + [(i, f'Level {i}') for i in range(1, 7)]

    def __init__(self, *args, **kwargs):
        staff = kwargs.pop('staff', None)
        super().__init__(*args, **kwargs)
        self.fields['title'].required = False
        self.fields['level'].required = False
        self.fields['level'].widget.choices = self.LEVEL_CHOICES
        self.fields['notes'].required = False
        if staff:
            self.fields['group'].queryset = Group.objects.filter(
                teacher=staff, is_archived=False
            )
        else:
            self.fields['group'].queryset = Group.objects.filter(is_archived=False)


class DashboardStoryForm(FormSettings):
    class Meta:
        model = DashboardStory
        fields = ['title', 'body', 'image', 'story_type', 'emoji', 'bg_color',
                  'target_groups', 'is_active', 'expires_at']
        widgets = {
            'title':         forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Story title'}),
            'body':          forms.Textarea(attrs={'class': 'form-control', 'rows': 3, 'placeholder': 'Short description…'}),
            'story_type':    forms.Select(attrs={'class': 'form-control'}),
            'emoji':         forms.TextInput(attrs={'class': 'form-control', 'placeholder': '📢', 'maxlength': 8}),
            'bg_color':      forms.TextInput(attrs={'class': 'form-control'}),
            'target_groups': forms.CheckboxSelectMultiple(),
            'is_active':     forms.CheckboxInput(),
            'expires_at':    forms.DateTimeInput(attrs={'class': 'form-control', 'type': 'datetime-local'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Prevent FormSettings from stamping form-control onto checkbox widgets
        for name in ('target_groups', 'is_active'):
            if name in self.fields:
                self.fields[name].widget.attrs.pop('class', None)
        # Initialise datetime-local input from existing value (converted to local time)
        if self.instance and self.instance.pk and self.instance.expires_at:
            from django.utils import timezone as _tz
            local_dt = _tz.localtime(self.instance.expires_at)
            self.initial['expires_at'] = local_dt.strftime('%Y-%m-%dT%H:%M')


class LeaderboardSettingsForm(FormSettings):
    class Meta:
        model = LeaderboardSettings
        fields = [
            'attendance_weight', 'homework_weight', 'quizzes_weight', 'results_weight',
            'enable_attendance', 'enable_homework', 'enable_quizzes', 'enable_results',
        ]
        widgets = {
            'attendance_weight': forms.NumberInput(attrs={'class': 'form-control', 'min': 0, 'max': 100}),
            'homework_weight':   forms.NumberInput(attrs={'class': 'form-control', 'min': 0, 'max': 100}),
            'quizzes_weight':    forms.NumberInput(attrs={'class': 'form-control', 'min': 0, 'max': 100}),
            'results_weight':    forms.NumberInput(attrs={'class': 'form-control', 'min': 0, 'max': 100}),
            'enable_attendance': forms.CheckboxInput(),
            'enable_homework':   forms.CheckboxInput(),
            'enable_quizzes':    forms.CheckboxInput(),
            'enable_results':    forms.CheckboxInput(),
        }


class LeaderboardSeasonForm(FormSettings):
    class Meta:
        model = LeaderboardSeason
        fields = ['name', 'period', 'start_date', 'end_date', 'is_active']
        widgets = {
            'name':       forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'e.g. October 2026'}),
            'period':     forms.Select(attrs={'class': 'form-control'}),
            'start_date': forms.DateInput(attrs={'class': 'form-control', 'type': 'date'}),
            'end_date':   forms.DateInput(attrs={'class': 'form-control', 'type': 'date'}),
            'is_active':  forms.CheckboxInput(),
        }


