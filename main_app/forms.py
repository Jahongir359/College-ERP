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


class CustomUserForm(FormSettings):
    email = forms.EmailField(required=True)
    gender = forms.ChoiceField(choices=[('M', 'Male'), ('F', 'Female')])
    first_name = forms.CharField(required=True)
    last_name = forms.CharField(required=True)
    address = forms.CharField(widget=forms.Textarea)
    password = forms.CharField(widget=forms.PasswordInput)
    widget = {
        'password': forms.PasswordInput(),
    }
    profile_pic = forms.ImageField()

    def __init__(self, *args, **kwargs):
        super(CustomUserForm, self).__init__(*args, **kwargs)
        self.fields['profile_pic'].required = False

        if kwargs.get('instance'):
            instance = kwargs.get('instance').admin.__dict__
            self.fields['password'].required = False
            for field in CustomUserForm.Meta.fields:
                self.fields[field].initial = instance.get(field)
            if self.instance.pk is not None:
                self.fields['password'].widget.attrs['placeholder'] = "Fill this only if you wish to update password"

    def clean_email(self, *args, **kwargs):
        formEmail = self.cleaned_data['email'].lower()
        if self.instance.pk is None:  # Insert
            if CustomUser.objects.filter(email=formEmail).exists():
                raise forms.ValidationError(
                    "The given email is already registered")
        else:  # Update
            dbEmail = self.Meta.model.objects.get(
                id=self.instance.pk).admin.email.lower()
            if dbEmail != formEmail:  # There has been changes
                if CustomUser.objects.filter(email=formEmail).exists():
                    raise forms.ValidationError("The given email is already registered")

        return formEmail

    class Meta:
        model = CustomUser
        fields = ['first_name', 'last_name', 'email', 'gender',  'password','profile_pic', 'address' ]


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
    def __init__(self, *args, **kwargs):
        super(AdminForm, self).__init__(*args, **kwargs)
        # Admin profile updates should not be blocked by optional legacy fields.
        self.fields['password'].required = False
        self.fields['profile_pic'].required = False
        self.fields['gender'].required = False
        self.fields['address'].required = False

    class Meta(CustomUserForm.Meta):
        model = Admin
        fields = CustomUserForm.Meta.fields


class StaffForm(CustomUserForm):
    def __init__(self, *args, **kwargs):
        super(StaffForm, self).__init__(*args, **kwargs)

    class Meta(CustomUserForm.Meta):
        model = Staff
        fields = CustomUserForm.Meta.fields + ['course', 'phone', 'specialization', 'is_active']


class CourseForm(FormSettings):
    def __init__(self, *args, **kwargs):
        super(CourseForm, self).__init__(*args, **kwargs)

    class Meta:
        fields = ['name', 'is_english', 'is_active']
        model = Course


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
        fields = CustomUserForm.Meta.fields + ['course', 'phone', 'specialization', 'is_active']


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
        fields = ['group', 'day_number', 'title', 'level', 'release_at', 'notes']
        widgets = {
            'day_number': forms.NumberInput(attrs={
                'class': 'form-control', 'min': '1', 'max': '365', 'placeholder': '1',
            }),
            'title': forms.TextInput(attrs={
                'class': 'form-control', 'placeholder': 'e.g. Describing People',
            }),
            'level': forms.Select(attrs={'class': 'form-control'}),
            'release_at': forms.DateTimeInput(
                attrs={'class': 'form-control', 'type': 'datetime-local'},
                format='%Y-%m-%dT%H:%M',
            ),
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
        self.fields['level'].choices = self.LEVEL_CHOICES
        self.fields['notes'].required = False
        if staff:
            self.fields['group'].queryset = Group.objects.filter(
                teacher=staff, is_archived=False
            )
        else:
            self.fields['group'].queryset = Group.objects.filter(is_archived=False)
        if self.instance and self.instance.pk and self.instance.release_at:
            self.initial['release_at'] = self.instance.release_at.strftime('%Y-%m-%dT%H:%M')


class VocabularyForm(forms.ModelForm):
    class Meta:
        model = models.Vocabulary
        fields = ['word', 'definition', 'example_sentence', 'translation',
                  'part_of_speech', 'level', 'group']
        widgets = {
            'word': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'e.g. Diligent'}),
            'definition': forms.Textarea(attrs={'class': 'form-control', 'rows': 3, 'placeholder': 'Clear English definition'}),
            'example_sentence': forms.Textarea(attrs={'class': 'form-control', 'rows': 2, 'placeholder': 'She was diligent in her studies.'}),
            'translation': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Optional native-language translation'}),
            'part_of_speech': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'noun / verb / adjective…'}),
            'level': forms.Select(attrs={'class': 'form-control'}),
            'group': forms.Select(attrs={'class': 'form-control'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['group'].queryset = models.Group.objects.filter(is_archived=False)
        self.fields['group'].required = False
        self.fields['group'].empty_label = '— All groups —'
        self.fields['example_sentence'].required = False
        self.fields['translation'].required = False
        self.fields['part_of_speech'].required = False
