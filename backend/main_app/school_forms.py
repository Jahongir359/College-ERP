"""Admin forms for Iceberg School data (plan task P1.7: parents and their children).

The admin API validates through these same forms, and the admin parents page
(P3.3) renders them. Labels and messages use gettext so P3.0 can translate them.
"""

from django import forms
from django.contrib.auth.password_validation import validate_password
from django.utils.translation import gettext_lazy as _

from . import branching
from .models import Parent, ParentChild, Student
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
