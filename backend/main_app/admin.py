from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import (
    Admin,
    CustomUser,
    Staff,
    Student,
    Parent,
    ParentChild,
    Course,
    Book,
    Loan,
    Subject,
    Session,
    Term,
    Branch,
    Group,
    Enrollment,
    ChatThread,
    ChatMessage,
    ChatReadState,
    Assignment,
    Submission,
    Notification,
    RegistrationLead,
)


@admin.register(Admin)
class AdminAdmin(admin.ModelAdmin):
    list_display = ("full_name", "email", "is_super_admin", "branch_list")
    list_filter = ("is_super_admin",)
    search_fields = ("admin__email", "admin__first_name", "admin__last_name")
    filter_horizontal = ("branches",)
    raw_id_fields = ("admin",)
    readonly_fields = ("admin",)

    def full_name(self, obj):
        return obj.admin.get_full_name() or "—"

    full_name.short_description = "Name"

    def email(self, obj):
        return obj.admin.email

    email.short_description = "Email"

    def branch_list(self, obj):
        if obj.is_super_admin:
            return "All branches (super admin)"
        names = ", ".join(obj.branches.values_list("name", flat=True)[:3])
        extra = max(obj.branches.count() - 3, 0)
        return f"{names} +{extra} more" if extra else names or "—"

    branch_list.short_description = "Branches"

    def save_model(self, request, obj, form, change):
        if obj.is_super_admin:
            existing = Admin.objects.filter(is_super_admin=True).exclude(pk=obj.pk)
            if existing.exists():
                name = existing.first().admin.get_full_name() or existing.first().admin.email
                self.message_user(
                    request,
                    f"Could not save: {name} is already the super admin. "
                    "Only one super admin is allowed. Demote the existing super admin first.",
                    level="error",
                )
                return
        super().save_model(request, obj, form, change)

    def has_add_permission(self, request):
        # Admin profiles are created automatically via signal — block manual creation.
        return False

    def has_delete_permission(self, request, obj=None):
        # Protect the only super admin from deletion.
        if obj is not None and obj.is_super_admin:
            other_super = Admin.objects.filter(is_super_admin=True).exclude(pk=obj.pk)
            if not other_super.exists():
                return False
        return super().has_delete_permission(request, obj)


@admin.register(CustomUser)
class CustomUserAdmin(UserAdmin):
    ordering = ("email",)
    list_display = ("login_id", "email", "first_name", "last_name", "user_type", "is_active")
    list_filter = ("user_type", "is_active", "gender")
    search_fields = ("login_id", "email", "first_name", "last_name")
    readonly_fields = ("login_id", "created_at", "updated_at")

    fieldsets = (
        (None, {"fields": ("email", "password")}),
        ("ICE Identity", {"fields": ("login_id", "user_type")}),
        (
            "Personal info",
            {"fields": ("first_name", "last_name", "gender", "profile_pic", "avatar", "address")},
        ),
        (
            "Permissions",
            {"fields": ("is_active", "is_staff", "is_superuser", "groups", "user_permissions")},
        ),
        ("Timestamps", {"fields": ("created_at", "updated_at", "last_login", "date_joined")}),
    )
    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),
                "fields": (
                    "email",
                    "password1",
                    "password2",
                    "user_type",
                    "first_name",
                    "last_name",
                ),
            },
        ),
    )

    def get_user_type_display(self, obj):
        return obj.get_user_type_display()

    get_user_type_display.short_description = "Role"


@admin.register(Staff)
class StaffAdmin(admin.ModelAdmin):
    list_display = ("teacher_id", "full_name", "course", "is_active")
    list_filter = ("is_active", "course")
    search_fields = ("admin__login_id", "admin__first_name", "admin__last_name", "admin__email")
    raw_id_fields = ("admin",)

    def teacher_id(self, obj):
        return obj.admin.login_id or "—"

    teacher_id.short_description = "Teacher ID"

    def full_name(self, obj):
        return f"{obj.admin.first_name} {obj.admin.last_name}".strip() or obj.admin.email

    full_name.short_description = "Name"


@admin.register(Student)
class StudentAdmin(admin.ModelAdmin):
    list_display = ("ice_id", "full_name", "course", "status")
    list_filter = ("status", "course")
    search_fields = ("admin__login_id", "admin__first_name", "admin__last_name", "admin__email")
    raw_id_fields = ("admin",)

    def ice_id(self, obj):
        return obj.admin.login_id or "—"

    ice_id.short_description = "ICE ID"

    def full_name(self, obj):
        return f"{obj.admin.first_name} {obj.admin.last_name}".strip() or obj.admin.email

    full_name.short_description = "Name"


class ParentChildInline(admin.TabularInline):
    model = ParentChild
    extra = 0
    raw_id_fields = ("student",)


@admin.register(Parent)
class ParentAdmin(admin.ModelAdmin):
    list_display = ("login", "full_name", "phone")
    search_fields = ("admin__login_id", "admin__first_name", "admin__last_name", "phone")
    raw_id_fields = ("admin",)
    inlines = [ParentChildInline]

    def login(self, obj):
        return obj.admin.login_id or "—"

    def full_name(self, obj):
        return f"{obj.admin.first_name} {obj.admin.last_name}".strip() or obj.admin.email

    full_name.short_description = "Name"


admin.site.register(Course)
admin.site.register(Book)
admin.site.register(Loan)
admin.site.register(Subject)


class TermInline(admin.TabularInline):
    model = Term
    extra = 0


@admin.register(Session)
class SessionAdmin(admin.ModelAdmin):
    list_display = ("__str__", "start_year", "end_year", "is_current")
    inlines = [TermInline]


admin.site.register(Branch)
admin.site.register(Group)
admin.site.register(Enrollment)


@admin.register(ChatThread)
class ChatThreadAdmin(admin.ModelAdmin):
    list_display = ("group", "updated_at", "created_at")
    search_fields = ("group__name",)
    readonly_fields = ("created_at", "updated_at")


@admin.register(ChatMessage)
class ChatMessageAdmin(admin.ModelAdmin):
    list_display = ("thread", "sender", "created_at", "preview")
    list_filter = ("created_at",)
    search_fields = (
        "body",
        "sender__email",
        "sender__first_name",
        "sender__last_name",
        "thread__group__name",
    )
    readonly_fields = ("created_at",)

    def preview(self, obj):
        return obj.body[:80]


@admin.register(ChatReadState)
class ChatReadStateAdmin(admin.ModelAdmin):
    list_display = ("thread", "user", "last_read_at", "updated_at")
    search_fields = ("thread__group__name", "user__email", "user__first_name", "user__last_name")
    readonly_fields = ("updated_at",)


admin.site.register(Assignment)
admin.site.register(Submission)
admin.site.register(Notification)


@admin.register(RegistrationLead)
class RegistrationLeadAdmin(admin.ModelAdmin):
    list_display = ("full_name", "phone", "program", "source", "status", "created_at")
    list_filter = ("status", "source", "created_at")
    search_fields = (
        "full_name",
        "first_name",
        "last_name",
        "phone",
        "parent_phone",
        "email",
        "program",
        "social_handle",
    )
    readonly_fields = ("raw_payload", "remote_addr", "user_agent", "created_at", "updated_at")
