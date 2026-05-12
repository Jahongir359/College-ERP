from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import *
# Register your models here.


class UserModel(UserAdmin):
    ordering = ('email',)


admin.site.register(CustomUser, UserModel)
admin.site.register(Staff)
admin.site.register(Student)
admin.site.register(Course)
admin.site.register(Book)
admin.site.register(IssuedBook)   # legacy, retained for one release; superseded by Loan
admin.site.register(Library)      # legacy, unused; superseded by Loan
admin.site.register(Loan)
admin.site.register(Subject)
admin.site.register(Session)
admin.site.register(Branch)
admin.site.register(Group)
admin.site.register(Enrollment)
admin.site.register(Assignment)
admin.site.register(Submission)
