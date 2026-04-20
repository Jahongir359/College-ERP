from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model

from .models import Staff, Student


class EmailBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        UserModel = get_user_model()
        identifier = (username or "").strip()

        if not identifier or password is None:
            return None

        user = None

        # Allow login with staff/student unique IDs: STA0001 / STU0001
        upper_identifier = identifier.upper()
        if upper_identifier.startswith('STA') and upper_identifier[3:].isdigit():
            staff = Staff.objects.select_related('admin').filter(id=int(upper_identifier[3:])).first()
            if staff:
                user = staff.admin
        elif upper_identifier.startswith('STU') and upper_identifier[3:].isdigit():
            student = Student.objects.select_related('admin').filter(id=int(upper_identifier[3:])).first()
            if student:
                user = student.admin
        else:
            user = UserModel.objects.filter(email__iexact=identifier).first()

        if user and user.check_password(password) and self.user_can_authenticate(user):
            return user
        return None
