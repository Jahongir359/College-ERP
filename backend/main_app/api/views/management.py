import datetime

from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import transaction
from django.db.models import Q
from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.views import APIView

from ... import branching
from ...models import Branch, CustomUser, RegistrationLead, Staff, Student
from ..permissions import IsAdmin
from ..serializers import AdminStaffSerializer, AdminStudentSerializer, RegistrationLeadSerializer


def _resolve_branch(user, branch_id):
    """Return (branch, error_response) for a branch the admin may assign.

    Branch admins must pick one of their own branches — otherwise they could
    create accounts inside another branch (or with no branch, invisible to
    them afterwards). Super admins may leave it blank.
    """
    if not branch_id:
        if branching.is_super_admin(user):
            return None, None
        return None, Response({"detail": "branch is required."}, status=status.HTTP_400_BAD_REQUEST)
    branch = Branch.objects.filter(pk=branch_id).first()
    if branch is None or not branching.user_can_access_branch(user, branch):
        return None, Response(
            {"detail": "You don't have access to that branch."}, status=status.HTTP_403_FORBIDDEN
        )
    return branch, None


def _scoped_leads(user):
    return branching.filter_registration_leads_for_user(user, RegistrationLead.objects.all())


# ---------------------------------------------------------------------------
# Admin: Registration leads
# ---------------------------------------------------------------------------


class AdminLeadListView(APIView):
    permission_classes = [IsAdmin]

    def get(self, request):
        from rest_framework.pagination import PageNumberPagination

        qs = _scoped_leads(request.user).order_by("-created_at")
        status_filter = request.query_params.get("status")
        search = request.query_params.get("search")
        if status_filter:
            qs = qs.filter(status=status_filter)
        if search:
            qs = qs.filter(
                Q(full_name__icontains=search)
                | Q(first_name__icontains=search)
                | Q(last_name__icontains=search)
                | Q(phone__icontains=search)
                | Q(email__icontains=search)
            )
        paginator = PageNumberPagination()
        paginator.page_size = 30
        page = paginator.paginate_queryset(qs, request)
        return paginator.get_paginated_response(RegistrationLeadSerializer(page, many=True).data)

    def post(self, request):
        serializer = RegistrationLeadSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        lead = serializer.save()
        return Response(RegistrationLeadSerializer(lead).data, status=status.HTTP_201_CREATED)


class AdminLeadDetailView(APIView):
    permission_classes = [IsAdmin]

    def get(self, request, pk):
        try:
            lead = _scoped_leads(request.user).get(pk=pk)
        except RegistrationLead.DoesNotExist:
            return Response({"detail": "Lead not found."}, status=status.HTTP_404_NOT_FOUND)
        return Response(RegistrationLeadSerializer(lead).data)

    def patch(self, request, pk):
        try:
            lead = _scoped_leads(request.user).get(pk=pk)
        except RegistrationLead.DoesNotExist:
            return Response({"detail": "Lead not found."}, status=status.HTTP_404_NOT_FOUND)
        serializer = RegistrationLeadSerializer(lead, data=request.data, partial=True)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        serializer.save()
        return Response(serializer.data)


# ---------------------------------------------------------------------------
# Admin: Student management
# ---------------------------------------------------------------------------


class AdminStudentListView(generics.ListAPIView):
    permission_classes = [IsAdmin]
    serializer_class = AdminStudentSerializer

    def get_queryset(self):
        qs = Student.objects.select_related("admin", "course", "branch")
        qs = branching.filter_students_for_user(self.request.user, qs)
        search = self.request.query_params.get("search")
        status_filter = self.request.query_params.get("status")
        if status_filter:
            qs = qs.filter(status=status_filter)
        if search:
            qs = qs.filter(
                Q(admin__first_name__icontains=search)
                | Q(admin__last_name__icontains=search)
                | Q(admin__email__icontains=search)
                | Q(admin__login_id__icontains=search)
                | Q(phone__icontains=search)
            )
        return qs.order_by("admin__first_name")

    @transaction.atomic
    def post(self, request):
        """Create a new student account."""
        from ...hod_views import _generate_login_id

        data = request.data
        first_name = data.get("first_name", "").strip()
        last_name = data.get("last_name", "").strip()
        password = data.get("password", "").strip()
        phone = data.get("phone", "").strip()
        gender = data.get("gender", "M")
        address = data.get("address", "").strip()
        course_id = data.get("course")
        branch_id = data.get("branch")
        status_val = data.get("status", Student.STATUS_ACTIVE)
        level = data.get("level")
        dob_str = data.get("date_of_birth", "")

        if not first_name or not password:
            return Response(
                {"detail": "first_name and password are required."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            validate_password(password)
        except DjangoValidationError as exc:
            return Response({"password": exc.messages}, status=status.HTTP_400_BAD_REQUEST)

        dob = None
        if dob_str:
            try:
                dob = datetime.date.fromisoformat(dob_str)
            except ValueError:
                return Response(
                    {"detail": "Invalid date_of_birth format. Use YYYY-MM-DD."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        branch, error = _resolve_branch(request.user, branch_id)
        if error:
            return error

        login_id = _generate_login_id("IC", dob)
        email = f"{login_id.lower()}@iceberg.internal"

        user = CustomUser.objects.create_user(
            email=email,
            password=password,
            user_type=3,
            first_name=first_name,
            last_name=last_name,
            login_id=login_id,
        )
        user.gender = gender
        user.address = address
        user.date_of_birth = dob
        user.save()

        student = user.student
        if course_id:
            from ...models import Course as CourseModel

            try:
                student.course = CourseModel.objects.get(pk=course_id)
            except CourseModel.DoesNotExist:
                pass
        student.branch = branch
        student.phone = phone
        student.status = status_val
        student.level = int(level) if level else None
        student.save()

        return Response(
            AdminStudentSerializer(student, context={"request": request}).data,
            status=status.HTTP_201_CREATED,
        )


class AdminStudentDetailView(APIView):
    permission_classes = [IsAdmin]

    def _get_student(self, request, pk):
        try:
            student = Student.objects.select_related("admin", "course", "branch").get(pk=pk)
        except Student.DoesNotExist:
            return None, Response(
                {"detail": "Student not found."}, status=status.HTTP_404_NOT_FOUND
            )
        if not branching.is_super_admin(request.user):
            allowed = branching.filter_students_for_user(request.user, Student.objects.all())
            if not allowed.filter(pk=pk).exists():
                return None, Response(
                    {"detail": "Access denied."}, status=status.HTTP_403_FORBIDDEN
                )
        return student, None

    def get(self, request, pk):
        student, err = self._get_student(request, pk)
        if err:
            return err
        return Response(AdminStudentSerializer(student, context={"request": request}).data)

    def patch(self, request, pk):
        student, err = self._get_student(request, pk)
        if err:
            return err
        serializer = AdminStudentSerializer(
            student, data=request.data, partial=True, context={"request": request}
        )
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        serializer.save()
        return Response(serializer.data)

    def delete(self, request, pk):
        student, err = self._get_student(request, pk)
        if err:
            return err
        user = student.admin
        user.delete()  # deletes CustomUser; Student is deleted via CASCADE
        return Response(status=status.HTTP_204_NO_CONTENT)


# ---------------------------------------------------------------------------
# Admin: Staff management
# ---------------------------------------------------------------------------


class AdminStaffListView(generics.ListAPIView):
    permission_classes = [IsAdmin]
    serializer_class = AdminStaffSerializer

    def get_queryset(self):
        qs = Staff.objects.select_related("admin", "course", "branch")
        qs = branching.filter_staff_for_user(self.request.user, qs)
        search = self.request.query_params.get("search")
        active_filter = self.request.query_params.get("is_active")
        if active_filter is not None:
            qs = qs.filter(is_active=(active_filter == "1"))
        if search:
            qs = qs.filter(
                Q(admin__first_name__icontains=search)
                | Q(admin__last_name__icontains=search)
                | Q(admin__email__icontains=search)
                | Q(admin__login_id__icontains=search)
                | Q(phone__icontains=search)
            )
        return qs.order_by("admin__first_name")

    @transaction.atomic
    def post(self, request):
        """Create a new staff account."""
        from ...hod_views import _generate_login_id

        data = request.data
        first_name = data.get("first_name", "").strip()
        last_name = data.get("last_name", "").strip()
        password = data.get("password", "").strip()
        phone = data.get("phone", "").strip()
        specialization = data.get("specialization", "").strip()
        gender = data.get("gender", "M")
        course_id = data.get("course")
        branch_id = data.get("branch")
        dob_str = data.get("date_of_birth", "")

        if not first_name or not password:
            return Response(
                {"detail": "first_name and password are required."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            validate_password(password)
        except DjangoValidationError as exc:
            return Response({"password": exc.messages}, status=status.HTTP_400_BAD_REQUEST)

        dob = None
        if dob_str:
            try:
                dob = datetime.date.fromisoformat(dob_str)
            except ValueError:
                return Response(
                    {"detail": "Invalid date_of_birth format. Use YYYY-MM-DD."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        branch, error = _resolve_branch(request.user, branch_id)
        if error:
            return error

        login_id = _generate_login_id("TC", dob)
        email = f"{login_id.lower()}@iceberg.internal"

        user = CustomUser.objects.create_user(
            email=email,
            password=password,
            user_type=2,
            first_name=first_name,
            last_name=last_name,
            login_id=login_id,
        )
        user.gender = gender
        user.date_of_birth = dob
        user.save()

        staff = user.staff
        if course_id:
            from ...models import Course as CourseModel

            try:
                staff.course = CourseModel.objects.get(pk=course_id)
            except CourseModel.DoesNotExist:
                pass
        staff.branch = branch
        staff.phone = phone
        staff.specialization = specialization
        staff.save()

        return Response(
            AdminStaffSerializer(staff, context={"request": request}).data,
            status=status.HTTP_201_CREATED,
        )


class AdminStaffDetailView(APIView):
    permission_classes = [IsAdmin]

    def _get_staff(self, request, pk):
        try:
            staff = Staff.objects.select_related("admin", "course", "branch").get(pk=pk)
        except Staff.DoesNotExist:
            return None, Response({"detail": "Staff not found."}, status=status.HTTP_404_NOT_FOUND)
        if not branching.is_super_admin(request.user):
            allowed = branching.filter_staff_for_user(request.user, Staff.objects.all())
            if not allowed.filter(pk=pk).exists():
                return None, Response(
                    {"detail": "Access denied."}, status=status.HTTP_403_FORBIDDEN
                )
        return staff, None

    def get(self, request, pk):
        staff, err = self._get_staff(request, pk)
        if err:
            return err
        return Response(AdminStaffSerializer(staff, context={"request": request}).data)

    def patch(self, request, pk):
        staff, err = self._get_staff(request, pk)
        if err:
            return err
        serializer = AdminStaffSerializer(
            staff, data=request.data, partial=True, context={"request": request}
        )
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        serializer.save()
        return Response(serializer.data)

    def delete(self, request, pk):
        staff, err = self._get_staff(request, pk)
        if err:
            return err
        user = staff.admin
        user.delete()  # deletes CustomUser; Staff is deleted via CASCADE
        return Response(status=status.HTTP_204_NO_CONTENT)
