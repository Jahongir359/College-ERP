from rest_framework import status
from rest_framework.pagination import PageNumberPagination
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from ... import branching
from ...models import LeaveReportStaff, LeaveReportStudent, Staff, Student
from ..permissions import IsAdmin
from ..serializers import (
    AdminStaffLeaveSerializer,
    AdminStudentLeaveSerializer,
    StaffLeaveSerializer,
    StudentLeaveSerializer,
)


class LeaveView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        user_type = str(user.user_type)

        if user_type == "3":
            try:
                qs = LeaveReportStudent.objects.filter(student=user.student).order_by("-created_at")
            except Student.DoesNotExist:
                return Response({"count": 0, "results": []})
            paginator = PageNumberPagination()
            paginator.page_size = 20
            page = paginator.paginate_queryset(qs, request)
            return paginator.get_paginated_response(StudentLeaveSerializer(page, many=True).data)

        if user_type == "2":
            try:
                qs = LeaveReportStaff.objects.filter(staff=user.staff).order_by("-created_at")
            except Staff.DoesNotExist:
                return Response({"count": 0, "results": []})
            paginator = PageNumberPagination()
            paginator.page_size = 20
            page = paginator.paginate_queryset(qs, request)
            return paginator.get_paginated_response(StaffLeaveSerializer(page, many=True).data)

        # Admin: return combined leave from both students and staff with optional filters
        if user_type == "1":
            leave_type = request.query_params.get("type", "student")
            status_filter = request.query_params.get("status")
            paginator = PageNumberPagination()
            paginator.page_size = 20

            if leave_type == "staff":
                # Branch isolation: branch admins only see leave from staff in their
                # branches; super admins see all (filter_staff_for_user returns the
                # full queryset for super admins).
                allowed_staff = branching.filter_staff_for_user(user, Staff.objects.all())
                qs = (
                    LeaveReportStaff.objects.filter(staff__in=allowed_staff)
                    .select_related("staff__admin")
                    .order_by("-created_at")
                )
                if status_filter is not None:
                    qs = qs.filter(status=status_filter)
                page = paginator.paginate_queryset(qs, request)
                return paginator.get_paginated_response(
                    AdminStaffLeaveSerializer(page, many=True).data
                )
            else:
                allowed_students = branching.filter_students_for_user(user, Student.objects.all())
                qs = (
                    LeaveReportStudent.objects.filter(student__in=allowed_students)
                    .select_related("student__admin")
                    .order_by("-created_at")
                )
                if status_filter is not None:
                    qs = qs.filter(status=status_filter)
                page = paginator.paginate_queryset(qs, request)
                return paginator.get_paginated_response(
                    AdminStudentLeaveSerializer(page, many=True).data
                )

        return Response({"detail": "Permission denied."}, status=status.HTTP_403_FORBIDDEN)

    def post(self, request):
        user = request.user
        user_type = str(user.user_type)

        if user_type == "3":
            try:
                student = user.student
            except Student.DoesNotExist:
                return Response(
                    {"detail": "Student profile not found."}, status=status.HTTP_403_FORBIDDEN
                )
            serializer = StudentLeaveSerializer(data=request.data)
            if not serializer.is_valid():
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            leave = serializer.save(student=student)
            return Response(StudentLeaveSerializer(leave).data, status=status.HTTP_201_CREATED)

        if user_type == "2":
            try:
                staff = user.staff
            except Staff.DoesNotExist:
                return Response(
                    {"detail": "Staff profile not found."}, status=status.HTTP_403_FORBIDDEN
                )
            serializer = StaffLeaveSerializer(data=request.data)
            if not serializer.is_valid():
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            leave = serializer.save(staff=staff)
            return Response(StaffLeaveSerializer(leave).data, status=status.HTTP_201_CREATED)

        return Response({"detail": "Permission denied."}, status=status.HTTP_403_FORBIDDEN)


class LeaveDetailView(APIView):
    """Admin: PATCH to approve (status=1) or reject (status=-1)."""

    permission_classes = [IsAdmin]

    def patch(self, request, pk):
        leave_type = request.query_params.get("type", "student")
        new_status = request.data.get("status")

        if new_status not in (1, -1, "1", "-1"):
            return Response(
                {"detail": "status must be 1 (approved) or -1 (rejected)."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        new_status = int(new_status)

        if leave_type == "staff":
            try:
                leave = LeaveReportStaff.objects.get(pk=pk)
            except LeaveReportStaff.DoesNotExist:
                return Response({"detail": "Leave not found."}, status=status.HTTP_404_NOT_FOUND)
            # Branch isolation: a branch admin may only action staff in their scope.
            if not branching.filter_staff_for_user(
                request.user, Staff.objects.filter(pk=leave.staff_id)
            ).exists():
                return Response(
                    {"detail": "Outside your branch scope."}, status=status.HTTP_403_FORBIDDEN
                )
            leave.status = new_status
            leave.save(update_fields=["status", "updated_at"])
            return Response(AdminStaffLeaveSerializer(leave).data)
        else:
            try:
                leave = LeaveReportStudent.objects.get(pk=pk)
            except LeaveReportStudent.DoesNotExist:
                return Response({"detail": "Leave not found."}, status=status.HTTP_404_NOT_FOUND)
            # Branch isolation: a branch admin may only action students in their scope.
            if not branching.filter_students_for_user(
                request.user, Student.objects.filter(pk=leave.student_id)
            ).exists():
                return Response(
                    {"detail": "Outside your branch scope."}, status=status.HTTP_403_FORBIDDEN
                )
            leave.status = new_status
            leave.save(update_fields=["status", "updated_at"])
            return Response(AdminStudentLeaveSerializer(leave).data)
