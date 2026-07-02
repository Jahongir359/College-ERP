from rest_framework import status
from rest_framework.pagination import PageNumberPagination
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from ... import branching
from ...models import FeedbackStaff, FeedbackStudent, Staff, Student
from ..permissions import IsAdmin
from ..serializers import (
    AdminStaffFeedbackSerializer,
    AdminStudentFeedbackSerializer,
    StaffFeedbackSerializer,
    StudentFeedbackSerializer,
)


class FeedbackView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        user_type = str(user.user_type)
        paginator = PageNumberPagination()
        paginator.page_size = 20

        if user_type == "3":
            try:
                qs = FeedbackStudent.objects.filter(student=user.student).order_by("-created_at")
            except Student.DoesNotExist:
                return Response({"count": 0, "results": []})
            page = paginator.paginate_queryset(qs, request)
            return paginator.get_paginated_response(StudentFeedbackSerializer(page, many=True).data)

        if user_type == "2":
            try:
                qs = FeedbackStaff.objects.filter(staff=user.staff).order_by("-created_at")
            except Staff.DoesNotExist:
                return Response({"count": 0, "results": []})
            page = paginator.paginate_queryset(qs, request)
            return paginator.get_paginated_response(StaffFeedbackSerializer(page, many=True).data)

        if user_type == "1":
            feedback_type = request.query_params.get("type", "student")
            if feedback_type == "staff":
                # Branch isolation: a branch admin only sees feedback from staff in
                # their branches; a super admin sees all (filter_staff_for_user
                # returns the full queryset for super admins).
                allowed_staff = branching.filter_staff_for_user(user, Staff.objects.all())
                qs = (
                    FeedbackStaff.objects.filter(staff__in=allowed_staff)
                    .select_related("staff__admin")
                    .order_by("-created_at")
                )
                page = paginator.paginate_queryset(qs, request)
                return paginator.get_paginated_response(
                    AdminStaffFeedbackSerializer(page, many=True).data
                )
            else:
                allowed_students = branching.filter_students_for_user(user, Student.objects.all())
                qs = (
                    FeedbackStudent.objects.filter(student__in=allowed_students)
                    .select_related("student__admin")
                    .order_by("-created_at")
                )
                page = paginator.paginate_queryset(qs, request)
                return paginator.get_paginated_response(
                    AdminStudentFeedbackSerializer(page, many=True).data
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
            text = request.data.get("feedback", "").strip()
            if not text:
                return Response(
                    {"feedback": "This field is required."}, status=status.HTTP_400_BAD_REQUEST
                )
            fb = FeedbackStudent.objects.create(student=student, feedback=text)
            return Response(StudentFeedbackSerializer(fb).data, status=status.HTTP_201_CREATED)

        if user_type == "2":
            try:
                staff = user.staff
            except Staff.DoesNotExist:
                return Response(
                    {"detail": "Staff profile not found."}, status=status.HTTP_403_FORBIDDEN
                )
            text = request.data.get("feedback", "").strip()
            if not text:
                return Response(
                    {"feedback": "This field is required."}, status=status.HTTP_400_BAD_REQUEST
                )
            fb = FeedbackStaff.objects.create(staff=staff, feedback=text)
            return Response(StaffFeedbackSerializer(fb).data, status=status.HTTP_201_CREATED)

        return Response({"detail": "Permission denied."}, status=status.HTTP_403_FORBIDDEN)


class FeedbackDetailView(APIView):
    """Admin: PATCH to add a reply."""

    permission_classes = [IsAdmin]

    def patch(self, request, pk):
        feedback_type = request.query_params.get("type", "student")
        reply = request.data.get("reply", "").strip()
        if not reply:
            return Response(
                {"reply": "Reply text is required."}, status=status.HTTP_400_BAD_REQUEST
            )

        if feedback_type == "staff":
            try:
                fb = FeedbackStaff.objects.get(pk=pk)
            except FeedbackStaff.DoesNotExist:
                return Response({"detail": "Feedback not found."}, status=status.HTTP_404_NOT_FOUND)
            # Branch isolation: a branch admin may only reply to staff in their scope.
            if not branching.filter_staff_for_user(
                request.user, Staff.objects.filter(pk=fb.staff_id)
            ).exists():
                return Response(
                    {"detail": "Outside your branch scope."}, status=status.HTTP_403_FORBIDDEN
                )
            fb.reply = reply
            fb.save(update_fields=["reply", "updated_at"])
            return Response(AdminStaffFeedbackSerializer(fb).data)
        else:
            try:
                fb = FeedbackStudent.objects.get(pk=pk)
            except FeedbackStudent.DoesNotExist:
                return Response({"detail": "Feedback not found."}, status=status.HTTP_404_NOT_FOUND)
            # Branch isolation: a branch admin may only reply to students in their scope.
            if not branching.filter_students_for_user(
                request.user, Student.objects.filter(pk=fb.student_id)
            ).exists():
                return Response(
                    {"detail": "Outside your branch scope."}, status=status.HTTP_403_FORBIDDEN
                )
            fb.reply = reply
            fb.save(update_fields=["reply", "updated_at"])
            return Response(AdminStudentFeedbackSerializer(fb).data)
