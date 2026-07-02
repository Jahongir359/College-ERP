from rest_framework import status
from rest_framework.pagination import PageNumberPagination
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from ... import branching
from ...models import Enrollment, Group, Notification, Student, StudentResult
from ..serializers import StudentResultSerializer


class ResultView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        group_id = request.query_params.get("group_id")

        qs = StudentResult.objects.select_related("student__admin", "group")
        qs = branching.filter_results_for_user(user, qs)

        if group_id:
            qs = qs.filter(group_id=group_id)

        paginator = PageNumberPagination()
        paginator.page_size = 20
        page = paginator.paginate_queryset(qs, request)
        serializer = StudentResultSerializer(page, many=True, context={"request": request})
        return paginator.get_paginated_response(serializer.data)

    def post(self, request):
        if str(request.user.user_type) not in ("1", "2"):
            return Response({"detail": "Permission denied."}, status=status.HTTP_403_FORBIDDEN)

        student_id = request.data.get("student_id")
        group_id = request.data.get("group_id")
        if not student_id or not group_id:
            return Response(
                {"detail": "student_id and group_id are required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            student = Student.objects.get(id=student_id)
            group = Group.objects.get(id=group_id)
        except (Student.DoesNotExist, Group.DoesNotExist):
            return Response(
                {"detail": "Student or group not found."}, status=status.HTTP_404_NOT_FOUND
            )

        if not branching.user_can_access_group(request.user, group):
            return Response(
                {"detail": "You can only update results for groups in your scope."},
                status=status.HTTP_403_FORBIDDEN,
            )

        # Object-level auth: the student must actually be enrolled in this group,
        # otherwise a teacher could write a result onto any student's record.
        if not Enrollment.objects.filter(student=student, group=group, is_active=True).exists():
            return Response(
                {"detail": "That student is not enrolled in this group."},
                status=status.HTTP_403_FORBIDDEN,
            )

        result, created = StudentResult.objects.update_or_create(
            student=student,
            group=group,
            defaults={
                "test": request.data.get("test", 0),
                "exam": request.data.get("exam", 0),
                "comment": request.data.get("comment", ""),
            },
        )

        Notification.objects.create(
            recipient=student.admin,
            category=Notification.RESULT,
            message=(
                f"Your result for {group.name}: "
                f"Test={result.test}, Exam={result.exam}."
                + (f" {result.comment}" if result.comment else "")
            ),
        )

        serializer = StudentResultSerializer(result, context={"request": request})
        return Response(
            serializer.data,
            status=status.HTTP_201_CREATED if created else status.HTTP_200_OK,
        )
