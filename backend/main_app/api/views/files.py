from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from ... import branching
from ...models import Enrollment, Group, Notification, ResultFile, Staff, Student
from ..permissions import IsAdminOrTeacher


class FileUploadView(APIView):
    permission_classes = [IsAdminOrTeacher]

    def post(self, request):
        file_obj = request.FILES.get("file")
        if not file_obj:
            return Response({"detail": "No file provided."}, status=status.HTTP_400_BAD_REQUEST)

        group_id = request.data.get("group_id")
        if not group_id:
            return Response({"detail": "group_id is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            group = Group.objects.get(id=group_id)
        except Group.DoesNotExist:
            return Response({"detail": "Group not found."}, status=status.HTTP_404_NOT_FOUND)

        user_type = str(request.user.user_type)
        if user_type == "2":
            try:
                staff = request.user.staff
            except Staff.DoesNotExist:
                return Response(
                    {"detail": "Staff profile not found."}, status=status.HTTP_403_FORBIDDEN
                )
            if group.teacher_id != staff.id:
                return Response(
                    {"detail": "You are not the teacher of this group."},
                    status=status.HTTP_403_FORBIDDEN,
                )
        else:
            # Admin upload: branch-scoped, and attributed to the group's teacher
            # because ResultFile.uploaded_by is a required FK to Staff (passing
            # None here used to crash with an IntegrityError → 500).
            if not branching.user_can_access_group(request.user, group):
                return Response({"detail": "Group not found."}, status=status.HTTP_404_NOT_FOUND)
            staff = group.teacher
            if staff is None:
                return Response(
                    {"detail": "Assign a teacher to this group before uploading result files."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        student_id = request.data.get("student_id")
        student = None
        if student_id:
            try:
                student = Student.objects.get(id=student_id)
            except Student.DoesNotExist:
                return Response({"detail": "Student not found."}, status=status.HTTP_404_NOT_FOUND)
            if not Enrollment.objects.filter(student=student, group=group, is_active=True).exists():
                return Response(
                    {"detail": "Student is not enrolled in this group."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        title = request.data.get("title", file_obj.name)
        description = request.data.get("description", "")

        result_file = ResultFile.objects.create(
            group=group,
            student=student,
            file=file_obj,
            title=title,
            description=description,
            uploaded_by=staff,
        )

        if student:
            Notification.objects.create(
                recipient=student.admin,
                category=Notification.RESULT,
                message=f"New result file: {title}",
            )

        return Response(
            {
                "id": result_file.id,
                "title": result_file.title,
                "file_url": request.build_absolute_uri(result_file.file.url),
                "uploaded_at": result_file.uploaded_at,
            },
            status=status.HTTP_201_CREATED,
        )
