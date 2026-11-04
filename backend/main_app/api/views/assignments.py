from rest_framework import generics, status
from rest_framework.pagination import PageNumberPagination
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from ... import branching
from ...models import Assignment, Enrollment, Staff, Student, Submission
from ..family import student_for_request
from ..permissions import IsStudent
from ..serializers import (
    AssignmentDetailSerializer,
    AssignmentSerializer,
    SubmissionSerializer,
    SubmitAssignmentSerializer,
)


class AssignmentListView(APIView):
    permission_classes = [IsAuthenticated]

    def _queryset(self, user):
        user_type = str(user.user_type)
        qs = Assignment.objects.select_related("group", "created_by__admin")
        if user_type == "1":
            if branching.is_super_admin(user):
                return qs
            ids = list(branching.get_accessible_branches(user).values_list("id", flat=True))
            return qs.filter(group__branch_id__in=ids)
        if user_type == "2":
            try:
                return qs.filter(created_by=user.staff)
            except Staff.DoesNotExist:
                return qs.none()
        if user_type == "3":
            try:
                ids = Enrollment.objects.filter(
                    student=user.student,
                    is_active=True,
                ).values_list("group_id", flat=True)
                return qs.filter(group_id__in=ids)
            except Student.DoesNotExist:
                return qs.none()
        return qs.none()

    def get(self, request):
        if str(request.user.user_type) == "4":
            # Parents (plan P4.4, P4.8): one child's homework, read-only, chosen
            # with ?student=<id> (family.py). No submission data: status stays None.
            # The child must always be named here, even in a one-child family.
            if not request.query_params.get("student", "").strip():
                return Response({"detail": "Student not found."}, status=status.HTTP_404_NOT_FOUND)
            student, error = student_for_request(request)
            if error is not None:
                return error
            groups = Enrollment.objects.filter(student=student, is_active=True).values("group_id")
            qs = Assignment.objects.select_related("group", "created_by__admin").filter(
                group_id__in=groups
            )
        else:
            qs = self._queryset(request.user)
        qs = qs.select_related("subject").order_by("-created_at")

        context = {"request": request}
        if str(request.user.user_type) == "3":
            try:
                subs = Submission.objects.filter(student=request.user.student, assignment__in=qs)
                context["submission_map"] = {s.assignment_id: s for s in subs}
            except Student.DoesNotExist:
                context["submission_map"] = {}

        paginator = PageNumberPagination()
        paginator.page_size = 50
        page = paginator.paginate_queryset(qs, request)
        serializer = AssignmentSerializer(page, many=True, context=context)
        return paginator.get_paginated_response(serializer.data)

    def post(self, request):
        if str(request.user.user_type) not in ("1", "2"):
            return Response({"detail": "Permission denied."}, status=status.HTTP_403_FORBIDDEN)
        try:
            staff = request.user.staff
        except Staff.DoesNotExist:
            return Response(
                {"detail": "Staff profile not found."}, status=status.HTTP_403_FORBIDDEN
            )

        serializer = AssignmentSerializer(data=request.data, context={"request": request})
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        # Object-level auth: only create assignments for a group the caller may
        # access (a teacher's own group, or a branch admin's branch). Without
        # this a teacher could target any group by id.
        group = serializer.validated_data.get("group")
        if group is None or not branching.user_can_access_group(request.user, group):
            return Response(
                {"detail": "You can only create assignments for your own groups."},
                status=status.HTTP_403_FORBIDDEN,
            )
        assignment = serializer.save(created_by=staff)
        return Response(
            AssignmentSerializer(assignment, context={"request": request}).data,
            status=status.HTTP_201_CREATED,
        )


class AssignmentDetailView(generics.RetrieveAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = AssignmentDetailSerializer

    def get_queryset(self):
        user = self.request.user
        user_type = str(user.user_type)
        qs = Assignment.objects.select_related("group", "created_by__admin")
        if user_type == "1":
            if branching.is_super_admin(user):
                return qs
            ids = list(branching.get_accessible_branches(user).values_list("id", flat=True))
            return qs.filter(group__branch_id__in=ids)
        if user_type == "2":
            try:
                return qs.filter(created_by=user.staff)
            except Staff.DoesNotExist:
                return qs.none()
        if user_type == "3":
            try:
                ids = Enrollment.objects.filter(
                    student=user.student,
                    is_active=True,
                ).values_list("group_id", flat=True)
                return qs.filter(group_id__in=ids)
            except Student.DoesNotExist:
                return qs.none()
        return qs.none()


class SubmitAssignmentView(APIView):
    permission_classes = [IsStudent]

    def post(self, request, pk):
        try:
            assignment = Assignment.objects.get(pk=pk)
        except Assignment.DoesNotExist:
            return Response({"detail": "Assignment not found."}, status=status.HTTP_404_NOT_FOUND)

        try:
            student = request.user.student
        except Student.DoesNotExist:
            return Response(
                {"detail": "Student profile not found."}, status=status.HTTP_403_FORBIDDEN
            )

        if not Enrollment.objects.filter(
            student=student, group=assignment.group, is_active=True
        ).exists():
            return Response(
                {"detail": "You are not enrolled in this group."}, status=status.HTTP_403_FORBIDDEN
            )

        serializer = SubmitAssignmentSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        submission, created = Submission.objects.update_or_create(
            assignment=assignment,
            student=student,
            defaults={
                "file": serializer.validated_data.get("file"),
                "note": serializer.validated_data.get("note", ""),
            },
        )
        return Response(
            SubmissionSerializer(submission, context={"request": request}).data,
            status=status.HTTP_201_CREATED if created else status.HTTP_200_OK,
        )
