from django.db import transaction
from rest_framework import status
from rest_framework.pagination import PageNumberPagination
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from ... import branching
from ...models import Attendance, AttendanceReport, Enrollment, Group
from ..family import student_for_request
from ..serializers import AttendanceSaveSerializer, AttendanceSerializer


class AttendanceView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        user_type = str(user.user_type)
        group_id = request.query_params.get("group_id")
        date_str = request.query_params.get("date")

        if user_type in ("3", "4"):
            student, error = student_for_request(request)
            if error is not None:
                if user_type == "3":
                    return Response({"count": 0, "results": []})
                return error
            reports = (
                AttendanceReport.objects.filter(student=student)
                .select_related("attendance__group")
                .order_by("-attendance__date")
            )
            if group_id:
                reports = reports.filter(attendance__group_id=group_id)
            paginator = PageNumberPagination()
            paginator.page_size = 20
            page = paginator.paginate_queryset(reports, request)
            data = [
                {
                    "date": r.attendance.date,
                    "group_id": r.attendance.group_id,
                    "group_name": r.attendance.group.name if r.attendance.group else None,
                    "status": r.status,
                    "status_display": r.get_status_display(),
                }
                for r in page
            ]
            return paginator.get_paginated_response(data)

        qs = Attendance.objects.select_related("group").prefetch_related(
            "attendancereport_set__student__admin"
        )
        qs = branching.filter_attendance_for_user(user, qs)
        if group_id:
            qs = qs.filter(group_id=group_id)
        if date_str:
            qs = qs.filter(date=date_str)
        qs = qs.order_by("-date")

        paginator = PageNumberPagination()
        paginator.page_size = 20
        page = paginator.paginate_queryset(qs, request)
        serializer = AttendanceSerializer(page, many=True, context={"request": request})
        return paginator.get_paginated_response(serializer.data)

    def post(self, request):
        if str(request.user.user_type) not in ("1", "2"):
            return Response({"detail": "Permission denied."}, status=status.HTTP_403_FORBIDDEN)

        serializer = AttendanceSaveSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        data = serializer.validated_data
        try:
            group = Group.objects.get(id=data["group_id"])
        except Group.DoesNotExist:
            return Response({"detail": "Group not found."}, status=status.HTTP_404_NOT_FOUND)

        if not branching.user_can_access_group(request.user, group):
            return Response(
                {"detail": "You can only take attendance for groups in your scope."},
                status=status.HTTP_403_FORBIDDEN,
            )

        records = data["records"]
        # Object-level auth: only accept records for students actually enrolled in
        # this group. Without this filter a teacher could write attendance onto any
        # student's record by supplying an arbitrary student_id.
        enrolled_ids = set(
            Enrollment.objects.filter(group=group, is_active=True).values_list(
                "student_id", flat=True
            )
        )
        with transaction.atomic():
            attendance, _ = Attendance.objects.get_or_create(group=group, date=data["date"])
            existing = {
                r.student_id: r for r in AttendanceReport.objects.filter(attendance=attendance)
            }
            to_create, to_update = [], []
            for rec in records:
                sid = int(rec["student_id"])
                if sid not in enrolled_ids:
                    continue
                st = int(rec["status"])
                if sid in existing:
                    existing[sid].status = st
                    to_update.append(existing[sid])
                else:
                    to_create.append(
                        AttendanceReport(attendance=attendance, student_id=sid, status=st)
                    )
            if to_create:
                AttendanceReport.objects.bulk_create(to_create)
            if to_update:
                AttendanceReport.objects.bulk_update(to_update, ["status"])

        return Response({"detail": "Attendance saved.", "attendance_id": attendance.id})
