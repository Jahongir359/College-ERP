import datetime

from django.conf import settings
from django.core.cache import cache
from django.db import models
from django.db.models import Count, DecimalField, F, Q, Sum
from django.db.models.functions import Coalesce
from rest_framework import generics, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from ... import branching
from ...models import (
    Assignment,
    AttendanceReport,
    Branch,
    Course,
    CustomUser,
    DashboardStory,
    Enrollment,
    Group,
    Invoice,
    LeaderboardSnapshot,
    Notification,
    Payment,
    RegistrationLead,
    Staff,
    Student,
    StudentResult,
    Submission,
    VocabularyDay,
    class_enrollment_conflict,
)
from ..permissions import IsAdmin
from ..serializers import EnrollmentSerializer, GroupSerializer, UserSerializer


class AdminStatsView(APIView):
    permission_classes = [IsAdmin]

    def get(self, request):
        user = request.user
        cache_key = f"admin_stats:{user.pk}"
        cached = cache.get(cache_key)
        if cached is not None:
            return Response(cached)

        students = branching.filter_students_for_user(user, Student.objects.all())
        staff = branching.filter_staff_for_user(user, Staff.objects.all())
        groups = branching.filter_groups_for_user(user, Group.objects.all())
        payload = {
            "student_count": students.count(),
            "active_students": students.filter(status="active").count(),
            "staff_count": staff.count(),
            "group_count": groups.filter(is_archived=False).count(),
            "archived_groups": groups.filter(is_archived=True).count(),
            "course_count": Course.objects.filter(is_active=True).count(),
        }
        cache.set(cache_key, payload, settings.DASHBOARD_CACHE_TTL)
        return Response(payload)


class AdminUserListView(generics.ListAPIView):
    permission_classes = [IsAdmin]
    serializer_class = UserSerializer

    def get_queryset(self):
        qs = CustomUser.objects.all()
        if not branching.is_super_admin(self.request.user):
            allowed_students = branching.filter_students_for_user(
                self.request.user, Student.objects.all()
            )
            allowed_staff = branching.filter_staff_for_user(self.request.user, Staff.objects.all())
            qs = qs.filter(Q(student__in=allowed_students) | Q(staff__in=allowed_staff))
        user_type = self.request.query_params.get("user_type")
        if user_type:
            qs = qs.filter(user_type=user_type)
        search = self.request.query_params.get("search")
        if search:
            qs = qs.filter(
                Q(first_name__icontains=search)
                | Q(last_name__icontains=search)
                | Q(email__icontains=search)
            )
        return qs.order_by("-date_joined")


class AdminGroupListView(generics.ListAPIView):
    permission_classes = [IsAdmin]
    serializer_class = GroupSerializer

    def get_queryset(self):
        qs = Group.objects.select_related("course", "teacher__admin", "branch")
        if self.request.query_params.get("archived") != "1":
            qs = qs.filter(is_archived=False)
        return branching.filter_groups_for_user(self.request.user, qs)


class AdminEnrollmentView(APIView):
    permission_classes = [IsAdmin]

    def post(self, request):
        serializer = EnrollmentSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        student = serializer.validated_data["student"]
        group = serializer.validated_data["group"]

        if not branching.user_can_access_group(request.user, group):
            return Response(
                {"detail": "You don't have access to that group's branch."},
                status=status.HTTP_403_FORBIDDEN,
            )
        if (
            not branching.is_super_admin(request.user)
            and group.branch_id
            and student.branch_id
            and group.branch_id != student.branch_id
        ):
            return Response(
                {"detail": "Student belongs to a different branch than the group."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        other_class = class_enrollment_conflict(student.id, group)
        if other_class is not None:
            return Response(
                {"detail": f"Student is already in class {other_class.name} this academic year."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        enrollment, created = Enrollment.objects.get_or_create(
            student=student, group=group, defaults={"is_active": True}
        )
        if not created and not enrollment.is_active:
            enrollment.is_active = True
            enrollment.save(update_fields=["is_active"])

        return Response(
            EnrollmentSerializer(enrollment).data,
            status=status.HTTP_201_CREATED if created else status.HTTP_200_OK,
        )

    def delete(self, request):
        student_id = request.data.get("student")
        group_id = request.data.get("group")
        scoped = branching.filter_enrollments_for_user(request.user, Enrollment.objects.all())
        updated = scoped.filter(
            student_id=student_id,
            group_id=group_id,
        ).update(is_active=False)
        if not updated:
            return Response({"detail": "Enrollment not found."}, status=status.HTTP_404_NOT_FOUND)
        return Response({"detail": "Student unenrolled."})


class AdminBranchListView(generics.ListAPIView):
    """Superadmin: list all branches; branch-admin: list own branches."""

    permission_classes = [IsAdmin]

    def get_serializer_class(self):
        from ..serializers import BranchSerializer

        return BranchSerializer

    def get_queryset(self):
        return branching.get_accessible_branches(self.request.user)


class StudentDashboardView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        if str(user.user_type) != "3":
            return Response({"detail": "Permission denied."}, status=status.HTTP_403_FORBIDDEN)

        cache_key = f"student_dashboard:{user.pk}"
        cached = cache.get(cache_key)
        if cached is not None:
            return Response(cached)

        from django.utils import timezone as tz

        try:
            student = user.student
        except Student.DoesNotExist:
            return Response(
                {
                    "rank": None,
                    "tier": "",
                    "streak_days": 0,
                    "attendance_percentage": None,
                    "total_subjects": 0,
                    "average_score": None,
                    "enrolled_groups": 0,
                    "pending_assignments": 0,
                    "unread_notifications": 0,
                    "new_vocab_words": 0,
                    "performance_trend": [],
                    "notices": [],
                    "stories": [],
                    "assignments_preview": [],
                }
            )

        # Attendance
        reports = AttendanceReport.objects.filter(student=student)
        total = reports.count()
        present = reports.filter(status=AttendanceReport.PRESENT).count()
        att_pct = round(present / total * 100, 1) if total > 0 else None

        # Enrollments
        enrollments = Enrollment.objects.filter(student=student, is_active=True).select_related(
            "group__course", "group__teacher__admin"
        )
        enrolled_count = enrollments.count()
        course_ids = {e.group.course_id for e in enrollments if e.group.course_id}
        total_subjects = len(course_ids) if course_ids else enrolled_count
        enrolled_group_ids = [e.group_id for e in enrollments]

        # Enrolled classes (group schedule cards on the home dashboard)
        classes = [
            {
                "id": e.group_id,
                "name": e.group.name,
                "course_name": e.group.course.name if e.group.course_id else "",
                "room": e.group.room,
                "schedule": e.group.schedule,
                "teacher_name": (
                    e.group.teacher.admin.get_full_name()
                    if e.group.teacher_id and e.group.teacher.admin_id
                    else ""
                ),
            }
            for e in enrollments
        ]

        # Results / performance trend (last 8 scores)
        results = list(StudentResult.objects.filter(student=student).order_by("-id")[:8])
        scores = [r.test + r.exam for r in results]
        avg_score = round(sum(scores) / len(scores), 1) if scores else None
        # Return oldest→newest dicts so the chart can plot attendance_pct on Y.
        # test+exam is out of 100, so the value is already a percentage.
        performance_trend = [
            {
                "attendance_pct": round(r.test + r.exam, 1),
                "label": r.created_at.strftime("%-m/%-d") if r.created_at else str(i + 1),
            }
            for i, r in enumerate(reversed(results))
        ]

        # Rank from latest leaderboard snapshot
        rank = None
        tier = ""
        snapshot = (
            LeaderboardSnapshot.objects.filter(student=student)
            .select_related("season")
            .order_by("-season__start_date", "-id")
            .first()
        )
        if snapshot:
            rank = snapshot.rank
            tier = snapshot.badge

        # Notifications
        unread_count = Notification.objects.filter(recipient=user, is_read=False).count()
        notifications = Notification.objects.filter(recipient=user).order_by("-created_at")[:5]
        notices = [{"title": n.get_category_display(), "message": n.message} for n in notifications]

        # Pending assignments (due in future, not yet submitted)
        now = tz.now()
        submitted_ids = set(
            Submission.objects.filter(student=student).values_list("assignment_id", flat=True)
        )
        pending_qs = Assignment.objects.filter(
            group_id__in=enrolled_group_ids,
            due_date__gte=now,
        ).exclude(id__in=submitted_ids)
        pending_count = pending_qs.count()

        # Upcoming assignments preview (next 3)
        upcoming = pending_qs.order_by("due_date")[:3]
        assignments_preview = [
            {
                "id": a.id,
                "title": a.title,
                "due_date": a.due_date.isoformat() if a.due_date else None,
            }
            for a in upcoming
        ]

        # New vocab words added in the last 7 days
        week_ago = now - datetime.timedelta(days=7)
        new_vocab = VocabularyDay.objects.filter(
            group_id__in=enrolled_group_ids,
            created_at__gte=week_ago,
        ).count()

        # Stories visible to this student
        stories_qs = (
            DashboardStory.objects.filter(is_active=True)
            .filter(models.Q(expires_at__isnull=True) | models.Q(expires_at__gt=now))
            .prefetch_related("target_groups")
            .order_by("-created_at")[:20]
        )
        stories_out = []
        for s in stories_qs:
            target_ids = [g.id for g in s.target_groups.all()]
            if not target_ids or any(gid in target_ids for gid in enrolled_group_ids):
                stories_out.append(
                    {
                        "id": s.id,
                        "title": s.title,
                        "content": s.body,
                        "story_type": s.story_type,
                        "emoji": s.emoji,
                        "image_url": (
                            request.build_absolute_uri(s.safe_image_url)
                            if s.safe_image_url
                            else None
                        ),
                        "created_at": s.created_at.isoformat(),
                        "author_name": s.created_by.get_full_name() if s.created_by else "",
                    }
                )

        # Outstanding balance (sum of unpaid amounts minus payments already made)
        unpaid_invoices = Invoice.objects.filter(
            student=student,
            status__in=[Invoice.STATUS_DUE, Invoice.STATUS_PARTIAL],
        )
        gross_due = unpaid_invoices.aggregate(
            total=Coalesce(
                Sum(F("amount") - F("discount")),
                0,
                output_field=DecimalField(),
            )
        )["total"]
        paid_against = Payment.objects.filter(invoice__in=unpaid_invoices).aggregate(
            total=Coalesce(Sum("amount"), 0, output_field=DecimalField())
        )["total"]
        balance_due = max(0, int(gross_due - paid_against))
        next_inv = unpaid_invoices.order_by("due_date").first()
        balance_due_date = next_inv.due_date.isoformat() if next_inv else None

        payload = {
            "rank": rank,
            "tier": tier,
            "streak_days": 0,  # streak tracking not yet implemented
            "attendance_percentage": att_pct,
            "total_subjects": total_subjects,
            "average_score": avg_score,
            "enrolled_groups": enrolled_count,
            "pending_assignments": pending_count,
            "unread_notifications": unread_count,
            "new_vocab_words": new_vocab,
            "performance_trend": performance_trend,
            "notices": notices,
            "stories": stories_out,
            "assignments_preview": assignments_preview,
            "classes": classes,
            "balance_due": balance_due,
            "balance_due_date": balance_due_date,
        }
        cache.set(cache_key, payload, settings.DASHBOARD_CACHE_TTL)
        return Response(payload)


class AdminDashboardView(APIView):
    permission_classes = [IsAdmin]

    def get(self, request):
        user = request.user

        cache_key = f"admin_dashboard:{user.pk}"
        cached = cache.get(cache_key)
        if cached is not None:
            return Response(cached)

        students = branching.filter_students_for_user(user, Student.objects.all())
        staff = branching.filter_staff_for_user(user, Staff.objects.all())
        groups = branching.filter_groups_for_user(user, Group.objects.filter(is_archived=False))
        group_ids = list(groups.values_list("id", flat=True))

        today = datetime.date.today()
        window_start = today - datetime.timedelta(days=6)
        per_day = (
            AttendanceReport.objects.filter(attendance__group_id__in=group_ids)
            .values("attendance__date")
            .filter(attendance__date__gte=window_start, attendance__date__lte=today)
            .annotate(
                total=Count("id"),
                present=Count("id", filter=Q(status=AttendanceReport.PRESENT)),
            )
        )
        by_day = {row["attendance__date"]: row for row in per_day}
        spark = []
        for i in range(6, -1, -1):
            row = by_day.get(today - datetime.timedelta(days=i))
            if row and row["total"]:
                spark.append(round(row["present"] / row["total"] * 100))
            else:
                spark.append(0)

        totals = AttendanceReport.objects.filter(attendance__group_id__in=group_ids).aggregate(
            total=Count("id"),
            present=Count("id", filter=Q(status=AttendanceReport.PRESENT)),
        )
        avg_att = round(totals["present"] / totals["total"] * 100, 1) if totals["total"] else None

        leads = RegistrationLead.objects.all()
        total_branches = Branch.objects.count()

        recent_leads = []
        for lead in leads.order_by("-created_at")[:5]:
            recent_leads.append(
                {
                    "name": lead.name,
                    "phone": lead.phone,
                    "course": getattr(lead, "interested_course", "") or "",
                    "date": lead.created_at.strftime("%b %d")
                    if getattr(lead, "created_at", None)
                    else "",
                }
            )

        recent_enrollments = []
        for e in (
            Enrollment.objects.filter(group_id__in=group_ids)
            .select_related("student__admin", "group")
            .order_by("-id")[:5]
        ):
            try:
                student_name = e.student.admin.get_full_name() or str(e.student)
            except Exception:
                student_name = str(e.student)
            recent_enrollments.append(
                {
                    "student": student_name,
                    "group": e.group.name if e.group else "",
                }
            )

        payload = {
            "total_students": students.count(),
            "total_staff": staff.count(),
            "total_groups": groups.count(),
            "avg_attendance": avg_att,
            "new_leads": leads.count(),
            "total_leads": leads.count(),
            "total_branches": total_branches,
            "attendance_spark": spark,
            "recent_leads": recent_leads,
            "recent_enrollments": recent_enrollments,
        }
        cache.set(cache_key, payload, settings.DASHBOARD_CACHE_TTL)
        return Response(payload)


class StaffStatsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        user_type = str(user.user_type)
        today = datetime.date.today()

        cache_key = f"staff_stats:{user.pk}"
        cached = cache.get(cache_key)
        if cached is not None:
            return Response(cached)

        if user_type == "2":
            try:
                staff = user.staff
            except Staff.DoesNotExist:
                return Response(
                    {
                        "total_students": 0,
                        "total_groups": 0,
                        "sessions_today": 0,
                        "avg_attendance": None,
                    }
                )
            from ...models import Attendance

            groups = Group.objects.filter(teacher=staff, is_archived=False)
            group_ids = list(groups.values_list("id", flat=True))
            student_ids = (
                Enrollment.objects.filter(group_id__in=group_ids, is_active=True)
                .values_list("student_id", flat=True)
                .distinct()
            )
            sessions_today = Attendance.objects.filter(group_id__in=group_ids, date=today).count()
            total_reports = AttendanceReport.objects.filter(
                attendance__group_id__in=group_ids
            ).count()
            present_reports = AttendanceReport.objects.filter(
                attendance__group_id__in=group_ids,
                status=AttendanceReport.PRESENT,
            ).count()
            avg_att = round(present_reports / total_reports * 100, 1) if total_reports else None
            payload = {
                "total_students": len(set(student_ids)),
                "total_groups": groups.count(),
                "sessions_today": sessions_today,
                "avg_attendance": avg_att,
            }
            cache.set(cache_key, payload, settings.DASHBOARD_CACHE_TTL)
            return Response(payload)

        if user_type == "1":
            from ...models import Attendance

            students = branching.filter_students_for_user(user, Student.objects.all())
            groups = branching.filter_groups_for_user(user, Group.objects.filter(is_archived=False))
            group_ids = list(groups.values_list("id", flat=True))
            sessions_today = Attendance.objects.filter(group_id__in=group_ids, date=today).count()
            total_reports = AttendanceReport.objects.filter(
                attendance__group_id__in=group_ids
            ).count()
            present_reports = AttendanceReport.objects.filter(
                attendance__group_id__in=group_ids,
                status=AttendanceReport.PRESENT,
            ).count()
            avg_att = round(present_reports / total_reports * 100, 1) if total_reports else None
            payload = {
                "total_students": students.count(),
                "total_groups": groups.count(),
                "sessions_today": sessions_today,
                "avg_attendance": avg_att,
            }
            cache.set(cache_key, payload, settings.DASHBOARD_CACHE_TTL)
            return Response(payload)

        return Response({"detail": "Permission denied."}, status=status.HTTP_403_FORBIDDEN)
