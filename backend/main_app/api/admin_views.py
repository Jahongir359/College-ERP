"""admin_views.py — Additional admin-only REST API endpoints.

All views in this module:
  - Require authentication (IsAuthenticated).
  - Check that request.user.user_type == '1' (admin role).
  - Apply branch-scoping through the `branching` module so that branch admins
    only see their own branch, while super admins see everything.
"""

from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import transaction
from django.db.models import ProtectedError, Q
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .. import branching
from ..models import (
    Admin,
    Attendance,
    AttendanceReport,
    Branch,
    Course,
    DashboardStory,
    Enrollment,
    Group,
    Invoice,
    LeaveReportStaff,
    LeaveReportStudent,
    Notification,
    Payment,
    Session,
    Staff,
    Student,
    Subject,
    CustomUser,
    Term,
    class_enrollment_conflict,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _require_admin(request):
    """Return (True, None) if the user is an admin, else (False, 403 Response)."""
    if not request.user.is_authenticated:
        return False, Response(
            {"detail": "Authentication required."}, status=status.HTTP_401_UNAUTHORIZED
        )
    if str(request.user.user_type) != "1":
        return False, Response(
            {"detail": "Admin access required."}, status=status.HTTP_403_FORBIDDEN
        )
    return True, None


def _super_admin_error(request):
    """403 Response unless the user is a super admin, else None.

    Branches, courses, sessions and subjects are shared across branches, so
    only super admins may create/change/delete them (matches the web UI).
    """
    ok, err = _require_admin(request)
    if not ok:
        return err
    if not branching.is_super_admin(request.user):
        return Response(
            {"detail": "Only a super admin can change shared settings."},
            status=status.HTTP_403_FORBIDDEN,
        )
    return None


# ---------------------------------------------------------------------------
# 1 & 2.  Branches
# ---------------------------------------------------------------------------


class BranchListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        ok, err = _require_admin(request)
        if not ok:
            return err

        qs = branching.filter_branches_for_user(request.user, Branch.objects.all())
        data = []
        for branch in qs.order_by("name"):
            student_count = (
                Student.objects.filter(Q(branch=branch) | Q(enrollment__group__branch=branch))
                .distinct()
                .count()
            )
            staff_count = (
                Staff.objects.filter(Q(branch=branch) | Q(group__branch=branch)).distinct().count()
            )
            data.append(
                {
                    "id": branch.id,
                    "name": branch.name,
                    "address": branch.address,
                    "brand": branch.brand,
                    "student_count": student_count,
                    "staff_count": staff_count,
                }
            )
        return Response(data)

    def post(self, request):
        err = _super_admin_error(request)
        if err:
            return err
        ok, err = _require_admin(request)
        if not ok:
            return err

        name = request.data.get("name", "").strip()
        if not name:
            return Response({"detail": "name is required."}, status=status.HTTP_400_BAD_REQUEST)

        address = request.data.get("address", "")
        brand = request.data.get("brand", Branch.BRAND_CENTER)
        if brand not in dict(Branch.BRAND_CHOICES):
            return Response({"detail": "Invalid brand."}, status=status.HTTP_400_BAD_REQUEST)
        branch = Branch.objects.create(name=name, address=address, brand=brand)
        return Response(
            {
                "id": branch.id,
                "name": branch.name,
                "address": branch.address,
                "brand": branch.brand,
            },
            status=status.HTTP_201_CREATED,
        )


class BranchDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def _get_branch(self, request, pk):
        ok, err = _require_admin(request)
        if not ok:
            return None, err
        qs = branching.filter_branches_for_user(request.user, Branch.objects.all())
        try:
            return qs.get(pk=pk), None
        except Branch.DoesNotExist:
            return None, Response({"detail": "Branch not found."}, status=status.HTTP_404_NOT_FOUND)

    def get(self, request, pk):
        branch, err = self._get_branch(request, pk)
        if err:
            return err
        student_count = (
            Student.objects.filter(Q(branch=branch) | Q(enrollment__group__branch=branch))
            .distinct()
            .count()
        )
        staff_count = (
            Staff.objects.filter(Q(branch=branch) | Q(group__branch=branch)).distinct().count()
        )
        return Response(
            {
                "id": branch.id,
                "name": branch.name,
                "address": branch.address,
                "brand": branch.brand,
                "student_count": student_count,
                "staff_count": staff_count,
            }
        )

    def patch(self, request, pk):
        branch, err = self._get_branch(request, pk)
        if err:
            return err
        if "name" in request.data:
            branch.name = request.data["name"]
        if "address" in request.data:
            branch.address = request.data["address"]
        if "brand" in request.data:
            # Only super admins may switch a branch between Learning Center and School.
            err = _super_admin_error(request)
            if err:
                return err
            if request.data["brand"] not in dict(Branch.BRAND_CHOICES):
                return Response({"detail": "Invalid brand."}, status=status.HTTP_400_BAD_REQUEST)
            branch.brand = request.data["brand"]
        branch.save()
        return Response(
            {"id": branch.id, "name": branch.name, "address": branch.address, "brand": branch.brand}
        )

    def delete(self, request, pk):
        err = _super_admin_error(request)
        if err:
            return err
        branch, err = self._get_branch(request, pk)
        if err:
            return err

        student_count = Student.objects.filter(branch=branch).count()
        staff_count = Staff.objects.filter(branch=branch).count()
        group_count = Group.objects.filter(branch=branch).count()
        if student_count or staff_count or group_count:
            return Response(
                {
                    "detail": (
                        "Cannot delete a branch that still has students, staff, or groups. "
                        f"(students={student_count}, staff={staff_count}, groups={group_count})"
                    )
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        branch.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


# ---------------------------------------------------------------------------
# 3 & 4.  Courses
# ---------------------------------------------------------------------------


class CourseListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        ok, err = _require_admin(request)
        if not ok:
            return err

        qs = Course.objects.all().order_by("name")
        data = []
        for course in qs:
            student_count = Student.objects.filter(course=course).count()
            data.append(
                {
                    "id": course.id,
                    "name": course.name,
                    "is_active": course.is_active,
                    "is_english": course.is_english,
                    "monthly_fee": str(course.monthly_fee)
                    if course.monthly_fee is not None
                    else None,
                    "student_count": student_count,
                }
            )
        return Response(data)

    def post(self, request):
        err = _super_admin_error(request)
        if err:
            return err
        ok, err = _require_admin(request)
        if not ok:
            return err

        name = request.data.get("name", "").strip()
        if not name:
            return Response({"detail": "name is required."}, status=status.HTTP_400_BAD_REQUEST)

        is_english = bool(request.data.get("is_english", False))
        monthly_fee = request.data.get("monthly_fee")
        course = Course.objects.create(
            name=name,
            is_english=is_english,
            monthly_fee=monthly_fee if monthly_fee else None,
        )
        return Response(
            {"id": course.id, "name": course.name, "is_active": course.is_active},
            status=status.HTTP_201_CREATED,
        )


class CourseDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def _get_course(self, request, pk):
        ok, err = _require_admin(request)
        if not ok:
            return None, err
        try:
            return Course.objects.get(pk=pk), None
        except Course.DoesNotExist:
            return None, Response({"detail": "Course not found."}, status=status.HTTP_404_NOT_FOUND)

    def get(self, request, pk):
        course, err = self._get_course(request, pk)
        if err:
            return err
        student_count = Student.objects.filter(course=course).count()
        return Response(
            {
                "id": course.id,
                "name": course.name,
                "is_active": course.is_active,
                "is_english": course.is_english,
                "monthly_fee": str(course.monthly_fee) if course.monthly_fee is not None else None,
                "student_count": student_count,
            }
        )

    def patch(self, request, pk):
        err = _super_admin_error(request)
        if err:
            return err
        course, err = self._get_course(request, pk)
        if err:
            return err
        for field in ("name", "is_active", "is_english", "monthly_fee"):
            if field in request.data:
                setattr(course, field, request.data[field])
        course.save()
        return Response(
            {
                "id": course.id,
                "name": course.name,
                "is_active": course.is_active,
            }
        )

    def delete(self, request, pk):
        err = _super_admin_error(request)
        if err:
            return err
        course, err = self._get_course(request, pk)
        if err:
            return err
        # Prevent deletion if students or groups use this course.
        student_count = Student.objects.filter(course=course).count()
        group_count = Group.objects.filter(course=course).count()
        if student_count or group_count:
            return Response(
                {
                    "detail": (
                        f"Cannot delete course with active students ({student_count}) "
                        f"or groups ({group_count})."
                    )
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        course.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


# ---------------------------------------------------------------------------
# 5 & 6.  Sessions
# ---------------------------------------------------------------------------


def _session_dict(session, current_id):
    return {
        "id": session.id,
        "name": session.name,
        "start_year": str(session.start_year),
        "end_year": str(session.end_year),
        # The marked session, or (when none is marked) the one covering today.
        "is_current": session.id == current_id,
        "is_marked_current": session.is_current,
    }


def _term_dict(term):
    return {
        "id": term.id,
        "session": term.session_id,
        "number": term.number,
        "name": term.name,
        "start_date": str(term.start_date),
        "end_date": str(term.end_date),
    }


def _validation_response(exc):
    detail = exc.message_dict if hasattr(exc, "message_dict") else {"detail": exc.messages}
    return Response(detail, status=status.HTTP_400_BAD_REQUEST)


def _current_session_id():
    current = Session.current()
    return current.id if current else None


class SessionListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        ok, err = _require_admin(request)
        if not ok:
            return err
        current_id = _current_session_id()
        sessions = Session.objects.all().order_by("-start_year")
        return Response([_session_dict(s, current_id) for s in sessions])

    def post(self, request):
        err = _super_admin_error(request)
        if err:
            return err
        ok, err = _require_admin(request)
        if not ok:
            return err

        start_year = request.data.get("start_year")
        end_year = request.data.get("end_year")
        if not start_year or not end_year:
            return Response(
                {"detail": "start_year and end_year are required."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        session = Session(
            start_year=start_year,
            end_year=end_year,
            name=request.data.get("name", "") or "",
            is_current=bool(request.data.get("is_current", False)),
        )
        try:
            session.full_clean()
        except DjangoValidationError as exc:
            return _validation_response(exc)
        session.save()
        return Response(
            _session_dict(session, _current_session_id()), status=status.HTTP_201_CREATED
        )


class SessionDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def _get_session(self, request, pk):
        ok, err = _require_admin(request)
        if not ok:
            return None, err
        try:
            return Session.objects.get(pk=pk), None
        except Session.DoesNotExist:
            return None, Response(
                {"detail": "Session not found."}, status=status.HTTP_404_NOT_FOUND
            )

    def get(self, request, pk):
        session, err = self._get_session(request, pk)
        if err:
            return err
        data = _session_dict(session, _current_session_id())
        data["terms"] = [_term_dict(t) for t in session.terms.all()]
        return Response(data)

    def patch(self, request, pk):
        err = _super_admin_error(request)
        if err:
            return err
        session, err = self._get_session(request, pk)
        if err:
            return err
        for field in ("start_year", "end_year", "name"):
            if field in request.data:
                setattr(session, field, request.data[field])
        if "is_current" in request.data:
            session.is_current = bool(request.data["is_current"])
        try:
            session.full_clean()
        except DjangoValidationError as exc:
            return _validation_response(exc)
        session.save()
        return Response(_session_dict(session, _current_session_id()))

    def delete(self, request, pk):
        err = _super_admin_error(request)
        if err:
            return err
        session, err = self._get_session(request, pk)
        if err:
            return err
        try:
            session.delete()
        except ProtectedError:
            return Response(
                {"detail": "School classes use this academic year. Move them first."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        return Response(status=status.HTTP_204_NO_CONTENT)


class SessionTermListView(APIView):
    """Quarters of one academic year: admins read, super admins add."""

    permission_classes = [IsAuthenticated]

    def get(self, request, pk):
        ok, err = _require_admin(request)
        if not ok:
            return err
        session = Session.objects.filter(pk=pk).first()
        if session is None:
            return Response({"detail": "Session not found."}, status=status.HTTP_404_NOT_FOUND)
        return Response([_term_dict(t) for t in session.terms.all()])

    def post(self, request, pk):
        err = _super_admin_error(request)
        if err:
            return err
        ok, err = _require_admin(request)
        if not ok:
            return err
        session = Session.objects.filter(pk=pk).first()
        if session is None:
            return Response({"detail": "Session not found."}, status=status.HTTP_404_NOT_FOUND)
        term = Term(
            session=session,
            number=request.data.get("number"),
            name=request.data.get("name", "") or "",
            start_date=request.data.get("start_date"),
            end_date=request.data.get("end_date"),
        )
        try:
            term.full_clean()
        except DjangoValidationError as exc:
            return _validation_response(exc)
        term.save()
        return Response(_term_dict(term), status=status.HTTP_201_CREATED)


class TermDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def _get_term(self, request, pk):
        err = _super_admin_error(request)
        if err:
            return None, err
        ok, err = _require_admin(request)
        if not ok:
            return None, err
        term = Term.objects.select_related("session").filter(pk=pk).first()
        if term is None:
            return None, Response({"detail": "Term not found."}, status=status.HTTP_404_NOT_FOUND)
        return term, None

    def patch(self, request, pk):
        term, err = self._get_term(request, pk)
        if err:
            return err
        for field in ("number", "name", "start_date", "end_date"):
            if field in request.data:
                setattr(term, field, request.data[field])
        try:
            term.full_clean()
        except DjangoValidationError as exc:
            return _validation_response(exc)
        term.save()
        return Response(_term_dict(term))

    def delete(self, request, pk):
        term, err = self._get_term(request, pk)
        if err:
            return err
        term.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


# ---------------------------------------------------------------------------
# 7 & 8.  Subjects
# ---------------------------------------------------------------------------


class SubjectListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        ok, err = _require_admin(request)
        if not ok:
            return err

        qs = Subject.objects.select_related("course", "staff__admin").order_by("name")

        # Branch admins: only subjects belonging to courses taught in their branches.
        if not branching.is_super_admin(request.user):
            accessible_branches = branching.get_accessible_branches(request.user)
            course_ids = (
                Group.objects.filter(branch__in=accessible_branches)
                .values_list("course_id", flat=True)
                .distinct()
            )
            qs = qs.filter(course_id__in=course_ids)

        data = [
            {
                "id": s.id,
                "name": s.name,
                "course_id": s.course_id,
                "course_name": s.course.name,
                "staff_id": s.staff_id,
                "staff_name": str(s.staff) if s.staff_id else "",
            }
            for s in qs
        ]
        return Response(data)

    def post(self, request):
        err = _super_admin_error(request)
        if err:
            return err
        ok, err = _require_admin(request)
        if not ok:
            return err

        name = request.data.get("name", "").strip()
        course_id = request.data.get("course_id")
        staff_id = request.data.get("staff_id")
        if not name or not course_id:
            return Response(
                {"detail": "name and course_id are required."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            course = Course.objects.get(pk=course_id)
        except Course.DoesNotExist:
            return Response({"detail": "Course not found."}, status=status.HTTP_404_NOT_FOUND)
        # Optional: school subjects get their teacher per class (ClassSubject).
        staff = None
        if staff_id:
            try:
                staff = Staff.objects.get(pk=staff_id)
            except Staff.DoesNotExist:
                return Response({"detail": "Staff not found."}, status=status.HTTP_404_NOT_FOUND)

        subject = Subject.objects.create(name=name, course=course, staff=staff)
        return Response(
            {"id": subject.id, "name": subject.name, "course_name": course.name},
            status=status.HTTP_201_CREATED,
        )


class SubjectDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def _get_subject(self, request, pk):
        ok, err = _require_admin(request)
        if not ok:
            return None, err
        try:
            return Subject.objects.select_related("course", "staff__admin").get(pk=pk), None
        except Subject.DoesNotExist:
            return None, Response(
                {"detail": "Subject not found."}, status=status.HTTP_404_NOT_FOUND
            )

    def get(self, request, pk):
        subject, err = self._get_subject(request, pk)
        if err:
            return err
        return Response(
            {
                "id": subject.id,
                "name": subject.name,
                "course_id": subject.course_id,
                "course_name": subject.course.name,
                "staff_id": subject.staff_id,
                "staff_name": str(subject.staff) if subject.staff_id else "",
            }
        )

    def patch(self, request, pk):
        err = _super_admin_error(request)
        if err:
            return err
        subject, err = self._get_subject(request, pk)
        if err:
            return err
        if "name" in request.data:
            subject.name = request.data["name"]
        if "course_id" in request.data:
            try:
                subject.course = Course.objects.get(pk=request.data["course_id"])
            except Course.DoesNotExist:
                return Response({"detail": "Course not found."}, status=status.HTTP_404_NOT_FOUND)
        if "staff_id" in request.data:
            try:
                subject.staff = Staff.objects.get(pk=request.data["staff_id"])
            except Staff.DoesNotExist:
                return Response({"detail": "Staff not found."}, status=status.HTTP_404_NOT_FOUND)
        subject.save()
        return Response(
            {
                "id": subject.id,
                "name": subject.name,
                "course_name": subject.course.name,
            }
        )

    def delete(self, request, pk):
        err = _super_admin_error(request)
        if err:
            return err
        subject, err = self._get_subject(request, pk)
        if err:
            return err
        subject.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


# ---------------------------------------------------------------------------
# 9.  Group detail (admin view with enrolled students)
# ---------------------------------------------------------------------------


class GroupDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, pk):
        ok, err = _require_admin(request)
        if not ok:
            return err

        qs = Group.objects.select_related("course", "teacher__admin", "branch")
        qs = branching.filter_groups_for_user(request.user, qs)
        try:
            group = qs.get(pk=pk)
        except Group.DoesNotExist:
            return Response({"detail": "Group not found."}, status=status.HTTP_404_NOT_FOUND)

        enrollments = Enrollment.objects.filter(group=group, is_active=True).select_related(
            "student__admin"
        )
        students = [
            {
                "id": e.student.id,
                "name": f"{e.student.admin.first_name} {e.student.admin.last_name}".strip(),
                "login_id": e.student.admin.login_id,
            }
            for e in enrollments
        ]

        teacher = group.teacher
        staff_name = (
            f"{teacher.admin.first_name} {teacher.admin.last_name}".strip()
            if teacher and teacher.admin
            else None
        )

        return Response(
            {
                "id": group.id,
                "name": group.name,
                "course_name": group.course.name if group.course else None,
                "session_name": str(group.session) if group.session_id else None,
                "staff_name": staff_name,
                "branch_name": group.branch.name if group.branch else None,
                "is_archived": group.is_archived,
                "capacity": group.capacity,
                "schedule": group.schedule,
                "room": group.room,
                "students": students,
            }
        )


# ---------------------------------------------------------------------------
# 10.  Enrollments
# ---------------------------------------------------------------------------


class EnrollmentView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        ok, err = _require_admin(request)
        if not ok:
            return err

        qs = branching.filter_enrollments_for_user(
            request.user,
            Enrollment.objects.select_related("student__admin", "group"),
        )
        group_id = request.query_params.get("group_id")
        if group_id:
            qs = qs.filter(group_id=group_id)

        data = [
            {
                "id": e.id,
                "student_id": e.student_id,
                "student_name": f"{e.student.admin.first_name} {e.student.admin.last_name}".strip(),
                "group_id": e.group_id,
                "group_name": e.group.name,
                "is_active": e.is_active,
                "enrolled_on": str(e.enrolled_on),
            }
            for e in qs.order_by("-enrolled_on")
        ]
        return Response(data)

    def post(self, request):
        ok, err = _require_admin(request)
        if not ok:
            return err

        student_id = request.data.get("student_id")
        group_id = request.data.get("group_id")
        if not student_id or not group_id:
            return Response(
                {"detail": "student_id and group_id are required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            student = Student.objects.get(pk=student_id)
        except Student.DoesNotExist:
            return Response({"detail": "Student not found."}, status=status.HTTP_404_NOT_FOUND)

        try:
            group = Group.objects.get(pk=group_id)
        except Group.DoesNotExist:
            return Response({"detail": "Group not found."}, status=status.HTTP_404_NOT_FOUND)

        if not branching.user_can_access_group(request.user, group):
            return Response(
                {"detail": "You don't have access to that group's branch."},
                status=status.HTTP_403_FORBIDDEN,
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
            {
                "id": enrollment.id,
                "student_id": enrollment.student_id,
                "group_id": enrollment.group_id,
                "is_active": enrollment.is_active,
            },
            status=status.HTTP_201_CREATED if created else status.HTTP_200_OK,
        )

    def delete(self, request):
        ok, err = _require_admin(request)
        if not ok:
            return err

        scoped = branching.filter_enrollments_for_user(request.user, Enrollment.objects.all())

        enrollment_id = request.data.get("enrollment_id")
        if enrollment_id:
            updated = scoped.filter(id=enrollment_id).update(is_active=False)
            if not updated:
                return Response(
                    {"detail": "Enrollment not found."}, status=status.HTTP_404_NOT_FOUND
                )
            return Response({"detail": "Student unenrolled."})

        student_id = request.data.get("student_id")
        group_id = request.data.get("group_id")
        if not student_id or not group_id:
            return Response(
                {"detail": "enrollment_id or (student_id + group_id) required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        updated = scoped.filter(student_id=student_id, group_id=group_id).update(is_active=False)
        if not updated:
            return Response({"detail": "Enrollment not found."}, status=status.HTTP_404_NOT_FOUND)
        return Response({"detail": "Student unenrolled."})


# ---------------------------------------------------------------------------
# 11.  Leave requests
# ---------------------------------------------------------------------------


class AdminLeaveListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        ok, err = _require_admin(request)
        if not ok:
            return err

        user_type_filter = request.query_params.get("user_type")  # "student" | "staff"
        data = []

        include_students = user_type_filter in (None, "student")
        include_staff = user_type_filter in (None, "staff")

        if include_students:
            student_qs = LeaveReportStudent.objects.select_related(
                "student__admin", "student__branch"
            )
            # Branch scoping
            if not branching.is_super_admin(request.user):
                accessible_students = branching.filter_students_for_user(
                    request.user, Student.objects.all()
                )
                student_qs = student_qs.filter(student__in=accessible_students)
            for leave in student_qs.order_by("-created_at"):
                data.append(
                    {
                        "id": leave.id,
                        "user_name": f"{leave.student.admin.first_name} {leave.student.admin.last_name}".strip(),
                        "user_type": "student",
                        "date": str(leave.date) if leave.date else None,
                        "reason": leave.message,
                        "status": leave.get_status_display(),
                        "status_code": leave.status,
                        "created_at": leave.created_at.isoformat(),
                    }
                )

        if include_staff:
            staff_qs = LeaveReportStaff.objects.select_related("staff__admin", "staff__branch")
            if not branching.is_super_admin(request.user):
                accessible_staff = branching.filter_staff_for_user(
                    request.user, Staff.objects.all()
                )
                staff_qs = staff_qs.filter(staff__in=accessible_staff)
            for leave in staff_qs.order_by("-created_at"):
                data.append(
                    {
                        "id": leave.id,
                        "user_name": f"{leave.staff.admin.first_name} {leave.staff.admin.last_name}".strip(),
                        "user_type": "staff",
                        "date": str(leave.date) if leave.date else None,
                        "reason": leave.message,
                        "status": leave.get_status_display(),
                        "status_code": leave.status,
                        "created_at": leave.created_at.isoformat(),
                    }
                )

        # Sort combined list by created_at descending (already strings — use iso)
        data.sort(key=lambda x: x["created_at"], reverse=True)
        return Response(data)


class AdminLeaveDetailView(APIView):
    """PATCH to approve or reject a leave request."""

    permission_classes = [IsAuthenticated]

    STATUS_MAP = {
        "Approved": 1,
        "Rejected": -1,
        "Pending": 0,
    }

    def patch(self, request, pk):
        ok, err = _require_admin(request)
        if not ok:
            return err

        new_status_str = request.data.get("status")
        if new_status_str not in self.STATUS_MAP:
            return Response(
                {"detail": f"status must be one of: {list(self.STATUS_MAP.keys())}"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        new_status = self.STATUS_MAP[new_status_str]

        # Determine whether this is a student or staff leave record.
        user_type = request.query_params.get("user_type", "")

        # Try student leave first (unless explicitly staff).
        if user_type != "staff":
            student_qs = LeaveReportStudent.objects.all()
            if not branching.is_super_admin(request.user):
                accessible_students = branching.filter_students_for_user(
                    request.user, Student.objects.all()
                )
                student_qs = student_qs.filter(student__in=accessible_students)
            try:
                leave = student_qs.get(pk=pk)
                leave.status = new_status
                leave.save(update_fields=["status", "updated_at"])
                return Response({"detail": "Leave status updated.", "status": new_status_str})
            except LeaveReportStudent.DoesNotExist:
                pass

        # Try staff leave.
        staff_qs = LeaveReportStaff.objects.all()
        if not branching.is_super_admin(request.user):
            accessible_staff = branching.filter_staff_for_user(request.user, Staff.objects.all())
            staff_qs = staff_qs.filter(staff__in=accessible_staff)
        try:
            leave = staff_qs.get(pk=pk)
            leave.status = new_status
            leave.save(update_fields=["status", "updated_at"])
            return Response({"detail": "Leave status updated.", "status": new_status_str})
        except LeaveReportStaff.DoesNotExist:
            pass

        return Response({"detail": "Leave request not found."}, status=status.HTTP_404_NOT_FOUND)


# ---------------------------------------------------------------------------
# 12.  Attendance report
# ---------------------------------------------------------------------------


class AdminAttendanceView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        ok, err = _require_admin(request)
        if not ok:
            return err

        group_id = request.query_params.get("group_id")
        start_date = request.query_params.get("start_date")
        end_date = request.query_params.get("end_date")

        if not group_id:
            return Response(
                {"detail": "group_id query parameter is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        group_qs = branching.filter_groups_for_user(
            request.user,
            Group.objects.select_related("course", "branch"),
        )
        try:
            group = group_qs.get(pk=group_id)
        except Group.DoesNotExist:
            return Response({"detail": "Group not found."}, status=status.HTTP_404_NOT_FOUND)

        # Students enrolled in this group
        enrollments = Enrollment.objects.filter(group=group, is_active=True).select_related(
            "student__admin"
        )
        students = [e.student for e in enrollments]
        total_students = len(students)

        # Attendance sessions for this group
        attendance_qs = Attendance.objects.filter(group=group).order_by("date")
        if start_date:
            attendance_qs = attendance_qs.filter(date__gte=start_date)
        if end_date:
            attendance_qs = attendance_qs.filter(date__lte=end_date)

        sessions = [{"id": a.id, "date": str(a.date)} for a in attendance_qs]

        # Per-student summary
        attendance_data = []
        for student in students:
            reports = AttendanceReport.objects.filter(
                student=student,
                attendance__group=group,
            )
            if start_date:
                reports = reports.filter(attendance__date__gte=start_date)
            if end_date:
                reports = reports.filter(attendance__date__lte=end_date)

            total = reports.count()
            present = reports.filter(status=AttendanceReport.PRESENT).count()
            late = reports.filter(status=AttendanceReport.LATE).count()
            absent = reports.filter(status=AttendanceReport.ABSENT).count()
            pct = round(present / total * 100, 1) if total > 0 else None

            attendance_data.append(
                {
                    "student_id": student.id,
                    "student_name": f"{student.admin.first_name} {student.admin.last_name}".strip(),
                    "total_sessions": total,
                    "present": present,
                    "late": late,
                    "absent": absent,
                    "attendance_percentage": pct,
                }
            )

        return Response(
            {
                "group_id": group.id,
                "group_name": group.name,
                "total_students": total_students,
                "sessions": sessions,
                "attendance_data": attendance_data,
            }
        )


# ---------------------------------------------------------------------------
# 13.  Stories  (DashboardStory)
# ---------------------------------------------------------------------------


class AdminStoriesListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        ok, err = _require_admin(request)
        if not ok:
            return err

        qs = DashboardStory.objects.select_related("created_by").prefetch_related("target_groups")

        # Branch scoping: filter stories whose target groups are in the admin's branches.
        if not branching.is_super_admin(request.user):
            accessible_branches = branching.get_accessible_branches(request.user)
            accessible_group_ids = Group.objects.filter(branch__in=accessible_branches).values_list(
                "id", flat=True
            )
            # Include stories targeting no specific group (global) OR a group in scope
            qs = qs.filter(
                Q(target_groups__isnull=True) | Q(target_groups__id__in=accessible_group_ids)
            ).distinct()

        data = []
        for story in qs.order_by("-created_at"):
            target_group_ids = list(story.target_groups.values_list("id", flat=True))
            data.append(
                {
                    "id": story.id,
                    "title": story.title,
                    "body": story.body,
                    "story_type": story.story_type,
                    "is_active": story.is_active,
                    "expires_at": story.expires_at.isoformat() if story.expires_at else None,
                    "created_at": story.created_at.isoformat(),
                    "created_by": story.created_by.get_full_name() if story.created_by else None,
                    "target_group_ids": target_group_ids,
                }
            )
        return Response(data)

    def post(self, request):
        ok, err = _require_admin(request)
        if not ok:
            return err

        title = request.data.get("title", "").strip()
        if not title:
            return Response({"detail": "title is required."}, status=status.HTTP_400_BAD_REQUEST)

        content = request.data.get("content", "") or request.data.get("body", "")
        target_group_id = request.data.get("target_group_id")
        story_type = request.data.get("story_type", DashboardStory.TYPE_ANNOUNCEMENT)
        expires_at = request.data.get("expires_at")

        story = DashboardStory.objects.create(
            title=title,
            body=content,
            story_type=story_type,
            created_by=request.user,
            expires_at=expires_at if expires_at else None,
        )

        if target_group_id:
            story.target_groups.set(Group.objects.filter(pk=target_group_id))
        # Trim to the admin's branches; branch admins can't post school-wide.
        branching.scope_story_target_groups(request.user, story)

        return Response(
            {
                "id": story.id,
                "title": story.title,
                "body": story.body,
                "is_active": story.is_active,
            },
            status=status.HTTP_201_CREATED,
        )


_user_can_modify_story = branching.user_can_modify_story


class AdminStoriesDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def _get_story(self, request, pk):
        ok, err = _require_admin(request)
        if not ok:
            return None, err
        try:
            story = DashboardStory.objects.get(pk=pk)
        except DashboardStory.DoesNotExist:
            return None, Response({"detail": "Story not found."}, status=status.HTTP_404_NOT_FOUND)
        if not _user_can_modify_story(request.user, story):
            return None, Response(
                {"detail": "You don't have access to modify this story."},
                status=status.HTTP_403_FORBIDDEN,
            )
        return story, None

    def delete(self, request, pk):
        story, err = self._get_story(request, pk)
        if err:
            return err
        story.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

    def patch(self, request, pk):
        story, err = self._get_story(request, pk)
        if err:
            return err

        for field in ("title", "body", "story_type", "is_active", "expires_at"):
            if field in request.data:
                setattr(story, field, request.data[field])
        story.save()
        return Response({"id": story.id, "title": story.title, "is_active": story.is_active})


# ---------------------------------------------------------------------------
# 14.  Send notification
# ---------------------------------------------------------------------------


class AdminSendNotificationView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        ok, err = _require_admin(request)
        if not ok:
            return err

        title = request.data.get("title", "").strip()
        body = request.data.get("body", "").strip()
        target = request.data.get("target", "all")  # "all" | "students" | "staff"
        group_id = request.data.get("group_id")

        if not title or not body:
            return Response(
                {"detail": "title and body are required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        message = f"{title}: {body}"

        # Build the set of recipient CustomUser objects.
        recipient_users = CustomUser.objects.none()

        if target in ("all", "students"):
            student_qs = branching.filter_students_for_user(
                request.user, Student.objects.select_related("admin")
            )
            if group_id:
                enrolled_ids = Enrollment.objects.filter(
                    group_id=group_id, is_active=True
                ).values_list("student_id", flat=True)
                student_qs = student_qs.filter(id__in=enrolled_ids)
            student_user_ids = student_qs.values_list("admin_id", flat=True)
            recipient_users = recipient_users | CustomUser.objects.filter(id__in=student_user_ids)

        if target in ("all", "staff"):
            staff_qs = branching.filter_staff_for_user(
                request.user, Staff.objects.select_related("admin")
            )
            staff_user_ids = staff_qs.values_list("admin_id", flat=True)
            recipient_users = recipient_users | CustomUser.objects.filter(id__in=staff_user_ids)

        recipient_users = recipient_users.distinct()
        recipients = list(recipient_users)

        notifications = [
            Notification(
                recipient=user,
                category=Notification.ANNOUNCEMENT,
                message=message,
            )
            for user in recipients
        ]
        Notification.objects.bulk_create(notifications)

        return Response({"sent_count": len(notifications)}, status=status.HTTP_201_CREATED)


# ---------------------------------------------------------------------------
# 15.  Invoice list / create
# ---------------------------------------------------------------------------


class AdminInvoiceListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        ok, err = _require_admin(request)
        if not ok:
            return err

        accessible_students = branching.filter_students_for_user(
            request.user, Student.objects.all()
        )
        qs = (
            Invoice.objects.select_related("student__admin")
            .prefetch_related("payments")
            .filter(student__in=accessible_students)
            .order_by("-period", "-created_at")
        )

        # Optional filters
        student_id = request.query_params.get("student_id")
        inv_status = request.query_params.get("status")
        if student_id:
            qs = qs.filter(student_id=student_id)
        if inv_status:
            qs = qs.filter(status=inv_status)

        data = []
        for inv in qs:
            student_name = (
                f"{inv.student.admin.first_name} {inv.student.admin.last_name}".strip()
                if inv.student and inv.student.admin
                else ""
            )
            data.append(
                {
                    "id": inv.id,
                    "student_id": inv.student_id,
                    "student_name": student_name,
                    "amount": str(inv.amount),
                    "discount": str(inv.discount),
                    "total_due": str(inv.total_due),
                    "paid_amount": str(inv.paid_amount),
                    "balance": str(inv.balance),
                    "due_date": str(inv.due_date),
                    "period": str(inv.period),
                    "status": inv.status,
                    "status_display": inv.get_status_display(),
                    "note": inv.note,
                }
            )
        return Response(data)

    def post(self, request):
        ok, err = _require_admin(request)
        if not ok:
            return err

        student_id = request.data.get("student_id")
        amount = request.data.get("amount")
        due_date = request.data.get("due_date")
        period = request.data.get("period")
        description = request.data.get("description", "")

        if not student_id or not amount or not due_date or not period:
            return Response(
                {"detail": "student_id, amount, due_date, and period are required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        accessible_students = branching.filter_students_for_user(
            request.user, Student.objects.all()
        )
        try:
            student = accessible_students.get(pk=student_id)
        except Student.DoesNotExist:
            return Response(
                {"detail": "Student not found or not accessible."},
                status=status.HTTP_404_NOT_FOUND,
            )

        invoice = Invoice.objects.create(
            student=student,
            amount=amount,
            due_date=due_date,
            period=period,
            note=description,
            created_by=request.user,
        )
        return Response(
            {
                "id": invoice.id,
                "student_id": invoice.student_id,
                "amount": str(invoice.amount),
                "due_date": str(invoice.due_date),
                "status": invoice.status,
            },
            status=status.HTTP_201_CREATED,
        )


# ---------------------------------------------------------------------------
# 16.  Record payment against invoice
# ---------------------------------------------------------------------------


class AdminRecordPaymentView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        ok, err = _require_admin(request)
        if not ok:
            return err

        accessible_students = branching.filter_students_for_user(
            request.user, Student.objects.all()
        )
        try:
            invoice = Invoice.objects.prefetch_related("payments").get(
                pk=pk, student__in=accessible_students
            )
        except Invoice.DoesNotExist:
            return Response({"detail": "Invoice not found."}, status=status.HTTP_404_NOT_FOUND)

        amount_paid = request.data.get("amount_paid")
        paid_date = request.data.get("paid_date")
        method = request.data.get("method", Payment.METHOD_CASH)

        if not amount_paid:
            return Response(
                {"detail": "amount_paid is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        with transaction.atomic():
            payment = Payment.objects.create(
                invoice=invoice,
                amount=amount_paid,
                paid_on=paid_date if paid_date else None,
                method=method,
                received_by=request.user,
            )
            invoice.refresh_status(save=True)

        return Response(
            {
                "payment_id": payment.id,
                "invoice_id": invoice.id,
                "invoice_status": invoice.status,
                "invoice_status_display": invoice.get_status_display(),
                "amount_paid": str(payment.amount),
            },
            status=status.HTTP_201_CREATED,
        )


# ---------------------------------------------------------------------------
# Group CRUD (admin)
# ---------------------------------------------------------------------------


def _class_fields(group):
    """School-class keys on group responses (course groups: kind "course", rest null)."""
    return {
        "kind": group.kind,
        "grade_level": group.grade_level,
        "letter": group.letter,
        "session": group.session_id,
    }


def _apply_class_fields(group, data):
    """Set kind/grade_level/letter/session from request data and validate the group.

    Returns a 400 Response on bad input, else None. Course groups sent without
    these keys are unchanged.
    """
    if "kind" in data:
        if data["kind"] not in (Group.KIND_COURSE, Group.KIND_CLASS):
            return Response({"kind": ["Use course or class."]}, status=status.HTTP_400_BAD_REQUEST)
        group.kind = data["kind"]
    if "grade_level" in data:
        try:
            group.grade_level = int(data["grade_level"]) if data["grade_level"] else None
        except (TypeError, ValueError):
            return Response(
                {"grade_level": ["A whole number is required."]},
                status=status.HTTP_400_BAD_REQUEST,
            )
    if "letter" in data:
        group.letter = (data["letter"] or "").strip().upper()
    if "session" in data:
        if data["session"]:
            session = Session.objects.filter(pk=data["session"]).first()
            if session is None:
                return Response({"session": ["Not found."]}, status=status.HTTP_400_BAD_REQUEST)
            group.session = session
        else:
            group.session = None
    try:
        group.clean()
    except DjangoValidationError as exc:
        return _validation_response(exc)
    return None


class AdminGroupListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        ok, err = _require_admin(request)
        if not ok:
            return err
        qs = Group.objects.select_related("course", "teacher__admin", "branch")
        if request.query_params.get("archived") != "1":
            qs = qs.filter(is_archived=False)
        qs = branching.filter_groups_for_user(request.user, qs)
        data = []
        for g in qs:
            teacher_name = None
            if g.teacher and g.teacher.admin:
                u = g.teacher.admin
                teacher_name = f"{u.first_name} {u.last_name}".strip()
            enrolled = g.enrollment_set.count()
            data.append(
                {
                    "id": g.id,
                    "name": g.name,
                    "course": g.course_id,
                    "course_name": g.course.name if g.course else None,
                    "teacher": g.teacher_id,
                    "teacher_name": teacher_name,
                    "branch": g.branch_id,
                    "branch_name": g.branch.name if g.branch else None,
                    "room": g.room,
                    "schedule": g.schedule,
                    "capacity": g.capacity,
                    "monthly_fee": str(g.monthly_fee) if g.monthly_fee is not None else None,
                    "start_date": g.start_date.isoformat() if g.start_date else None,
                    "is_archived": g.is_archived,
                    "enrolled_count": enrolled,
                    **_class_fields(g),
                }
            )
        return Response(data)

    def post(self, request):
        ok, err = _require_admin(request)
        if not ok:
            return err
        d = request.data
        # Validate required fields
        if not d.get("name"):
            return Response(
                {"name": ["This field is required."]}, status=status.HTTP_400_BAD_REQUEST
            )
        if not d.get("course"):
            return Response(
                {"course": ["This field is required."]}, status=status.HTTP_400_BAD_REQUEST
            )

        try:
            course = Course.objects.get(pk=d["course"])
        except Course.DoesNotExist:
            return Response({"course": ["Not found."]}, status=status.HTTP_400_BAD_REQUEST)

        teacher = None
        if d.get("teacher"):
            try:
                teacher = Staff.objects.get(pk=d["teacher"])
                if not branching.user_can_access_group(request.user, Group(branch=teacher.branch)):
                    return Response(
                        {"detail": "Access denied to that teacher's branch."},
                        status=status.HTTP_403_FORBIDDEN,
                    )
            except Staff.DoesNotExist:
                return Response({"teacher": ["Not found."]}, status=status.HTTP_400_BAD_REQUEST)

        branch = None
        if d.get("branch"):
            try:
                branch = Branch.objects.get(pk=d["branch"])
                accessible = branching.get_accessible_branches(request.user)
                if not accessible.filter(pk=branch.pk).exists():
                    return Response(
                        {"detail": "Access denied to that branch."},
                        status=status.HTTP_403_FORBIDDEN,
                    )
            except Branch.DoesNotExist:
                return Response({"branch": ["Not found."]}, status=status.HTTP_400_BAD_REQUEST)
        elif not branching.is_super_admin(request.user):
            return Response(
                {"branch": ["This field is required."]}, status=status.HTTP_400_BAD_REQUEST
            )

        group = Group(
            name=d["name"],
            course=course,
            teacher=teacher,
            branch=branch,
            room=d.get("room", ""),
            schedule=d.get("schedule", ""),
            capacity=int(d.get("capacity", 20)),
            monthly_fee=d.get("monthly_fee") or None,
            start_date=d.get("start_date") or None,
        )
        err = _apply_class_fields(group, d)
        if err:
            return err
        group.save()
        return Response({"id": group.id, "name": group.name}, status=status.HTTP_201_CREATED)


class AdminGroupDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def _get_group(self, request, pk):
        try:
            g = Group.objects.select_related("course", "teacher__admin", "branch").get(pk=pk)
        except Group.DoesNotExist:
            return None, Response({"detail": "Not found."}, status=status.HTTP_404_NOT_FOUND)
        ok, err = _require_admin(request)
        if not ok:
            return None, err
        if not branching.user_can_access_group(request.user, g):
            return None, Response({"detail": "Access denied."}, status=status.HTTP_403_FORBIDDEN)
        return g, None

    def get(self, request, pk):
        g, err = self._get_group(request, pk)
        if err:
            return err
        students = []
        for enr in g.enrollment_set.select_related("student__admin").all():
            s = enr.student
            u = s.admin
            students.append(
                {
                    "id": s.id,
                    "first_name": u.first_name,
                    "last_name": u.last_name,
                    "login_id": u.login_id,
                    "status": s.status,
                }
            )
        teacher_name = None
        if g.teacher and g.teacher.admin:
            u2 = g.teacher.admin
            teacher_name = f"{u2.first_name} {u2.last_name}".strip()
        return Response(
            {
                "id": g.id,
                "name": g.name,
                "course": g.course_id,
                "course_name": g.course.name if g.course else None,
                "teacher": g.teacher_id,
                "teacher_name": teacher_name,
                "branch": g.branch_id,
                "branch_name": g.branch.name if g.branch else None,
                "room": g.room,
                "schedule": g.schedule,
                "capacity": g.capacity,
                "monthly_fee": str(g.monthly_fee) if g.monthly_fee is not None else None,
                "start_date": g.start_date.isoformat() if g.start_date else None,
                "is_archived": g.is_archived,
                **_class_fields(g),
                "students": students,
                "enrolled_count": len(students),
            }
        )

    def patch(self, request, pk):
        g, err = self._get_group(request, pk)
        if err:
            return err
        d = request.data
        if "name" in d:
            g.name = d["name"]
        if "room" in d:
            g.room = d["room"]
        if "schedule" in d:
            g.schedule = d["schedule"]
        if "capacity" in d:
            g.capacity = int(d["capacity"])
        if "monthly_fee" in d:
            g.monthly_fee = d["monthly_fee"] or None
        if "start_date" in d:
            g.start_date = d["start_date"] or None
        if "is_archived" in d:
            g.is_archived = bool(d["is_archived"])
        if "course" in d:
            try:
                g.course = Course.objects.get(pk=d["course"])
            except Course.DoesNotExist:
                return Response({"course": ["Not found."]}, status=status.HTTP_400_BAD_REQUEST)
        if "teacher" in d:
            if d["teacher"]:
                teacher = branching.filter_staff_for_user(
                    request.user, Staff.objects.filter(pk=d["teacher"])
                ).first()
                if teacher is None:
                    return Response({"teacher": ["Not found."]}, status=status.HTTP_400_BAD_REQUEST)
                g.teacher = teacher
            else:
                g.teacher = None
        if "branch" in d:
            if d["branch"]:
                try:
                    b = Branch.objects.get(pk=d["branch"])
                    if not branching.get_accessible_branches(request.user).filter(pk=b.pk).exists():
                        return Response(
                            {"detail": "Access denied."}, status=status.HTTP_403_FORBIDDEN
                        )
                    g.branch = b
                except Branch.DoesNotExist:
                    return Response({"branch": ["Not found."]}, status=status.HTTP_400_BAD_REQUEST)
            elif branching.is_super_admin(request.user):
                g.branch = None
            else:
                # Clearing the branch would move the group out of every branch
                # admin's scope (including this one's).
                return Response(
                    {"branch": ["Branch is required."]}, status=status.HTTP_400_BAD_REQUEST
                )
        err = _apply_class_fields(g, d)
        if err:
            return err
        g.save()
        return Response({"id": g.id, "name": g.name, "is_archived": g.is_archived})

    def delete(self, request, pk):
        g, err = self._get_group(request, pk)
        if err:
            return err
        enrolled = g.enrollment_set.count()
        if enrolled:
            return Response(
                {
                    "detail": f"Cannot delete group '{g.name}': {enrolled} student(s) enrolled. Archive it instead."
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        g.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


# ---------------------------------------------------------------------------
# Admin user (HOD) management  — superadmin only
# ---------------------------------------------------------------------------


class AdminAdminListView(APIView):
    """
    GET  /admin/admins/        — list all admin users (superadmin only)
    POST /admin/admins/        — create a new branch admin
    """

    permission_classes = [IsAuthenticated]

    def _require_superadmin(self, request):
        ok, err = _require_admin(request)
        if not ok:
            return False, err
        if not branching.is_super_admin(request.user):
            return False, Response(
                {"detail": "Only super-admins can manage admin accounts."},
                status=status.HTTP_403_FORBIDDEN,
            )
        return True, None

    def get(self, request):
        ok, err = self._require_superadmin(request)
        if not ok:
            return err

        qs = CustomUser.objects.filter(user_type="1").order_by("-date_joined")
        search = request.query_params.get("search", "").strip()
        if search:
            qs = qs.filter(
                Q(first_name__icontains=search)
                | Q(last_name__icontains=search)
                | Q(email__icontains=search)
            )

        data = []
        for u in qs.select_related("admin").prefetch_related("admin__branches"):
            # Branch assignment and the superadmin flag live on the Admin
            # profile row, not on CustomUser.
            profile = getattr(u, "admin", None)
            profile_branches = list(profile.branches.all()) if profile else []
            data.append(
                {
                    "id": u.id,
                    "email": u.email,
                    "first_name": u.first_name,
                    "last_name": u.last_name,
                    "full_name": f"{u.first_name} {u.last_name}".strip(),
                    "phone": getattr(u, "phone", ""),
                    "is_super_admin": bool(profile and profile.is_super_admin),
                    "is_active": u.is_active,
                    "date_joined": str(u.date_joined.date()),
                    "branch_ids": [b.id for b in profile_branches],
                    "branch_names": [b.name for b in profile_branches],
                }
            )
        return Response(data)

    def post(self, request):
        ok, err = self._require_superadmin(request)
        if not ok:
            return err

        email = request.data.get("email", "").strip().lower()
        password = request.data.get("password", "").strip()
        first_name = request.data.get("first_name", "").strip()
        last_name = request.data.get("last_name", "").strip()
        phone = request.data.get("phone", "").strip()
        branch_ids = request.data.get("branch_ids", [])

        if not email or not password:
            return Response(
                {"detail": "email and password are required."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            validate_password(password)
        except DjangoValidationError as exc:
            return Response({"password": exc.messages}, status=status.HTTP_400_BAD_REQUEST)
        if CustomUser.objects.filter(email=email).exists():
            return Response(
                {"detail": "An account with this email already exists."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        with transaction.atomic():
            user = CustomUser.objects.create_user(
                email=email,
                password=password,
                first_name=first_name,
                last_name=last_name,
                user_type="1",
            )
            if hasattr(user, "phone"):
                user.phone = phone
                user.save(update_fields=["phone"])

            # The post_save signal creates the Admin profile with
            # is_super_admin defaulting to True — API-created admins must
            # always be branch admins.
            profile, _ = Admin.objects.get_or_create(admin=user)
            profile.is_super_admin = False
            profile.save(update_fields=["is_super_admin"])
            if branch_ids:
                profile.branches.set(Branch.objects.filter(pk__in=branch_ids))

        return Response(
            {
                "id": user.id,
                "email": user.email,
                "full_name": f"{user.first_name} {user.last_name}".strip(),
            },
            status=status.HTTP_201_CREATED,
        )


class AdminAdminDetailView(APIView):
    """
    PATCH  /admin/admins/<pk>/  — update admin details
    DELETE /admin/admins/<pk>/  — delete admin (cannot delete self or other superadmins)
    """

    permission_classes = [IsAuthenticated]

    def _get_target(self, request, pk):
        ok, err = _require_admin(request)
        if not ok:
            return None, err
        if not branching.is_super_admin(request.user):
            return None, Response(
                {"detail": "Only super-admins can manage admin accounts."},
                status=status.HTTP_403_FORBIDDEN,
            )
        try:
            return CustomUser.objects.get(pk=pk, user_type="1"), None
        except CustomUser.DoesNotExist:
            return None, Response({"detail": "Admin not found."}, status=status.HTTP_404_NOT_FOUND)

    def patch(self, request, pk):
        target, err = self._get_target(request, pk)
        if err:
            return err

        d = request.data
        if "first_name" in d:
            target.first_name = d["first_name"]
        if "last_name" in d:
            target.last_name = d["last_name"]
        if "email" in d:
            new_email = d["email"].strip().lower()
            if CustomUser.objects.exclude(pk=pk).filter(email=new_email).exists():
                return Response(
                    {"detail": "Email already in use."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            target.email = new_email
        if "phone" in d and hasattr(target, "phone"):
            target.phone = d["phone"]
        if "is_active" in d:
            target.is_active = bool(d["is_active"])
        if "password" in d and d["password"]:
            try:
                validate_password(d["password"], target)
            except DjangoValidationError as exc:
                return Response({"password": exc.messages}, status=status.HTTP_400_BAD_REQUEST)
            target.set_password(d["password"])
        target.save()

        if "branch_ids" in d:
            profile, _ = Admin.objects.get_or_create(admin=target)
            profile.branches.set(Branch.objects.filter(pk__in=(d["branch_ids"] or [])))

        return Response({"id": target.id, "email": target.email})

    def delete(self, request, pk):
        target, err = self._get_target(request, pk)
        if err:
            return err

        if target.pk == request.user.pk:
            return Response(
                {"detail": "You cannot delete your own account."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        target_profile = getattr(target, "admin", None)
        if target_profile and target_profile.is_super_admin:
            return Response(
                {"detail": "Super-admin accounts cannot be deleted via API."},
                status=status.HTTP_403_FORBIDDEN,
            )

        target.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
