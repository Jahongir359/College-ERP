from django.contrib.auth import authenticate
from django.core.exceptions import PermissionDenied as DjangoPermissionDenied
from django.db import transaction
from django.db.models import Q
from rest_framework import generics, status
from rest_framework.pagination import PageNumberPagination
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken

from ..models import (
    Assignment, Attendance, AttendanceReport, Course, CustomUser,
    Enrollment, Group, Notification, ResultFile, Staff, Student,
    StudentResult, Submission,
)
from .permissions import IsAdmin, IsAdminOrTeacher, IsStudent, IsTeacher
from .serializers import (
    AssignmentDetailSerializer, AssignmentSerializer, AttendanceSaveSerializer,
    AttendanceSerializer, ChangePasswordSerializer, CourseSerializer,
    EnrollmentSerializer, FcmTokenSerializer, GroupDetailSerializer,
    GroupSerializer, MeSerializer, NotificationSerializer, StudentResultSerializer,
    StudentSummarySerializer, SubmissionSerializer, SubmitAssignmentSerializer,
    UserSerializer,
)


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email', '').strip()
        password = request.data.get('password', '')

        if not email or not password:
            return Response(
                {'detail': 'Email and password are required.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            user = authenticate(request=request, username=email, password=password)
        except DjangoPermissionDenied:
            return Response(
                {'detail': 'Account temporarily locked. Try again later.'},
                status=status.HTTP_403_FORBIDDEN,
            )

        if user is None:
            return Response(
                {'detail': 'Invalid email or password.'},
                status=status.HTTP_401_UNAUTHORIZED,
            )
        if not user.is_active:
            return Response(
                {'detail': 'Account is disabled.'},
                status=status.HTTP_403_FORBIDDEN,
            )

        refresh = RefreshToken.for_user(user)
        return Response({
            'access': str(refresh.access_token),
            'refresh': str(refresh),
            'user': UserSerializer(user, context={'request': request}).data,
        })


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        refresh_token = request.data.get('refresh')
        if not refresh_token:
            return Response(
                {'detail': 'Refresh token required.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            RefreshToken(refresh_token).blacklist()
        except TokenError:
            return Response(
                {'detail': 'Invalid or expired token.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        return Response({'detail': 'Logged out successfully.'})


# ---------------------------------------------------------------------------
# Profile
# ---------------------------------------------------------------------------

class MeView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response(MeSerializer(request.user, context={'request': request}).data)

    def patch(self, request):
        user = request.user
        # Profile picture arrives as a file upload (multipart).
        if 'profile_pic' in request.FILES:
            user.profile_pic = request.FILES['profile_pic']
        serializer = MeSerializer(
            user, data=request.data, partial=True, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response(MeSerializer(user, context={'request': request}).data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        user = request.user
        if not user.check_password(serializer.validated_data['old_password']):
            return Response(
                {'old_password': 'Incorrect password.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        user.set_password(serializer.validated_data['new_password'])
        user.save()
        return Response({'detail': 'Password changed successfully.'})


class FcmTokenView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = FcmTokenSerializer(data=request.data)
        if serializer.is_valid():
            request.user.fcm_token = serializer.validated_data['token']
            request.user.save(update_fields=['fcm_token'])
            return Response({'detail': 'FCM token updated.'})
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# ---------------------------------------------------------------------------
# Courses
# ---------------------------------------------------------------------------

class CourseListView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = CourseSerializer
    pagination_class = None

    def get_queryset(self):
        return Course.objects.filter(is_active=True).order_by('name')


# ---------------------------------------------------------------------------
# Groups
# ---------------------------------------------------------------------------

class GroupListView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = GroupSerializer

    def get_queryset(self):
        user = self.request.user
        user_type = str(user.user_type)
        qs = Group.objects.select_related(
            'course', 'teacher__admin', 'branch').filter(is_archived=False)

        if user_type == '1':
            return qs
        if user_type == '2':
            try:
                return qs.filter(teacher=user.staff)
            except Staff.DoesNotExist:
                return qs.none()
        if user_type == '3':
            try:
                ids = Enrollment.objects.filter(
                    student=user.student, is_active=True,
                ).values_list('group_id', flat=True)
                return qs.filter(id__in=ids)
            except Student.DoesNotExist:
                return qs.none()
        return qs.none()


class GroupDetailView(generics.RetrieveAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = GroupDetailSerializer

    def get_queryset(self):
        user = self.request.user
        user_type = str(user.user_type)
        qs = Group.objects.select_related('course', 'teacher__admin', 'branch')

        if user_type == '1':
            return qs
        if user_type == '2':
            try:
                return qs.filter(teacher=user.staff)
            except Staff.DoesNotExist:
                return qs.none()
        if user_type == '3':
            try:
                ids = Enrollment.objects.filter(
                    student=user.student, is_active=True,
                ).values_list('group_id', flat=True)
                return qs.filter(id__in=ids)
            except Student.DoesNotExist:
                return qs.none()
        return qs.none()


# ---------------------------------------------------------------------------
# Attendance
# ---------------------------------------------------------------------------

class AttendanceView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        user_type = str(user.user_type)
        group_id = request.query_params.get('group_id')
        date_str = request.query_params.get('date')

        # Students get their own attendance timeline
        if user_type == '3':
            try:
                student = user.student
            except Student.DoesNotExist:
                return Response({'count': 0, 'results': []})
            reports = (
                AttendanceReport.objects
                .filter(student=student)
                .select_related('attendance__group')
                .order_by('-attendance__date')
            )
            if group_id:
                reports = reports.filter(attendance__group_id=group_id)
            paginator = PageNumberPagination()
            paginator.page_size = 20
            page = paginator.paginate_queryset(reports, request)
            data = [{
                'date': r.attendance.date,
                'group_id': r.attendance.group_id,
                'group_name': r.attendance.group.name if r.attendance.group else None,
                'status': r.status,
                'status_display': r.get_status_display(),
            } for r in page]
            return paginator.get_paginated_response(data)

        # Admin and Teachers get full attendance records
        qs = (
            Attendance.objects
            .select_related('group')
            .prefetch_related('attendancereport_set__student__admin')
        )
        if user_type == '2':
            try:
                qs = qs.filter(group__teacher=user.staff)
            except Staff.DoesNotExist:
                return Response({'count': 0, 'results': []})
        if group_id:
            qs = qs.filter(group_id=group_id)
        if date_str:
            qs = qs.filter(date=date_str)
        qs = qs.order_by('-date')

        paginator = PageNumberPagination()
        paginator.page_size = 20
        page = paginator.paginate_queryset(qs, request)
        serializer = AttendanceSerializer(page, many=True, context={'request': request})
        return paginator.get_paginated_response(serializer.data)

    def post(self, request):
        if str(request.user.user_type) not in ('1', '2'):
            return Response({'detail': 'Permission denied.'}, status=status.HTTP_403_FORBIDDEN)

        serializer = AttendanceSaveSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        data = serializer.validated_data
        group = Group.objects.get(id=data['group_id'])

        if str(request.user.user_type) == '2':
            try:
                if group.teacher_id != request.user.staff.id:
                    return Response(
                        {'detail': 'You can only take attendance for your own groups.'},
                        status=status.HTTP_403_FORBIDDEN,
                    )
            except Staff.DoesNotExist:
                return Response({'detail': 'Staff profile not found.'},
                                status=status.HTTP_403_FORBIDDEN)

        records = data['records']
        with transaction.atomic():
            attendance, _ = Attendance.objects.get_or_create(
                group=group, date=data['date'])

            existing = {
                r.student_id: r
                for r in AttendanceReport.objects.filter(attendance=attendance)
            }
            to_create, to_update = [], []
            for rec in records:
                sid = int(rec['student_id'])
                st = int(rec['status'])
                if sid in existing:
                    existing[sid].status = st
                    to_update.append(existing[sid])
                else:
                    to_create.append(
                        AttendanceReport(attendance=attendance, student_id=sid, status=st))
            if to_create:
                AttendanceReport.objects.bulk_create(to_create)
            if to_update:
                AttendanceReport.objects.bulk_update(to_update, ['status'])

        return Response(
            {'detail': 'Attendance saved.', 'attendance_id': attendance.id})


# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------

class ResultView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        user_type = str(user.user_type)
        group_id = request.query_params.get('group_id')

        qs = StudentResult.objects.select_related('student__admin', 'group')

        if user_type == '1':
            pass
        elif user_type == '2':
            try:
                teacher_group_ids = Group.objects.filter(
                    teacher=user.staff).values_list('id', flat=True)
                qs = qs.filter(group_id__in=teacher_group_ids)
            except Staff.DoesNotExist:
                return Response({'count': 0, 'results': []})
        elif user_type == '3':
            try:
                qs = qs.filter(student=user.student)
            except Student.DoesNotExist:
                return Response({'count': 0, 'results': []})

        if group_id:
            qs = qs.filter(group_id=group_id)

        paginator = PageNumberPagination()
        paginator.page_size = 20
        page = paginator.paginate_queryset(qs, request)
        serializer = StudentResultSerializer(page, many=True, context={'request': request})
        return paginator.get_paginated_response(serializer.data)

    def post(self, request):
        if str(request.user.user_type) not in ('1', '2'):
            return Response({'detail': 'Permission denied.'}, status=status.HTTP_403_FORBIDDEN)

        student_id = request.data.get('student_id')
        group_id = request.data.get('group_id')
        if not student_id or not group_id:
            return Response({'detail': 'student_id and group_id are required.'},
                            status=status.HTTP_400_BAD_REQUEST)

        try:
            student = Student.objects.get(id=student_id)
            group = Group.objects.get(id=group_id)
        except (Student.DoesNotExist, Group.DoesNotExist):
            return Response({'detail': 'Student or group not found.'},
                            status=status.HTTP_404_NOT_FOUND)

        if str(request.user.user_type) == '2':
            try:
                if group.teacher_id != request.user.staff.id:
                    return Response(
                        {'detail': 'You can only update results for your own groups.'},
                        status=status.HTTP_403_FORBIDDEN,
                    )
            except Staff.DoesNotExist:
                return Response({'detail': 'Staff profile not found.'},
                                status=status.HTTP_403_FORBIDDEN)

        result, created = StudentResult.objects.update_or_create(
            student=student, group=group,
            defaults={
                'test': request.data.get('test', 0),
                'exam': request.data.get('exam', 0),
                'comment': request.data.get('comment', ''),
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

        serializer = StudentResultSerializer(result, context={'request': request})
        return Response(
            serializer.data,
            status=status.HTTP_201_CREATED if created else status.HTTP_200_OK,
        )


# ---------------------------------------------------------------------------
# Assignments
# ---------------------------------------------------------------------------

class AssignmentListView(APIView):
    permission_classes = [IsAuthenticated]

    def _queryset(self, user):
        user_type = str(user.user_type)
        qs = Assignment.objects.select_related('group', 'created_by__admin')
        if user_type == '1':
            return qs
        if user_type == '2':
            try:
                return qs.filter(created_by=user.staff)
            except Staff.DoesNotExist:
                return qs.none()
        if user_type == '3':
            try:
                ids = Enrollment.objects.filter(
                    student=user.student, is_active=True,
                ).values_list('group_id', flat=True)
                return qs.filter(group_id__in=ids)
            except Student.DoesNotExist:
                return qs.none()
        return qs.none()

    def get(self, request):
        qs = self._queryset(request.user).order_by('-created_at')
        paginator = PageNumberPagination()
        paginator.page_size = 20
        page = paginator.paginate_queryset(qs, request)
        serializer = AssignmentSerializer(page, many=True, context={'request': request})
        return paginator.get_paginated_response(serializer.data)

    def post(self, request):
        if str(request.user.user_type) not in ('1', '2'):
            return Response({'detail': 'Permission denied.'}, status=status.HTTP_403_FORBIDDEN)
        try:
            staff = request.user.staff
        except Staff.DoesNotExist:
            return Response({'detail': 'Staff profile not found.'},
                            status=status.HTTP_403_FORBIDDEN)

        serializer = AssignmentSerializer(data=request.data, context={'request': request})
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        assignment = serializer.save(created_by=staff)
        return Response(
            AssignmentSerializer(assignment, context={'request': request}).data,
            status=status.HTTP_201_CREATED,
        )


class AssignmentDetailView(generics.RetrieveAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = AssignmentDetailSerializer

    def get_queryset(self):
        user = self.request.user
        user_type = str(user.user_type)
        qs = Assignment.objects.select_related('group', 'created_by__admin')
        if user_type == '1':
            return qs
        if user_type == '2':
            try:
                return qs.filter(created_by=user.staff)
            except Staff.DoesNotExist:
                return qs.none()
        if user_type == '3':
            try:
                ids = Enrollment.objects.filter(
                    student=user.student, is_active=True,
                ).values_list('group_id', flat=True)
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
            return Response({'detail': 'Assignment not found.'}, status=status.HTTP_404_NOT_FOUND)

        try:
            student = request.user.student
        except Student.DoesNotExist:
            return Response({'detail': 'Student profile not found.'},
                            status=status.HTTP_403_FORBIDDEN)

        if not Enrollment.objects.filter(
                student=student, group=assignment.group, is_active=True).exists():
            return Response({'detail': 'You are not enrolled in this group.'},
                            status=status.HTTP_403_FORBIDDEN)

        serializer = SubmitAssignmentSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        submission, created = Submission.objects.update_or_create(
            assignment=assignment,
            student=student,
            defaults={
                'file': serializer.validated_data.get('file'),
                'note': serializer.validated_data.get('note', ''),
            },
        )
        return Response(
            SubmissionSerializer(submission, context={'request': request}).data,
            status=status.HTTP_201_CREATED if created else status.HTTP_200_OK,
        )


# ---------------------------------------------------------------------------
# Notifications
# ---------------------------------------------------------------------------

class NotificationListView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = NotificationSerializer

    def get_queryset(self):
        qs = Notification.objects.filter(recipient=self.request.user)
        category = self.request.query_params.get('category')
        if category:
            qs = qs.filter(category=category)
        if self.request.query_params.get('unread') == '1':
            qs = qs.filter(is_read=False)
        return qs


class NotificationReadView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        updated = Notification.objects.filter(
            pk=pk, recipient=request.user).update(is_read=True)
        if not updated:
            return Response({'detail': 'Notification not found.'},
                            status=status.HTTP_404_NOT_FOUND)
        return Response({'detail': 'Marked as read.'})


class NotificationMarkAllReadView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        Notification.objects.filter(
            recipient=request.user, is_read=False).update(is_read=True)
        return Response({'detail': 'All notifications marked as read.'})


# ---------------------------------------------------------------------------
# File upload (result files)
# ---------------------------------------------------------------------------

class FileUploadView(APIView):
    permission_classes = [IsAdminOrTeacher]

    def post(self, request):
        file_obj = request.FILES.get('file')
        if not file_obj:
            return Response({'detail': 'No file provided.'},
                            status=status.HTTP_400_BAD_REQUEST)

        group_id = request.data.get('group_id')
        if not group_id:
            return Response({'detail': 'group_id is required.'},
                            status=status.HTTP_400_BAD_REQUEST)

        try:
            group = Group.objects.get(id=group_id)
        except Group.DoesNotExist:
            return Response({'detail': 'Group not found.'}, status=status.HTTP_404_NOT_FOUND)

        # Admins may upload to any group; teachers only to their own groups.
        user_type = str(request.user.user_type)
        if user_type == '2':
            try:
                staff = request.user.staff
            except Staff.DoesNotExist:
                return Response({'detail': 'Staff profile not found.'},
                                status=status.HTTP_403_FORBIDDEN)
            if group.teacher_id != staff.id:
                return Response(
                    {'detail': 'You are not the teacher of this group.'},
                    status=status.HTTP_403_FORBIDDEN,
                )
        else:
            staff = None

        student_id = request.data.get('student_id')
        student = None
        if student_id:
            try:
                student = Student.objects.get(id=student_id)
            except Student.DoesNotExist:
                return Response({'detail': 'Student not found.'}, status=status.HTTP_404_NOT_FOUND)
            # Verify the student is enrolled in this group.
            if not Enrollment.objects.filter(
                student=student, group=group, is_active=True
            ).exists():
                return Response(
                    {'detail': 'Student is not enrolled in this group.'},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        if staff is None:
            try:
                staff = request.user.staff
            except Staff.DoesNotExist:
                return Response({'detail': 'Staff profile not found.'},
                                status=status.HTTP_403_FORBIDDEN)

        title = request.data.get('title', file_obj.name)
        description = request.data.get('description', '')

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

        return Response({
            'id': result_file.id,
            'title': result_file.title,
            'file_url': request.build_absolute_uri(result_file.file.url),
            'uploaded_at': result_file.uploaded_at,
        }, status=status.HTTP_201_CREATED)


# ---------------------------------------------------------------------------
# Admin endpoints
# ---------------------------------------------------------------------------

class AdminStatsView(APIView):
    permission_classes = [IsAdmin]

    def get(self, request):
        return Response({
            'student_count': Student.objects.count(),
            'active_students': Student.objects.filter(status='active').count(),
            'staff_count': Staff.objects.count(),
            'group_count': Group.objects.filter(is_archived=False).count(),
            'archived_groups': Group.objects.filter(is_archived=True).count(),
            'course_count': Course.objects.filter(is_active=True).count(),
        })


class AdminUserListView(generics.ListAPIView):
    permission_classes = [IsAdmin]
    serializer_class = UserSerializer

    def get_queryset(self):
        qs = CustomUser.objects.all()
        user_type = self.request.query_params.get('user_type')
        if user_type:
            qs = qs.filter(user_type=user_type)
        search = self.request.query_params.get('search')
        if search:
            qs = qs.filter(
                Q(first_name__icontains=search)
                | Q(last_name__icontains=search)
                | Q(email__icontains=search)
            )
        return qs.order_by('-date_joined')


class AdminGroupListView(generics.ListAPIView):
    permission_classes = [IsAdmin]
    serializer_class = GroupSerializer

    def get_queryset(self):
        qs = Group.objects.select_related('course', 'teacher__admin', 'branch')
        if self.request.query_params.get('archived') != '1':
            qs = qs.filter(is_archived=False)
        return qs


class AdminEnrollmentView(APIView):
    permission_classes = [IsAdmin]

    def post(self, request):
        serializer = EnrollmentSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        student = serializer.validated_data['student']
        group = serializer.validated_data['group']

        enrollment, created = Enrollment.objects.get_or_create(
            student=student, group=group, defaults={'is_active': True})
        if not created and not enrollment.is_active:
            enrollment.is_active = True
            enrollment.save(update_fields=['is_active'])

        return Response(
            EnrollmentSerializer(enrollment).data,
            status=status.HTTP_201_CREATED if created else status.HTTP_200_OK,
        )

    def delete(self, request):
        student_id = request.data.get('student')
        group_id = request.data.get('group')
        updated = Enrollment.objects.filter(
            student_id=student_id, group_id=group_id,
        ).update(is_active=False)
        if not updated:
            return Response({'detail': 'Enrollment not found.'}, status=status.HTTP_404_NOT_FOUND)
        return Response({'detail': 'Student unenrolled.'})
