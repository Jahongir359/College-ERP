from django.urls import path

from . import (
    views,
    admin_views,
    marks_views,
    parent_messages,
    register_views,
    school_views,
    student_views,
    term_grades_views,
)

urlpatterns = [
    # ── App start (no login) ──────────────────────────────────────────────────
    path("app/version/", views.AppVersionView.as_view(), name="api_app_version"),
    # ── Auth ─────────────────────────────────────────────────────────────────
    path("auth/login/", views.LoginView.as_view(), name="api_login"),
    path("auth/logout/", views.LogoutView.as_view(), name="api_logout"),
    # ── Profile (all roles) ───────────────────────────────────────────────────
    path("me/", views.MeView.as_view(), name="api_me"),
    path("me/change-password/", views.ChangePasswordView.as_view(), name="api_change_password"),
    path("me/fcm-token/", views.FcmTokenView.as_view(), name="api_fcm_token"),
    # ── Courses & Groups ──────────────────────────────────────────────────────
    path("courses/", views.CourseListView.as_view(), name="api_courses"),
    path("groups/", views.GroupListView.as_view(), name="api_groups"),
    path("groups/<int:pk>/", views.GroupDetailView.as_view(), name="api_group_detail"),
    # ── Attendance ────────────────────────────────────────────────────────────
    path("attendance/", views.AttendanceView.as_view(), name="api_attendance"),
    # ── Results ───────────────────────────────────────────────────────────────
    path("results/", views.ResultView.as_view(), name="api_results"),
    # ── Assignments ───────────────────────────────────────────────────────────
    path("assignments/", views.AssignmentListView.as_view(), name="api_assignments"),
    path(
        "assignments/<int:pk>/", views.AssignmentDetailView.as_view(), name="api_assignment_detail"
    ),
    path(
        "assignments/<int:pk>/submit/",
        views.SubmitAssignmentView.as_view(),
        name="api_submit_assignment",
    ),
    # ── Notifications ─────────────────────────────────────────────────────────
    path("notifications/", views.NotificationListView.as_view(), name="api_notifications"),
    path(
        "notifications/mark-all-read/",
        views.NotificationMarkAllReadView.as_view(),
        name="api_notifications_mark_all",
    ),
    path(
        "notifications/<int:pk>/read/",
        views.NotificationReadView.as_view(),
        name="api_notification_read",
    ),
    # ── Leave  (student/staff POST own; admin GET all + PATCH approve/reject) ─
    path("leave/", views.LeaveView.as_view(), name="api_leave"),
    path("leave/<int:pk>/", views.LeaveDetailView.as_view(), name="api_leave_detail"),
    # ── Feedback  (student/staff POST own; admin GET all + PATCH reply) ───────
    path("feedback/", views.FeedbackView.as_view(), name="api_feedback"),
    path("feedback/<int:pk>/", views.FeedbackDetailView.as_view(), name="api_feedback_detail"),
    # ── Invoices  (student: own; admin: all) ─────────────────────────────────
    path("invoices/", views.InvoiceView.as_view(), name="api_invoices"),
    path("invoices/<int:pk>/", views.InvoiceDetailView.as_view(), name="api_invoice_detail"),
    # ── Dashboard endpoints (mobile home screens) ────────────────────────────
    path("student/home/", views.StudentDashboardView.as_view(), name="api_student_home"),
    path("admin/home/", views.AdminDashboardView.as_view(), name="api_admin_home"),
    # ── Stats  (staff + admin dashboard) ─────────────────────────────────────
    path("stats/", views.StaffStatsView.as_view(), name="api_stats"),
    # ── File upload ───────────────────────────────────────────────────────────
    path("upload/", views.FileUploadView.as_view(), name="api_upload"),
    # ── Admin: core stats & users ─────────────────────────────────────────────
    path("admin/stats/", views.AdminStatsView.as_view(), name="api_admin_stats"),
    path("admin/users/", views.AdminUserListView.as_view(), name="api_admin_users"),
    path("admin/groups/", views.AdminGroupListView.as_view(), name="api_admin_groups"),
    path("admin/enroll/", views.AdminEnrollmentView.as_view(), name="api_admin_enroll"),
    # ── Admin: student management ─────────────────────────────────────────────
    path("admin/students/", views.AdminStudentListView.as_view(), name="api_admin_students"),
    path(
        "admin/students/<int:pk>/",
        views.AdminStudentDetailView.as_view(),
        name="api_admin_student_detail",
    ),
    # ── Admin: staff management ───────────────────────────────────────────────
    path("admin/staff/", views.AdminStaffListView.as_view(), name="api_admin_staff"),
    path(
        "admin/staff/<int:pk>/", views.AdminStaffDetailView.as_view(), name="api_admin_staff_detail"
    ),
    # ── Admin: registration leads ─────────────────────────────────────────────
    path("admin/leads/", views.AdminLeadListView.as_view(), name="api_admin_leads"),
    path(
        "admin/leads/<int:pk>/", views.AdminLeadDetailView.as_view(), name="api_admin_lead_detail"
    ),
    # ── Admin: branches ───────────────────────────────────────────────────────
    path("admin/branches/", views.AdminBranchListView.as_view(), name="api_admin_branches"),
    # ── Vocabulary (student) ──────────────────────────────────────────────────
    path("vocabulary/", views.VocabularyDayListView.as_view(), name="api_vocabulary"),
    path(
        "vocabulary/<int:pk>/",
        views.VocabularyDayDetailView.as_view(),
        name="api_vocabulary_detail",
    ),
    path(
        "vocabulary/<int:pk>/complete/",
        views.VocabularyDayCompleteView.as_view(),
        name="api_vocabulary_complete",
    ),
    path(
        "vocabulary/<int:pk>/quiz/", views.VocabularyQuizView.as_view(), name="api_vocabulary_quiz"
    ),
    path(
        "vocabulary/<int:pk>/quiz-result/",
        views.VocabularyQuizResultView.as_view(),
        name="api_vocabulary_quiz_result",
    ),
    # ── Student Progress ──────────────────────────────────────────────────────
    path("student/progress/", views.StudentProgressView.as_view(), name="api_student_progress"),
    # ── Student: attendance hub, result files, app settings ──────────────────
    path(
        "student/attendance/summary/",
        student_views.StudentAttendanceSummaryView.as_view(),
        name="api_student_attendance_summary",
    ),
    path(
        "result-files/",
        student_views.StudentResultFileListView.as_view(),
        name="api_student_result_files",
    ),
    path(
        "result-files/<int:pk>/download/",
        student_views.StudentResultFileDownloadView.as_view(),
        name="api_student_result_file_download",
    ),
    path(
        "student/settings/",
        student_views.StudentSettingsView.as_view(),
        name="api_student_settings",
    ),
    # ── Stories ───────────────────────────────────────────────────────────────
    path("stories/", views.StoryListView.as_view(), name="api_stories"),
    path("stories/create/", views.StoryCreateView.as_view(), name="api_story_create"),
    path("stories/<int:pk>/", views.StoryDetailView.as_view(), name="api_story_detail"),
    # ── Staff Vocabulary Management ───────────────────────────────────────────
    path("staff/vocabulary/", views.StaffVocabularyListView.as_view(), name="api_staff_vocabulary"),
    path(
        "staff/vocabulary/create/",
        views.StaffVocabularyCreateView.as_view(),
        name="api_staff_vocabulary_create",
    ),
    path(
        "staff/vocabulary/<int:pk>/",
        views.StaffVocabularyDetailView.as_view(),
        name="api_staff_vocabulary_detail",
    ),
    path(
        "staff/vocabulary/<int:pk>/words/",
        views.StaffVocabularyWordView.as_view(),
        name="api_staff_vocabulary_words",
    ),
    path(
        "staff/vocabulary/<int:pk>/words/<int:word_pk>/",
        views.StaffVocabularyWordView.as_view(),
        name="api_staff_vocabulary_word_delete",
    ),
    path("staff/payments/", views.StaffPaymentBoardView.as_view(), name="api_staff_payments"),
    # ── Leaderboard ───────────────────────────────────────────────────────────
    path("leaderboard/", views.LeaderboardView.as_view(), name="api_leaderboard"),
    # ── Group chat & library ──────────────────────────────────────────────────
    path("messages/", views.MessageThreadListView.as_view(), name="api_messages"),
    path(
        "messages/<int:group_id>/",
        views.MessageThreadDetailView.as_view(),
        name="api_message_thread",
    ),
    path("books/", views.BookListView.as_view(), name="api_books"),
    # ── Admin: branch/course/session/subject management ───────────────────────
    path(
        "admin/branches-manage/",
        admin_views.BranchListView.as_view(),
        name="api_admin_branches_manage",
    ),
    path(
        "admin/branches-manage/<int:pk>/",
        admin_views.BranchDetailView.as_view(),
        name="api_admin_branch_detail",
    ),
    path("admin/courses/", admin_views.CourseListView.as_view(), name="api_admin_courses"),
    path(
        "admin/courses/<int:pk>/",
        admin_views.CourseDetailView.as_view(),
        name="api_admin_course_detail",
    ),
    path("admin/sessions/", admin_views.SessionListView.as_view(), name="api_admin_sessions"),
    path(
        "admin/sessions/<int:pk>/",
        admin_views.SessionDetailView.as_view(),
        name="api_admin_session_detail",
    ),
    path(
        "admin/sessions/<int:pk>/terms/",
        admin_views.SessionTermListView.as_view(),
        name="api_admin_session_terms",
    ),
    path(
        "admin/terms/<int:pk>/", admin_views.TermDetailView.as_view(), name="api_admin_term_detail"
    ),
    # ── Admin: School subjects per class (P1.3) ──────────────────────────────
    path(
        "admin/classes/<int:pk>/subjects/",
        school_views.ClassSubjectListView.as_view(),
        name="api_admin_class_subjects",
    ),
    path(
        "admin/class-subjects/<int:pk>/",
        school_views.ClassSubjectDetailView.as_view(),
        name="api_admin_class_subject_detail",
    ),
    # ── Admin: School parents and their children (P1.7) ──────────────────────
    path("admin/parents/", school_views.ParentListView.as_view(), name="api_admin_parents"),
    path(
        "admin/parents/link-by-login/",
        school_views.ParentLinkByLoginView.as_view(),
        name="api_admin_parent_link_by_login",
    ),
    path(
        "admin/parents/<int:pk>/",
        school_views.ParentDetailView.as_view(),
        name="api_admin_parent_detail",
    ),
    path(
        "admin/parents/<int:pk>/children/",
        school_views.ParentChildListView.as_view(),
        name="api_admin_parent_children",
    ),
    path(
        "admin/parents/<int:pk>/children/<int:student_pk>/",
        school_views.ParentChildDetailView.as_view(),
        name="api_admin_parent_child_detail",
    ),
    # ── Admin + all roles: bell periods and timetable (P2.1) ─────────────────
    path(
        "admin/bell-periods/",
        school_views.BellPeriodListView.as_view(),
        name="api_admin_bell_periods",
    ),
    path(
        "admin/bell-periods/<int:pk>/",
        school_views.BellPeriodDetailView.as_view(),
        name="api_admin_bell_period_detail",
    ),
    path(
        "admin/classes/<int:pk>/lessons/",
        school_views.ClassLessonListView.as_view(),
        name="api_admin_class_lessons",
    ),
    path(
        "admin/lessons/<int:pk>/",
        school_views.LessonDetailView.as_view(),
        name="api_admin_lesson_detail",
    ),
    path(
        "school/timetable/",
        school_views.TimetableView.as_view(),
        name="api_school_timetable",
    ),
    # ── School daily register (P2.2) ─────────────────────────────────────────
    path(
        "school/register/<int:pk>/<str:day>/",
        register_views.RegisterView.as_view(),
        name="api_school_register",
    ),
    path(
        "messages/parent/",
        parent_messages.ParentThreadListView.as_view(),
        name="api_parent_threads",
    ),
    path(
        "messages/parent/contacts/",
        parent_messages.ParentContactsView.as_view(),
        name="api_parent_thread_contacts",
    ),
    path(
        "messages/parent/<int:pk>/",
        parent_messages.ParentThreadDetailView.as_view(),
        name="api_parent_thread",
    ),
    path("admin/subjects/", admin_views.SubjectListView.as_view(), name="api_admin_subjects"),
    path(
        "admin/subjects/<int:pk>/",
        admin_views.SubjectDetailView.as_view(),
        name="api_admin_subject_detail",
    ),
    # ── Admin: group CRUD + detail (with enrolled students) ──────────────────
    path(
        "admin/groups-manage/",
        admin_views.AdminGroupListView.as_view(),
        name="api_admin_groups_manage",
    ),
    path(
        "admin/groups-manage/<int:pk>/",
        admin_views.AdminGroupDetailView.as_view(),
        name="api_admin_group_manage_detail",
    ),
    # Legacy detail endpoint (read-only, from admin_views.GroupDetailView):
    path(
        "admin/groups/<int:pk>/",
        admin_views.GroupDetailView.as_view(),
        name="api_admin_group_detail",
    ),
    # ── Admin: enrollments ────────────────────────────────────────────────────
    path("admin/enrollments/", admin_views.EnrollmentView.as_view(), name="api_admin_enrollments"),
    # ── Admin: leave requests ─────────────────────────────────────────────────
    path(
        "admin/leave-requests/",
        admin_views.AdminLeaveListView.as_view(),
        name="api_admin_leave_requests",
    ),
    path(
        "admin/leave-requests/<int:pk>/",
        admin_views.AdminLeaveDetailView.as_view(),
        name="api_admin_leave_detail",
    ),
    # ── Admin: attendance report ──────────────────────────────────────────────
    path(
        "admin/attendance-report/",
        admin_views.AdminAttendanceView.as_view(),
        name="api_admin_attendance_report",
    ),
    # ── Admin: stories ────────────────────────────────────────────────────────
    path("admin/stories/", admin_views.AdminStoriesListView.as_view(), name="api_admin_stories"),
    path(
        "admin/stories/<int:pk>/",
        admin_views.AdminStoriesDetailView.as_view(),
        name="api_admin_story_detail",
    ),
    # ── Admin: notifications ──────────────────────────────────────────────────
    path(
        "admin/send-notification/",
        admin_views.AdminSendNotificationView.as_view(),
        name="api_admin_send_notification",
    ),
    # ── Admin: invoices ───────────────────────────────────────────────────────
    path(
        "admin/invoices-manage/",
        admin_views.AdminInvoiceListView.as_view(),
        name="api_admin_invoices_manage",
    ),
    path(
        "admin/invoices-manage/<int:pk>/pay/",
        admin_views.AdminRecordPaymentView.as_view(),
        name="api_admin_invoice_pay",
    ),
    # ── Admin: admin user management (superadmin only) ────────────────────────
    path("admin/admins/", admin_views.AdminAdminListView.as_view(), name="api_admin_admins"),
    path(
        "admin/admins/<int:pk>/",
        admin_views.AdminAdminDetailView.as_view(),
        name="api_admin_admin_detail",
    ),
    # ── School gradebook (P2.4) ──────────────────────────────────────────────
    path("school/marks/", marks_views.MarkListView.as_view(), name="api_school_marks"),
    # ── School quarter and year grades (P2.5) ────────────────────────────────
    path(
        "school/term-grades/",
        term_grades_views.TermGradeListView.as_view(),
        name="api_school_term_grades",
    ),
]
