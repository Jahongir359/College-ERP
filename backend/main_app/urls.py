"""college_management_system URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""

from django.contrib.auth import views as auth_views
from django.urls import path

from main_app.EditResultView import EditResultView

from . import (
    hod_views,
    language,
    messaging_views,
    password_recovery,
    payments_views,
    public_views,
    school_admin_views,
    school_board_views,
    school_parent_views,
    school_timetable_views,
    staff_views,
    student_views,
    views,
)

urlpatterns = [
    path("health/", views.health, name="health"),
    path("", views.login_page, name="entry_page"),
    path("login/", views.login_page, name="login_page"),
    path("language/", language.set_language, name="set_language"),
    # ── Maktab: School admin pages (P3.1) ────────────────────────────────────
    path("maktab/", school_board_views.school_board, name="school_board"),
    path("maktab/classes/", school_admin_views.classes, name="school_classes"),
    path("maktab/classes/add/", school_admin_views.class_add, name="school_class_add"),
    path("maktab/classes/<int:pk>/", school_admin_views.class_detail, name="school_class_detail"),
    path("maktab/classes/<int:pk>/edit/", school_admin_views.class_edit, name="school_class_edit"),
    path(
        "maktab/classes/<int:pk>/students/add/",
        school_admin_views.class_student_add,
        name="school_class_student_add",
    ),
    path(
        "maktab/classes/<int:pk>/students/<int:student_pk>/remove/",
        school_admin_views.class_student_remove,
        name="school_class_student_remove",
    ),
    path(
        "maktab/classes/<int:pk>/subjects/add/",
        school_admin_views.class_subject_add,
        name="school_class_subject_add",
    ),
    path(
        "maktab/classes/<int:pk>/subjects/<int:cs_pk>/",
        school_admin_views.class_subject_edit,
        name="school_class_subject_edit",
    ),
    path(
        "maktab/classes/<int:pk>/subjects/<int:cs_pk>/remove/",
        school_admin_views.class_subject_remove,
        name="school_class_subject_remove",
    ),
    path("maktab/years/", school_admin_views.school_years, name="school_years"),
    path(
        "maktab/years/<int:pk>/current/",
        school_admin_views.school_year_make_current,
        name="school_year_make_current",
    ),
    path(
        "maktab/years/<int:pk>/quarters/add/",
        school_admin_views.school_term_add,
        name="school_term_add",
    ),
    path(
        "maktab/quarters/<int:term_pk>/",
        school_admin_views.school_term_edit,
        name="school_term_edit",
    ),
    path(
        "maktab/quarters/<int:term_pk>/delete/",
        school_admin_views.school_term_delete,
        name="school_term_delete",
    ),
    path("maktab/timetable/", school_timetable_views.timetable, name="school_timetable"),
    path("maktab/bells/", school_timetable_views.bells, name="school_bells"),
    path(
        "maktab/bells/branch/<int:branch_pk>/add/",
        school_timetable_views.bell_add,
        name="school_bell_add",
    ),
    path("maktab/bells/<int:pk>/", school_timetable_views.bell_edit, name="school_bell_edit"),
    path(
        "maktab/bells/<int:pk>/delete/",
        school_timetable_views.bell_delete,
        name="school_bell_delete",
    ),
    path("maktab/parents/", school_parent_views.parent_list, name="school_parents"),
    path(
        "maktab/parents/<int:pk>/", school_parent_views.parent_detail, name="school_parent_detail"
    ),
    path(
        "maktab/parents/<int:pk>/password/",
        school_parent_views.parent_reset_password,
        name="school_parent_reset_password",
    ),
    path(
        "maktab/parents/<int:pk>/delete/",
        school_parent_views.parent_delete,
        name="school_parent_delete",
    ),
    path(
        "maktab/parents/<int:pk>/children/add/",
        school_parent_views.parent_child_add,
        name="school_parent_child_add",
    ),
    path(
        "maktab/parents/<int:pk>/children/<int:student_pk>/",
        school_parent_views.parent_child_edit,
        name="school_parent_child_edit",
    ),
    path(
        "maktab/parents/<int:pk>/children/<int:student_pk>/remove/",
        school_parent_views.parent_child_remove,
        name="school_parent_child_remove",
    ),
    path(
        "accounts/password_reset/",
        views.SafePasswordResetView.as_view(),
        name="password_reset",
    ),
    path(
        "accounts/password_reset/done/",
        auth_views.PasswordResetDoneView.as_view(
            template_name="registration/password_reset_done.html"
        ),
        name="password_reset_done",
    ),
    path(
        "accounts/reset/<uidb64>/<token>/",
        auth_views.PasswordResetConfirmView.as_view(
            template_name="registration/password_reset_confirm.html",
            success_url="/accounts/reset/done/",
        ),
        name="password_reset_confirm",
    ),
    path(
        "accounts/reset/done/",
        auth_views.PasswordResetCompleteView.as_view(
            template_name="registration/password_reset_complete.html"
        ),
        name="password_reset_complete",
    ),
    path("forgot-password/", password_recovery.forgot_password, name="forgot_password"),
    path("verify-reset-code/", password_recovery.verify_reset_code, name="verify_reset_code"),
    path("reset-password/", password_recovery.reset_password, name="reset_password"),
    path(
        "password-reset-success/",
        password_recovery.password_reset_success,
        name="password_reset_success",
    ),
    path("resend-reset-code/", password_recovery.resend_code, name="resend_reset_code"),
    path(
        "public/registration-leads",
        public_views.registration_leads_receiver,
        name="public_registration_leads_no_slash",
    ),
    path(
        "public/registration-leads/",
        public_views.registration_leads_receiver,
        name="public_registration_leads",
    ),
    path("messages/", messaging_views.messages_home, name="messages"),
    path("messages/group/<int:group_id>/", messaging_views.messages_home, name="message_thread"),
    path("get_attendance", views.get_attendance, name="get_attendance"),
    path("doLogin/", views.doLogin, name="user_login"),
    path("logout_user/", views.logout_user, name="user_logout"),
    path("profile/", views.profile_settings_hub, name="profile_hub"),
    path("admin/home/", hod_views.admin_home, name="admin_home"),
    path("staff/add", hod_views.add_staff, name="add_staff"),
    path("course/add", hod_views.add_course, name="add_course"),
    path(
        "send_student_notification/",
        hod_views.send_student_notification,
        name="send_student_notification",
    ),
    path(
        "send_staff_notification/",
        hod_views.send_staff_notification,
        name="send_staff_notification",
    ),
    path("add_session/", hod_views.add_session, name="add_session"),
    path("admin_notify_student", hod_views.admin_notify_student, name="admin_notify_student"),
    path("admin_notify_staff", hod_views.admin_notify_staff, name="admin_notify_staff"),
    path("admin_view_profile", hod_views.admin_view_profile, name="admin_view_profile"),
    path(
        "check_email_availability",
        hod_views.check_email_availability,
        name="check_email_availability",
    ),
    path("session/manage/", hod_views.manage_session, name="manage_session"),
    path("session/edit/<int:session_id>", hod_views.edit_session, name="edit_session"),
    path(
        "student/view/feedback/",
        hod_views.student_feedback_message,
        name="student_feedback_message",
    ),
    path(
        "staff/view/feedback/",
        hod_views.staff_feedback_message,
        name="staff_feedback_message",
    ),
    path(
        "student/view/leave/",
        hod_views.view_student_leave,
        name="view_student_leave",
    ),
    path(
        "staff/view/leave/",
        hod_views.view_staff_leave,
        name="view_staff_leave",
    ),
    path(
        "attendance/view/",
        hod_views.admin_view_attendance,
        name="admin_view_attendance",
    ),
    path("attendance/fetch/", hod_views.get_admin_attendance, name="get_admin_attendance"),
    path("student/add/", hod_views.add_student, name="add_student"),
    path("subject/add/", hod_views.add_subject, name="add_subject"),
    path("staff/manage/", hod_views.manage_staff, name="manage_staff"),
    path("student/manage/", hod_views.manage_student, name="manage_student"),
    path(
        "admin/registration-leads/",
        hod_views.manage_registration_leads,
        name="manage_registration_leads",
    ),
    path("course/manage/", hod_views.manage_course, name="manage_course"),
    path("subject/manage/", hod_views.manage_subject, name="manage_subject"),
    path("staff/edit/<int:staff_id>", hod_views.edit_staff, name="edit_staff"),
    path("staff/delete/<int:staff_id>", hod_views.delete_staff, name="delete_staff"),
    path("course/delete/<int:course_id>", hod_views.delete_course, name="delete_course"),
    path("subject/delete/<int:subject_id>", hod_views.delete_subject, name="delete_subject"),
    path("session/delete/<int:session_id>", hod_views.delete_session, name="delete_session"),
    path("student/delete/<int:student_id>", hod_views.delete_student, name="delete_student"),
    path("student/edit/<int:student_id>", hod_views.edit_student, name="edit_student"),
    path("course/edit/<int:course_id>", hod_views.edit_course, name="edit_course"),
    path(
        "course/toggle-active/<int:course_id>",
        hod_views.toggle_course_active,
        name="toggle_course_active",
    ),
    path("subject/edit/<int:subject_id>", hod_views.edit_subject, name="edit_subject"),
    # Admin management
    path("admin/add/", hod_views.add_admin, name="add_admin"),
    path("admin/manage/", hod_views.manage_admin, name="manage_admin"),
    path("admin/edit/<int:admin_id>/", hod_views.edit_admin, name="edit_admin"),
    path("admin/delete/<int:admin_id>/", hod_views.delete_admin, name="delete_admin"),
    # Branch
    path("branch/manage/", hod_views.manage_branch, name="manage_branch"),
    path("branch/add/", hod_views.add_branch, name="add_branch"),
    path("branch/edit/<int:branch_id>", hod_views.edit_branch, name="edit_branch"),
    path("branch/delete/<int:branch_id>", hod_views.delete_branch, name="delete_branch"),
    path(
        "branch/admin-access/<int:admin_id>/",
        hod_views.update_admin_branch_access,
        name="update_admin_branch_access",
    ),
    # Group
    path("group/manage/", hod_views.manage_group, name="manage_group"),
    path("group/add/", hod_views.add_group, name="add_group"),
    path("group/edit/<int:group_id>", hod_views.edit_group, name="edit_group"),
    path("group/delete/<int:group_id>", hod_views.delete_group, name="delete_group"),
    path("group/archive/<int:group_id>", hod_views.archive_group, name="archive_group"),
    path("group/<int:group_id>/students/", hod_views.admin_group_detail, name="admin_group_detail"),
    # Enrollment
    path("enrollment/manage/", hod_views.manage_enrollment, name="manage_enrollment"),
    path("enrollment/add/", hod_views.add_enrollment, name="add_enrollment"),
    path(
        "enrollment/delete/<int:enrollment_id>",
        hod_views.delete_enrollment,
        name="delete_enrollment",
    ),
    path("enrollment/group-info/", hod_views.get_group_info, name="get_group_info"),
    # Staff
    path("staff/home/", staff_views.staff_home, name="staff_home"),
    path("staff/apply/leave/", staff_views.staff_apply_leave, name="staff_apply_leave"),
    path("staff/feedback/", staff_views.staff_feedback, name="staff_feedback"),
    path("staff/view/profile/", staff_views.staff_view_profile, name="staff_view_profile"),
    path("staff/attendance/take/", staff_views.staff_take_attendance, name="staff_take_attendance"),
    path(
        "staff/attendance/update/",
        staff_views.staff_update_attendance,
        name="staff_update_attendance",
    ),
    path("staff/get_students/", staff_views.get_students, name="get_students"),
    path("staff/addbook/", staff_views.add_book, name="add_book"),
    path("staff/issue_book/", staff_views.issue_book, name="issue_book"),
    path("staff/view_issued_book/", staff_views.view_issued_book, name="view_issued_book"),
    path("staff/return_book/<int:loan_id>/", staff_views.return_book, name="return_book"),
    path(
        "staff/attendance/fetch/", staff_views.get_student_attendance, name="get_student_attendance"
    ),
    path("staff/attendance/save/", staff_views.save_attendance, name="save_attendance"),
    path("staff/attendance/update_save/", staff_views.update_attendance, name="update_attendance"),
    path(
        "staff/view/notification/",
        staff_views.staff_view_notification,
        name="staff_view_notification",
    ),
    path("staff/result/add/", staff_views.staff_add_result, name="staff_add_result"),
    path("staff/result/edit/", EditResultView.as_view(), name="edit_student_result"),
    path("staff/result/fetch/", staff_views.fetch_student_result, name="fetch_student_result"),
    # Student
    path("student/home/", student_views.student_home, name="student_home"),
    path(
        "student/view/attendance/",
        student_views.student_view_attendance,
        name="student_view_attendance",
    ),
    path("student/apply/leave/", student_views.student_apply_leave, name="student_apply_leave"),
    path("student/feedback/", student_views.student_feedback, name="student_feedback"),
    path("student/view/profile/", student_views.student_view_profile, name="student_view_profile"),
    path("student/save-theme/", student_views.student_save_theme, name="student_save_theme"),
    path("student/viewbooks/", student_views.view_books, name="view_books"),
    path(
        "student/view/notification/",
        student_views.student_view_notification,
        name="student_view_notification",
    ),
    path("student/view/result/", student_views.student_view_result, name="student_view_result"),
    # Assignments (Teacher)
    path("staff/assignments/", staff_views.staff_assignments, name="staff_assignments"),
    path("staff/assignment/add/", staff_views.add_assignment, name="add_assignment"),
    path(
        "staff/assignment/edit/<int:assignment_id>",
        staff_views.edit_assignment,
        name="edit_assignment",
    ),
    path(
        "staff/assignment/delete/<int:assignment_id>",
        staff_views.delete_assignment,
        name="delete_assignment",
    ),
    path(
        "staff/assignment/<int:assignment_id>/submissions/",
        staff_views.view_submissions,
        name="view_submissions",
    ),
    path(
        "staff/submission/<int:submission_id>/grade/",
        staff_views.grade_submission,
        name="grade_submission",
    ),
    # Assignments (Student)
    path("student/assignments/", student_views.student_assignments, name="student_assignments"),
    path(
        "student/assignment/<int:assignment_id>/submit/",
        student_views.submit_assignment,
        name="submit_assignment",
    ),
    # Result Files (Staff)
    path("staff/result/files/", staff_views.staff_result_files, name="staff_result_files"),
    path("staff/result/upload-file/", staff_views.upload_result_file, name="upload_result_file"),
    path(
        "staff/result/delete-file/<int:file_id>/",
        staff_views.delete_result_file,
        name="delete_result_file",
    ),
    # Result Files (Student)
    path("student/result/files/", student_views.student_result_files, name="student_result_files"),
    # Leaderboard (Student)
    path("student/leaderboard/", student_views.student_leaderboard, name="student_leaderboard"),
    path(
        "student/leaderboard/history/",
        student_views.student_leaderboard_history,
        name="student_leaderboard_history",
    ),
    path(
        "student/leaderboard/season/<int:season_id>/",
        student_views.student_leaderboard_season,
        name="student_leaderboard_season",
    ),
    # Leaderboard (Admin)
    path(
        "admin/leaderboard/settings/",
        hod_views.admin_leaderboard_settings,
        name="admin_leaderboard_settings",
    ),
    path("admin/leaderboard/seasons/", hod_views.admin_manage_seasons, name="admin_manage_seasons"),
    # AJAX helpers (admin)
    path(
        "ajax/teachers-for-course/",
        hod_views.get_teachers_for_course,
        name="get_teachers_for_course",
    ),
    path(
        "ajax/groups-for-teacher/", hod_views.get_groups_for_teacher, name="get_groups_for_teacher"
    ),
    # AJAX helpers (staff)
    path(
        "staff/ajax/teachers-for-course/",
        staff_views.staff_get_teachers_for_course,
        name="staff_get_teachers_for_course",
    ),
    path(
        "staff/ajax/groups-for-teacher/",
        staff_views.staff_get_groups_for_teacher,
        name="staff_get_groups_for_teacher",
    ),
    # Vocabulary Days (Student)
    path("student/vocabulary-days/", student_views.vocabulary_day_list, name="vocabulary_day_list"),
    path(
        "student/vocabulary-days/<int:day_id>/",
        student_views.vocabulary_day_detail,
        name="vocabulary_day_detail",
    ),
    path(
        "student/vocabulary-days/<int:day_id>/complete/",
        student_views.vocabulary_day_complete,
        name="vocabulary_day_complete",
    ),
    path(
        "student/vocabulary-days/<int:day_id>/flashcard/",
        student_views.vocabulary_day_flashcard,
        name="vocabulary_day_flashcard",
    ),
    path(
        "student/vocabulary-days/<int:day_id>/quiz/",
        student_views.vocabulary_day_quiz,
        name="vocabulary_day_quiz",
    ),
    path(
        "student/vocabulary-days/<int:day_id>/quiz/save/",
        student_views.save_quiz_result,
        name="save_quiz_result",
    ),
    # Progress page (Student)
    path("student/progress/", student_views.student_progress, name="student_progress"),
    # Avatar (all user types — lives in views.py to bypass role middleware)
    path("profile/save-avatar/", views.save_avatar, name="save_avatar"),
    # Result file download — in views.py so the role middleware never blocks it
    path("result/download/<int:file_id>/", views.result_file_download, name="result_file_download"),
    # Vocabulary Days (Staff)
    path("staff/vocabulary-days/", staff_views.staff_vocabulary_days, name="staff_vocabulary_days"),
    path("staff/vocabulary-days/add/", staff_views.add_vocabulary_day, name="add_vocabulary_day"),
    path(
        "staff/vocabulary-days/<int:day_id>/",
        staff_views.staff_vocabulary_day_detail,
        name="staff_vocabulary_day_detail",
    ),
    path(
        "staff/vocabulary-days/<int:day_id>/edit/",
        staff_views.edit_vocabulary_day,
        name="edit_vocabulary_day",
    ),
    path(
        "staff/vocabulary-days/<int:day_id>/delete/",
        staff_views.delete_vocabulary_day,
        name="delete_vocabulary_day",
    ),
    # Vocabulary Days (Admin/HOD)
    path("admin/vocabulary-days/", hod_views.manage_vocabulary_days, name="manage_vocabulary_days"),
    # Dashboard Stories (Admin/HOD)
    path("admin/stories/", hod_views.manage_stories, name="manage_stories"),
    path("admin/stories/add/", hod_views.add_story, name="add_story"),
    path("admin/stories/<int:story_id>/edit/", hod_views.edit_story, name="edit_story"),
    path("admin/stories/<int:story_id>/delete/", hod_views.delete_story, name="delete_story"),
    # Dashboard Stories (Staff)
    path("staff/stories/post/", staff_views.staff_create_story, name="staff_create_story"),
    # Payments (Admin/HOD)
    path("admin/payments/", payments_views.admin_payments, name="admin_payments"),
    path("admin/payments/collections/", payments_views.admin_collections, name="admin_collections"),
    path(
        "admin/payments/generate/",
        payments_views.admin_generate_invoices,
        name="admin_generate_invoices",
    ),
    path("admin/payments/invoice/add/", payments_views.admin_add_invoice, name="admin_add_invoice"),
    path(
        "admin/payments/invoice/<int:invoice_id>/record/",
        payments_views.admin_record_payment,
        name="admin_record_payment",
    ),
    path(
        "admin/payments/invoice/<int:invoice_id>/cancel/",
        payments_views.admin_cancel_invoice,
        name="admin_cancel_invoice",
    ),
    path(
        "admin/payments/invoice/<int:invoice_id>/remind/",
        payments_views.admin_send_payment_reminder,
        name="admin_send_payment_reminder",
    ),
    path(
        "admin/payments/payment/<int:payment_id>/void/",
        payments_views.admin_void_payment,
        name="admin_void_payment",
    ),
    # Payments (Staff — read-only)
    path("staff/payments/", payments_views.staff_payments, name="staff_payments"),
    # Payments (Student)
    path("student/payments/", payments_views.student_payments, name="student_payments"),
    path(
        "payments/receipt/<int:payment_id>/",
        payments_views.payment_receipt,
        name="payment_receipt",
    ),
]
