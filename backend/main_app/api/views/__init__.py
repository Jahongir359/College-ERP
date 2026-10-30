# Re-export every public class so that `from . import views` in urls.py
# continues to work unchanged after the monolith was split into sub-modules.
from .auth import LoginView, LogoutView, MeView, ChangePasswordView, FcmTokenView
from .app_version import AppVersionView
from .courses import CourseListView, GroupListView, GroupDetailView
from .attendance import AttendanceView
from .results import ResultView
from .assignments import AssignmentListView, AssignmentDetailView, SubmitAssignmentView
from .notifications import NotificationListView, NotificationReadView, NotificationMarkAllReadView
from .files import FileUploadView
from .dashboard import (
    AdminStatsView,
    AdminUserListView,
    AdminGroupListView,
    AdminEnrollmentView,
    AdminBranchListView,
    StudentDashboardView,
    AdminDashboardView,
    StaffStatsView,
)
from .leave import LeaveView, LeaveDetailView
from .feedback import FeedbackView, FeedbackDetailView
from .payments import InvoiceView, InvoiceDetailView, StaffPaymentBoardView
from .management import (
    AdminStudentListView,
    AdminStudentDetailView,
    AdminStaffListView,
    AdminStaffDetailView,
    AdminLeadListView,
    AdminLeadDetailView,
)
from .content import (
    VocabularyDayListView,
    VocabularyDayDetailView,
    VocabularyDayCompleteView,
    VocabularyQuizView,
    VocabularyQuizResultView,
    StudentProgressView,
    StoryListView,
    StoryCreateView,
    StoryDetailView,
    StaffVocabularyListView,
    StaffVocabularyCreateView,
    StaffVocabularyDetailView,
    StaffVocabularyWordView,
    MessageThreadListView,
    MessageThreadDetailView,
    BookListView,
    LeaderboardView,
)

__all__ = [
    "AppVersionView",
    "LoginView",
    "LogoutView",
    "MeView",
    "ChangePasswordView",
    "FcmTokenView",
    "CourseListView",
    "GroupListView",
    "GroupDetailView",
    "AttendanceView",
    "ResultView",
    "AssignmentListView",
    "AssignmentDetailView",
    "SubmitAssignmentView",
    "NotificationListView",
    "NotificationReadView",
    "NotificationMarkAllReadView",
    "FileUploadView",
    "AdminStatsView",
    "AdminUserListView",
    "AdminGroupListView",
    "AdminEnrollmentView",
    "StudentDashboardView",
    "AdminDashboardView",
    "StaffStatsView",
    "LeaveView",
    "LeaveDetailView",
    "FeedbackView",
    "FeedbackDetailView",
    "InvoiceView",
    "InvoiceDetailView",
    "StaffPaymentBoardView",
    "AdminLeadListView",
    "AdminLeadDetailView",
    "AdminStudentListView",
    "AdminStudentDetailView",
    "AdminStaffListView",
    "AdminStaffDetailView",
    "VocabularyDayListView",
    "VocabularyDayDetailView",
    "VocabularyDayCompleteView",
    "LeaderboardView",
    "AdminBranchListView",
    "VocabularyQuizView",
    "VocabularyQuizResultView",
    "StudentProgressView",
    "StoryListView",
    "StoryCreateView",
    "StoryDetailView",
    "StaffVocabularyListView",
    "StaffVocabularyCreateView",
    "StaffVocabularyDetailView",
    "StaffVocabularyWordView",
    "MessageThreadListView",
    "MessageThreadDetailView",
    "BookListView",
]
