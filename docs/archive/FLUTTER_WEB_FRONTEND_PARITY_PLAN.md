# ICEBERG ERP Flutter Web Frontend Parity Plan

Document date: 2026-06-12
Source UI: Django server-rendered frontend in `main_app/templates`, `main_app/static`, `main_app/urls.py`, and role view modules
Target UI: New Flutter Web app with complete feature parity before replacement

## 1. Goal

Build a new Flutter Web application that can replace the current Django frontend without losing any user-facing feature, role rule, data workflow, visual behavior, upload/download flow, notification behavior, dashboard metric, or admin operation.

This plan is intentionally web-first. The existing Flutter app under `iceberg_app/` is useful reference code, but it is not the source of truth for parity. The source of truth is the current Django frontend.

## 2. Non-Negotiable Parity Rules

1. Every Django template route must map to a Flutter route, dialog, tab, or documented backend-only flow.
2. Every POST/AJAX action in the Django frontend must have a typed API endpoint before the Flutter screen is marked complete.
3. Every role restriction must match the Django middleware/decorator behavior:
   - Admin/HOD: `user_type == "1"`
   - Staff/Teacher: `user_type == "2"`
   - Student: `user_type == "3"`
   - Super admin: admin profile with global branch access
4. Branch, group, teacher, and student scoping must be enforced server-side, not only hidden in Flutter.
5. File upload limits and allowed file types must match Django behavior.
6. The Flutter app must support desktop, tablet, and phone layouts because the current frontend does.
7. No placeholder screens are allowed in the final parity build.
8. Existing Django frontend remains available until the parity checklist is fully green.

## 3. Current Frontend Inventory

### 3.1 Shared Shell

Source templates/assets:

- `main_app/templates/main_app/base.html`
- `main_app/templates/main_app/erpnext_sidebar.html`
- `main_app/templates/main_app/partials/glowing_bottom_nav.html`
- `main_app/static/dist/css/iceberg.css`
- `main_app/static/dist/css/iceberg-bold.css`
- `main_app/static/dist/css/mobile-adaptive.css`
- `main_app/static/dist/css/glowing-bottom-nav.css`
- `main_app/static/dist/css/profile-hub.css`
- `main_app/static/dist/js/platform-detect.js`
- `main_app/static/dist/js/profile-hub.js`
- `main_app/static/dist/js/admin-manage-mobile.js`
- `main_app/static/dist/js/responsive-tables.js`
- `main_app/static/dist/js/iceberg-interactive.js`
- `main_app/static/dist/js/trend-chart.js`

Flutter must reproduce:

- Desktop top navbar.
- Desktop persistent sidebar.
- Mobile 4-tab bottom navigation per role.
- Message unread badge.
- Notification unread badge.
- User avatar/profile entry.
- Logout action.
- Role-aware active route states.
- Page title, subtitle, breadcrumb equivalent.
- Flash/toast message system.
- Dark, bright, and system theme behavior.
- Student DB-persisted theme preference.
- Admin/staff browser-local theme preference unless we intentionally move it server-side.
- Apple-style glass and Android/other solid visual treatment where practical.
- Loading states, skeletons, empty states, confirmation prompts, and responsive table-to-card behavior.
- PWA metadata and offline shell behavior.

### 3.2 Public/Auth Frontend

Source:

- `main_app/templates/main_app/login.html`
- `main_app/templates/main_app/entry.html`
- `main_app/templates/registration/forgot_password.html`
- `main_app/templates/registration/verify_reset_code.html`
- `main_app/templates/registration/reset_password.html`
- `main_app/templates/registration/password_reset_success.html`
- `main_app/templates/main_app/error.html`

Required Flutter routes:

- `/login`
- `/forgot-password`
- `/verify-reset-code`
- `/reset-password`
- `/password-reset-success`
- `/error/400`, `/error/403`, `/error/404`, `/error/500` or equivalent error states

Important note: the password recovery view functions exist in `main_app/password_recovery.py`, but active URL routes for these paths were not found in `main_app/urls.py`. Wire these routes or expose equivalent API endpoints before Flutter Web depends on them.

### 3.3 Shared Authenticated Features

Source:

- `main_app/templates/main_app/profile_hub.html`
- `main_app/templates/main_app/messages.html`
- `main_app/templates/main_app/payment_receipt.html`
- `main_app/views.py`
- `main_app/messaging_views.py`

Required Flutter modules:

- Profile and settings hub:
  - Identity card.
  - Role-specific metadata and stats.
  - Quick actions.
  - Role-specific settings groups.
  - Edit profile fields.
  - Password change.
  - Profile picture upload where supported.
  - Emoji/sticker avatar picker.
  - Theme picker.
  - Logout.
- Group messages:
  - Thread list.
  - Active group chat.
  - Last message preview.
  - Unread count.
  - Recent message list.
  - Send text message.
  - Attachment upload/download.
  - Attachment validation: max 10 MB; images, documents, archives, audio, video.
  - Mobile hub/conversation split behavior.
- Payment receipt:
  - Printable receipt view.
  - Student access to own receipt.
  - Admin access to scoped branch receipts.

## 4. Admin/HOD Parity Matrix

### 4.1 Dashboard

Source:

- `hod_template/home_content.html`
- `hod_views.admin_home`

Flutter route: `/admin/home`

Must include:

- KPI metric cards: students, teachers, courses/groups, leads.
- Sparkline/trend/progress values.
- New students and new leads this week.
- Today attendance rate and present/total counts.
- Active enrollments and capacity.
- Assignments due soon.
- Recent registration leads.
- Recent students.
- Teacher activity.
- Today attendance groups.
- Upcoming classes.
- Recent activity feed.
- Charts:
  - Group attendance.
  - Student attendance present/leave.
  - Course student counts.
  - Monthly trend.
  - Branch chart.
- Empty chart states.
- Dark mode chart colors.

### 4.2 People Management

Routes/templates:

- `/student/manage/` -> `manage_student.html`
- `/student/add/` -> `add_student_template.html`
- `/student/edit/<id>` -> `edit_student_template.html`
- `/student/delete/<id>` -> delete action
- `/staff/manage/` -> `manage_staff.html`
- `/staff/add` -> `add_staff_template.html`
- `/staff/edit/<id>` -> `edit_staff_template.html`
- `/staff/delete/<id>` -> delete action
- `/admin/manage/` -> `manage_admin.html`
- `/admin/add/` -> `add_admin_template.html`
- `/admin/delete/<id>/` -> delete action
- `/branch/admin-access/<admin_id>/` -> update admin branch access

Flutter routes:

- `/admin/students`
- `/admin/students/new`
- `/admin/students/:id/edit`
- `/admin/staff`
- `/admin/staff/new`
- `/admin/staff/:id/edit`
- `/admin/admins`
- `/admin/admins/new`

Must include:

- Search.
- Desktop data table.
- Mobile card list.
- Add/edit forms.
- Delete confirmations.
- Generated login ID display after create.
- Student fields: name, gender, birth date, branch, course, group, phone, status, English level, password, profile image.
- Staff fields: name, gender, birth date, branch, course, phone, specialization, active flag, password, profile image.
- Admin fields: name, email/login, password, super admin toggle, branch assignment.
- Super admin protections:
  - Only super admin can manage admin accounts.
  - Exactly one super admin rule.
  - Cannot delete current admin.
  - Cannot delete only super admin.
- Branch admin scoping.

### 4.3 Academic Management

Routes/templates:

- `/course/manage/`, `/course/add`, `/course/edit/<id>`, `/course/delete/<id>`, `/course/toggle-active/<id>`
- `/subject/manage/`, `/subject/add/`, `/subject/edit/<id>`, `/subject/delete/<id>`
- `/session/manage/`, `/add_session/`, `/session/edit/<id>`, `/session/delete/<id>`
- `/branch/manage/`, `/branch/add/`, `/branch/edit/<id>`, `/branch/delete/<id>`
- `/group/manage/`, `/group/add/`, `/group/edit/<id>`, `/group/archive/<id>`, `/group/delete/<id>`
- `/group/<id>/students/`
- `/enrollment/manage/`, `/enrollment/add/`, `/enrollment/delete/<id>`, `/enrollment/group-info/`

Flutter routes:

- `/admin/courses`
- `/admin/subjects`
- `/admin/sessions`
- `/admin/branches`
- `/admin/groups`
- `/admin/groups/new`
- `/admin/groups/:id`
- `/admin/groups/:id/edit`
- `/admin/enrollments`
- `/admin/enrollments/new`

Must include:

- CRUD for course, subject, session, branch.
- Course active/deactivate action.
- Branch delete guard: cannot delete only branch; cannot delete branches with linked data.
- Group CRUD with branch-scoped teacher/course fields.
- Archive/restore group instead of delete when records exist.
- Group detail with enrolled active students and inactive count.
- Group start date notification behavior.
- Enrollment create/delete.
- Enrollment group-info preview:
  - teacher
  - program
  - schedule
  - enrolled count
  - capacity
  - already-enrolled student IDs
- Cross-branch enrollment validation.

### 4.4 Attendance Oversight

Routes/templates:

- `/attendance/view/` -> `admin_view_attendance.html`
- `/attendance/fetch/` -> AJAX

Flutter route: `/admin/attendance`

Must include:

- Group/date filters.
- Attendance record loading.
- Group-level attendance table.
- Status display for present, late, absent.
- Branch/group scoping.
- Empty/error states.

### 4.5 Payments and Receipts

Routes/templates:

- `/admin/payments/`
- `/admin/payments/generate/`
- `/admin/payments/invoice/add/`
- `/admin/payments/invoice/<id>/record/`
- `/admin/payments/invoice/<id>/cancel/`
- `/admin/payments/invoice/<id>/remind/`
- `/admin/payments/payment/<id>/void/`
- `/payments/receipt/<payment_id>/`

Flutter routes:

- `/admin/payments`
- `/admin/payments/generate`
- `/admin/payments/invoices/new`
- `/admin/payments/invoices/:id/record`
- `/payments/receipt/:paymentId`

Must include:

- Month selector.
- Status filter including overdue.
- Branch and group filters.
- CSV export.
- KPI totals:
  - total billed
  - total collected
  - total outstanding
  - overdue count
- Invoice table/card list.
- Generate monthly invoices.
- Manual one-off invoice.
- Record payment.
- Cancel unpaid invoice.
- Send reminder.
- Void payment, super admin only.
- Printable receipt.
- UZS formatting.

### 4.6 Communications and Requests

Routes/templates:

- `/admin/registration-leads/`
- `/student/view/feedback/`
- `/staff/view/feedback/`
- `/student/view/leave/`
- `/staff/view/leave/`
- `/admin_notify_student`
- `/admin_notify_staff`
- `/send_student_notification/`
- `/send_staff_notification/`

Flutter routes:

- `/admin/leads`
- `/admin/feedback/students`
- `/admin/feedback/staff`
- `/admin/leave/students`
- `/admin/leave/staff`
- `/admin/notifications/students`
- `/admin/notifications/staff`

Must include:

- Registration lead filters: status, source, branch text, search.
- Lead status and admin notes update.
- Lead status summary counts.
- Student feedback list, reply modal/action.
- Staff feedback list, reply modal/action.
- Student leave approve/reject.
- Staff leave approve/reject.
- Targeted student notification sender.
- Targeted staff notification sender.
- Search/list/card responsive behavior.

### 4.7 Vocabulary, Stories, and Leaderboard Admin

Routes/templates:

- `/admin/vocabulary-days/`
- `/admin/stories/`
- `/admin/stories/add/`
- `/admin/stories/<id>/edit/`
- `/admin/stories/<id>/delete/`
- `/admin/leaderboard/settings/`
- `/admin/leaderboard/seasons/`

Flutter routes:

- `/admin/vocabulary`
- `/admin/stories`
- `/admin/stories/new`
- `/admin/stories/:id/edit`
- `/admin/leaderboard/settings`
- `/admin/leaderboard/seasons`

Must include:

- Admin vocabulary day list with group, creator, release state, word count, completion count.
- Story list, active/expired state, target groups, creator.
- Story form:
  - title
  - body
  - story type
  - emoji
  - background color
  - cover image upload
  - target groups
  - expiry presets and custom expiry
  - active/draft toggle
  - storage warning state
- Story access rules:
  - super admin can modify all
  - branch admin can modify authored stories or stories fully inside accessible groups
- Leaderboard settings:
  - weights and toggles
  - validation and save
- Leaderboard seasons:
  - create
  - end
  - snapshot
  - delete
  - snapshot counts

## 5. Staff/Teacher Parity Matrix

### 5.1 Dashboard

Source:

- `staff_template/erpnext_staff_home.html`
- `staff_views.staff_home`

Flutter route: `/staff/home`

Must include:

- Hero and quick actions.
- KPIs:
  - my students
  - attendance sessions
  - leave requests
  - my groups
- Group list.
- Charts:
  - sessions per group
  - attendance rate by group
  - monthly sessions and attendance rate trend
- Empty chart states.

### 5.2 Attendance

Routes/templates:

- `/staff/attendance/take/`
- `/staff/get_students/`
- `/staff/attendance/save/`
- `/staff/attendance/update/`
- `/get_attendance`
- `/staff/attendance/fetch/`
- `/staff/attendance/update_save/`

Flutter routes:

- `/staff/attendance/take`
- `/staff/attendance/update`

Must include:

- Teacher-owned group selector.
- Date picker.
- Roster loading.
- Three-state attendance buttons:
  - present = 1
  - late = 2
  - absent = 0
- Counters for present/late/absent.
- Sticky save action.
- Idempotent save for take attendance.
- Existing attendance selector for update.
- Load existing statuses.
- Bulk update only changed records.
- Notify absent/late students.
- Server-side ownership protection.

### 5.3 Scores and Result Files

Routes/templates:

- `/staff/result/add/`
- `/staff/result/edit/`
- `/staff/result/fetch/`
- `/staff/result/files/`
- `/staff/result/upload-file/`
- `/staff/result/delete-file/<id>/`
- `/result/download/<file_id>/`

Flutter routes:

- `/staff/results`
- `/staff/results/edit`
- `/staff/result-files`
- `/staff/result-files/upload`

Must include:

- Add/update student result.
- Group selector.
- Student selector loaded by group.
- Existing result fetch.
- Test score max: `StudentResult.TEST_MAX`.
- Exam score max: `StudentResult.EXAM_MAX`.
- Optional teacher comment.
- Result notification to student.
- Result file list.
- Upload result file:
  - course -> teacher -> group cascade where applicable
  - group required
  - optional specific student
  - title required
  - description optional
  - allowed extensions: pdf, doc, docx, jpg, jpeg, png, gif, webp
  - max size 10 MB
  - notify target student or whole group
- Delete own uploaded result file.
- Student/admin download access.

### 5.4 Assignments

Routes/templates:

- `/staff/assignments/`
- `/staff/assignment/add/`
- `/staff/assignment/edit/<id>`
- `/staff/assignment/delete/<id>`
- `/staff/assignment/<id>/submissions/`
- `/staff/submission/<id>/grade/`

Flutter routes:

- `/staff/assignments`
- `/staff/assignments/new`
- `/staff/assignments/:id/edit`
- `/staff/assignments/:id/submissions`

Must include:

- Teacher-owned assignment list.
- Search.
- Add/edit form.
- Group limited to teacher groups.
- Delete confirmation.
- Submissions table.
- Download submitted file.
- Grade submission.

### 5.5 Library

Routes/templates:

- `/staff/addbook/`
- `/staff/issue_book/`
- `/staff/view_issued_book/`
- `/staff/return_book/<loan_id>/`

Flutter routes:

- `/staff/library/books/new`
- `/staff/library/issue`
- `/staff/library/loans`

Must include:

- Add book.
- Issue book to branch/group-scoped students.
- Active loan uniqueness validation.
- View loan list.
- Return loan.
- Fine display for overdue returned loans.
- Search and responsive list/card behavior.

### 5.6 Vocabulary and Stories

Routes/templates:

- `/staff/vocabulary-days/`
- `/staff/vocabulary-days/add/`
- `/staff/vocabulary-days/<id>/`
- `/staff/vocabulary-days/<id>/edit/`
- `/staff/vocabulary-days/<id>/delete/`
- `/staff/stories/post/`

Flutter routes:

- `/staff/vocabulary`
- `/staff/vocabulary/new`
- `/staff/vocabulary/:id`
- `/staff/vocabulary/:id/edit`
- `/staff/stories/new`

Must include:

- Vocabulary day list with group filter, search, release state, word count, completion count.
- Add/edit vocabulary day:
  - group
  - day number
  - title
  - level
  - release scope
  - notes
  - dynamic word builder with word, meaning, example, pronunciation
  - JSON payload equivalent
- Delete vocabulary day.
- Detail page:
  - word list
  - enrolled student rows
  - completion state
  - best quiz score
- Notify students for released days.
- Staff story post form:
  - same story fields as admin
  - target groups restricted to teacher groups
  - empty target group means all teacher groups, not whole school

### 5.7 Staff Self-Service

Routes/templates:

- `/staff/apply/leave/`
- `/staff/feedback/`
- `/staff/view/notification/`
- `/staff/payments/`

Flutter routes:

- `/staff/leave`
- `/staff/feedback`
- `/staff/notifications`
- `/staff/payments`

Must include:

- Leave request form and history.
- Feedback form and admin replies.
- Notifications inbox with unread mark-on-open.
- Read-only payment status board by group and month.

## 6. Student Parity Matrix

### 6.1 Dashboard

Source:

- `student_template/erpnext_student_home.html`
- `student_views.student_home`

Flutter route: `/student/home`

Must include:

- Attendance summary: present %, absent %, total.
- Per-group attendance breakdown.
- Group schedule, room, teacher, branch, start date.
- English program/level badge.
- Dashboard stories carousel/list.
- Recent unread notifications.
- Hero rank badge:
  - current group/month rank
  - score
  - total competitors
  - tier/icon/label
  - streak
- Quick-access counters:
  - pending assignments
  - unread notifications
  - new result files
  - new vocabulary days
- Recent assignments.
- Latest result.
- Overall performance trend chart.
- Cache/no-store behavior for story freshness or equivalent data refresh.

### 6.2 Attendance

Routes/templates:

- `/student/view/attendance/`

Flutter route: `/student/attendance`

Must include:

- Month summary.
- Present/late/absent counts.
- Attendance message.
- Recent rows.
- Calendar/status map.
- 12-week trend chart.
- All-time totals.
- Current streak.
- Group/date range filter with AJAX-equivalent API.
- Only own enrolled group data.

### 6.3 Results and Result Files

Routes/templates:

- `/student/view/result/`
- `/student/result/files/`
- `/result/download/<file_id>/`

Flutter routes:

- `/student/results`
- `/student/result-files`

Must include:

- Result list per enrolled group.
- Test, exam, total.
- Average score.
- Pass count.
- Score charts:
  - test
  - exam
  - total
  - trend
- Result file list:
  - group-wide files
  - student-specific files
  - uploader
  - download action

### 6.4 Assignments

Routes/templates:

- `/student/assignments/`
- `/student/assignment/<id>/submit/`

Flutter routes:

- `/student/assignments`
- `/student/assignments/:id/submit`

Must include:

- Assignment list for enrolled groups.
- Submission status.
- Due date.
- Teacher/subject/group metadata.
- Homework trend.
- Submit or replace file submission.
- Show existing submission.
- Grade display.
- Enrollment validation.

### 6.5 Vocabulary Learning

Routes/templates:

- `/student/vocabulary-days/`
- `/student/vocabulary-days/<id>/`
- `/student/vocabulary-days/<id>/complete/`
- `/student/vocabulary-days/<id>/flashcard/`
- `/student/vocabulary-days/<id>/quiz/`
- `/student/vocabulary-days/<id>/quiz/save/`

Flutter routes:

- `/student/vocabulary`
- `/student/vocabulary/:id`
- `/student/vocabulary/:id/flashcards`
- `/student/vocabulary/:id/quiz`

Must include:

- Released vocabulary days for enrolled groups plus all-student releases.
- Completion percentage.
- Total words.
- Quiz trend.
- Day detail:
  - word list
  - completion state
  - best quiz
  - mark complete action
- Flashcard mode:
  - card navigation
  - flip/reveal behavior
  - examples and pronunciation notes
- Quiz mode:
  - randomized questions
  - randomized choices
  - score calculation
  - save quiz result
  - auto-complete day when score >= 60
  - best quiz display

### 6.6 Leaderboard and Progress

Routes/templates:

- `/student/leaderboard/`
- `/student/leaderboard/history/`
- `/student/leaderboard/season/<id>/`
- `/student/progress/`

Flutter routes:

- `/student/leaderboard`
- `/student/leaderboard/history`
- `/student/leaderboard/seasons/:id`
- `/student/progress`

Must include:

- Leaderboard filters:
  - scope: group, branch, all
  - time: month and other supported filters
  - mode: students, groups, branches where current page supports it
- Top 3 podium.
- Current student callout.
- Ranking list.
- Detail modal data.
- Recent closed seasons.
- My history.
- Frozen season view.
- Progress page:
  - 30-day vocabulary completions
  - average quiz score line
  - exam result bars
  - completion totals
  - recent quiz
  - English/level badge
  - empty state

### 6.7 Student Self-Service

Routes/templates:

- `/student/apply/leave/`
- `/student/feedback/`
- `/student/view/notification/`
- `/student/payments/`
- `/student/viewbooks/`

Flutter routes:

- `/student/leave`
- `/student/feedback`
- `/student/notifications`
- `/student/payments`
- `/student/library`

Must include:

- Leave request form and history.
- Feedback form and admin replies.
- Notifications inbox with unread mark-on-open.
- Payment dashboard:
  - outstanding total
  - open count
  - overdue count
  - invoice list
  - payment history
  - receipt links
- Library book catalogue with availability.

## 7. Flutter Web Architecture

### 7.1 Recommended App Structure

```text
lib/
  main.dart
  core/
    api/
      api_client.dart
      api_error.dart
      paged_result.dart
    auth/
      auth_controller.dart
      auth_models.dart
      token_storage_web.dart
    config/
      app_config.dart
    router/
      app_router.dart
      route_guards.dart
    theme/
      ice_colors.dart
      ice_theme.dart
      ice_typography.dart
    widgets/
      app_shell.dart
      role_sidebar.dart
      role_bottom_nav.dart
      page_header.dart
      data_table_view.dart
      responsive_record_list.dart
      empty_state.dart
      error_state.dart
      confirm_dialog.dart
      file_picker_field.dart
      chart_card.dart
      status_badge.dart
  features/
    auth/
    profile/
    messages/
    admin/
    staff/
    student/
    payments/
    library/
    vocabulary/
    leaderboard/
    stories/
```

### 7.2 State Management

Use Riverpod with repositories per feature:

- `AuthController`
- `ProfileRepository`
- `MessageRepository`
- `AdminRepository`
- `StaffRepository`
- `StudentRepository`
- `PaymentRepository`
- `VocabularyRepository`
- `LeaderboardRepository`
- `StoryRepository`

Use immutable models and typed request/response DTOs. Avoid passing raw `Map<String, dynamic>` into UI beyond the repository boundary.

### 7.3 Routing

Use `go_router` with:

- Auth redirect.
- Role redirect.
- Deep link support under `/app/`.
- Unknown route -> branded not found page.
- Route-level permissions for super admin-only pages.

### 7.4 Visual System

Translate design tokens from CSS:

- Brand navy: `#06343A`
- Navy mid: `#0E6873`
- Navy deep: `#03181C`
- Lime: `#DFFF2F`
- Cyan: `#00CFE8`
- Background: `#F4FAFB`
- Surface: `#FFFFFF`
- Surface 2: `#EEF5F6`
- Border: `#D4E4E6`
- Text: `#06343A`
- Muted: `#5A7A7E`
- Success: `#22C55E`
- Warning: `#F59E0B`
- Danger: `#EF4444`
- Info: `#3B82F6`

Flutter components should preserve the current operational UI style:

- Dense but readable dashboard pages.
- Desktop tables with sortable/filterable columns.
- Mobile cards for management lists.
- Hero/summary panels for dashboards and learning pages.
- Fixed navigation that does not cover content.
- Safe-area padding on mobile.
- Branded loading and empty states.

### 7.5 Web Platform Requirements

- Build with `--base-href /app/` if served beside Django.
- Use path URL strategy only if Django SPA fallback is maintained.
- Store JWT tokens securely for web using the best available Flutter Web storage strategy.
- Avoid browser-only APIs in core code without wrappers.
- Keep uploads and downloads browser-compatible.
- Configure PWA:
  - manifest name and short name: ICEBERG Study Center
  - correct icons
  - theme color
  - offline fallback
  - cache policy compatible with Django serving `/app/`

## 8. Backend API Gap List

The existing DRF API is a good start, but full parity needs additional or corrected endpoints.

### 8.1 Must Fix Before Flutter Implementation

1. Password recovery API or URL wiring:
   - request reset code
   - verify code
   - reset password
   - resend code
2. Staff attendance/result contract mismatch:
   - expose roster endpoint for teacher-owned group or use `/groups/<id>/` `enrolled_students`
   - align attendance save payload with `group_id`, `date`, `records`
   - align result save with `student_id`, `group_id`, `test`, `exam`, `comment`
3. Messaging attachments:
   - current API message post supports text only
   - add multipart attachment support, validation, and attachment metadata in message list
4. Profile avatar sticker:
   - expose `/api/v1/me/avatar/` or extend `me/` PATCH for `avatar`
5. Theme preference:
   - support student server-side theme
   - decide whether admin/staff theme stays local or moves to API

### 8.2 Admin API Gaps

Add or verify endpoints for:

- Dashboard full metric payload matching `hod_views.admin_home`.
- Course toggle active.
- Subject/session full CRUD if not already complete.
- Branch delete protection and super admin-only create/delete.
- Group archive/restore.
- Group start-date notification behavior.
- Enrollment group-info preview.
- Admin feedback reply for student/staff feedback.
- Student/staff leave approve/reject with status transitions.
- Student/staff notification sender with target selection.
- Registration lead filters and update.
- Payment CSV export.
- Generate monthly invoices.
- Manual invoice.
- Cancel invoice.
- Send payment reminder.
- Void payment.
- Receipt JSON/HTML access.
- Leaderboard settings update.
- Leaderboard season create/end/snapshot/delete.
- Admin vocabulary day list with completion counts.

### 8.3 Staff API Gaps

Add or verify endpoints for:

- Teacher dashboard full chart payload.
- Result file upload/delete.
- Dynamic course/teacher/group/student cascade for upload.
- Assignment edit/delete.
- Submission list and grade.
- Book create.
- Issue book.
- Loan list.
- Return book.
- Staff story create with teacher group restriction.
- Staff payments board by month/group.

### 8.4 Student API Gaps

Add or verify endpoints for:

- Student dashboard full payload including stories, rank, quick counts, recent assignments, latest result, trend.
- Attendance calendar/range query.
- Result chart data and trend.
- Result file list/download metadata.
- Leaderboard history and season snapshots.
- Progress page chart data.
- Payment history and receipt metadata.
- Library availability.

## 9. Implementation Phases

### Phase 0: Lock the Parity Contract

Deliverables:

- Keep this document as the checklist.
- Create route-to-screen inventory tests.
- Create API response examples for every screen.
- Decide whether Flutter Web replaces `/` or lives under `/app/`.
- Freeze current Django frontend behavior with screenshots for desktop and mobile.

Exit criteria:

- Every template in `main_app/templates` is mapped.
- Every Django route in `main_app/urls.py` is mapped.
- Every missing API endpoint has a ticket.

### Phase 1: Backend API Parity Foundation

Deliverables:

- Add missing DRF endpoints.
- Add serializers for every screen model.
- Add request validation matching forms.
- Add branch/role permission tests.
- Add upload/download tests.

Exit criteria:

- Flutter does not call server-rendered HTML endpoints for application data.
- All current AJAX/POST flows have equivalent JSON/multipart APIs.
- API tests cover wrong-role and wrong-branch attempts.

### Phase 2: Flutter Web Shell and Auth

Deliverables:

- New Flutter Web app scaffold.
- `go_router` route tree.
- JWT login/logout/refresh.
- Role guard.
- Responsive app shell.
- Sidebar and bottom nav parity.
- Theme system.
- PWA metadata.
- Shared toast/error/loading components.

Exit criteria:

- Login works.
- Auth persists after refresh.
- Wrong role cannot access pages.
- `/app/...` deep links work.
- Desktop and mobile shell screenshots match expected structure.

### Phase 3: Shared Modules

Deliverables:

- Profile/settings.
- Avatar picker.
- Theme picker.
- Change password.
- Messages with attachments.
- Notifications.
- Payment receipt.
- Shared upload/download helpers.

Exit criteria:

- All roles can use shared modules.
- Unread counts update after reading messages/notifications.
- Attachments enforce size/type rules.

### Phase 4: Admin Modules

Recommended order:

1. Dashboard.
2. Students/staff/admins.
3. Branches/courses/subjects/sessions.
4. Groups/enrollments/group detail.
5. Attendance oversight.
6. Feedback and leave management.
7. Notifications and leads.
8. Payments.
9. Stories.
10. Vocabulary admin.
11. Leaderboard settings/seasons.

Exit criteria:

- Admin can complete every existing management task without Django templates.
- Super admin and branch admin behavior is tested separately.

### Phase 5: Staff Modules

Recommended order:

1. Dashboard.
2. Attendance take/update.
3. Scores.
4. Assignments/submissions.
5. Result files.
6. Vocabulary.
7. Library.
8. Payments.
9. Leave/feedback/notifications.
10. Stories.

Exit criteria:

- Teacher can run daily operations entirely in Flutter Web.
- Teacher cannot access another teacher's groups, rosters, attendance, files, or submissions.

### Phase 6: Student Modules

Recommended order:

1. Dashboard.
2. Attendance.
3. Results/result files.
4. Assignments/submission.
5. Vocabulary detail/flashcard/quiz.
6. Leaderboard/history/seasons.
7. Progress.
8. Payments/receipts.
9. Library.
10. Leave/feedback/notifications.

Exit criteria:

- Student can complete all learning and self-service workflows in Flutter Web.
- Student only sees own enrolled data.

### Phase 7: Production Cutover

Deliverables:

- Build Flutter Web in CI/CD.
- Serve Flutter under `/app/` first.
- Add feature flag or staff-only beta access.
- Run side-by-side parity verification.
- Redirect role home pages to Flutter after sign-off.
- Keep old Django frontend routes available temporarily as fallback.

Exit criteria:

- No unresolved parity failures.
- No placeholder Flutter pages.
- No known broken deep links.
- Production smoke tests pass.

## 10. Verification Plan

### 10.1 Static Coverage

- Script checks every `main_app/urls.py` frontend route is represented in a Flutter route or documented backend-only action.
- Script checks every template has a mapped Flutter screen/module.
- Script checks every old AJAX URL has a DRF endpoint.

### 10.2 API Tests

For every API endpoint:

- unauthenticated request
- wrong-role request
- wrong-branch request
- valid request
- validation failure
- empty state
- pagination or large-list behavior where relevant

### 10.3 Flutter Tests

- Widget tests for shared components.
- Router tests for role guards.
- Repository tests against mocked API responses.
- Golden tests for core pages:
  - login
  - admin dashboard
  - admin management table and mobile cards
  - staff attendance
  - student dashboard
  - student vocabulary quiz
  - messages
  - profile hub

### 10.4 Browser/E2E Tests

Use Playwright against Flutter Web:

- desktop: 1440 x 900
- tablet: 1024 x 768
- phone: 390 x 844

Critical journeys:

- Login/logout for all roles.
- Admin creates student, staff, group, enrollment.
- Teacher takes and updates attendance.
- Teacher uploads result and result file.
- Student views attendance/result file and submits assignment.
- Student completes vocabulary flashcards and quiz.
- Admin records payment; student opens receipt.
- Messages with attachment.
- Theme switching.
- Deep link refresh on nested routes.

### 10.5 Data Reconciliation

For selected seed users, compare Django frontend vs Flutter:

- dashboard counts
- attendance totals
- result totals
- invoice balances
- unread message/notification counts
- leaderboard rank
- vocabulary completion and quiz score

No screen is complete until the values match.

## 11. Deployment Plan

### Recommended CI Build

Current deployment only installs Python dependencies and runs `collectstatic`; it does not build Flutter Web. Update deployment to include:

```bash
cd iceberg_app
flutter pub get
flutter build web --release --base-href /app/ --dart-define=API_BASE_URL=https://app.iceberglc.com/api/v1
cd ..
rm -rf flutter_web
cp -R iceberg_app/build/web flutter_web
python manage.py collectstatic --noinput
```

For local development:

```bash
cd iceberg_app
flutter run -d chrome --dart-define=API_BASE_URL=http://127.0.0.1:8000/api/v1
```

### Serving Strategy

Short term:

- Keep Django frontend at existing role URLs.
- Serve Flutter Web at `/app/`.
- Test role parity with real users.

Long term:

- Redirect `/admin/home/`, `/staff/home/`, and `/student/home/` to Flutter routes.
- Keep server-rendered receipt or public pages only if deliberately chosen.
- Remove old templates only after a full release cycle without fallback use.

## 12. High-Risk Areas

1. Branch scoping: must be tested aggressively.
2. Staff roster and attendance payloads: current Flutter source has mismatches.
3. Payment states and invoice balance math: must match backend model methods.
4. Message attachments: current API lacks full parity.
5. File upload/download permissions.
6. Password recovery routing/API.
7. Leaderboard calculations: should remain backend-owned; Flutter should display results.
8. Story expiry and dashboard cache freshness.
9. Theme behavior differences across admin/staff/student.
10. Mobile management pages: current Django has table-to-card behavior that Flutter must reproduce.

## 13. Definition of Done

The Flutter Web app is ready to replace the Django frontend only when:

- Every item in Sections 3-6 is implemented.
- Every API gap in Section 8 is closed or explicitly deemed unnecessary because a better equivalent exists.
- All Phase 0-7 exit criteria pass.
- No Flutter route displays "coming soon" or placeholder content.
- Browser screenshots pass at desktop/tablet/phone sizes.
- Values reconcile with the existing Django frontend on seeded test accounts.
- Production build is generated automatically by deployment.
- A rollback path to the Django frontend exists for at least one release.

## Appendix A: Template Coverage Checklist

Every template below must be represented in Flutter as a route, modal, shared component, or intentionally retained server-rendered utility.

### Admin/HOD Templates

| Django template | Flutter coverage |
|---|---|
| `hod_template/home_content.html` | `/admin/home` dashboard |
| `hod_template/manage_student.html` | `/admin/students` list |
| `hod_template/add_student_template.html` | `/admin/students/new` |
| `hod_template/edit_student_template.html` | `/admin/students/:id/edit` |
| `hod_template/manage_staff.html` | `/admin/staff` list |
| `hod_template/add_staff_template.html` | `/admin/staff/new` |
| `hod_template/edit_staff_template.html` | `/admin/staff/:id/edit` |
| `hod_template/manage_admin.html` | `/admin/admins` list and branch access |
| `hod_template/add_admin_template.html` | `/admin/admins/new` |
| `hod_template/manage_branch.html` | `/admin/branches` |
| `hod_template/add_branch.html` | `/admin/branches/new` and `/admin/branches/:id/edit` |
| `hod_template/manage_course.html` | `/admin/courses` |
| `hod_template/add_course_template.html` | `/admin/courses/new` |
| `hod_template/edit_course_template.html` | `/admin/courses/:id/edit` |
| `hod_template/manage_subject.html` | `/admin/subjects` |
| `hod_template/add_subject_template.html` | `/admin/subjects/new` |
| `hod_template/edit_subject_template.html` | `/admin/subjects/:id/edit` |
| `hod_template/manage_session.html` | `/admin/sessions` |
| `hod_template/add_session_template.html` | `/admin/sessions/new` |
| `hod_template/edit_session_template.html` | `/admin/sessions/:id/edit` |
| `hod_template/manage_group.html` | `/admin/groups` |
| `hod_template/add_group.html` | `/admin/groups/new` and `/admin/groups/:id/edit` |
| `hod_template/group_detail.html` | `/admin/groups/:id` |
| `hod_template/manage_enrollment.html` | `/admin/enrollments` |
| `hod_template/add_enrollment.html` | `/admin/enrollments/new` |
| `hod_template/admin_view_attendance.html` | `/admin/attendance` |
| `hod_template/manage_payments.html` | `/admin/payments` |
| `hod_template/generate_invoices.html` | `/admin/payments/generate` |
| `hod_template/add_invoice.html` | `/admin/payments/invoices/new` |
| `hod_template/record_payment.html` | `/admin/payments/invoices/:id/record` |
| `hod_template/manage_registration_leads.html` | `/admin/leads` |
| `hod_template/student_feedback_template.html` | `/admin/feedback/students` |
| `hod_template/staff_feedback_template.html` | `/admin/feedback/staff` |
| `hod_template/student_leave_view.html` | `/admin/leave/students` |
| `hod_template/staff_leave_view.html` | `/admin/leave/staff` |
| `hod_template/student_notification.html` | `/admin/notifications/students` |
| `hod_template/staff_notification.html` | `/admin/notifications/staff` |
| `hod_template/manage_vocabulary_days.html` | `/admin/vocabulary` |
| `hod_template/manage_stories.html` | `/admin/stories` |
| `hod_template/story_form.html` | `/admin/stories/new` and `/admin/stories/:id/edit` |
| `hod_template/admin_leaderboard_settings.html` | `/admin/leaderboard/settings` |
| `hod_template/admin_manage_seasons.html` | `/admin/leaderboard/seasons` |
| `hod_template/admin_view_profile.html` | Replaced by shared `/profile`; current route redirects/legacy |

### Staff Templates

| Django template | Flutter coverage |
|---|---|
| `staff_template/erpnext_staff_home.html` | `/staff/home` dashboard |
| `staff_template/staff_take_attendance.html` | `/staff/attendance/take` |
| `staff_template/staff_update_attendance.html` | `/staff/attendance/update` |
| `staff_template/staff_add_result.html` | `/staff/results` add/update |
| `staff_template/edit_student_result.html` | `/staff/results/edit` |
| `staff_template/staff_result_files.html` | `/staff/result-files` |
| `staff_template/upload_result_file.html` | `/staff/result-files/upload` |
| `staff_template/staff_assignments.html` | `/staff/assignments` |
| `staff_template/add_assignment.html` | `/staff/assignments/new` and `/staff/assignments/:id/edit` |
| `staff_template/view_submissions.html` | `/staff/assignments/:id/submissions` |
| `staff_template/add_book.html` | `/staff/library/books/new` |
| `staff_template/issue_book.html` | `/staff/library/issue` |
| `staff_template/view_issued_book.html` | `/staff/library/loans` |
| `staff_template/includes/library_tabs.html` | Staff library tab/segmented-control component |
| `staff_template/staff_vocabulary_days.html` | `/staff/vocabulary` |
| `staff_template/add_vocabulary_day.html` | `/staff/vocabulary/new` and `/staff/vocabulary/:id/edit` |
| `staff_template/staff_vocabulary_day_detail.html` | `/staff/vocabulary/:id` |
| `staff_template/staff_story_form.html` | `/staff/stories/new` |
| `staff_template/staff_apply_leave.html` | `/staff/leave` |
| `staff_template/staff_feedback.html` | `/staff/feedback` |
| `staff_template/staff_view_notification.html` | `/staff/notifications` |
| `staff_template/staff_payments.html` | `/staff/payments` |
| `staff_template/staff_view_profile.html` | Replaced by shared `/profile`; current route redirects |

### Student Templates

| Django template | Flutter coverage |
|---|---|
| `student_template/erpnext_student_home.html` | `/student/home` dashboard |
| `student_template/student_view_attendance.html` | `/student/attendance` |
| `student_template/student_view_result.html` | `/student/results` |
| `student_template/student_result_files.html` | `/student/result-files` |
| `student_template/student_assignments.html` | `/student/assignments` |
| `student_template/submit_assignment.html` | `/student/assignments/:id/submit` |
| `student_template/vocabulary_day_list.html` | `/student/vocabulary` |
| `student_template/vocabulary_day_detail.html` | `/student/vocabulary/:id` |
| `student_template/vocabulary_day_flashcard.html` | `/student/vocabulary/:id/flashcards` |
| `student_template/vocabulary_day_quiz.html` | `/student/vocabulary/:id/quiz` |
| `student_template/leaderboard.html` | `/student/leaderboard` |
| `student_template/leaderboard_history.html` | `/student/leaderboard/history` |
| `student_template/leaderboard_season.html` | `/student/leaderboard/seasons/:id` |
| `student_template/student_progress.html` | `/student/progress` |
| `student_template/student_payments.html` | `/student/payments` |
| `student_template/view_books.html` | `/student/library` |
| `student_template/student_apply_leave.html` | `/student/leave` |
| `student_template/student_feedback.html` | `/student/feedback` |
| `student_template/student_view_notification.html` | `/student/notifications` |
| `student_template/student_view_profile.html` | Replaced by shared `/profile`; current route redirects |

### Shared, Auth, and Utility Templates

| Django template | Flutter coverage |
|---|---|
| `main_app/base.html` | Flutter app shell |
| `main_app/erpnext_sidebar.html` | Role sidebar component |
| `main_app/partials/glowing_bottom_nav.html` | Role bottom navigation component |
| `main_app/form_template.html` | Shared form layout components |
| `main_app/includes/animated_logout_button.html` | Logout component |
| `main_app/includes/profile_settings_row.html` | Profile settings row component |
| `main_app/login.html` | `/login` |
| `main_app/entry.html` | Public entry/redirect behavior |
| `main_app/profile_hub.html` | `/profile` |
| `main_app/messages.html` | `/messages` and `/messages/group/:groupId` |
| `main_app/payment_receipt.html` | `/payments/receipt/:paymentId` or retained printable HTML route |
| `main_app/error.html` | Shared Flutter error pages |
| `registration/erpnext_base.html` | Auth-shell component for recovery screens |
| `registration/forgot_password.html` | `/forgot-password` |
| `registration/verify_reset_code.html` | `/verify-reset-code` |
| `registration/reset_password.html` | `/reset-password` |
| `registration/password_reset_success.html` | `/password-reset-success` |
| `registration/password_reset_form.html` | Legacy Django password reset equivalent or redirect to Flutter recovery |
| `registration/password_reset_done.html` | Legacy Django password reset equivalent or redirect to Flutter recovery |
| `registration/password_reset_confirm.html` | Legacy Django password reset equivalent or redirect to Flutter recovery |
| `registration/password_reset_complete.html` | Legacy Django password reset equivalent or redirect to Flutter recovery |
| `registration/password_reset_email.html` | Backend email template retained server-side |
| `registration/password_reset_subject.txt` | Backend email subject retained server-side |
