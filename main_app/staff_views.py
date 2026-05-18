import json
import logging

from django.contrib import messages
from django.core.files.storage import default_storage
from django.db import transaction
from django.http import HttpResponse, JsonResponse
from django.shortcuts import (HttpResponseRedirect, get_object_or_404,redirect, render)
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.http import require_POST

from .decorators import staff_only
from .forms import *
from .models import *
from . import forms, models
from datetime import date

logger = logging.getLogger(__name__)


@staff_only
def staff_home(request):
    staff = get_object_or_404(Staff, admin=request.user)
    groups = Group.objects.filter(teacher=staff, is_archived=False)
    total_groups = groups.count()
    total_students = (
        Enrollment.objects
        .filter(group__in=groups, is_active=True)
        .values('student').distinct().count()
    )
    total_leave = LeaveReportStaff.objects.filter(staff=staff).count()
    total_attendance = Attendance.objects.filter(group__in=groups).count()

    group_label_list = []
    attendance_list = []
    for group in groups:
        group_label_list.append(group.name[:12])
        attendance_list.append(Attendance.objects.filter(group=group).count())

    context = {
        'page_title': f"{staff.admin.first_name} {staff.admin.last_name}" + (f" · {staff.course}" if staff.course else ""),
        'total_students': total_students,
        'total_attendance': total_attendance,
        'total_leave': total_leave,
        'total_subject': total_groups,
        'subject_list': group_label_list,
        'attendance_list': attendance_list,
        'groups': groups,
    }
    return render(request, "staff_template/erpnext_staff_home.html", context)


@staff_only
def staff_take_attendance(request):
    staff = get_object_or_404(Staff, admin=request.user)
    groups = Group.objects.filter(teacher=staff, is_archived=False).select_related('course').order_by('name')
    context = {
        'groups': groups,
        'today': date.today().isoformat(),
        'page_title': 'Take Attendance',
    }
    return render(request, 'staff_template/staff_take_attendance.html', context)


@staff_only
def get_students(request):
    group_id = request.POST.get('group')
    try:
        # Scope to the teacher's own groups — prevents IDOR enumeration
        # of other teachers' rosters via a forged group_id.
        staff = get_object_or_404(Staff, admin=request.user)
        group = get_object_or_404(Group, id=group_id, teacher=staff)
        enrollments = Enrollment.objects.filter(
            group=group, is_active=True
        ).select_related('student__admin')
        student_data = [
            {
                "id": e.student.id,
                "name": e.student.admin.last_name + " " + e.student.admin.first_name,
            }
            for e in enrollments
        ]
        return JsonResponse(json.dumps(student_data), content_type='application/json', safe=False)
    except Exception:
        return JsonResponse({'error': 'Unable to fetch students.'}, status=400)


_STATUS_LABELS = {
    AttendanceReport.ABSENT: 'Absent',
    AttendanceReport.PRESENT: 'Present',
    AttendanceReport.LATE: 'Late',
}


@staff_only
@require_POST
def save_attendance(request):
    """Save attendance for a group on a date in one atomic write.

    Replaces the previous loop-per-student pattern (1 + N + N inserts) with
    a single transaction containing bulk_create calls (≤ 4 round-trips).
    Re-submitting the same group+date is idempotent: existing reports for
    that attendance row are wiped before bulk insertion, so partial saves
    cannot leave stale rows behind.
    """
    try:
        rows = json.loads(request.POST.get('student_ids') or '[]')
    except json.JSONDecodeError:
        return HttpResponse("Invalid student data", status=400)

    group_id = request.POST.get('group')
    att_date = request.POST.get('date')
    if not group_id or not att_date or not rows:
        return HttpResponse("Missing group/date/students", status=400)

    group = get_object_or_404(Group, id=group_id)
    staff = get_object_or_404(Staff, admin=request.user)
    if group.teacher_id != staff.id:
        return HttpResponse("You do not own this group", status=403)
    student_ids = {int(r['id']) for r in rows if 'id' in r}
    if not student_ids:
        return HttpResponse("No student IDs supplied", status=400)

    try:
        with transaction.atomic():
            attendance, _ = Attendance.objects.get_or_create(
                group=group, date=att_date,
            )
            # Idempotent: wipe any prior reports for this row before inserting.
            AttendanceReport.objects.filter(attendance=attendance).delete()

            AttendanceReport.objects.bulk_create([
                AttendanceReport(
                    attendance=attendance,
                    student_id=int(r['id']),
                    status=int(r.get('status', AttendanceReport.ABSENT)),
                ) for r in rows
            ], batch_size=200)

            # Only notify absent/late students — "present" is the default
            # and doesn't need to spam every inbox.
            notable = [r for r in rows
                       if int(r.get('status', 0)) != AttendanceReport.PRESENT]
            if notable:
                notable_ids = [int(r['id']) for r in notable]
                admin_id_map = dict(Student.objects.filter(id__in=notable_ids).values_list('id', 'admin_id'))
                Notification.objects.bulk_create([
                    Notification(
                        recipient_id=admin_id_map[int(r['id'])],
                        category=Notification.ATTENDANCE,
                        message=(
                            f"Attendance for {group.name} on {att_date}: "
                            f"{_STATUS_LABELS.get(int(r.get('status', 0)), 'Unknown')}."
                        ),
                    ) for r in notable if int(r['id']) in admin_id_map
                ], batch_size=200)
    except Exception:
        logger.exception("save_attendance failed for group=%s date=%s", group_id, att_date)
        return HttpResponse("ERROR", status=400)
    return HttpResponse("OK")


@staff_only
def staff_update_attendance(request):
    staff = get_object_or_404(Staff, admin=request.user)
    groups = Group.objects.filter(teacher=staff, is_archived=False).select_related('course').order_by('name')
    context = {
        'groups': groups,
        'page_title': 'Update Attendance',
    }
    return render(request, 'staff_template/staff_update_attendance.html', context)


@staff_only
def get_student_attendance(request):
    attendance_date_id = request.POST.get('attendance_date_id')
    try:
        attendance = get_object_or_404(Attendance, id=attendance_date_id)
        reports = AttendanceReport.objects.filter(
            attendance=attendance
        ).select_related('student__admin')
        student_data = [
            {
                "id": r.student.id,   # student PK (not admin PK)
                "name": r.student.admin.last_name + " " + r.student.admin.first_name,
                "status": r.status,   # 0/1/2
            }
            for r in reports
        ]
        return JsonResponse(json.dumps(student_data), content_type='application/json', safe=False)
    except Exception:
        return JsonResponse({'error': 'Unable to fetch student attendance.'}, status=400)


@staff_only
@require_POST
def update_attendance(request):
    """Bulk-update existing attendance reports.

    Loads all relevant reports in a single query, applies the new
    statuses in-memory, then writes them back with bulk_update.
    """
    try:
        rows = json.loads(request.POST.get('student_ids') or '[]')
    except json.JSONDecodeError:
        return HttpResponse("Invalid student data", status=400)

    attendance_id = request.POST.get('date')
    if not attendance_id or not rows:
        return HttpResponse("Missing attendance/students", status=400)

    attendance = get_object_or_404(Attendance, id=attendance_id)
    # A teacher can only edit attendance for groups they own — otherwise a
    # crafted attendance_id could update another teacher's records.
    staff = get_object_or_404(Staff, admin=request.user)
    if attendance.group.teacher_id != staff.id:
        return HttpResponse("You do not own this group", status=403)
    status_by_student = {
        int(r['id']): int(r.get('status', AttendanceReport.ABSENT))
        for r in rows if 'id' in r
    }
    if not status_by_student:
        return HttpResponse("No student IDs supplied", status=400)

    try:
        with transaction.atomic():
            reports = list(
                AttendanceReport.objects
                .filter(attendance=attendance, student_id__in=status_by_student)
            )
            changed = []
            for report in reports:
                new_status = status_by_student[report.student_id]
                if report.status != new_status:
                    report.status = new_status
                    changed.append(report)
            if changed:
                AttendanceReport.objects.bulk_update(changed, ['status'], batch_size=200)

            # Notify only the students whose status actually changed (and
            # only when the new status is not "Present").
            notable = [r for r in changed if r.status != AttendanceReport.PRESENT]
            if notable:
                notable_student_ids = [r.student_id for r in notable]
                admin_id_map = dict(Student.objects.filter(id__in=notable_student_ids).values_list('id', 'admin_id'))
                Notification.objects.bulk_create([
                    Notification(
                        recipient_id=admin_id_map[r.student_id],
                        category=Notification.ATTENDANCE,
                        message=(
                            f"Attendance for {attendance.group.name} on "
                            f"{attendance.date} updated to "
                            f"{_STATUS_LABELS.get(r.status, 'Unknown')}."
                        ),
                    ) for r in notable if r.student_id in admin_id_map
                ], batch_size=200)
    except Exception:
        logger.exception("update_attendance failed for attendance=%s", attendance_id)
        return HttpResponse("ERROR", status=400)
    return HttpResponse("OK")


@staff_only
def staff_apply_leave(request):
    form = LeaveReportStaffForm(request.POST or None)
    staff = get_object_or_404(Staff, admin_id=request.user.id)
    context = {
        'form': form,
        'leave_history': LeaveReportStaff.objects.filter(staff=staff),
        'page_title': 'Apply for Leave'
    }
    if request.method == 'POST':
        if form.is_valid():
            try:
                obj = form.save(commit=False)
                obj.staff = staff
                obj.save()
                admin_users = CustomUser.objects.filter(user_type='1')
                Notification.objects.bulk_create([
                    Notification(
                        recipient=admin,
                        category=Notification.GENERAL,
                        message=(
                            f"Leave request from teacher {request.user.get_full_name()}: "
                            f"{obj.message[:120]}"
                        ),
                    ) for admin in admin_users
                ])
                messages.success(
                    request, "Application for leave has been submitted for review")
                return redirect(reverse('staff_apply_leave'))
            except Exception:
                messages.error(request, "Could not apply!")
        else:
            messages.error(request, "Form has errors!")
    return render(request, "staff_template/staff_apply_leave.html", context)


@staff_only
def staff_feedback(request):
    form = FeedbackStaffForm(request.POST or None)
    staff = get_object_or_404(Staff, admin_id=request.user.id)
    context = {
        'form': form,
        'feedbacks': FeedbackStaff.objects.filter(staff=staff),
        'page_title': 'Add Feedback'
    }
    if request.method == 'POST':
        if form.is_valid():
            try:
                obj = form.save(commit=False)
                obj.staff = staff
                obj.save()
                messages.success(request, "Feedback submitted for review")
                return redirect(reverse('staff_feedback'))
            except Exception:
                messages.error(request, "Could not Submit!")
        else:
            messages.error(request, "Form has errors!")
    return render(request, "staff_template/staff_feedback.html", context)


@staff_only
def staff_view_profile(request):
    staff = get_object_or_404(Staff, admin=request.user)
    form = StaffProfileForm(instance=staff, data=request.POST or None)
    context = {'form': form, 'page_title': 'My Profile', 'staff': staff}
    if request.method == 'POST':
        if form.is_valid():
            try:
                admin = staff.admin
                password = form.cleaned_data.get('password') or None
                if password:
                    admin.set_password(password)
                admin.first_name = form.cleaned_data['first_name']
                admin.last_name = form.cleaned_data['last_name']
                admin.gender = form.cleaned_data.get('gender', '')
                admin.save()
                staff.phone = form.cleaned_data.get('phone', '')
                staff.specialization = form.cleaned_data.get('specialization', '')
                staff.save()
                messages.success(request, "Profile updated!")
                return redirect(reverse('staff_view_profile'))
            except Exception as e:
                messages.error(request, f"Error updating profile: {e}")
        else:
            messages.error(request, "Please fix the errors below.")
    return render(request, "staff_template/staff_view_profile.html", context)


@staff_only
def staff_fcmtoken(request):
    token = request.POST.get('token')
    try:
        staff_user = get_object_or_404(CustomUser, id=request.user.id)
        staff_user.fcm_token = token
        staff_user.save()
        return HttpResponse("True")
    except Exception as e:
        return HttpResponse("False")


@staff_only
def staff_view_notification(request):
    notifications = Notification.objects.filter(recipient=request.user).order_by('-created_at')
    notifications.filter(is_read=False).update(is_read=True)
    context = {
        'notifications': notifications,
        'page_title': "View Notifications"
    }
    return render(request, "staff_template/staff_view_notification.html", context)


@staff_only
def staff_add_result(request):
    staff = get_object_or_404(Staff, admin=request.user)
    groups = Group.objects.filter(teacher=staff, is_archived=False).select_related('course')
    context = {
        'page_title': 'Result Upload',
        'groups': groups,
    }
    if request.method == 'POST':
        try:
            student_id = request.POST.get('student_list')
            group_id = request.POST.get('group')
            test = float(request.POST.get('test') or 0)
            exam = float(request.POST.get('exam') or 0)
            comment = (request.POST.get('comment') or '').strip()
            group = get_object_or_404(Group, id=group_id, teacher=staff)
            student = get_object_or_404(Student, id=student_id)
            if not Enrollment.objects.filter(student=student, group=group, is_active=True).exists():
                messages.warning(request, "That student is not enrolled in the selected group.")
            else:
                result, created = StudentResult.objects.get_or_create(
                    student=student, group=group,
                    defaults={'test': test, 'exam': exam, 'comment': comment},
                )
                if not created:
                    result.test = test
                    result.exam = exam
                    result.comment = comment
                    result.save()
                action = "Saved" if created else "Updated"
                messages.success(request, f"Scores {action}")
                note = f" — {comment}" if comment else ""
                Notification.objects.create(
                    recipient=student.admin,
                    category=Notification.RESULT,
                    message=f"Your result for {group.name}: Test={test}, Exam={exam}{note}.",
                )
        except ValueError:
            messages.warning(request, "Test and exam scores must be numbers.")
        except Exception as e:
            messages.warning(request, "Error processing form: " + str(e))
    return render(request, "staff_template/staff_add_result.html", context)


@staff_only
def fetch_student_result(request):
    try:
        group_id = request.POST.get('group')
        student_id = request.POST.get('student')
        student = get_object_or_404(Student, id=student_id)
        group = get_object_or_404(Group, id=group_id)
        result = StudentResult.objects.get(student=student, group=group)
        return HttpResponse(json.dumps({'exam': result.exam, 'test': result.test, 'comment': result.comment}))
    except StudentResult.DoesNotExist:
        return HttpResponse('False')
    except Exception:
        return HttpResponse('False')

# ── Library ───────────────────────────────────────────────────────────────────

@staff_only
def add_book(request):
    form = BookForm(request.POST or None)
    if request.method == 'POST':
        if form.is_valid():
            form.save()
            messages.success(request, "Book added successfully.")
            form = BookForm()
        else:
            messages.warning(request, "Please correct the errors below.")
    return render(request, "staff_template/add_book.html", {
        'form': form,
        'page_title': "Add Book",
    })

# ── Lending (issue / return) ───────────────────────────────────────────────────


@staff_only
def issue_book(request):
    """Create a new Loan from the IssueBookForm.

    Validation lives in the form (uniqueness against active loans);
    the view never reads raw request.POST anymore.
    """
    if request.method == "POST":
        form = forms.IssueBookForm(request.POST)
        if form.is_valid():
            loan = Loan.objects.create(
                student=form.cleaned_data['student'],
                book=form.cleaned_data['book'],
            )
            messages.success(
                request,
                f"Issued '{loan.book.name}' to {loan.student}. Due {loan.due_on}.",
            )
            return redirect('issue_book')
    else:
        form = forms.IssueBookForm()
    return render(request, "staff_template/issue_book.html",
                  {'form': form, 'page_title': 'Issue Book'})


@staff_only
def view_issued_book(request):
    """Single-query list of all loans with student + book joined.

    Eliminates the previous N+1 (one Book lookup per issued row).
    Fine is computed by the model's property — single source of truth.
    """
    loans = (
        Loan.objects
        .select_related('student__admin', 'book')
        .order_by('returned_on', '-issued_on')   # active first, newest first
    )
    return render(request, "staff_template/view_issued_book.html",
                  {'loans': loans, 'page_title': 'Issued Books'})


@staff_only
@require_POST
def return_book(request, loan_id):
    """Mark a loan as returned. Fine is computed automatically at display time."""
    loan = get_object_or_404(Loan, id=loan_id, returned_on__isnull=True)
    loan.returned_on = timezone.localdate()
    loan.save(update_fields=['returned_on'])
    messages.success(
        request,
        f"Returned '{loan.book.name}' from {loan.student}." +
        (f" Fine due: ₹{loan.fine_amount}." if loan.days_overdue > 0 else "")
    )
    return redirect('view_issued_book')

# ── Assignments ───────────────────────────────────────────────────────────────

@staff_only
def staff_assignments(request):
    staff = get_object_or_404(Staff, admin=request.user)
    assignments = Assignment.objects.filter(created_by=staff).select_related('subject', 'group').order_by('-created_at')
    return render(request, 'staff_template/staff_assignments.html', {
        'assignments': assignments,
        'page_title': 'Assignments',
    })


@staff_only
def add_assignment(request):
    staff = get_object_or_404(Staff, admin=request.user)
    form = AssignmentForm(request.POST or None)
    if request.method == 'POST':
        if form.is_valid():
            obj = form.save(commit=False)
            obj.created_by = staff
            obj.save()
            messages.success(request, "Assignment created!")
            return redirect(reverse('staff_assignments'))
    form.fields['group'].queryset = Group.objects.filter(teacher=staff, is_archived=False)
    return render(request, 'staff_template/add_assignment.html', {
        'form': form,
        'page_title': 'Add Assignment',
    })


@staff_only
def edit_assignment(request, assignment_id):
    staff = get_object_or_404(Staff, admin=request.user)
    assignment = get_object_or_404(Assignment, id=assignment_id, created_by=staff)
    form = AssignmentForm(request.POST or None, instance=assignment)
    if request.method == 'POST':
        if form.is_valid():
            form.save()
            messages.success(request, "Assignment updated!")
            return redirect(reverse('staff_assignments'))
    form.fields['group'].queryset = Group.objects.filter(teacher=staff, is_archived=False)
    return render(request, 'staff_template/add_assignment.html', {
        'form': form,
        'page_title': 'Edit Assignment',
    })


@staff_only
def delete_assignment(request, assignment_id):
    staff = get_object_or_404(Staff, admin=request.user)
    assignment = get_object_or_404(Assignment, id=assignment_id, created_by=staff)
    assignment.delete()
    messages.success(request, "Assignment deleted.")
    return redirect(reverse('staff_assignments'))


@staff_only
def view_submissions(request, assignment_id):
    staff = get_object_or_404(Staff, admin=request.user)
    assignment = get_object_or_404(Assignment, id=assignment_id, created_by=staff)
    submissions = Submission.objects.filter(assignment=assignment).select_related('student__admin')
    return render(request, 'staff_template/view_submissions.html', {
        'assignment': assignment,
        'submissions': submissions,
        'page_title': f'Submissions — {assignment.title}',
    })


@staff_only
def grade_submission(request, submission_id):
    staff = get_object_or_404(Staff, admin=request.user)
    submission = get_object_or_404(Submission, id=submission_id, assignment__created_by=staff)
    if request.method == 'POST':
        grade = request.POST.get('grade')
        try:
            submission.grade = float(grade)
            submission.save()
            messages.success(request, "Grade saved!")
        except (ValueError, TypeError):
            messages.error(request, "Invalid grade value.")
    return redirect(reverse('view_submissions', args=[submission.assignment_id]))


# ── Result Files ──────────────────────────────────────────────────────────────

_ALLOWED_RESULT_EXTENSIONS = {'.pdf', '.doc', '.docx', '.jpg', '.jpeg', '.png', '.gif', '.webp'}
_MAX_RESULT_FILE_BYTES = 10 * 1024 * 1024  # 10 MB


@staff_only
def staff_result_files(request):
    staff = get_object_or_404(Staff, admin=request.user)
    files = (
        ResultFile.objects
        .filter(uploaded_by=staff)
        .select_related('group', 'student__admin')
    )
    return render(request, 'staff_template/staff_result_files.html', {
        'files': files,
        'page_title': 'Result Files',
    })


@staff_only
def upload_result_file(request):
    import os
    staff = get_object_or_404(Staff, admin=request.user)
    courses = Course.objects.filter(is_active=True).order_by('name')

    if request.method != 'POST':
        return render(request, 'staff_template/upload_result_file.html', {
            'courses': courses,
            'page_title': 'Upload Result File',
        })

    group_id = request.POST.get('group', '').strip()
    student_id = request.POST.get('student', '').strip() or None
    title = request.POST.get('title', '').strip()
    description = request.POST.get('description', '').strip()
    uploaded_file = request.FILES.get('file')

    errors = {}
    if not group_id:
        errors['group'] = 'Please select a group.'
    if not title:
        errors['title'] = 'Title is required.'
    if not uploaded_file:
        errors['file'] = 'Please choose a file to upload.'
    elif os.path.splitext(uploaded_file.name)[1].lower() not in _ALLOWED_RESULT_EXTENSIONS:
        errors['file'] = 'Only PDF, Word (.doc/.docx), or image files are allowed.'
    elif uploaded_file.size > _MAX_RESULT_FILE_BYTES:
        errors['file'] = 'File too large. Maximum size is 10 MB.'

    if errors:
        return render(request, 'staff_template/upload_result_file.html', {
            'courses': courses,
            'errors': errors,
            'post': request.POST,
            'page_title': 'Upload Result File',
        })

    # Only allow uploading to a group the logged-in teacher owns.
    group = get_object_or_404(Group, id=group_id, teacher=staff)
    # If a specific student was selected, they must be enrolled in that group.
    if student_id:
        student = get_object_or_404(
            Student, id=student_id, enrollment__group=group, enrollment__is_active=True
        )
    else:
        student = None

    result_file = ResultFile.objects.create(
        group=group,
        student=student,
        file=uploaded_file,
        title=title,
        description=description,
        uploaded_by=staff,
    )

    if student:
        Notification.objects.create(
            recipient=student.admin,
            category=Notification.RESULT,
            message=f"A result file '{title}' has been uploaded for you in {group.name}.",
        )
    else:
        enrollments = Enrollment.objects.filter(group=group, is_active=True).select_related('student__admin')
        Notification.objects.bulk_create([
            Notification(
                recipient=e.student.admin,
                category=Notification.RESULT,
                message=f"A result file '{title}' has been uploaded for {group.name}.",
            )
            for e in enrollments
        ], batch_size=200)

    messages.success(request, f"File '{title}' uploaded successfully.")
    return redirect(reverse('staff_result_files'))


@staff_only
def delete_result_file(request, file_id):
    staff = get_object_or_404(Staff, admin=request.user)
    result_file = get_object_or_404(ResultFile, id=file_id, uploaded_by=staff)
    result_file.file.delete(save=False)
    result_file.delete()
    messages.success(request, "File deleted.")
    return redirect(reverse('staff_result_files'))


@staff_only
def staff_get_teachers_for_course(request):
    """AJAX: return staff members who teach a given course (for the result-file cascade)."""
    if request.method != 'POST':
        return JsonResponse({'teachers': []})
    course_id = request.POST.get('course_id', '').strip()
    if not course_id:
        return JsonResponse({'teachers': []})
    teachers = (
        Staff.objects.filter(course_id=course_id, is_active=True)
        .select_related('admin')
        .order_by('admin__first_name', 'admin__last_name')
    )
    data = [
        {
            'id': t.id,
            'name': f"{t.admin.first_name} {t.admin.last_name}".strip() or t.admin.email,
        }
        for t in teachers
    ]
    return JsonResponse({'teachers': data})


@staff_only
def staff_get_groups_for_teacher(request):
    """Return active groups for the logged-in teacher, optionally filtered by course."""
    staff = get_object_or_404(Staff, admin=request.user)
    qs = Group.objects.filter(teacher=staff, is_archived=False).order_by('name')
    course_id = request.POST.get('course_id', '').strip()
    if course_id:
        qs = qs.filter(course_id=course_id)
    groups = [{'id': g.id, 'name': g.name} for g in qs]
    return JsonResponse({'groups': groups})


# ── Vocabulary Days ───────────────────────────────────────────────────────────

@staff_only
def staff_vocabulary_days(request):
    staff = get_object_or_404(Staff, admin=request.user)
    my_groups = Group.objects.filter(teacher=staff, is_archived=False)
    group_filter = request.GET.get('group', '')
    qs = VocabularyDay.objects.filter(
        group__in=my_groups
    ).select_related('group').prefetch_related('words', 'completions')
    if group_filter:
        try:
            qs = qs.filter(group_id=int(group_filter))
        except (ValueError, TypeError):
            pass
    days = list(qs)
    for d in days:
        d.wc = d.words.count()
        d.cc = d.completions.count()
    return render(request, 'staff_template/staff_vocabulary_days.html', {
        'days': days,
        'my_groups': my_groups,
        'selected_group': group_filter,
        'page_title': 'Vocabulary Days',
    })


@staff_only
def add_vocabulary_day(request):
    import json as _json
    staff = get_object_or_404(Staff, admin=request.user)
    form = VocabularyDayForm(request.POST or None, staff=staff)
    if request.method == 'POST':
        if form.is_valid():
            day = form.save(commit=False)
            day.created_by = staff
            day.release_at = timezone.now()
            raw_level = form.cleaned_data.get('level')
            day.level = int(raw_level) if raw_level else None
            day.save()

            # Save words from JSON payload
            words_json = request.POST.get('words_json', '[]')
            try:
                words_data = _json.loads(words_json)
            except _json.JSONDecodeError:
                words_data = []
            word_objs = []
            for i, w in enumerate(words_data):
                word = (w.get('word') or '').strip()
                meaning = (w.get('meaning') or '').strip()
                if word and meaning:
                    word_objs.append(VocabularyDayWord(
                        day=day,
                        word=word,
                        meaning=meaning,
                        example_sentence=(w.get('example') or '').strip(),
                        pronunciation_note=(w.get('pronunciation') or '').strip(),
                        order=i,
                    ))
            VocabularyDayWord.objects.bulk_create(word_objs)

            # Send notifications immediately if already released
            _notify_vocab_day(day)

            messages.success(request, f"Day {day.day_number} created with {len(word_objs)} words!")
            return redirect(reverse('staff_vocabulary_days'))
        else:
            messages.error(request, "Please fix the errors below.")
    return render(request, 'staff_template/add_vocabulary_day.html', {
        'form': form,
        'page_title': 'Create Vocabulary Day',
        'editing': False,
    })


@staff_only
def edit_vocabulary_day(request, day_id):
    import json as _json
    staff = get_object_or_404(Staff, admin=request.user)
    day = get_object_or_404(VocabularyDay, id=day_id, created_by=staff)
    form = VocabularyDayForm(request.POST or None, instance=day, staff=staff)
    existing_words = list(day.words.all())
    if request.method == 'POST':
        if form.is_valid():
            day = form.save(commit=False)
            day.release_at = timezone.now()
            raw_level = form.cleaned_data.get('level')
            day.level = int(raw_level) if raw_level else None
            day.save()

            # Replace all words
            day.words.all().delete()
            words_json = request.POST.get('words_json', '[]')
            try:
                words_data = _json.loads(words_json)
            except _json.JSONDecodeError:
                words_data = []
            word_objs = []
            for i, w in enumerate(words_data):
                word = (w.get('word') or '').strip()
                meaning = (w.get('meaning') or '').strip()
                if word and meaning:
                    word_objs.append(VocabularyDayWord(
                        day=day,
                        word=word,
                        meaning=meaning,
                        example_sentence=(w.get('example') or '').strip(),
                        pronunciation_note=(w.get('pronunciation') or '').strip(),
                        order=i,
                    ))
            VocabularyDayWord.objects.bulk_create(word_objs)
            _notify_vocab_day(day)
            messages.success(request, f"Day {day.day_number} updated with {len(word_objs)} words!")
            return redirect(reverse('staff_vocabulary_days'))
        else:
            messages.error(request, "Please fix the errors below.")
    import json as _json
    existing_words_json = _json.dumps([{
        'word': w.word,
        'meaning': w.meaning,
        'example_sentence': w.example_sentence,
        'pronunciation_note': w.pronunciation_note,
    } for w in existing_words])
    return render(request, 'staff_template/add_vocabulary_day.html', {
        'form': form,
        'day': day,
        'existing_words_json': existing_words_json,
        'page_title': f'Edit Day {day.day_number}',
        'editing': True,
    })


@staff_only
def delete_vocabulary_day(request, day_id):
    staff = get_object_or_404(Staff, admin=request.user)
    day = get_object_or_404(VocabularyDay, id=day_id, created_by=staff)
    num = day.day_number
    day.delete()
    messages.success(request, f"Day {num} deleted.")
    return redirect(reverse('staff_vocabulary_days'))


@staff_only
def staff_vocabulary_day_detail(request, day_id):
    staff = get_object_or_404(Staff, admin=request.user)
    day = get_object_or_404(VocabularyDay, id=day_id, created_by=staff)
    words = day.words.all()
    # Enrolled students for this group
    enrollments = Enrollment.objects.filter(
        group=day.group, is_active=True
    ).select_related('student__admin')
    completed_ids = set(
        VocabularyDayCompletion.objects.filter(day=day)
        .values_list('student_id', flat=True)
    )
    quiz_map = {}
    for qr in VocabularyQuizResult.objects.filter(day=day).select_related('student'):
        if qr.student_id not in quiz_map or qr.score > quiz_map[qr.student_id]:
            quiz_map[qr.student_id] = qr.score
    student_rows = []
    for e in enrollments:
        s = e.student
        student_rows.append({
            'student': s,
            'completed': s.id in completed_ids,
            'best_quiz': quiz_map.get(s.id),
        })
    return render(request, 'staff_template/staff_vocabulary_day_detail.html', {
        'day': day,
        'words': words,
        'student_rows': student_rows,
        'page_title': f'Day {day.day_number} — {day.group.name}',
    })


def _notify_vocab_day(day: VocabularyDay):
    """Create Notification objects for students when a vocabulary day is released.

    Scope 'all'  → every active student in the system.
    Scope 'group' → only students actively enrolled in day.group.
    """
    from django.urls import reverse as _rev
    if not day.is_released:
        return

    if day.release_scope == VocabularyDay.SCOPE_ALL:
        students_qs = (
            Student.objects.filter(admin__is_active=True)
            .select_related('admin')
        )
    else:
        students_qs = (
            Student.objects.filter(
                enrollment__group=day.group, enrollment__is_active=True,
            ).select_related('admin')
        )

    word_count = day.word_count
    link = _rev('vocabulary_day_detail', args=[day.id])
    already = set(day.notified_students.values_list('id', flat=True))
    new_notifs = []
    new_notified = []
    for student in students_qs:
        if student.id not in already:
            new_notifs.append(Notification(
                recipient=student.admin,
                category=Notification.VOCABULARY,
                message=(
                    f"Day {day.day_number} Vocabulary is ready"
                    + (f' — "{day.title}"' if day.title else '')
                    + f"! Review {word_count} new words."
                ),
                link=link,
            ))
            new_notified.append(student)
    if new_notifs:
        Notification.objects.bulk_create(new_notifs)
        day.notified_students.add(*new_notified)


def _story_storage_ok():
    """True when a persistent remote storage backend (S3/Spaces) is configured."""
    import os
    return bool(os.environ.get('SPACES_KEY') and os.environ.get('SPACES_BUCKET'))


@staff_only
def staff_create_story(request):
    staff = get_object_or_404(Staff, admin=request.user)
    teacher_groups = Group.objects.filter(teacher=staff, is_archived=False)
    if request.method == 'POST':
        form = DashboardStoryForm(request.POST, request.FILES)
        # Restrict target_groups choices to teacher's own groups before validation,
        # so a teacher can't post to a group they don't own even by tampering payload.
        form.fields['target_groups'].queryset = teacher_groups
        if form.is_valid():
            try:
                story = form.save(commit=False)
                story.created_by = request.user
                story.save()
                form.save_m2m()
                # If the teacher did not pick any specific group, default to ALL of
                # their groups — so the story reaches only their students, not the
                # entire school (which would happen with an empty M2M).
                if not story.target_groups.exists():
                    story.target_groups.set(teacher_groups)
                messages.success(request, 'Story published to student dashboards.')
                return redirect(reverse('staff_create_story'))
            except Exception as exc:
                logger.exception("staff_create_story save failed for user=%s", request.user.id)
                messages.error(request, f"Could not publish story: {exc}")
    else:
        form = DashboardStoryForm()
        form.fields['target_groups'].queryset = teacher_groups
    return render(request, 'staff_template/staff_story_form.html', {
        'form': form,
        'page_title': 'Post a Story',
        'storage_ok': _story_storage_ok(),
    })
