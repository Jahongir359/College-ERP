import json
import math
from datetime import datetime

from django.contrib import messages
from django.core.files.storage import default_storage
from django.db.models import Q
from django.http import HttpResponse, JsonResponse
from django.shortcuts import (HttpResponseRedirect, get_object_or_404,
                              redirect, render)
from django.urls import reverse

from .decorators import student_only
from .forms import *
from .models import *


@student_only
def student_home(request):
    student = get_object_or_404(Student, admin=request.user)

    # Overall attendance (Present=1 and Late=2 both count as attended)
    total_attendance = AttendanceReport.objects.filter(student=student).count()
    total_present = AttendanceReport.objects.filter(
        student=student, status__in=[AttendanceReport.PRESENT, AttendanceReport.LATE]
    ).count()
    if total_attendance == 0:
        percent_absent = percent_present = 0
    else:
        percent_present = math.floor((total_present / total_attendance) * 100)
        percent_absent = math.ceil(100 - percent_present)

    # Per-group breakdown
    enrollments = Enrollment.objects.filter(
        student=student, is_active=True
    ).select_related('group')
    total_groups = enrollments.count()

    group_name = []
    data_present = []
    data_absent = []
    subject_rows = []
    for enrollment in enrollments:
        group = enrollment.group
        att_qs = Attendance.objects.filter(group=group)
        present_count = AttendanceReport.objects.filter(
            attendance__in=att_qs,
            status__in=[AttendanceReport.PRESENT, AttendanceReport.LATE],
            student=student,
        ).count()
        absent_count = AttendanceReport.objects.filter(
            attendance__in=att_qs, status=AttendanceReport.ABSENT, student=student
        ).count()
        total_cls = present_count + absent_count
        pct = round((present_count / total_cls) * 100) if total_cls > 0 else 0
        group_name.append(group.name)
        data_present.append(present_count)
        data_absent.append(absent_count)
        subject_rows.append({
            'name': group.name,
            'present': present_count,
            'absent': absent_count,
            'total': total_cls,
            'pct': pct,
            'start_date': group.start_date,
        })

    # Level & English program detection
    is_english = student.is_english_student
    student_level = student.level

    # Notify student of any newly released vocabulary days
    _check_and_notify_vocab_days(student, [e.group_id for e in enrollments])

    # Recent unread notifications (show up to 3 on dashboard)
    recent_notifications = Notification.objects.filter(
        recipient=request.user, is_read=False
    ).order_by('-created_at')[:3]

    context = {
        'total_attendance': total_attendance,
        'percent_present': percent_present,
        'percent_absent': percent_absent,
        'total_subject': total_groups,
        'subject_rows': subject_rows,
        'data_present': data_present,
        'data_absent': data_absent,
        'data_name': group_name,
        'recent_assignments': _recent_assignments(student),
        'latest_result': _latest_result(student),
        'is_english': is_english,
        'student_level': student_level,
        'recent_notifications': recent_notifications,
        'student_theme': student.theme,
        'page_title': 'My Dashboard',
    }
    return render(request, 'student_template/erpnext_student_home.html', context)


def _recent_assignments(student):
    enrolled_groups = Enrollment.objects.filter(
        student=student, is_active=True
    ).values_list('group_id', flat=True)
    assignments = (
        Assignment.objects.filter(group_id__in=enrolled_groups)
        .select_related('group', 'subject')
        .order_by('due_date')[:4]
    )
    submitted_ids = set(
        Submission.objects.filter(student=student)
        .values_list('assignment_id', flat=True)
    )
    rows = []
    for a in assignments:
        submitted = a.id in submitted_ids
        rows.append({
            'id': a.id,
            'title': a.title,
            'group_name': a.group.name if a.group else '',
            'due_date': a.due_date,
            'submitted': submitted,
            'progress': 100 if submitted else 0,
        })
    return rows


def _latest_result(student):
    return (
        StudentResult.objects.filter(student=student)
        .select_related('group')
        .order_by('-id')
        .first()
    )


@student_only
def student_view_attendance(request):
    student = get_object_or_404(Student, admin=request.user)
    enrolled_group_ids = Enrollment.objects.filter(
        student=student, is_active=True
    ).values_list('group_id', flat=True)
    groups = Group.objects.filter(id__in=enrolled_group_ids).select_related('course')

    if request.method != 'POST':
        # Build a month-aware calendar of the student's attendance status
        all_reports = (
            AttendanceReport.objects.filter(student=student)
            .select_related('attendance')
            .order_by('-attendance__date')
        )

        month_present = month_late = month_absent = month_total = 0
        recent_rows = []
        status_by_date = {}
        today = datetime.now().date()
        month_start = today.replace(day=1)
        for r in all_reports:
            d = r.attendance.date
            iso = d.isoformat()
            if iso not in status_by_date:
                status_by_date[iso] = r.status
            if d >= month_start:
                month_total += 1
                if r.status == AttendanceReport.PRESENT:
                    month_present += 1
                elif r.status == AttendanceReport.LATE:
                    month_late += 1
                else:
                    month_absent += 1
            if len(recent_rows) < 8:
                recent_rows.append({
                    'date': d,
                    'status': r.status,
                    'group_name': r.attendance.group.name if r.attendance.group_id else '',
                })

        month_pct = round(((month_present + month_late) / month_total) * 100) if month_total else 0
        if month_pct >= 90:
            month_message = 'Excellent consistency'
        elif month_pct >= 75:
            month_message = 'Healthy attendance'
        elif month_pct >= 50:
            month_message = 'Could be better'
        else:
            month_message = 'Needs your attention'

        context = {
            'groups': groups,
            'page_title': 'Attendance',
            'month_pct': month_pct,
            'month_present': month_present,
            'month_late': month_late,
            'month_absent': month_absent,
            'month_total': month_total,
            'month_message': month_message,
            'recent_rows': recent_rows,
            'status_by_date': json.dumps(status_by_date),
        }
        return render(request, 'student_template/student_view_attendance.html', context)

    # AJAX POST: return attendance records for a group in a date range
    group_id = request.POST.get('group')
    start = request.POST.get('start_date')
    end = request.POST.get('end_date')
    try:
        group = get_object_or_404(Group, id=group_id)
        start_date = datetime.strptime(start, "%Y-%m-%d")
        end_date = datetime.strptime(end, "%Y-%m-%d")
        attendance_qs = Attendance.objects.filter(
            group=group, date__range=(start_date, end_date)
        )
        reports = AttendanceReport.objects.filter(
            attendance__in=attendance_qs, student=student
        ).select_related('attendance')
        json_data = [
            {"date": str(r.attendance.date), "status": r.status}
            for r in reports.order_by('attendance__date')
        ]
        return JsonResponse(json.dumps(json_data), safe=False)
    except Exception:
        return JsonResponse({'error': 'Unable to fetch attendance.'}, status=400)


@student_only
def student_apply_leave(request):
    form = LeaveReportStudentForm(request.POST or None)
    student = get_object_or_404(Student, admin_id=request.user.id)
    context = {
        'form': form,
        'leave_history': LeaveReportStudent.objects.filter(student=student),
        'page_title': 'Apply for leave'
    }
    if request.method == 'POST':
        if form.is_valid():
            try:
                obj = form.save(commit=False)
                obj.student = student
                obj.save()
                admin_users = CustomUser.objects.filter(user_type='1')
                Notification.objects.bulk_create([
                    Notification(
                        recipient=admin,
                        category=Notification.GENERAL,
                        message=(
                            f"Leave request from student {request.user.get_full_name()}: "
                            f"{obj.message[:120]}"
                        ),
                    ) for admin in admin_users
                ])
                messages.success(
                    request, "Application for leave has been submitted for review")
                return redirect(reverse('student_apply_leave'))
            except Exception:
                messages.error(request, "Could not submit")
        else:
            messages.error(request, "Form has errors!")
    return render(request, "student_template/student_apply_leave.html", context)


@student_only
def student_feedback(request):
    form = FeedbackStudentForm(request.POST or None)
    student = get_object_or_404(Student, admin_id=request.user.id)
    context = {
        'form': form,
        'feedbacks': FeedbackStudent.objects.filter(student=student),
        'page_title': 'Student Feedback'

    }
    if request.method == 'POST':
        if form.is_valid():
            try:
                obj = form.save(commit=False)
                obj.student = student
                obj.save()
                messages.success(
                    request, "Feedback submitted for review")
                return redirect(reverse('student_feedback'))
            except Exception:
                messages.error(request, "Could not Submit!")
        else:
            messages.error(request, "Form has errors!")
    return render(request, "student_template/student_feedback.html", context)


@student_only
def student_view_profile(request):
    student = get_object_or_404(Student, admin=request.user)
    form = StudentProfileForm(instance=student, data=request.POST or None)
    context = {'form': form, 'page_title': 'My Profile', 'student': student}
    if request.method == 'POST':
        if form.is_valid():
            try:
                admin = student.admin
                password = form.cleaned_data.get('password') or None
                if password:
                    admin.set_password(password)
                admin.first_name = form.cleaned_data['first_name']
                admin.last_name = form.cleaned_data['last_name']
                admin.gender = form.cleaned_data.get('gender', '')
                admin.save()
                student.phone = form.cleaned_data.get('phone', '')
                student.save()
                messages.success(request, "Profile updated!")
                return redirect(reverse('student_view_profile'))
            except Exception as e:
                messages.error(request, f"Error updating profile: {e}")
        else:
            messages.error(request, "Please fix the errors below.")
    return render(request, "student_template/student_view_profile.html", context)


@student_only
def student_save_theme(request):
    if request.method == 'POST':
        theme = request.POST.get('theme', 'system')
        if theme not in ('dark', 'bright', 'system'):
            theme = 'system'
        student = get_object_or_404(Student, admin=request.user)
        student.theme = theme
        student.save(update_fields=['theme'])
        return JsonResponse({'status': 'ok', 'theme': theme})
    return JsonResponse({'status': 'error'}, status=400)


@student_only
def student_fcmtoken(request):
    token = request.POST.get('token')
    student_user = get_object_or_404(CustomUser, id=request.user.id)
    try:
        student_user.fcm_token = token
        student_user.save()
        return HttpResponse("True")
    except Exception as e:
        return HttpResponse("False")


@student_only
def student_view_notification(request):
    notifications = Notification.objects.filter(recipient=request.user).order_by('-created_at')
    notifications.filter(is_read=False).update(is_read=True)
    context = {
        'notifications': notifications,
        'page_title': "View Notifications"
    }
    return render(request, "student_template/student_view_notification.html", context)


@student_only
def student_view_result(request):
    student = get_object_or_404(Student, admin=request.user)
    enrolled_group_ids = list(Enrollment.objects.filter(
        student=student, is_active=True
    ).values_list('group_id', flat=True))
    results = list(
        StudentResult.objects.filter(
            student=student, group_id__in=enrolled_group_ids
        ).select_related('group')
    )
    for r in results:
        r.total = int(r.test) + int(r.exam)

    subject_count = len(results)
    avg_score = round(sum(r.total for r in results) / subject_count) if subject_count else 0
    pass_count = sum(1 for r in results if r.total >= 45)

    # Chart data — scores per group
    chart_labels = [r.group.name if r.group else "General" for r in results]
    chart_test   = [int(r.test) for r in results]
    chart_exam   = [int(r.exam) for r in results]
    chart_total  = [r.total for r in results]

    # Vocab progress breakdown (legacy VocabularyProgress removed; counts zeroed)
    vocab_stage_counts = [0, 0, 0, 0]
    is_english = student.is_english_student

    context = {
        'results': results,
        'subject_count': subject_count,
        'avg_score': avg_score,
        'pass_count': pass_count,
        'is_english': is_english,
        'student_level': student.level_display,
        'chart_labels': json.dumps(chart_labels),
        'chart_test':   json.dumps(chart_test),
        'chart_exam':   json.dumps(chart_exam),
        'chart_total':  json.dumps(chart_total),
        'vocab_stage_counts': json.dumps(vocab_stage_counts),
        'page_title': "View Results",
    }
    return render(request, "student_template/student_view_result.html", context)


@student_only
def student_result_files(request):
    from django.db.models import Q
    student = get_object_or_404(Student, admin=request.user)
    enrolled_group_ids = Enrollment.objects.filter(
        student=student, is_active=True
    ).values_list('group_id', flat=True)
    files = (
        ResultFile.objects
        .filter(group_id__in=enrolled_group_ids)
        .filter(Q(student=student) | Q(student__isnull=True))
        .select_related('group', 'uploaded_by__admin')
    )
    return render(request, 'student_template/student_result_files.html', {
        'files': files,
        'page_title': 'Result Files',
    })


#library

@student_only
def view_books(request):
    books = Book.objects.all()
    context = {
        'books': books,
        'page_title': "Library"
    }
    return render(request, "student_template/view_books.html", context)



# ── Assignments ───────────────────────────────────────────────────────────────

@student_only
def student_assignments(request):
    student = get_object_or_404(Student, admin=request.user)
    enrolled_groups = Enrollment.objects.filter(student=student, is_active=True).values_list('group_id', flat=True)
    assignments = Assignment.objects.filter(group__in=enrolled_groups).select_related('subject', 'group', 'created_by__admin').order_by('due_date')
    submitted_ids = set(Submission.objects.filter(student=student).values_list('assignment_id', flat=True))
    return render(request, 'student_template/student_assignments.html', {
        'assignments': assignments,
        'submitted_ids': submitted_ids,
        'page_title': 'Assignments',
    })


@student_only
def submit_assignment(request, assignment_id):
    student = get_object_or_404(Student, admin=request.user)
    assignment = get_object_or_404(Assignment, id=assignment_id)
    existing = Submission.objects.filter(assignment=assignment, student=student).first()
    form = SubmissionForm(request.POST or None, request.FILES or None, instance=existing)
    if request.method == 'POST':
        if form.is_valid():
            obj = form.save(commit=False)
            obj.assignment = assignment
            obj.student = student
            obj.save()
            messages.success(request, "Submitted successfully!")
            return redirect(reverse('student_assignments'))
        else:
            messages.error(request, "Form has errors!")
    return render(request, 'student_template/submit_assignment.html', {
        'form': form,
        'assignment': assignment,
        'existing': existing,
        'page_title': f'Submit — {assignment.title}',
    })


# ── Vocabulary ────────────────────────────────────────────────────────────────

def _check_and_notify_vocab_days(student, enrolled_group_ids):
    """Create notifications for any released VocabularyDays the student hasn't been told about."""
    from django.utils import timezone as tz
    from django.urls import reverse as _rev
    now = tz.now()
    new_days = (
        VocabularyDay.objects.filter(
            group_id__in=enrolled_group_ids,
            release_at__lte=now,
        ).exclude(notified_students=student)
        .select_related('group')
    )
    notifs = []
    for day in new_days:
        link = _rev('vocabulary_day_detail', args=[day.id])
        notifs.append(Notification(
            recipient=student.admin,
            category=Notification.VOCABULARY,
            message=(
                f"Day {day.day_number} Vocabulary is ready"
                + (f' — "{day.title}"' if day.title else '')
                + f"! Review {day.word_count} new words for {day.group.name}."
            ),
            link=link,
        ))
        day.notified_students.add(student)
    if notifs:
        Notification.objects.bulk_create(notifs)


@student_only
def vocabulary_day_list(request):
    """Show all released vocabulary days for this student's enrolled groups."""
    from django.utils import timezone as tz
    student = get_object_or_404(Student, admin=request.user)
    enrolled_group_ids = list(
        Enrollment.objects.filter(student=student, is_active=True)
        .values_list('group_id', flat=True)
    )
    now = tz.now()
    days = (
        VocabularyDay.objects.filter(group_id__in=enrolled_group_ids, release_at__lte=now)
        .select_related('group', 'created_by__admin')
        .prefetch_related('words', 'completions')
        .order_by('day_number')
    )
    completed_ids = set(
        VocabularyDayCompletion.objects.filter(student=student)
        .values_list('day_id', flat=True)
    )
    day_rows = []
    for d in days:
        day_rows.append({
            'day': d,
            'word_count': d.words.count(),
            'completed': d.id in completed_ids,
        })
    return render(request, 'student_template/vocabulary_day_list.html', {
        'day_rows': day_rows,
        'page_title': 'Daily Vocabulary',
    })


@student_only
def vocabulary_day_detail(request, day_id):
    """Show the words for one vocabulary day and allow marking complete."""
    from django.utils import timezone as tz
    student = get_object_or_404(Student, admin=request.user)
    day = get_object_or_404(VocabularyDay, id=day_id)
    # Security: student must be in the day's group
    if not Enrollment.objects.filter(student=student, group=day.group, is_active=True).exists():
        messages.error(request, "You are not enrolled in this group.")
        return redirect(reverse('vocabulary_day_list'))
    if not day.is_released:
        messages.warning(request, "This vocabulary set is not available yet.")
        return redirect(reverse('vocabulary_day_list'))
    words = day.words.all()
    completed = VocabularyDayCompletion.objects.filter(student=student, day=day).exists()
    best_quiz = (
        VocabularyQuizResult.objects.filter(student=student, day=day)
        .order_by('-score').first()
    )
    return render(request, 'student_template/vocabulary_day_detail.html', {
        'day': day,
        'words': words,
        'completed': completed,
        'best_quiz': best_quiz,
        'page_title': f'Day {day.day_number} — {day.group.name}',
    })


@student_only
def vocabulary_day_complete(request, day_id):
    """AJAX endpoint: mark a vocabulary day as completed."""
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)
    student = get_object_or_404(Student, admin=request.user)
    day = get_object_or_404(VocabularyDay, id=day_id)
    if not Enrollment.objects.filter(student=student, group=day.group, is_active=True).exists():
        return JsonResponse({'error': 'Not enrolled'}, status=403)
    _, created = VocabularyDayCompletion.objects.get_or_create(student=student, day=day)
    return JsonResponse({'status': 'ok', 'created': created})


@student_only
def vocabulary_day_flashcard(request, day_id):
    """Flashcard mode for a specific vocabulary day."""
    from django.utils import timezone as tz
    student = get_object_or_404(Student, admin=request.user)
    day = get_object_or_404(VocabularyDay, id=day_id)
    if not Enrollment.objects.filter(student=student, group=day.group, is_active=True).exists():
        messages.error(request, "You are not enrolled in this group.")
        return redirect(reverse('vocabulary_day_list'))
    if not day.is_released:
        messages.warning(request, "This vocabulary set is not available yet.")
        return redirect(reverse('vocabulary_day_list'))
    words = list(day.words.all())
    words_json = json.dumps([{
        'id': w.id,
        'word': w.word,
        'meaning': w.meaning,
        'example_sentence': w.example_sentence,
        'pronunciation_note': w.pronunciation_note,
    } for w in words])
    completed = VocabularyDayCompletion.objects.filter(student=student, day=day).exists()
    return render(request, 'student_template/vocabulary_day_flashcard.html', {
        'day': day,
        'words': words,
        'words_json': words_json,
        'completed': completed,
        'page_title': f'Flashcards — Day {day.day_number}',
    })


@student_only
def vocabulary_day_quiz(request, day_id):
    """Quiz mode for a specific vocabulary day."""
    import random
    student = get_object_or_404(Student, admin=request.user)
    day = get_object_or_404(VocabularyDay, id=day_id)
    if not Enrollment.objects.filter(student=student, group=day.group, is_active=True).exists():
        messages.error(request, "You are not enrolled in this group.")
        return redirect(reverse('vocabulary_day_list'))
    if not day.is_released:
        messages.warning(request, "This vocabulary set is not available yet.")
        return redirect(reverse('vocabulary_day_list'))

    all_words = list(day.words.all())
    if len(all_words) < 2:
        messages.warning(request, "Need at least 2 words for a quiz.")
        return redirect(reverse('vocabulary_day_detail', args=[day_id]))

    # Build quiz questions: show meaning, pick correct word (MCQ 4 choices)
    questions = []
    for w in all_words:
        distractors = random.sample([x for x in all_words if x.id != w.id],
                                    min(3, len(all_words) - 1))
        choices = [{'id': w.id, 'word': w.word}] + [{'id': d.id, 'word': d.word} for d in distractors]
        random.shuffle(choices)
        questions.append({
            'id': w.id,
            'meaning': w.meaning,
            'example': w.example_sentence,
            'correct_id': w.id,
            'choices': choices,
        })
    random.shuffle(questions)
    best_quiz = (
        VocabularyQuizResult.objects.filter(student=student, day=day)
        .order_by('-score').first()
    )
    return render(request, 'student_template/vocabulary_day_quiz.html', {
        'day': day,
        'questions_json': json.dumps(questions),
        'total_questions': len(questions),
        'best_quiz': best_quiz,
        'page_title': f'Quiz — Day {day.day_number}',
    })


@student_only
def save_quiz_result(request, day_id):
    """AJAX: save quiz result and return updated stats."""
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)
    student = get_object_or_404(Student, admin=request.user)
    day = get_object_or_404(VocabularyDay, id=day_id)
    try:
        if request.content_type and 'application/json' in request.content_type:
            data = json.loads(request.body)
        else:
            data = request.POST
        correct = int(data.get('correct', 0))
        total = int(data.get('total', 1))
        score = round((correct / total) * 100, 1) if total else 0
        VocabularyQuizResult.objects.create(
            student=student, day=day,
            score=score, correct=correct, total=total,
        )
        # Auto-complete day if quiz score >= 60%
        if score >= 60:
            VocabularyDayCompletion.objects.get_or_create(student=student, day=day)
        return JsonResponse({'status': 'ok', 'score': score})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)


@student_only
def student_progress(request):
    """Dedicated progress page with real line-graph data."""
    from django.db.models import Avg, Count
    from django.db.models.functions import TruncDate
    from django.utils import timezone as tz
    from datetime import timedelta

    student = get_object_or_404(Student, admin=request.user)
    enrolled_group_ids = list(
        Enrollment.objects.filter(student=student, is_active=True)
        .values_list('group_id', flat=True)
    )
    today = tz.localdate()
    days_30 = [(today - timedelta(days=i)) for i in range(29, -1, -1)]
    date_labels = [d.strftime('%b %d') for d in days_30]
    date_set = set(days_30)

    # ── Vocabulary days completed per day (last 30 days) ─────────────────────
    completions_qs = dict(
        VocabularyDayCompletion.objects.filter(student=student)
        .annotate(d=TruncDate('completed_at'))
        .values('d').annotate(cnt=Count('id'))
        .values_list('d', 'cnt')
    )
    completions_line = [completions_qs.get(d, 0) for d in days_30]

    # ── Quiz scores per day (average if multiple) ─────────────────────────────
    quiz_qs = dict(
        VocabularyQuizResult.objects.filter(student=student)
        .annotate(d=TruncDate('taken_at'))
        .values('d').annotate(avg=Avg('score'))
        .values_list('d', 'avg')
    )
    quiz_line = [round(quiz_qs[d], 1) if d in quiz_qs else None for d in days_30]

    # ── Exam results per group (snapshot — bar chart) ─────────────────────────
    results = list(
        StudentResult.objects.filter(
            student=student, group_id__in=enrolled_group_ids
        ).select_related('group')
    )
    for r in results:
        r.total = int(r.test) + int(r.exam)
    exam_labels = [r.group.name if r.group else 'General' for r in results]
    exam_totals = [r.total for r in results]

    # ── Summary stats ─────────────────────────────────────────────────────────
    total_days_available = VocabularyDay.objects.filter(
        group_id__in=enrolled_group_ids,
        release_at__lte=tz.now(),
    ).count()
    total_completed = VocabularyDayCompletion.objects.filter(student=student).count()
    recent_quiz = VocabularyQuizResult.objects.filter(student=student).first()

    has_any_data = any(completions_line) or any(q is not None for q in quiz_line)

    context = {
        'date_labels': json.dumps(date_labels),
        'completions_line': json.dumps(completions_line),
        'quiz_line': json.dumps(quiz_line),
        'exam_labels': json.dumps(exam_labels),
        'exam_totals': json.dumps(exam_totals),
        'has_any_data': has_any_data,
        'total_days_available': total_days_available,
        'total_completed': total_completed,
        'recent_quiz': recent_quiz,
        'results': results,
        'is_english': student.is_english_student,
        'student_level': student.level_display,
        'page_title': 'My Progress',
    }
    return render(request, 'student_template/student_progress.html', context)


from django.contrib.auth.decorators import login_required

@login_required
def save_avatar(request):
    if request.method != 'POST':
        return JsonResponse({'status': 'error'}, status=405)
    avatar = request.POST.get('avatar', '')
    valid = [str(i) for i in range(1, 25)] + ['']
    if avatar not in valid:
        return JsonResponse({'status': 'error', 'message': 'Invalid avatar'}, status=400)
    request.user.avatar = avatar
    request.user.save(update_fields=['avatar'])
    return JsonResponse({'status': 'ok', 'avatar': avatar})
