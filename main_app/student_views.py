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
        })

    # Level & English program detection
    is_english = student.is_english_student
    student_level = student.level

    # Today's vocabulary (level-filtered, for English students)
    todays_vocab = []
    if is_english:
        from django.utils import timezone
        enrolled_group_ids = [e.group_id for e in enrollments]
        vocab_qs = Vocabulary.objects.filter(
            level__in=([Vocabulary.LEVEL_ALL] + ([student_level] if student_level else []))
        ).filter(
            Q(group__isnull=True) | Q(group_id__in=enrolled_group_ids)
        ).order_by('?')[:5]
        todays_vocab = list(vocab_qs)

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
        'todays_vocab': todays_vocab,
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
    form = StudentEditForm(request.POST or None, request.FILES or None,
                           instance=student)
    context = {'form': form,
               'page_title': 'View/Edit Profile'
               }
    if request.method == 'POST':
        try:
            if form.is_valid():
                first_name = form.cleaned_data.get('first_name')
                last_name = form.cleaned_data.get('last_name')
                password = form.cleaned_data.get('password') or None
                address = form.cleaned_data.get('address')
                gender = form.cleaned_data.get('gender')
                passport = request.FILES.get('profile_pic') or None
                admin = student.admin
                if password != None:
                    admin.set_password(password)
                if passport != None:
                    admin.profile_pic = default_storage.save(passport.name, passport)
                admin.first_name = first_name
                admin.last_name = last_name
                admin.address = address
                admin.gender = gender
                admin.save()
                student.save()
                messages.success(request, "Profile Updated!")
                return redirect(reverse('student_view_profile'))
            else:
                messages.error(request, "Invalid Data Provided")
        except Exception as e:
            messages.error(request, "Error Occured While Updating Profile " + str(e))

    return render(request, "student_template/student_view_profile.html", context)


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

    # Vocab progress breakdown (for English students)
    vocab_stage_counts = [0, 0, 0, 0]  # new, learning, review, mastered
    is_english = student.is_english_student
    if is_english:
        from django.db.models import Count
        stage_qs = (
            VocabularyProgress.objects
            .filter(student=student)
            .values('stage')
            .annotate(cnt=Count('id'))
        )
        for row in stage_qs:
            vocab_stage_counts[row['stage']] = row['cnt']

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

def _vocab_queryset_for_student(student, enrolled_group_ids):
    """Return vocabulary visible to this student filtered by their level and enrolled groups."""
    level_filter = [Vocabulary.LEVEL_ALL]
    if student.level:
        level_filter.append(student.level)
    return (
        Vocabulary.objects.filter(level__in=level_filter)
        .filter(Q(group__isnull=True) | Q(group_id__in=enrolled_group_ids))
        .select_related('group')
        .order_by('word')
    )


@student_only
def vocabulary_home(request):
    from django.utils import timezone as tz

    student = get_object_or_404(Student, admin=request.user)
    enrolled_group_ids = list(
        Enrollment.objects.filter(student=student, is_active=True)
        .values_list('group_id', flat=True)
    )

    vocab_qs = _vocab_queryset_for_student(student, enrolled_group_ids)

    today = tz.localdate()
    progress_map = {}
    for v in vocab_qs:
        prog, _ = VocabularyProgress.objects.get_or_create(
            student=student, vocabulary=v
        )
        progress_map[v.id] = prog

    total = vocab_qs.count()
    mastered = sum(1 for p in progress_map.values() if p.stage == VocabularyProgress.STAGE_MASTERED)
    learning = sum(1 for p in progress_map.values() if p.stage in (VocabularyProgress.STAGE_LEARNING, VocabularyProgress.STAGE_REVIEW))
    new_count = sum(1 for p in progress_map.values() if p.stage == VocabularyProgress.STAGE_NEW)
    due_today = sum(
        1 for p in progress_map.values()
        if p.stage < VocabularyProgress.STAGE_MASTERED and p.next_review_date <= today
    )

    return render(request, 'student_template/vocabulary_home.html', {
        'vocabulary_list': vocab_qs,
        'progress_map': progress_map,
        'total': total,
        'mastered': mastered,
        'learning': learning,
        'new_count': new_count,
        'due_today': due_today,
        'student_level': student.level,
        'is_english': student.is_english_student,
        'page_title': 'My Vocabulary',
    })


@student_only
def vocabulary_flashcard(request):
    from django.utils import timezone as tz

    student = get_object_or_404(Student, admin=request.user)
    enrolled_group_ids = list(
        Enrollment.objects.filter(student=student, is_active=True)
        .values_list('group_id', flat=True)
    )

    vocab_qs = _vocab_queryset_for_student(student, enrolled_group_ids)

    today = tz.localdate()
    progress_map = {}
    for v in vocab_qs:
        prog, _ = VocabularyProgress.objects.get_or_create(
            student=student, vocabulary=v
        )
        progress_map[v.id] = prog

    # Due cards: next_review_date <= today and not mastered, ordered by stage ASC
    due_vocab = [
        v for v in vocab_qs
        if progress_map[v.id].stage < VocabularyProgress.STAGE_MASTERED
        and progress_map[v.id].next_review_date <= today
    ]
    due_vocab.sort(key=lambda v: progress_map[v.id].stage)

    if request.method == 'POST':
        try:
            if request.content_type and 'application/json' in request.content_type:
                data = json.loads(request.body)
            else:
                data = request.POST
            vocab_id = int(data.get('vocab_id', 0))
            correct = str(data.get('correct', 'false')).lower() in ('true', '1', 'yes')
            vocab = get_object_or_404(Vocabulary, id=vocab_id)
            prog, _ = VocabularyProgress.objects.get_or_create(student=student, vocabulary=vocab)
            prog.record_answer(correct)
            return JsonResponse({
                'stage': prog.stage,
                'correct_count': prog.correct_count,
                'incorrect_count': prog.incorrect_count,
                'interval_days': prog.interval_days,
                'next_review_date': prog.next_review_date.isoformat(),
            })
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)

    vocab_json = json.dumps([{
        'id': v.id,
        'word': v.word,
        'definition': v.definition,
        'example_sentence': v.example_sentence,
        'translation': v.translation,
        'part_of_speech': v.part_of_speech,
        'stage': progress_map[v.id].stage,
    } for v in due_vocab])

    return render(request, 'student_template/vocabulary_flashcard.html', {
        'vocabulary_list': due_vocab,
        'progress_map': progress_map,
        'due_count': len(due_vocab),
        'vocab_json': vocab_json,
        'page_title': 'Flashcard Review',
    })


@student_only
def vocabulary_quiz(request):
    student = get_object_or_404(Student, admin=request.user)
    enrolled_group_ids = list(
        Enrollment.objects.filter(student=student, is_active=True)
        .values_list('group_id', flat=True)
    )

    vocab_qs = _vocab_queryset_for_student(student, enrolled_group_ids)

    progress_map = {}
    for v in vocab_qs:
        prog, _ = VocabularyProgress.objects.get_or_create(
            student=student, vocabulary=v
        )
        progress_map[v.id] = prog

    if request.method == 'POST':
        try:
            if request.content_type and 'application/json' in request.content_type:
                data = json.loads(request.body)
            else:
                data = request.POST
            vocab_id = int(data.get('vocab_id', 0))
            correct = str(data.get('correct', 'false')).lower() in ('true', '1', 'yes')
            vocab = get_object_or_404(Vocabulary, id=vocab_id)
            prog, _ = VocabularyProgress.objects.get_or_create(student=student, vocabulary=vocab)
            prog.record_answer(correct)
            return JsonResponse({
                'stage': prog.stage,
                'correct_count': prog.correct_count,
                'incorrect_count': prog.incorrect_count,
                'interval_days': prog.interval_days,
                'next_review_date': prog.next_review_date.isoformat(),
            })
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)

    vocab_json = json.dumps([{
        'id': v.id,
        'word': v.word,
        'definition': v.definition,
        'example_sentence': v.example_sentence,
        'translation': v.translation,
        'part_of_speech': v.part_of_speech,
        'stage': progress_map.get(v.id, {}).get('stage', 0) if isinstance(progress_map.get(v.id), dict) else getattr(progress_map.get(v.id), 'stage', 0),
    } for v in vocab_qs])

    return render(request, 'student_template/vocabulary_quiz.html', {
        'vocab_json': vocab_json,
        'page_title': 'Vocabulary Quiz',
    })


@student_only
def vocabulary_voice(request):
    student = get_object_or_404(Student, admin=request.user)
    enrolled_group_ids = list(
        Enrollment.objects.filter(student=student, is_active=True)
        .values_list('group_id', flat=True)
    )

    vocab_qs = _vocab_queryset_for_student(student, enrolled_group_ids)

    progress_map = {}
    for v in vocab_qs:
        prog, _ = VocabularyProgress.objects.get_or_create(
            student=student, vocabulary=v
        )
        progress_map[v.id] = prog

    vocab_json = json.dumps([{
        'id': v.id,
        'word': v.word,
        'definition': v.definition,
        'example_sentence': v.example_sentence,
        'translation': v.translation,
        'part_of_speech': v.part_of_speech,
        'stage': progress_map.get(v.id, {}).get('stage', 0) if isinstance(progress_map.get(v.id), dict) else getattr(progress_map.get(v.id), 'stage', 0),
    } for v in vocab_qs])

    return render(request, 'student_template/vocabulary_voice.html', {
        'vocab_json': vocab_json,
        'page_title': 'Voice Practice',
    })


@student_only
def vocabulary_progress_update(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)

    student = get_object_or_404(Student, admin=request.user)
    try:
        if request.content_type and 'application/json' in request.content_type:
            data = json.loads(request.body)
        else:
            data = request.POST
        vocab_id = int(data.get('vocab_id', 0))
        correct = str(data.get('correct', '0')) in ('1', 'true', 'True', 'yes')
        vocab = get_object_or_404(Vocabulary, id=vocab_id)
        prog, _ = VocabularyProgress.objects.get_or_create(student=student, vocabulary=vocab)
        prog.record_answer(correct)
        return JsonResponse({
            'stage': prog.stage,
            'correct_count': prog.correct_count,
            'incorrect_count': prog.incorrect_count,
            'interval_days': prog.interval_days,
            'next_review_date': prog.next_review_date.isoformat(),
        })
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)
