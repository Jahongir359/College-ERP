import random as _random

from django.db import models
from django.db.models import Avg, Count, Q
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from ... import branching
from ...models import (
    DashboardStory,
    Enrollment,
    Group,
    LeaderboardSeason,
    Staff,
    Student,
    StudentResult,
    AttendanceReport,
    VocabularyDay,
    VocabularyDayCompletion,
    VocabularyDayWord,
    VocabularyQuizResult,
)
from ..permissions import IsAdminOrTeacher, IsStudent, IsTeacher
from ..serializers import (
    StaffVocabularyDaySerializer,
    StorySerializer,
    VocabularyQuizSerializer,
    VocabularyWordWriteSerializer,
)


# ---------------------------------------------------------------------------
# Vocabulary (student-facing)
# ---------------------------------------------------------------------------


class VocabularyDayListView(APIView):
    """Student: list released vocabulary days for their enrolled groups."""

    permission_classes = [IsAuthenticated]

    def get(self, request):
        from django.utils import timezone as tz
        from ..serializers import VocabularyDaySerializer

        user = request.user
        try:
            student = user.student
        except Exception:
            return Response([], status=status.HTTP_200_OK)
        enrolled_groups = Group.objects.filter(
            enrollment__student=student, enrollment__is_active=True
        )
        qs = (
            VocabularyDay.objects.filter(group__in=enrolled_groups, release_at__lte=tz.now())
            .prefetch_related("words")
            .select_related("group")
            .order_by("group", "day_number")
        )
        return Response(VocabularyDaySerializer(qs, many=True, context={"request": request}).data)


class VocabularyDayDetailView(APIView):
    """Student: get full words for one vocabulary day."""

    permission_classes = [IsAuthenticated]

    def get(self, request, pk):
        from ..serializers import VocabularyDaySerializer

        try:
            student = request.user.student
        except Exception:
            return Response({"detail": "Students only."}, status=status.HTTP_403_FORBIDDEN)
        try:
            day = VocabularyDay.objects.prefetch_related("words").select_related("group").get(pk=pk)
        except VocabularyDay.DoesNotExist:
            return Response({"detail": "Not found."}, status=status.HTTP_404_NOT_FOUND)
        if not day.is_released:
            return Response({"detail": "Not released yet."}, status=status.HTTP_403_FORBIDDEN)
        enrolled = Group.objects.filter(
            enrollment__student=student, enrollment__is_active=True, pk=day.group_id
        ).exists()
        if not enrolled:
            return Response({"detail": "Access denied."}, status=status.HTTP_403_FORBIDDEN)
        return Response(VocabularyDaySerializer(day, context={"request": request}).data)


class VocabularyDayCompleteView(APIView):
    """Student: mark a vocabulary day as completed."""

    permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        try:
            student = request.user.student
        except Exception:
            return Response({"detail": "Students only."}, status=status.HTTP_403_FORBIDDEN)
        try:
            day = VocabularyDay.objects.get(pk=pk)
        except VocabularyDay.DoesNotExist:
            return Response({"detail": "Not found."}, status=status.HTTP_404_NOT_FOUND)
        if not day.student_can_view(student):
            return Response({"detail": "Access denied."}, status=status.HTTP_403_FORBIDDEN)
        VocabularyDayCompletion.objects.get_or_create(student=student, day=day)
        return Response({"status": "completed"})


# ---------------------------------------------------------------------------
# Vocabulary Quiz
# ---------------------------------------------------------------------------


class VocabularyQuizView(APIView):
    """Student: generate shuffled MCQ quiz for a vocabulary day."""

    permission_classes = [IsStudent]

    def get(self, request, pk):
        try:
            student = request.user.student
        except Student.DoesNotExist:
            return Response(
                {"detail": "Student profile not found."}, status=status.HTTP_403_FORBIDDEN
            )

        try:
            day = VocabularyDay.objects.prefetch_related("words").select_related("group").get(pk=pk)
        except VocabularyDay.DoesNotExist:
            return Response({"detail": "Not found."}, status=status.HTTP_404_NOT_FOUND)

        if not day.is_released:
            return Response({"detail": "Not released yet."}, status=status.HTTP_403_FORBIDDEN)

        enrolled = Enrollment.objects.filter(
            student=student, group=day.group, is_active=True
        ).exists()
        if day.release_scope != VocabularyDay.SCOPE_ALL and not enrolled:
            return Response({"detail": "Access denied."}, status=status.HTTP_403_FORBIDDEN)

        all_words = list(day.words.all())
        if len(all_words) < 2:
            return Response(
                {"detail": "Need at least 2 words for a quiz."}, status=status.HTTP_400_BAD_REQUEST
            )

        questions = []
        for w in all_words:
            distractors = _random.sample(
                [x for x in all_words if x.id != w.id], min(3, len(all_words) - 1)
            )
            choices = [{"id": w.id, "word": w.word}] + [
                {"id": d.id, "word": d.word} for d in distractors
            ]
            _random.shuffle(choices)
            questions.append(
                {
                    "id": w.id,
                    "meaning": w.meaning,
                    "example_sentence": w.example_sentence,
                    "correct_id": w.id,
                    "choices": choices,
                }
            )
        _random.shuffle(questions)

        data = {
            "day_number": day.day_number,
            "title": day.title,
            "questions": questions,
        }
        serializer = VocabularyQuizSerializer(data=data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data)


class VocabularyQuizResultView(APIView):
    """Student: submit quiz result, auto-complete day if score >= 60%."""

    permission_classes = [IsStudent]

    def post(self, request, pk):
        try:
            student = request.user.student
        except Student.DoesNotExist:
            return Response(
                {"detail": "Student profile not found."}, status=status.HTTP_403_FORBIDDEN
            )

        try:
            day = VocabularyDay.objects.get(pk=pk)
        except VocabularyDay.DoesNotExist:
            return Response({"detail": "Not found."}, status=status.HTTP_404_NOT_FOUND)

        if not day.student_can_view(student):
            return Response({"detail": "Access denied."}, status=status.HTTP_403_FORBIDDEN)

        correct = request.data.get("correct")
        total = request.data.get("total")
        if correct is None or total is None:
            return Response(
                {"detail": "correct and total are required."}, status=status.HTTP_400_BAD_REQUEST
            )

        try:
            correct, total, score = VocabularyQuizResult.score_submission(day, correct, total)
        except (ValueError, TypeError) as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)

        VocabularyQuizResult.objects.create(
            student=student,
            day=day,
            score=score,
            correct=correct,
            total=total,
        )

        if score >= 60:
            VocabularyDayCompletion.objects.get_or_create(student=student, day=day)

        best_result = (
            VocabularyQuizResult.objects.filter(student=student, day=day).order_by("-score").first()
        )
        best_score = best_result.score if best_result else score

        return Response({"status": "ok", "score": score, "best_score": best_score})


# ---------------------------------------------------------------------------
# Student Progress
# ---------------------------------------------------------------------------


class StudentProgressView(APIView):
    """Student: chart data for the progress screen."""

    permission_classes = [IsStudent]

    def get(self, request):
        import datetime
        from django.db.models.functions import TruncDate
        from django.utils import timezone as tz

        try:
            student = request.user.student
        except Student.DoesNotExist:
            return Response(
                {"detail": "Student profile not found."}, status=status.HTTP_403_FORBIDDEN
            )

        enrolled_group_ids = list(
            Enrollment.objects.filter(student=student, is_active=True).values_list(
                "group_id", flat=True
            )
        )
        today = tz.localdate()
        days_30 = [(today - datetime.timedelta(days=i)) for i in range(29, -1, -1)]
        date_labels_30d = [d.strftime("%b %d") for d in days_30]

        # Vocab days completed per day (last 30 days)
        completions_qs = dict(
            VocabularyDayCompletion.objects.filter(student=student)
            .annotate(d=TruncDate("completed_at"))
            .values("d")
            .annotate(cnt=Count("id"))
            .values_list("d", "cnt")
        )
        activity_30d = [completions_qs.get(d, 0) for d in days_30]

        # Last 20 quiz results ordered by taken_at
        quiz_results_qs = VocabularyQuizResult.objects.filter(student=student).order_by("taken_at")[
            :20
        ]
        quiz_scores = [
            {
                "score": qr.score,
                "taken_at_str": qr.taken_at.strftime("%b %d"),
                "day_title": qr.day.title if qr.day else "",
            }
            for qr in quiz_results_qs
        ]

        # Exam results per enrolled group
        results_qs = StudentResult.objects.filter(
            student=student, group_id__in=enrolled_group_ids
        ).select_related("group")
        exam_results = []
        for r in results_qs:
            total = int(r.test) + int(r.exam)
            score_pct = round(total / 2, 1)  # out of 100 total (50+50)
            exam_results.append(
                {
                    "group_name": r.group.name if r.group else "General",
                    "test_score": r.test,
                    "exam_score": r.exam,
                    "total": total,
                    "score_pct": score_pct,
                }
            )

        # Attendance percentage
        reports = AttendanceReport.objects.filter(student=student)
        total_att = reports.count()
        present_att = reports.filter(status=AttendanceReport.PRESENT).count()
        attendance_pct = round(present_att / total_att * 100, 1) if total_att else 0.0

        # Summary stats
        completed_days = VocabularyDayCompletion.objects.filter(student=student).count()
        quiz_count = VocabularyQuizResult.objects.filter(student=student).count()
        avg_quiz_agg = VocabularyQuizResult.objects.filter(student=student).aggregate(
            avg=Avg("score")
        )
        avg_quiz_score = round(avg_quiz_agg["avg"], 1) if avg_quiz_agg["avg"] is not None else 0.0

        return Response(
            {
                "activity_30d": activity_30d,
                "quiz_scores": quiz_scores,
                "exam_results": exam_results,
                "date_labels_30d": date_labels_30d,
                "attendance_pct": attendance_pct,
                "completed_days": completed_days,
                "quiz_count": quiz_count,
                "avg_quiz_score": avg_quiz_score,
            }
        )


# ---------------------------------------------------------------------------
# Leaderboard
# ---------------------------------------------------------------------------


class LeaderboardView(APIView):
    """Return the active season leaderboard (or a specified season by ?season_id=).

    ``?scope=overall|group|branch`` narrows the board for students:
    *group* keeps classmates from the student\'s active groups, *branch*
    keeps students of the same branch. Rows are re-ranked within the scope.
    """

    permission_classes = [IsAuthenticated]

    def get(self, request):
        from ..serializers import LeaderboardEntrySerializer

        season_id = request.query_params.get("season_id")
        if season_id:
            try:
                season = LeaderboardSeason.objects.get(pk=season_id)
            except LeaderboardSeason.DoesNotExist:
                return Response({"detail": "Season not found."}, status=status.HTTP_404_NOT_FOUND)
        else:
            season = (
                LeaderboardSeason.objects.filter(is_active=True).order_by("-start_date").first()
            )
            if not season:
                return Response(
                    {"detail": "No active leaderboard season."}, status=status.HTTP_404_NOT_FOUND
                )

        snapshots = season.snapshots.select_related("student__admin").order_by("rank")

        me_student = None
        if str(request.user.user_type) == "3":
            try:
                me_student = request.user.student
            except Student.DoesNotExist:
                me_student = None

        scope = request.query_params.get("scope", "overall")
        if me_student and scope == "group":
            classmate_ids = Enrollment.objects.filter(
                group__in=Group.objects.filter(
                    enrollment__student=me_student, enrollment__is_active=True
                ),
                is_active=True,
            ).values_list("student_id", flat=True)
            snapshots = snapshots.filter(student_id__in=classmate_ids)
        elif me_student and scope == "branch":
            branch = me_student.effective_branch
            if branch:
                snapshots = snapshots.filter(
                    models.Q(student__branch=branch)
                    | models.Q(
                        student__branch__isnull=True,
                        student__enrollment__group__branch=branch,
                        student__enrollment__is_active=True,
                    )
                ).distinct()

        entries = []
        my_rank = None
        for i, snap in enumerate(snapshots, start=1):
            row = LeaderboardEntrySerializer(snap, context={"request": request}).data
            row["rank"] = i  # re-rank within the scope
            row["is_me"] = me_student is not None and snap.student_id == me_student.id
            if row["is_me"]:
                my_rank = i
            entries.append(row)

        return Response(
            {
                "id": season.id,
                "name": season.name,
                "period": season.period,
                "start_date": season.start_date,
                "end_date": season.end_date,
                "is_active": season.is_active,
                "scope": scope if scope in ("overall", "group", "branch") else "overall",
                "my_rank": my_rank,
                "entries": entries,
            }
        )


# ---------------------------------------------------------------------------
# Stories
# ---------------------------------------------------------------------------


class StoryListView(APIView):
    """GET: all authenticated users. Filters by enrolled groups for students
    and by their children's groups for parents."""

    permission_classes = [IsAuthenticated]

    def get(self, request):
        from django.utils import timezone as tz

        user = request.user
        user_type = str(user.user_type)

        now = tz.now()
        qs = (
            DashboardStory.objects.filter(is_active=True)
            .filter(Q(expires_at__isnull=True) | Q(expires_at__gt=now))
            .prefetch_related("target_groups")
        )

        if user_type == "3":
            try:
                student = user.student
            except Student.DoesNotExist:
                return Response([], status=status.HTTP_200_OK)
            enrolled_group_ids = list(
                Enrollment.objects.filter(student=student, is_active=True).values_list(
                    "group_id", flat=True
                )
            )
            # Show stories targeted to enrolled groups OR stories with no target groups (all)
            qs = qs.filter(
                Q(target_groups__isnull=True) | Q(target_groups__in=enrolled_group_ids)
            ).distinct()
        elif user_type == "4":
            # Parents see what their children see: school-wide stories plus
            # stories aimed at any of their children's classes and groups.
            child_group_ids = list(
                Enrollment.objects.filter(
                    student__in=branching.children_for_parent(user), is_active=True
                ).values_list("group_id", flat=True)
            )
            qs = qs.filter(
                Q(target_groups__isnull=True) | Q(target_groups__in=child_group_ids)
            ).distinct()

        qs = qs.order_by("-created_at")
        serializer = StorySerializer(qs, many=True, context={"request": request})
        return Response(serializer.data)


class StoryCreateView(APIView):
    """POST: Admin or Staff only."""

    permission_classes = [IsAdminOrTeacher]

    def post(self, request):
        user = request.user
        user_type = str(user.user_type)

        title = request.data.get("title", "").strip()
        if not title:
            return Response(
                {"title": "This field is required."}, status=status.HTTP_400_BAD_REQUEST
            )

        body = request.data.get("body", "")
        story_type = request.data.get("story_type", DashboardStory.TYPE_ANNOUNCEMENT)
        emoji = request.data.get("emoji", "\U0001f4e2")
        bg_color = request.data.get("bg_color", "#0C1F45")
        expires_at = request.data.get("expires_at", None)
        target_group_ids = request.data.get("target_group_ids", [])

        # Resolve created_by: for staff, store the CustomUser (admin field of Staff)
        if user_type == "2":
            created_by = user  # DashboardStory.created_by is a FK to CustomUser
        else:
            created_by = user

        story = DashboardStory.objects.create(
            title=title,
            body=body,
            story_type=story_type,
            emoji=emoji,
            bg_color=bg_color,
            created_by=created_by,
            expires_at=expires_at or None,
        )

        if target_group_ids:
            story.target_groups.set(Group.objects.filter(id__in=target_group_ids))
        # Object-level auth: trim targets to groups the caller may access, and
        # never let a teacher/branch admin publish a school-wide story.
        branching.scope_story_target_groups(user, story)

        serializer = StorySerializer(story, context={"request": request})
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class StoryDetailView(APIView):
    """DELETE: Admin or creator (staff)."""

    permission_classes = [IsAdminOrTeacher]

    def delete(self, request, pk):
        try:
            story = DashboardStory.objects.get(pk=pk)
        except DashboardStory.DoesNotExist:
            return Response({"detail": "Not found."}, status=status.HTTP_404_NOT_FOUND)

        user = request.user
        user_type = str(user.user_type)

        # Staff can only delete their own; admins follow the branch rules.
        if user_type == "1":
            allowed = branching.user_can_modify_story(user, story)
        else:
            allowed = story.created_by_id == user.id
        if not allowed:
            return Response({"detail": "Permission denied."}, status=status.HTTP_403_FORBIDDEN)

        story.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


# ---------------------------------------------------------------------------
# Staff Vocabulary Management
# ---------------------------------------------------------------------------


class StaffVocabularyListView(APIView):
    """Staff: list vocabulary days they created."""

    permission_classes = [IsTeacher]

    def get(self, request):
        try:
            staff = request.user.staff
        except Staff.DoesNotExist:
            return Response(
                {"detail": "Staff profile not found."}, status=status.HTTP_403_FORBIDDEN
            )

        days = (
            VocabularyDay.objects.filter(created_by=staff)
            .select_related("group")
            .prefetch_related("words", "completions")
        )
        serializer = StaffVocabularyDaySerializer(days, many=True, context={"request": request})
        return Response(serializer.data)


class StaffVocabularyCreateView(APIView):
    """Staff: create a new vocabulary day."""

    permission_classes = [IsTeacher]

    def post(self, request):
        try:
            staff = request.user.staff
        except Staff.DoesNotExist:
            return Response(
                {"detail": "Staff profile not found."}, status=status.HTTP_403_FORBIDDEN
            )

        group_id = request.data.get("group")
        if not group_id:
            return Response({"detail": "group is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            group = Group.objects.get(pk=group_id)
        except Group.DoesNotExist:
            return Response({"detail": "Group not found."}, status=status.HTTP_404_NOT_FOUND)

        # Staff can only create vocab for groups assigned to them
        if group.teacher_id != staff.id:
            return Response(
                {"detail": "You can only create vocabulary for groups assigned to you."},
                status=status.HTTP_403_FORBIDDEN,
            )

        serializer = StaffVocabularyDaySerializer(data=request.data, context={"request": request})
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        day = serializer.save(created_by=staff, group=group)
        return Response(
            StaffVocabularyDaySerializer(day, context={"request": request}).data,
            status=status.HTTP_201_CREATED,
        )


class StaffVocabularyDetailView(APIView):
    """Staff: GET/PATCH/DELETE a vocabulary day they own."""

    permission_classes = [IsTeacher]

    def _get_day(self, request, pk):
        try:
            staff = request.user.staff
        except Staff.DoesNotExist:
            return None, Response(
                {"detail": "Staff profile not found."}, status=status.HTTP_403_FORBIDDEN
            )
        try:
            day = (
                VocabularyDay.objects.prefetch_related("words", "completions")
                .select_related("group")
                .get(pk=pk)
            )
        except VocabularyDay.DoesNotExist:
            return None, Response({"detail": "Not found."}, status=status.HTTP_404_NOT_FOUND)
        if day.created_by_id != staff.id:
            return None, Response(
                {"detail": "Permission denied."}, status=status.HTTP_403_FORBIDDEN
            )
        return day, None

    def get(self, request, pk):
        day, err = self._get_day(request, pk)
        if err:
            return err
        serializer = StaffVocabularyDaySerializer(day, context={"request": request})
        return Response(serializer.data)

    def patch(self, request, pk):
        day, err = self._get_day(request, pk)
        if err:
            return err
        serializer = StaffVocabularyDaySerializer(
            day, data=request.data, partial=True, context={"request": request}
        )
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        serializer.save()
        return Response(serializer.data)

    def delete(self, request, pk):
        day, err = self._get_day(request, pk)
        if err:
            return err
        day.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class StaffVocabularyWordView(APIView):
    """Staff: add or remove words from a vocabulary day they own."""

    permission_classes = [IsTeacher]

    def _get_day(self, request, pk):
        try:
            staff = request.user.staff
        except Staff.DoesNotExist:
            return None, Response(
                {"detail": "Staff profile not found."}, status=status.HTTP_403_FORBIDDEN
            )
        try:
            day = VocabularyDay.objects.get(pk=pk)
        except VocabularyDay.DoesNotExist:
            return None, Response({"detail": "Not found."}, status=status.HTTP_404_NOT_FOUND)
        if day.created_by_id != staff.id:
            return None, Response(
                {"detail": "Permission denied."}, status=status.HTTP_403_FORBIDDEN
            )
        return day, None

    def post(self, request, pk):
        day, err = self._get_day(request, pk)
        if err:
            return err
        serializer = VocabularyWordWriteSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        word = serializer.save(day=day)
        return Response(
            VocabularyWordWriteSerializer(word).data,
            status=status.HTTP_201_CREATED,
        )

    def delete(self, request, pk, word_pk):
        day, err = self._get_day(request, pk)
        if err:
            return err
        try:
            word = VocabularyDayWord.objects.get(pk=word_pk, day=day)
        except VocabularyDayWord.DoesNotExist:
            return Response({"detail": "Word not found."}, status=status.HTTP_404_NOT_FOUND)
        word.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


# ---------------------------------------------------------------------------
# Group chat (mirrors web messaging_views; scoping via messaging helpers)
# ---------------------------------------------------------------------------


class MessageThreadListView(APIView):
    """List chat threads (one per accessible group) for any role."""

    permission_classes = [IsAuthenticated]

    def get(self, request):
        from ... import messaging
        from ...models import ChatMessage

        threads = []
        for group in messaging.accessible_groups_for_user(request.user):
            thread = messaging.ensure_thread_for_group(group)
            last = (
                ChatMessage.objects.filter(thread=thread)
                .select_related("sender")
                .order_by("-created_at")
                .first()
            )
            threads.append(
                {
                    "id": group.id,
                    "group_id": group.id,
                    "group_name": group.name,
                    "last_message": (last.body[:120] if last else ""),
                    "last_message_time": (last.created_at.isoformat() if last else None),
                    "unread_count": messaging.unread_count_for_thread(request.user, thread),
                }
            )
        threads.sort(key=lambda t: t["last_message_time"] or "", reverse=True)
        return Response({"threads": threads})


class MessageThreadDetailView(APIView):
    """Read or post messages in a group\'s chat thread."""

    permission_classes = [IsAuthenticated]

    def _get_thread(self, request, group_id):
        from ... import messaging

        try:
            group = Group.objects.get(pk=group_id)
        except Group.DoesNotExist:
            return None, Response({"detail": "Group not found."}, status=status.HTTP_404_NOT_FOUND)
        if not messaging.can_access_group(request.user, group):
            return None, Response({"detail": "Not allowed."}, status=status.HTTP_403_FORBIDDEN)
        return messaging.ensure_thread_for_group(group), None

    def get(self, request, group_id):
        from django.utils import timezone as tz
        from ...models import ChatReadState

        thread, err = self._get_thread(request, group_id)
        if err:
            return err
        messages = [
            {
                "id": m.id,
                "message": m.body,
                "sender_name": m.sender.get_full_name() or m.sender.email,
                "is_mine": m.sender_id == request.user.id,
                "created_at": m.created_at.isoformat(),
                "attachment_url": (
                    request.build_absolute_uri(m.attachment.url) if m.attachment else None
                ),
                "attachment_name": m.attachment_display_name,
                "attachment_is_image": m.attachment_is_image,
            }
            for m in thread.messages.select_related("sender").order_by("created_at")[:500]
        ]
        ChatReadState.objects.update_or_create(
            thread=thread,
            user=request.user,
            defaults={"last_read_at": tz.now()},
        )
        return Response({"messages": messages})

    def post(self, request, group_id):
        from ...models import ChatMessage

        thread, err = self._get_thread(request, group_id)
        if err:
            return err
        body = str(request.data.get("message") or request.data.get("body") or "").strip()
        attachment = request.FILES.get("attachment")
        if not body and not attachment:
            return Response({"detail": "Message is required."}, status=status.HTTP_400_BAD_REQUEST)
        if attachment and attachment.size > 10 * 1024 * 1024:
            return Response(
                {"detail": "Attachment too large (max 10 MB)."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        msg = ChatMessage.objects.create(
            thread=thread,
            sender=request.user,
            body=body[:4000],
            attachment=attachment,
            attachment_name=(attachment.name if attachment else ""),
        )
        return Response(
            {
                "id": msg.id,
                "message": msg.body,
                "sender_name": request.user.get_full_name() or request.user.email,
                "is_mine": True,
                "created_at": msg.created_at.isoformat(),
                "attachment_url": (
                    request.build_absolute_uri(msg.attachment.url) if msg.attachment else None
                ),
                "attachment_name": msg.attachment_display_name,
                "attachment_is_image": msg.attachment_is_image,
            },
            status=status.HTTP_201_CREATED,
        )


# ---------------------------------------------------------------------------
# Library books (read-only catalogue; loans are managed by staff on the web)
# ---------------------------------------------------------------------------


class BookListView(APIView):
    """Catalogue of library books with availability."""

    permission_classes = [IsAuthenticated]

    def get(self, request):
        from ...models import Book, Loan

        on_loan = set(
            Loan.objects.filter(returned_on__isnull=True).values_list("book_id", flat=True)
        )
        books = [
            {
                "id": b.id,
                "title": b.name,
                "author": b.author,
                "category": b.category,
                "isbn": b.isbn,
                "is_available": b.id not in on_loan,
            }
            for b in Book.objects.all().order_by("name")
        ]
        return Response({"books": books})
