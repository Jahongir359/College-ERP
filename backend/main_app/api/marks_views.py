"""School gradebook (plan task P2.4): ``school/marks/``.

A subject teacher gives the pupils of a class marks from 2 to 5 on a lesson
date (eMaktab's scale and quarters, decision D18). Pupils and parents read the
marks of one child, grouped by subject (design screen 14); teachers and admins
read one class subject's marks for every pupil. Only the subject's own teacher
saves marks. Access rules live in ``branching.py``.
"""

from datetime import date

from django.db import transaction
from django.utils import timezone
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .. import branching
from ..models import ClassSubject, Enrollment, Group, Mark, Staff, Term
from .family import student_for_request

MARK_KINDS = [kind for kind, _ in Mark.KIND_CHOICES]
COMMENT_MAX = Mark._meta.get_field("comment").max_length


def _bad_request(detail):
    return Response(detail, status=status.HTTP_400_BAD_REQUEST)


def _not_found(detail):
    return Response({"detail": detail}, status=status.HTTP_404_NOT_FOUND)


def _term_dict(term):
    return {
        "id": term.pk,
        "number": term.number,
        "name": term.name or f"Q{term.number}",
        "start_date": term.start_date,
        "end_date": term.end_date,
    }


def _mark_dict(mark):
    return {
        "id": mark.pk,
        "date": mark.date,
        "value": mark.value,
        "kind": mark.kind,
        "comment": mark.comment,
    }


def _terms(session):
    return list(Term.objects.filter(session=session)) if session else []


def _pick_term(request, terms):
    """``(term or None, error_response or None)`` from ``?term=<id>``.

    Without ``?term`` the quarter containing today is used; on a holiday (no
    quarter today) the whole academic year is returned.
    """
    raw = request.query_params.get("term", "").strip()
    if not raw:
        today = timezone.localdate()
        return next((t for t in terms if t.start_date <= today <= t.end_date), None), None
    if not raw.isdigit():
        return None, _bad_request({"term": ["term must be a number."]})
    term = next((t for t in terms if t.pk == int(raw)), None)
    if term is None:
        return None, _not_found("Quarter not found.")
    return term, None


def _in_term(marks, term, session):
    if term is not None:
        return marks.filter(date__gte=term.start_date, date__lte=term.end_date)
    if session is not None:
        return marks.filter(date__gte=session.start_year, date__lte=session.end_year)
    return marks


def _check_day(group, day):
    """An error message when marks can't be given on ``day`` in ``group``, else None."""
    if day > timezone.localdate():
        return "Marks can't be given for a future date."
    session = group.session
    if session and not session.start_year <= day <= session.end_year:
        return "This date is outside the class's academic year."
    terms = _terms(session)
    if terms and not any(t.start_date <= day <= t.end_date for t in terms):
        return "This date is outside every quarter (a holiday)."
    return None


class MarkListView(APIView):
    """GET/POST /api/v1/school/marks/

    GET for a pupil or parent (``?student=<id>`` for a parent with several
    children, ``?term=<id>``): the child's marks by subject. GET for a teacher
    or admin needs ``?class_subject=<id>`` and returns every pupil's marks.
    POST ``{class_subject, date, kind?, records: [{student_id, value, comment?}]}``
    saves one lesson's marks; ``value`` null removes a mark, pupils left out
    keep theirs.
    """

    permission_classes = [IsAuthenticated]

    def _class_subject(self, request, raw, check):
        """``(class_subject, None)`` or ``(None, error_response)``."""
        try:
            pk = int(raw)
        except (TypeError, ValueError):
            return None, _bad_request({"class_subject": ["class_subject must be a number."]})
        cs = (
            ClassSubject.objects.select_related("group__session", "subject", "teacher__admin")
            .filter(pk=pk)
            .first()
        )
        if not check(request.user, cs):
            return None, _not_found("Class subject not found.")
        return cs, None

    def _pupils(self, group):
        return (
            Enrollment.objects.filter(group=group, is_active=True)
            .select_related("student__admin")
            .order_by("student__admin__last_name", "student__admin__first_name")
        )

    # ── Pupil and parent: one child's marks by subject ──────────────────────

    def _child_payload(self, request, student):
        group = (
            Group.objects.filter(
                kind=Group.KIND_CLASS, enrollment__student=student, enrollment__is_active=True
            )
            .select_related("session")
            .order_by("-session__start_year")
            .first()
        )
        session = group.session if group else None
        terms = _terms(session)
        term, err = _pick_term(request, terms)
        if err:
            return err

        marks = _in_term(
            branching.filter_marks_for_user(request.user, Mark.objects.filter(student=student)),
            term,
            session,
        ).select_related("class_subject__subject")
        subjects = {}
        if group is not None:
            for cs in group.class_subjects.select_related("subject"):
                subjects[cs.pk] = {"class_subject_id": cs.pk, "subject": cs.subject.name}
        by_subject = {}
        for mark in marks:
            cs = mark.class_subject
            subjects.setdefault(cs.pk, {"class_subject_id": cs.pk, "subject": cs.subject.name})
            by_subject.setdefault(cs.pk, []).append(_mark_dict(mark))
        rows = [
            {**info, "marks": by_subject.get(pk, [])}
            for pk, info in sorted(subjects.items(), key=lambda item: item[1]["subject"])
        ]
        return Response(
            {
                "student": {"id": student.pk, "name": student.admin.get_full_name()},
                "class": {"id": group.pk, "name": group.name} if group else None,
                "terms": [_term_dict(t) for t in terms],
                "term": _term_dict(term) if term else None,
                "subjects": rows,
            }
        )

    # ── Teacher and admin: one class subject, every pupil ───────────────────

    def _subject_payload(self, request, cs, term):
        group = cs.group
        session = group.session
        marks = _in_term(
            branching.filter_marks_for_user(request.user, Mark.objects.filter(class_subject=cs)),
            term,
            session,
        )
        by_pupil = {}
        for mark in marks:
            by_pupil.setdefault(mark.student_id, []).append(_mark_dict(mark))
        teacher = cs.teacher
        return {
            "class_subject": {
                "id": cs.pk,
                "subject": cs.subject.name,
                "class": {"id": group.pk, "name": group.name},
                "teacher": teacher.admin.get_full_name() if teacher else "",
            },
            "terms": [_term_dict(t) for t in _terms(session)],
            "term": _term_dict(term) if term else None,
            "can_edit": branching.user_can_give_marks(request.user, cs),
            "students": [
                {
                    "student_id": e.student_id,
                    "name": e.student.admin.get_full_name(),
                    "marks": by_pupil.get(e.student_id, []),
                }
                for e in self._pupils(group)
            ],
        }

    def get(self, request):
        user_type = str(getattr(request.user, "user_type", ""))
        if user_type in ("3", "4"):
            student, err = student_for_request(request)
            if err:
                return err
            return self._child_payload(request, student)

        raw = request.query_params.get("class_subject", "").strip()
        if not raw:
            return _bad_request({"class_subject": ["Pass ?class_subject=<id>."]})
        cs, err = self._class_subject(request, raw, branching.user_can_view_subject_marks)
        if err:
            return err
        term, err = _pick_term(request, _terms(cs.group.session))
        if err:
            return err
        return Response(self._subject_payload(request, cs, term))

    def post(self, request):
        cs, err = self._class_subject(
            request, request.data.get("class_subject"), branching.user_can_view_subject_marks
        )
        if err:
            return err
        if not branching.user_can_give_marks(request.user, cs):
            return Response(
                {"detail": "Only the subject's teacher can give marks."},
                status=status.HTTP_403_FORBIDDEN,
            )
        try:
            day = date.fromisoformat(str(request.data.get("date", "")))
        except ValueError:
            return _bad_request({"date": ["Use the format YYYY-MM-DD."]})
        problem = _check_day(cs.group, day)
        if problem:
            return _bad_request({"date": [problem]})
        kind = request.data.get("kind") or Mark.KIND_LESSON
        if kind not in MARK_KINDS:
            return _bad_request({"kind": ["kind must be lesson, test or exam."]})

        records = request.data.get("records", [])
        if not isinstance(records, list):
            return _bad_request({"records": ["Send a list of records."]})
        pupils = {e.student_id for e in self._pupils(cs.group)}
        values, errors = {}, {}
        for index, rec in enumerate(records):
            if not isinstance(rec, dict):
                errors[str(index)] = ["Each record must be an object."]
                continue
            try:
                student_id = int(rec.get("student_id"))
            except (TypeError, ValueError):
                errors[str(index)] = ["student_id must be a number."]
                continue
            if student_id not in pupils:
                errors[str(index)] = ["This pupil is not in the class."]
                continue
            value = rec.get("value")
            if value is not None and (
                isinstance(value, bool) or not isinstance(value, int) or not 2 <= value <= 5
            ):
                errors[str(index)] = ["value must be a whole number from 2 to 5, or null."]
                continue
            comment = str(rec.get("comment") or "").strip()
            if len(comment) > COMMENT_MAX:
                errors[str(index)] = [f"comment can have at most {COMMENT_MAX} characters."]
                continue
            values[student_id] = (value, comment)
        if errors:
            return _bad_request({"records": errors})

        teacher = Staff.objects.filter(admin=request.user).first()
        with transaction.atomic():
            existing = {
                m.student_id: m
                for m in Mark.objects.select_for_update().filter(
                    class_subject=cs, date=day, kind=kind, student_id__in=values
                )
            }
            to_create, to_update, to_delete = [], [], []
            for student_id, (value, comment) in values.items():
                mark = existing.get(student_id)
                if value is None:
                    if mark is not None:
                        to_delete.append(mark.pk)
                elif mark is None:
                    to_create.append(
                        Mark(
                            student_id=student_id,
                            class_subject=cs,
                            date=day,
                            kind=kind,
                            value=value,
                            comment=comment,
                            given_by=teacher,
                        )
                    )
                else:
                    mark.value, mark.comment, mark.given_by = value, comment, teacher
                    mark.updated_at = timezone.now()
                    to_update.append(mark)
            Mark.objects.bulk_create(to_create)
            Mark.objects.bulk_update(to_update, ["value", "comment", "given_by", "updated_at"])
            Mark.objects.filter(pk__in=to_delete).delete()

        terms = _terms(cs.group.session)
        term = next((t for t in terms if t.start_date <= day <= t.end_date), None)
        return Response(self._subject_payload(request, cs, term))
