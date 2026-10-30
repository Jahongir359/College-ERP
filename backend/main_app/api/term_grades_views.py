"""School quarter and year grades (plan task P2.5): ``school/term-grades/``.

At the end of a quarter the subject teacher confirms each pupil's quarter
grade (2–5); at the end of the year, the year grade. The average of the
quarter's marks (or of the four quarter grades) is shown as a suggestion only
(decision D3). Admins of the class's branch may correct a grade. Pupils and
parents read one child's confirmed grades. Access rules live in ``branching.py``.
"""

from django.db import transaction
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .. import branching
from ..models import ClassSubject, Enrollment, Group, Mark, TermGrade
from ..school import suggested_grade
from .family import student_for_request
from .marks_views import _bad_request, _not_found, _term_dict, _terms

YEAR = "year"


def _period(raw, terms):
    """``(term or None for the year, error_response or None)`` from a ``term`` value.

    ``"year"`` is the year grade; otherwise the id of a quarter of the class's year.
    """
    raw = str(raw if raw is not None else "").strip()
    if raw == YEAR:
        return None, None
    if not raw.isdigit():
        return None, _bad_request({"term": ['term must be a quarter id or "year".']})
    term = next((t for t in terms if t.pk == int(raw)), None)
    if term is None:
        return None, _not_found("Quarter not found.")
    return term, None


def _suggestion(values):
    average, grade = suggested_grade(values)
    return {"average": str(average) if average is not None else None, "grade": grade}


class TermGradeListView(APIView):
    """GET/POST /api/v1/school/term-grades/

    GET for a pupil or parent (``?student=<id>`` for a parent with several
    children): every subject with its quarter grades and year grade. GET for a
    teacher or admin needs ``?class_subject=<id>&term=<id>|year`` and returns
    every pupil with the saved grade and the suggestion. POST
    ``{class_subject, term: <id>|"year", records: [{student_id, value}]}``
    saves grades; ``value`` null means "not graded", pupils left out keep theirs.
    """

    permission_classes = [IsAuthenticated]

    def _class_subject(self, request, raw):
        try:
            pk = int(raw)
        except (TypeError, ValueError):
            return None, _bad_request({"class_subject": ["class_subject must be a number."]})
        cs = (
            ClassSubject.objects.select_related("group__session", "subject", "teacher__admin")
            .filter(pk=pk)
            .first()
        )
        if not branching.user_can_view_subject_marks(request.user, cs):
            return None, _not_found("Class subject not found.")
        return cs, None

    def _pupils(self, group):
        return (
            Enrollment.objects.filter(group=group, is_active=True)
            .select_related("student__admin")
            .order_by("student__admin__last_name", "student__admin__first_name")
        )

    # ── Pupil and parent: one child's confirmed grades ──────────────────────

    def _child_payload(self, request, student):
        group = (
            Group.objects.filter(
                kind=Group.KIND_CLASS, enrollment__student=student, enrollment__is_active=True
            )
            .select_related("session")
            .order_by("-session__start_year")
            .first()
        )
        terms = _terms(group.session if group else None)
        subjects = []
        if group is not None:
            grades = branching.filter_term_grades_for_user(
                request.user,
                TermGrade.objects.filter(student=student, class_subject__group=group),
            )
            saved = {(g.class_subject_id, g.term_id): g.value for g in grades}
            for cs in group.class_subjects.select_related("subject").order_by("subject__name"):
                subjects.append(
                    {
                        "class_subject_id": cs.pk,
                        "subject": cs.subject.name,
                        "quarters": [
                            {"term_id": t.pk, "value": saved.get((cs.pk, t.pk))} for t in terms
                        ],
                        "year": saved.get((cs.pk, None)),
                    }
                )
        return Response(
            {
                "student": {"id": student.pk, "name": student.admin.get_full_name()},
                "class": {"id": group.pk, "name": group.name} if group else None,
                "terms": [_term_dict(t) for t in terms],
                "subjects": subjects,
            }
        )

    # ── Teacher and admin: one class subject and period, every pupil ────────

    def _subject_payload(self, request, cs, term, terms):
        pupils = list(self._pupils(cs.group))
        ids = [e.student_id for e in pupils]
        grades = branching.filter_term_grades_for_user(
            request.user, TermGrade.objects.filter(class_subject=cs, student_id__in=ids)
        )
        saved = {(g.student_id, g.term_id): g for g in grades}

        basis = {}
        if term is not None:
            marks = branching.filter_marks_for_user(
                request.user,
                Mark.objects.filter(
                    class_subject=cs,
                    student_id__in=ids,
                    date__gte=term.start_date,
                    date__lte=term.end_date,
                ),
            )
            for mark in marks:
                basis.setdefault(mark.student_id, []).append(mark.value)
        else:
            for (student_id, term_id), grade in saved.items():
                if term_id is not None:
                    basis.setdefault(student_id, []).append(grade.value)

        rows = []
        for e in pupils:
            grade = saved.get((e.student_id, term.pk if term else None))
            row = {
                "student_id": e.student_id,
                "name": e.student.admin.get_full_name(),
                "saved": grade is not None,
                "value": grade.value if grade else None,
                "suggestion": _suggestion(basis.get(e.student_id, [])),
            }
            if term is None:
                row["quarters"] = [
                    {
                        "term_id": t.pk,
                        "value": saved[(e.student_id, t.pk)].value
                        if (e.student_id, t.pk) in saved
                        else None,
                    }
                    for t in terms
                ]
            else:
                row["marks"] = basis.get(e.student_id, [])
            rows.append(row)

        teacher = cs.teacher
        return {
            "class_subject": {
                "id": cs.pk,
                "subject": cs.subject.name,
                "class": {"id": cs.group.pk, "name": cs.group.name},
                "teacher": teacher.admin.get_full_name() if teacher else "",
            },
            "terms": [_term_dict(t) for t in terms],
            "term": _term_dict(term) if term else YEAR,
            "can_edit": branching.user_can_give_term_grades(request.user, cs),
            "students": rows,
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
        cs, err = self._class_subject(request, raw)
        if err:
            return err
        terms = _terms(cs.group.session)
        term, err = _period(request.query_params.get("term"), terms)
        if err:
            return err
        return Response(self._subject_payload(request, cs, term, terms))

    def post(self, request):
        cs, err = self._class_subject(request, request.data.get("class_subject"))
        if err:
            return err
        if not branching.user_can_give_term_grades(request.user, cs):
            return Response(
                {"detail": "Only the subject's teacher or the office can set these grades."},
                status=status.HTTP_403_FORBIDDEN,
            )
        terms = _terms(cs.group.session)
        term, err = _period(request.data.get("term"), terms)
        if err:
            return err

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
            values[student_id] = value
        if errors:
            return _bad_request({"records": errors})

        with transaction.atomic():
            for student_id, value in values.items():
                TermGrade.objects.update_or_create(
                    student_id=student_id,
                    class_subject=cs,
                    term=term,
                    defaults={"value": value, "given_by": request.user},
                )

        return Response(self._subject_payload(request, cs, term, terms))
