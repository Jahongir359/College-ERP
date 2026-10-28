"""Admin API for Iceberg School data: subjects per class (plan task P1.3) and
parents with their children (P1.7).

Who may see or change a class or parent is decided in ``branching.py``: super
admins everything, branch admins the classes and children of their branches.
Parent rules (one login per family, one primary contact) live in ``parents.py``.
"""

from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.db.models import Q
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .. import branching, parents
from ..models import ClassSubject, Group, Parent, Staff, Subject
from ..school_forms import ParentChildForm, ParentForm
from .serializers import _current_class
from .permissions import IsAdmin


def _class_subject_dict(cs):
    teacher = cs.teacher
    return {
        "id": cs.pk,
        "class_id": cs.group_id,
        "subject_id": cs.subject_id,
        "subject_name": cs.subject.name,
        "teacher_id": cs.teacher_id,
        "teacher_name": teacher.admin.get_full_name() if teacher else "",
        "weekly_hours": cs.weekly_hours,
    }


def _bad_request(detail):
    return Response(detail, status=status.HTTP_400_BAD_REQUEST)


def _not_found(what):
    return Response({"detail": f"{what} not found."}, status=status.HTTP_404_NOT_FOUND)


def _teacher_for(request, teacher_id):
    """(teacher or None, error_response). An empty id clears the teacher."""
    if teacher_id in (None, ""):
        return None, None
    staff = branching.filter_staff_for_user(request.user, Staff.objects.all())
    teacher = staff.filter(pk=teacher_id).select_related("admin").first()
    if teacher is None:
        return None, _not_found("Teacher")
    return teacher, None


def _save(cs):
    try:
        cs.full_clean()
        with transaction.atomic():
            cs.save()
    except ValidationError as exc:
        return _bad_request(exc.message_dict)
    except IntegrityError:
        return _bad_request({"subject": ["This class already has this subject."]})
    return None


class ClassSubjectListView(APIView):
    """GET/POST /api/v1/admin/classes/<pk>/subjects/"""

    permission_classes = [IsAuthenticated, IsAdmin]

    def _class(self, request, pk):
        classes = branching.filter_groups_for_user(
            request.user, Group.objects.filter(kind=Group.KIND_CLASS)
        )
        return classes.filter(pk=pk).first()

    def get(self, request, pk):
        group = self._class(request, pk)
        if group is None:
            return _not_found("Class")
        rows = group.class_subjects.select_related("subject", "teacher__admin")
        return Response([_class_subject_dict(cs) for cs in rows])

    def post(self, request, pk):
        group = self._class(request, pk)
        if group is None:
            return _not_found("Class")
        subject = Subject.objects.filter(pk=request.data.get("subject_id") or 0).first()
        if subject is None:
            return _not_found("Subject")
        teacher, err = _teacher_for(request, request.data.get("teacher_id"))
        if err:
            return err
        cs = ClassSubject(group=group, subject=subject, teacher=teacher)
        if "weekly_hours" in request.data:
            cs.weekly_hours = request.data["weekly_hours"]
        err = _save(cs)
        if err:
            return err
        return Response(_class_subject_dict(cs), status=status.HTTP_201_CREATED)


class ClassSubjectDetailView(APIView):
    """GET/PATCH/DELETE /api/v1/admin/class-subjects/<pk>/"""

    permission_classes = [IsAuthenticated, IsAdmin]

    def _get(self, request, pk):
        qs = branching.filter_class_subjects_for_user(
            request.user, ClassSubject.objects.select_related("group", "subject", "teacher__admin")
        )
        return qs.filter(pk=pk).first()

    def get(self, request, pk):
        cs = self._get(request, pk)
        if cs is None:
            return _not_found("Class subject")
        return Response(_class_subject_dict(cs))

    def patch(self, request, pk):
        cs = self._get(request, pk)
        if cs is None:
            return _not_found("Class subject")
        if "teacher_id" in request.data:
            teacher, err = _teacher_for(request, request.data["teacher_id"])
            if err:
                return err
            cs.teacher = teacher
        if "weekly_hours" in request.data:
            cs.weekly_hours = request.data["weekly_hours"]
        err = _save(cs)
        if err:
            return err
        return Response(_class_subject_dict(cs))

    def delete(self, request, pk):
        cs = self._get(request, pk)
        if cs is None:
            return _not_found("Class subject")
        cs.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


# ── Parents and their children (P1.7) ────────────────────────────────────────


def _form_errors(*forms):
    errors = {}
    for form in forms:
        errors.update({field: [str(e) for e in errs] for field, errs in form.errors.items()})
    return _bad_request(errors)


def _link_dict(link):
    student = link.student
    return {
        "student_id": student.pk,
        "name": student.admin.get_full_name(),
        "login_id": student.admin.login_id,
        "branch_name": student.branch.name if student.branch_id else None,
        "class": _current_class(student),
        "relation": link.relation,
        "is_primary": link.is_primary,
    }


def _parent_dict(request, parent):
    user = parent.admin
    links = list(parents.visible_links(request.user, parent))
    return {
        "id": parent.pk,
        "login_id": user.login_id,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "name": user.get_full_name(),
        "phone": parent.phone,
        "children": [_link_dict(link) for link in links],
        # Children in branches this admin can't see exist, but aren't listed.
        "has_other_children": parent.child_links.count() > len(links),
    }


def _visible_parent(request, pk):
    qs = branching.filter_parents_for_user(request.user, Parent.objects.select_related("admin"))
    return qs.filter(pk=pk).first()


def _link_payload(data, student_id=None):
    payload = {
        "student": student_id if student_id is not None else data.get("student_id"),
        "relation": data.get("relation") or "guardian",
    }
    if str(data.get("is_primary", "")).strip().lower() not in ("", "false", "0", "off", "none"):
        payload["is_primary"] = "on"
    return payload


class ParentListView(APIView):
    """GET/POST /api/v1/admin/parents/

    POST creates the parent login together with its first child:
    ``{first_name, last_name, phone, password, student_id, relation, is_primary}``.
    """

    permission_classes = [IsAuthenticated, IsAdmin]

    def get(self, request):
        qs = branching.filter_parents_for_user(request.user, Parent.objects.select_related("admin"))
        search = (request.query_params.get("search") or "").strip()
        if search:
            qs = qs.filter(
                Q(admin__first_name__icontains=search)
                | Q(admin__last_name__icontains=search)
                | Q(admin__login_id__icontains=search)
                | Q(phone__icontains=search)
            )
        qs = qs.order_by("admin__first_name", "admin__last_name")
        return Response([_parent_dict(request, p) for p in qs])

    def post(self, request):
        form = ParentForm(request.data, user=request.user)
        link_form = ParentChildForm(_link_payload(request.data), user=request.user)
        if not (form.is_valid() & link_form.is_valid()):
            return _form_errors(form, link_form)
        parent = parents.create_parent(
            first_name=form.cleaned_data["first_name"],
            last_name=form.cleaned_data["last_name"],
            phone=form.cleaned_data["phone"],
            password=form.cleaned_data["password"],
            student=link_form.cleaned_data["student"],
            relation=link_form.cleaned_data["relation"],
            is_primary=link_form.cleaned_data["is_primary"],
        )
        return Response(_parent_dict(request, parent), status=status.HTTP_201_CREATED)


class ParentDetailView(APIView):
    """GET/PATCH/DELETE /api/v1/admin/parents/<pk>/

    PATCH takes any of first_name, last_name, phone, password (a new password
    resets it). DELETE removes the login; it is refused while the parent also
    has children in a branch this admin can't see.
    """

    permission_classes = [IsAuthenticated, IsAdmin]

    def get(self, request, pk):
        parent = _visible_parent(request, pk)
        if parent is None:
            return _not_found("Parent")
        return Response(_parent_dict(request, parent))

    def patch(self, request, pk):
        parent = _visible_parent(request, pk)
        if parent is None:
            return _not_found("Parent")
        data = {
            "first_name": parent.admin.first_name,
            "last_name": parent.admin.last_name,
            "phone": parent.phone,
        }
        data.update({k: request.data[k] for k in (*data, "password") if k in request.data})
        form = ParentForm(data, user=request.user, instance=parent)
        if not form.is_valid():
            return _form_errors(form)
        parents.update_parent(parent, **form.cleaned_data)
        return Response(_parent_dict(request, parent))

    def delete(self, request, pk):
        parent = _visible_parent(request, pk)
        if parent is None:
            return _not_found("Parent")
        if parents.has_hidden_children(request.user, parent):
            return Response(
                {
                    "detail": "This parent also has children in another branch. "
                    "Remove your children from the parent instead."
                },
                status=status.HTTP_403_FORBIDDEN,
            )
        parent.admin.delete()  # the Parent profile and its links go with the login
        return Response(status=status.HTTP_204_NO_CONTENT)


class ParentChildListView(APIView):
    """POST /api/v1/admin/parents/<pk>/children/  ``{student_id, relation, is_primary}``"""

    permission_classes = [IsAuthenticated, IsAdmin]

    def post(self, request, pk):
        parent = _visible_parent(request, pk)
        if parent is None:
            return _not_found("Parent")
        return _link(request, parent)


class ParentLinkByLoginView(APIView):
    """POST /api/v1/admin/parents/link-by-login/
    ``{login_id, phone, student_id, relation, is_primary}``

    Links a child to a parent this admin can't see yet (for example a School
    parent whose younger child joins the Study Center), using the login ID the
    parent gives the office. One login per family (D4). The phone must match
    too, so a mistyped login ID can't hand a child's data to another family.
    """

    permission_classes = [IsAuthenticated, IsAdmin]

    def post(self, request):
        login_id = str(request.data.get("login_id") or "").strip()
        digits = parents.phone_digits(str(request.data.get("phone") or ""))
        parent = None
        if login_id and digits:
            parent = (
                Parent.objects.select_related("admin")
                .filter(admin__login_id__iexact=login_id)
                .first()
            )
        if parent is None or parents.phone_digits(parent.phone) != digits:
            return _not_found("Parent with this login ID and phone")
        return _link(request, parent)


def _link(request, parent):
    form = ParentChildForm(_link_payload(request.data), user=request.user)
    if not form.is_valid():
        return _form_errors(form)
    parents.link_child(parent, **form.cleaned_data)
    return Response(_parent_dict(request, parent), status=status.HTTP_201_CREATED)


class ParentChildDetailView(APIView):
    """PATCH/DELETE /api/v1/admin/parents/<pk>/children/<student_pk>/

    PATCH changes relation and/or is_primary; DELETE unlinks the child (the
    parent login stays).
    """

    permission_classes = [IsAuthenticated, IsAdmin]

    def _link(self, request, pk, student_pk):
        parent = _visible_parent(request, pk)
        if parent is None:
            return None
        return parents.visible_links(request.user, parent).filter(student_id=student_pk).first()

    def patch(self, request, pk, student_pk):
        link = self._link(request, pk, student_pk)
        if link is None:
            return _not_found("Child link")
        data = {"relation": link.relation, "is_primary": link.is_primary}
        data.update({k: request.data[k] for k in data if k in request.data})
        form = ParentChildForm(_link_payload(data, student_id=student_pk), user=request.user)
        if not form.is_valid():
            return _form_errors(form)
        parents.update_link(
            link, relation=form.cleaned_data["relation"], is_primary=form.cleaned_data["is_primary"]
        )
        return Response(_link_dict(link))

    def delete(self, request, pk, student_pk):
        link = self._link(request, pk, student_pk)
        if link is None:
            return _not_found("Child link")
        link.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
