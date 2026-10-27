from datetime import date

from django.utils import timezone as tz
from rest_framework import generics, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from ... import branching
from ...models import Enrollment, Group, Invoice, Staff, Student
from ..family import student_for_request
from ..serializers import InvoiceSerializer


def _staff_invoice_payload(invoice):
    return {
        "id": invoice.id,
        "status": invoice.status,
        "status_display": invoice.get_status_display(),
        "due_date": invoice.due_date.isoformat(),
        "amount": str(invoice.amount),
        "discount": str(invoice.discount),
        "amount_paid": str(invoice.paid_amount),
        "amount_due": str(invoice.balance),
        "is_overdue": invoice.is_overdue,
    }


class InvoiceView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = InvoiceSerializer

    def list(self, request, *args, **kwargs):
        if str(request.user.user_type) == "4":
            student, error = student_for_request(request)
            if error is not None:
                return error
            self.parent_child = student
        return super().list(request, *args, **kwargs)

    def get_queryset(self):
        user = self.request.user
        user_type = str(user.user_type)
        qs = Invoice.objects.prefetch_related("payments").select_related("group")
        if user_type == "3":
            try:
                return qs.filter(student=user.student).order_by("-period")
            except Student.DoesNotExist:
                return qs.none()
        if user_type == "4":
            return qs.filter(student=self.parent_child).order_by("-period")
        if user_type == "1":
            students = branching.filter_students_for_user(user, Student.objects.all())
            return qs.filter(student__in=students).order_by("-period")
        return qs.none()


class InvoiceDetailView(generics.RetrieveAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = InvoiceSerializer

    def get_queryset(self):
        user = self.request.user
        user_type = str(user.user_type)
        qs = Invoice.objects.prefetch_related("payments").select_related("group")
        if user_type == "3":
            try:
                return qs.filter(student=user.student)
            except Student.DoesNotExist:
                return qs.none()
        if user_type == "4":
            return qs.filter(student__in=branching.children_for_parent(user))
        if user_type == "1":
            students = branching.filter_students_for_user(user, Student.objects.all())
            return qs.filter(student__in=students)
        return qs.none()


class StaffPaymentBoardView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if str(request.user.user_type) != "2":
            return Response({"detail": "Permission denied."}, status=status.HTTP_403_FORBIDDEN)

        try:
            staff = request.user.staff
        except Staff.DoesNotExist:
            return Response(
                {"detail": "Staff profile not found."}, status=status.HTTP_403_FORBIDDEN
            )

        month = request.query_params.get("month", "")
        today = tz.localdate()
        try:
            year, month_no = [int(part) for part in month.split("-", 1)]
            period = date(year, month_no, 1)
        except (TypeError, ValueError):
            period = date(today.year, today.month, 1)

        groups = Group.objects.filter(teacher=staff, is_archived=False).order_by("name")
        boards = []
        summary = {"paid": 0, "overdue": 0, "due": 0, "none": 0}

        for group in groups:
            enrollments = (
                Enrollment.objects.filter(group=group, is_active=True)
                .select_related("student__admin")
                .order_by("student__admin__last_name", "student__admin__first_name")
            )
            invoices = {
                inv.student_id: inv
                for inv in Invoice.objects.filter(group=group, period=period).prefetch_related(
                    "payments"
                )
            }
            rows = []
            for enrollment in enrollments:
                student = enrollment.student
                user = student.admin
                invoice = invoices.get(student.id)
                if invoice is None or invoice.status == Invoice.STATUS_CANCELLED:
                    state = "none"
                    invoice_data = None
                elif invoice.status == Invoice.STATUS_PAID:
                    state = "paid"
                    invoice_data = _staff_invoice_payload(invoice)
                elif invoice.is_overdue:
                    state = "overdue"
                    invoice_data = _staff_invoice_payload(invoice)
                else:
                    state = "due"
                    invoice_data = _staff_invoice_payload(invoice)

                summary[state] += 1
                rows.append(
                    {
                        "student": {
                            "id": student.id,
                            "name": f"{user.first_name} {user.last_name}".strip() or str(student),
                            "email": user.email,
                            "login_id": user.login_id,
                        },
                        "state": state,
                        "invoice": invoice_data,
                    }
                )

            boards.append(
                {
                    "group": {
                        "id": group.id,
                        "name": group.name,
                        "schedule": group.schedule,
                        "room": group.room,
                    },
                    "rows": rows,
                }
            )

        return Response(
            {
                "period": period.isoformat(),
                "month": period.strftime("%Y-%m"),
                "summary": summary,
                "boards": boards,
            }
        )
