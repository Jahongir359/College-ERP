import json

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse

from main_app.models import (
    RegistrationLead,
)


_BASE_OVERRIDES = dict(
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
    # Disable SSL redirect so the test client (HTTP) reaches views without
    # being bounced to HTTPS (which then strips POST bodies on 301 redirect).
    SECURE_SSL_REDIRECT=False,
)


class RegistrationLeadReceiverTests(TestCase):
    @override_settings(**_BASE_OVERRIDES, REGISTRATION_LEADS_API_TOKEN="secret-token")
    def test_receiver_requires_configured_bearer_token(self):
        response = self.client.post(
            reverse("public_registration_leads"),
            data=json.dumps({"full_name": "Public Student", "phone": "+998901234567"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(RegistrationLead.objects.count(), 0)

    @override_settings(**_BASE_OVERRIDES, REGISTRATION_LEADS_API_TOKEN="secret-token")
    def test_receiver_stores_json_registration_lead(self):
        response = self.client.post(
            reverse("public_registration_leads"),
            data=json.dumps(
                {
                    "full_name": "Public Student",
                    "phone": "+998901234567",
                    "course": "IELTS Academic",
                    "source": "instagram",
                    "utm_campaign": "summer-intake",
                    "social_handle": "@publicstudent",
                }
            ),
            content_type="application/json",
            HTTP_AUTHORIZATION="Bearer secret-token",
            HTTP_USER_AGENT="website-test-client",
            REMOTE_ADDR="127.0.0.5",
        )
        self.assertEqual(response.status_code, 201)
        lead = RegistrationLead.objects.get()
        self.assertEqual(lead.full_name, "Public Student")
        self.assertEqual(lead.phone, "+998901234567")
        self.assertEqual(lead.program, "IELTS Academic")
        self.assertEqual(lead.source, "instagram")
        self.assertEqual(lead.utm_campaign, "summer-intake")
        self.assertEqual(lead.social_handle, "@publicstudent")
        self.assertEqual(lead.user_agent, "website-test-client")

    @override_settings(**_BASE_OVERRIDES, REGISTRATION_LEADS_API_TOKEN="secret-token")
    def test_receiver_accepts_minimal_name_and_phone_payload(self):
        response = self.client.post(
            reverse("public_registration_leads"),
            data=json.dumps(
                {
                    "full_name": "Minimal Website Lead",
                    "phone": "+998901112233",
                }
            ),
            content_type="application/json",
            HTTP_AUTHORIZATION="Bearer secret-token",
        )
        self.assertEqual(response.status_code, 201)
        lead = RegistrationLead.objects.get()
        self.assertEqual(lead.full_name, "Minimal Website Lead")
        self.assertEqual(lead.phone, "+998901112233")
        self.assertEqual(lead.program, "")
        self.assertEqual(lead.email, "")
        self.assertEqual(lead.parent_phone, "")
        self.assertEqual(lead.source, "website")

    @override_settings(**_BASE_OVERRIDES, REGISTRATION_LEADS_API_TOKEN="secret-token")
    def test_receiver_accepts_optional_website_fields(self):
        response = self.client.post(
            reverse("public_registration_leads"),
            data=json.dumps(
                {
                    "full_name": "Optional Website Lead",
                    "phone": "+998901112244",
                    "course": "General English",
                    "date_of_birth": "",
                    "parent_phone": "+998909998877",
                    "email": "lead@example.com",
                    "branch": "Main",
                    "preferred_schedule": "Evening",
                    "social_source": "instagram",
                    "social_handle": "@optional",
                    "utm_source": "meta",
                    "utm_medium": "paid-social",
                    "utm_campaign": "summer-intake",
                    "message": "Please call after 5pm",
                    "submitted_at": "2026-06-05T12:00:00Z",
                }
            ),
            content_type="application/json",
            HTTP_AUTHORIZATION="Bearer secret-token",
        )
        self.assertEqual(response.status_code, 201)
        lead = RegistrationLead.objects.get()
        self.assertEqual(lead.program, "General English")
        self.assertEqual(lead.parent_phone, "+998909998877")
        self.assertEqual(lead.email, "lead@example.com")
        self.assertEqual(lead.branch, "Main")
        self.assertEqual(lead.preferred_schedule, "Evening")
        self.assertEqual(lead.source, "instagram")
        self.assertEqual(lead.social_handle, "@optional")
        self.assertEqual(lead.utm_source, "meta")
        self.assertEqual(lead.utm_medium, "paid-social")
        self.assertEqual(lead.utm_campaign, "summer-intake")
        self.assertEqual(lead.message, "Please call after 5pm")
        self.assertEqual(lead.raw_payload["date_of_birth"], "")
        self.assertEqual(lead.raw_payload["submitted_at"], "2026-06-05T12:00:00Z")

    @override_settings(**_BASE_OVERRIDES, REGISTRATION_LEADS_API_TOKEN="secret-token")
    def test_receiver_requires_name_and_phone_only(self):
        missing_name = self.client.post(
            reverse("public_registration_leads"),
            data=json.dumps({"phone": "+998901112233", "course": "Optional Course"}),
            content_type="application/json",
            HTTP_AUTHORIZATION="Bearer secret-token",
        )
        self.assertEqual(missing_name.status_code, 400)
        self.assertEqual(missing_name.json()["detail"], "full_name is required.")

        missing_phone = self.client.post(
            reverse("public_registration_leads"),
            data=json.dumps(
                {
                    "full_name": "No Phone Lead",
                    "email": "lead@example.com",
                    "parent_phone": "+998909998877",
                    "date_of_birth": "2010-01-02",
                }
            ),
            content_type="application/json",
            HTTP_AUTHORIZATION="Bearer secret-token",
        )
        self.assertEqual(missing_phone.status_code, 400)
        self.assertEqual(missing_phone.json()["detail"], "phone is required.")
        self.assertEqual(RegistrationLead.objects.count(), 0)

    @override_settings(**_BASE_OVERRIDES, REGISTRATION_LEADS_API_TOKEN="secret-token")
    def test_receiver_accepts_slashless_url_and_registration_token_header(self):
        response = self.client.post(
            "/public/registration-leads",
            data={
                "Full Name": "Website Form Student",
                "Phone Number": "+998977777777",
                "Course Name": "Speaking Club",
                "Preferred Time": "Evening",
            },
            HTTP_X_REGISTRATION_TOKEN="secret-token",
        )
        self.assertEqual(response.status_code, 201)
        lead = RegistrationLead.objects.get()
        self.assertEqual(lead.full_name, "Website Form Student")
        self.assertEqual(lead.phone, "+998977777777")
        self.assertEqual(lead.program, "Speaking Club")
        self.assertEqual(lead.preferred_schedule, "Evening")

    @override_settings(**_BASE_OVERRIDES, REGISTRATION_LEADS_API_TOKEN="secret-token")
    def test_receiver_accepts_text_plain_json_and_redacts_body_token(self):
        response = self.client.post(
            reverse("public_registration_leads"),
            data=json.dumps(
                {
                    "Name": "Loose Fetch Student",
                    "WhatsApp Number": "+998936666666",
                    "Selected Course": "General English",
                    "apiKey": "secret-token",
                }
            ),
            content_type="text/plain",
        )
        self.assertEqual(response.status_code, 201)
        lead = RegistrationLead.objects.get()
        self.assertEqual(lead.full_name, "Loose Fetch Student")
        self.assertEqual(lead.phone, "+998936666666")
        self.assertEqual(lead.program, "General English")
        self.assertEqual(lead.raw_payload["apiKey"], "[redacted]")

    @override_settings(**_BASE_OVERRIDES, REGISTRATION_LEADS_API_TOKEN="", DEBUG=True)
    def test_receiver_accepts_form_encoded_payload_when_token_not_configured(self):
        # Local development (DEBUG) only — production refuses, see the test below.
        response = self.client.post(
            reverse("public_registration_leads"),
            data={
                "first_name": "Form",
                "last_name": "Lead",
                "phone": "+998900000001",
                "parent_phone": "+998991111111",
                "program": "General English",
            },
        )
        self.assertEqual(response.status_code, 201)
        lead = RegistrationLead.objects.get()
        self.assertEqual(lead.full_name, "Form Lead")
        self.assertEqual(lead.phone, "+998900000001")
        self.assertEqual(lead.parent_phone, "+998991111111")
        self.assertEqual(lead.program, "General English")

    @override_settings(**_BASE_OVERRIDES, REGISTRATION_LEADS_API_TOKEN="", DEBUG=False)
    def test_receiver_refuses_leads_in_production_without_token(self):
        with self.assertLogs("main_app.public_views", level="ERROR"):
            response = self.client.post(
                reverse("public_registration_leads"),
                data={"full_name": "No Token", "phone": "+998900000002"},
            )
        self.assertEqual(response.status_code, 503)
        self.assertFalse(RegistrationLead.objects.exists())

    @override_settings(REGISTRATION_LEADS_API_TOKEN="", DEBUG=False)
    def test_deploy_check_warns_when_token_missing(self):
        from main_app.checks import check_registration_leads_token

        self.assertEqual([w.id for w in check_registration_leads_token(None)], ["main_app.W002"])
        with override_settings(REGISTRATION_LEADS_API_TOKEN="set"):
            self.assertEqual(check_registration_leads_token(None), [])

    @override_settings(**_BASE_OVERRIDES)
    def test_admin_can_view_registration_leads(self):
        UserModel = get_user_model()
        admin = UserModel.objects.create_user(
            email="lead-admin@example.com",
            password="AdminPass123!",
            first_name="Lead",
            last_name="Admin",
            user_type="1",
            gender="M",
            address="",
            profile_pic="",
        )
        RegistrationLead.objects.create(
            full_name="Dashboard Lead",
            phone="+998900000000",
            program="Speaking",
            source="facebook",
        )
        self.client.force_login(admin)
        response = self.client.get(reverse("manage_registration_leads"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Dashboard Lead")
        self.assertContains(response, "facebook")
