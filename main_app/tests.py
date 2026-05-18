import re
from datetime import date
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core import mail
from django.test import TestCase, Client, override_settings
from django.urls import reverse

from main_app.hod_views import _generate_login_id
from main_app.models import (
    Course, Group, Student, Staff, Enrollment, Assignment,
    Attendance, AttendanceReport,
)


_BASE_OVERRIDES = dict(
    EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend',
    # Disable SSL redirect so the test client (HTTP) reaches views without
    # being bounced to HTTPS (which then strips POST bodies on 301 redirect).
    SECURE_SSL_REDIRECT=False,
)


class LoginPageTests(TestCase):
    def setUp(self):
        UserModel = get_user_model()
        self.admin = UserModel.objects.create_user(
            email='admin@example.com',
            password='AdminPass123!',
            first_name='Test',
            last_name='Admin',
            user_type='1',
            gender='M',
            address='Test',
            profile_pic='',
        )
        self.staff = UserModel.objects.create_user(
            email='staff@example.com',
            password='StaffPass123!',
            first_name='Test',
            last_name='Staff',
            user_type='2',
            gender='M',
            address='Test',
            profile_pic='',
            login_id='TC500',
        )
        self.student = UserModel.objects.create_user(
            email='student@example.com',
            password='StudentPass123!',
            first_name='Test',
            last_name='Student',
            user_type='3',
            gender='M',
            address='Test',
            profile_pic='',
            login_id='IC1000',
        )

    @override_settings(**_BASE_OVERRIDES)
    def test_login_page_get_returns_200(self):
        response = self.client.get(reverse('login_page'))
        self.assertEqual(response.status_code, 200)

    @override_settings(**_BASE_OVERRIDES)
    def test_login_invalid_credentials_shows_error(self):
        response = self.client.post(reverse('user_login'), {
            'email': 'nobody@example.com',
            'password': 'wrongpassword',
        }, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'not found', response.content)

    @override_settings(**_BASE_OVERRIDES)
    def test_admin_login_redirects_to_admin_home(self):
        response = self.client.post(reverse('user_login'), {
            'identifier': 'admin@example.com',
            'password': 'AdminPass123!',
        })
        self.assertRedirects(response, reverse('admin_home'), fetch_redirect_response=False)

    @override_settings(**_BASE_OVERRIDES)
    def test_staff_login_redirects_to_staff_home(self):
        response = self.client.post(reverse('user_login'), {
            'identifier': 'TC500',
            'password': 'StaffPass123!',
        })
        self.assertRedirects(response, reverse('staff_home'), fetch_redirect_response=False)

    @override_settings(**_BASE_OVERRIDES)
    def test_student_login_redirects_to_student_home(self):
        response = self.client.post(reverse('user_login'), {
            'identifier': 'IC1000',
            'password': 'StudentPass123!',
        })
        self.assertRedirects(response, reverse('student_home'), fetch_redirect_response=False)

    @override_settings(**_BASE_OVERRIDES)
    def test_no_role_confusion_admin_cannot_reach_student_home(self):
        # force_login bypasses auth backends (avoids axes request requirement).
        # We only need to test role-based routing here, not authentication.
        self.client.force_login(self.admin)
        response = self.client.get(reverse('student_home'))
        # Admin should be redirected away from student pages.
        self.assertNotEqual(response.status_code, 200)

    @override_settings(**_BASE_OVERRIDES)
    def test_unauthenticated_blocked_from_admin_home(self):
        response = self.client.get(reverse('admin_home'))
        self.assertNotEqual(response.status_code, 200)


class PasswordResetFlowTests(TestCase):
    @override_settings(**_BASE_OVERRIDES)
    def test_password_reset_end_to_end(self):
        user_model = get_user_model()
        user = user_model.objects.create_user(
            email='reset-flow@example.com',
            password='InitialPass123!',
            first_name='Reset',
            last_name='Flow',
            user_type='1',
            gender='M',
            address='Test Address',
            profile_pic='',
        )

        response = self.client.post('/accounts/password_reset/', {'email': user.email}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(mail.outbox), 1)

        body = mail.outbox[0].body
        match = re.search(r'https?://[^\s]+/accounts/reset/[^\s]+', body)
        self.assertIsNotNone(match)

        token_path = '/' + match.group(0).split('/', 3)[3]
        confirm_get_response = self.client.get(token_path, follow=True)
        final_path = confirm_get_response.wsgi_request.path

        new_password = 'ChangedPass123!'
        confirm_post_response = self.client.post(
            final_path,
            {'new_password1': new_password, 'new_password2': new_password},
            follow=True,
        )

        self.assertEqual(confirm_post_response.status_code, 200)
        user.refresh_from_db()
        self.assertTrue(user.check_password(new_password))


class LoginIdGeneratorTests(TestCase):
    """Birthday-based login_id generator: IC052401 etc."""

    def _make_user(self, login_id, dob=None, email=None, user_type='3'):
        UserModel = get_user_model()
        return UserModel.objects.create_user(
            email=email or f'{login_id.lower()}@iceberg.internal',
            password='x',
            first_name='X', last_name='Y',
            user_type=user_type,
            gender='M', address='', profile_pic='',
            login_id=login_id,
            date_of_birth=dob,
        )

    def test_student_id_encodes_birthday(self):
        lid = _generate_login_id('IC', date(2010, 5, 24))
        self.assertEqual(lid, 'IC052401')

    def test_teacher_id_encodes_birthday(self):
        lid = _generate_login_id('TC', date(1985, 2, 12))
        self.assertEqual(lid, 'TC021201')

    def test_suffix_increments_on_collision(self):
        dob = date(2009, 7, 7)
        self._make_user('IC070701', dob=dob)
        self._make_user('IC070702', dob=dob)
        self.assertEqual(_generate_login_id('IC', dob), 'IC070703')

    def test_pads_month_and_day(self):
        # January 5 should be 0105, not 15.
        self.assertEqual(_generate_login_id('IC', date(2000, 1, 5)), 'IC010501')

    def test_fallback_when_no_birthday(self):
        # Without DOB, falls back to sequential.
        lid = _generate_login_id('IC')
        self.assertTrue(lid.startswith('IC'))
        self.assertGreaterEqual(int(lid[2:]), 1000)

    def test_legacy_ids_do_not_collide(self):
        # Legacy formats (IC00005, IC1000, STU-0001) coexist with new format.
        self._make_user('IC00005')
        self._make_user('IC1000', email='legacy2@iceberg.internal')
        self._make_user('STU-0001', email='legacy3@iceberg.internal')
        new = _generate_login_id('IC', date(2012, 3, 15))
        self.assertEqual(new, 'IC031501')


class LoginFlowResilienceTests(TestCase):
    def setUp(self):
        self.user_model = get_user_model()
        self.user = self.user_model.objects.create_user(
            email='admin-login@example.com', password='AdminPass123!',
            first_name='Admin', last_name='User', user_type='1',
            gender='M', address='Admin Address', profile_pic='',
        )

    @override_settings(SECURE_SSL_REDIRECT=False)
    @patch('main_app.views.login', side_effect=Exception('session backend unavailable'))
    def test_login_failure_is_handled_without_500(self, _mock_login):
        response = self.client.post(
            '/doLogin/',
            {'email': self.user.email, 'password': 'AdminPass123!'},
            follow=False,
        )
        self.assertEqual(response.status_code, 302)
        # doLogin redirects to reverse('login_page') == '/login/' on failure.
        self.assertEqual(response['Location'], '/login/')


class StudentPrivacyTests(TestCase):
    """Students must not be able to access other students' group data."""

    def _make_user(self, email, user_type, login_id=None, dob=None):
        UserModel = get_user_model()
        return UserModel.objects.create_user(
            email=email, password='Pass123!',
            first_name='T', last_name='U', user_type=user_type,
            gender='M', address='', profile_pic='',
            login_id=login_id, date_of_birth=dob,
        )

    def setUp(self):
        self.course = Course.objects.create(name='General English')

        # Two separate teachers
        teacher_a_user = self._make_user('ta@iceberg.internal', '2', 'TC50001')
        teacher_b_user = self._make_user('tb@iceberg.internal', '2', 'TC50002')
        self.teacher_a = Staff.objects.get(admin=teacher_a_user)
        self.teacher_b = Staff.objects.get(admin=teacher_b_user)

        # Two separate groups
        self.group_a = Group.objects.create(name='Group A', course=self.course, teacher=self.teacher_a)
        self.group_b = Group.objects.create(name='Group B', course=self.course, teacher=self.teacher_b)

        # Student A → Group A only
        student_a_user = self._make_user('ic10001@iceberg.internal', '3', 'IC10001', date(2005, 5, 1))
        self.student_a = Student.objects.get(admin=student_a_user)
        self.student_a.course = self.course
        self.student_a.save()
        Enrollment.objects.create(student=self.student_a, group=self.group_a, is_active=True)

        # Student B → Group B only
        student_b_user = self._make_user('ic10002@iceberg.internal', '3', 'IC10002', date(2005, 6, 1))
        self.student_b = Student.objects.get(admin=student_b_user)
        self.student_b.course = self.course
        self.student_b.save()
        Enrollment.objects.create(student=self.student_b, group=self.group_b, is_active=True)

    @override_settings(SECURE_SSL_REDIRECT=False)
    def test_attendance_ajax_blocks_cross_group_access(self):
        """Student A cannot query attendance for Group B via the AJAX endpoint."""
        self.client.force_login(self.student_a.admin)
        response = self.client.post(
            reverse('student_view_attendance'),
            {
                'group': str(self.group_b.id),
                'start_date': '2026-01-01',
                'end_date': '2026-12-31',
            },
        )
        self.assertEqual(response.status_code, 403)

    @override_settings(SECURE_SSL_REDIRECT=False)
    def test_attendance_ajax_allows_own_group(self):
        """Student A can query attendance for Group A."""
        self.client.force_login(self.student_a.admin)
        response = self.client.post(
            reverse('student_view_attendance'),
            {
                'group': str(self.group_a.id),
                'start_date': '2026-01-01',
                'end_date': '2026-12-31',
            },
        )
        self.assertEqual(response.status_code, 200)

    @override_settings(SECURE_SSL_REDIRECT=False)
    def test_submit_assignment_blocks_cross_group(self):
        """Student A cannot submit an assignment belonging to Group B."""
        assignment = Assignment.objects.create(
            title='Test', group=self.group_b, due_date=date(2026, 12, 31),
            created_by=self.teacher_b,
        )
        self.client.force_login(self.student_a.admin)
        response = self.client.post(
            reverse('submit_assignment', args=[assignment.id]),
            {'note': 'hacked'},
        )
        self.assertEqual(response.status_code, 403)

    @override_settings(SECURE_SSL_REDIRECT=False)
    def test_student_b_cannot_access_student_home_as_student_a(self):
        """Student B logged in sees their own dashboard, not Student A's."""
        self.client.force_login(self.student_b.admin)
        response = self.client.get(reverse('student_home'))
        self.assertEqual(response.status_code, 200)
        # Student B should NOT see Group A's name in their dashboard
        self.assertNotIn(b'Group A', response.content)
