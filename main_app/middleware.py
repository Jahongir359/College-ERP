from django.contrib.auth import logout
from django.http import JsonResponse
from django.utils.deprecation import MiddlewareMixin
from django.urls import reverse
from django.shortcuts import redirect
from django.db.utils import OperationalError, ProgrammingError


class LoginCheckMiddleWare(MiddlewareMixin):
    def process_view(self, request, view_func, view_args, view_kwargs):
        # API paths use JWT authentication — let DRF handle auth/permission.
        if request.path.startswith('/api/'):
            return None

        modulename = view_func.__module__

        auth_allowed_paths = {
            reverse('login_page'),
            reverse('user_login'),
            reverse('user_logout'),
        }

        try:
            user = request.user
            user_type = str(getattr(user, 'user_type', ''))
        except (OperationalError, ProgrammingError):
            # DB tables not yet initialised (first deploy, pre-migrate).
            # Let auth and admin pages through so the site can bootstrap.
            if (
                request.path in auth_allowed_paths
                or modulename.startswith('django.contrib.auth')
                or request.path.startswith('/admin/')
            ):
                return None
            return redirect(reverse('login_page'))

        if user.is_authenticated:
            if user_type == '1':  # HOD / Admin
                if modulename in ('main_app.student_views', 'main_app.staff_views'):
                    return redirect(reverse('admin_home'))

            elif user_type == '2':  # Staff
                if modulename in ('main_app.student_views', 'main_app.hod_views'):
                    return redirect(reverse('staff_home'))

            elif user_type == '3':  # Student
                if modulename in ('main_app.hod_views', 'main_app.staff_views'):
                    return redirect(reverse('student_home'))

            else:
                # Unknown/corrupt user_type: log out and redirect to login.
                if request.path not in auth_allowed_paths:
                    logout(request)
                    return redirect(reverse('login_page'))

        else:
            if (
                request.path in auth_allowed_paths
                or modulename.startswith('django.contrib.auth')
                or request.path.startswith('/accounts/')
                or request.path.startswith('/admin/')
                or request.path == '/health/'
                # FCM service worker — browsers fetch this before login.
                or request.path == '/firebase-messaging-sw.js'
                # Custom code-based password recovery flow.
                or modulename == 'main_app.password_recovery'
                or request.path.startswith('/forgot-password')
                or request.path.startswith('/verify-reset-code')
                or request.path.startswith('/reset-password')
                or request.path.startswith('/password-reset-success')
            ):
                pass
            else:
                return redirect(reverse('login_page'))
