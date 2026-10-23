from functools import wraps
from django.shortcuts import redirect
from django.urls import reverse


def _role_required(required_type):
    """
    Factory that returns a decorator enforcing a single user_type.
    Unauthenticated users are sent to the login page.
    Authenticated users with a different role are sent to their own home page.
    """

    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return redirect("/")

            user_type = str(request.user.user_type)

            if user_type == required_type:
                return view_func(request, *args, **kwargs)

            # Wrong role — bounce to the correct home instead of 403/404.
            if user_type == "1":
                return redirect(reverse("admin_home"))
            if user_type == "2":
                return redirect(reverse("staff_home"))
            if user_type == "3":
                return redirect(reverse("student_home"))

            # Unknown type: force logout.
            from django.contrib.auth import logout

            logout(request)
            return redirect("/")

        return wrapper

    return decorator


admin_only = _role_required("1")
staff_only = _role_required("2")
student_only = _role_required("3")


def super_admin_only(view_func):
    """Admin view restricted to super admins.

    Courses, subjects, sessions and leaderboard settings are shared by every
    branch, so a branch admin editing them would change other branches' data.
    Branch admins are bounced back with a message instead of a 403 page.
    """

    @admin_only
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        from django.contrib import messages

        from . import branching

        if not branching.is_super_admin(request.user):
            messages.error(request, "Only a super admin can change shared settings.")
            return redirect(reverse("admin_home"))
        return view_func(request, *args, **kwargs)

    return wrapper
