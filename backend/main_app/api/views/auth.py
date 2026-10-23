from django.contrib.auth import authenticate
from django.core.exceptions import PermissionDenied as DjangoPermissionDenied
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken

from ...models import Student
from ..serializers import ChangePasswordSerializer, FcmTokenSerializer, MeSerializer


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------


class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        # Accept either `email` or `login_id` in the identifier field.
        # The mobile app sends `identifier`; the web API sends `email`.
        identifier = (
            request.data.get("identifier")
            or request.data.get("email")
            or request.data.get("login_id")
            or ""
        ).strip()
        password = request.data.get("password", "")

        if not identifier or not password:
            return Response(
                {"detail": "Identifier (email or login ID) and password are required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Pass the identifier directly — EmailBackend handles both email (admin)
        # and login_id (staff/student) lookup internally.
        try:
            user = authenticate(request=request, username=identifier, password=password)
        except DjangoPermissionDenied:
            return Response(
                {"detail": "Account temporarily locked. Try again later."},
                status=status.HTTP_403_FORBIDDEN,
            )

        if user is None:
            return Response(
                {"detail": "Invalid credentials."},
                status=status.HTTP_401_UNAUTHORIZED,
            )
        if not user.is_active:
            return Response(
                {"detail": "Account is disabled."},
                status=status.HTTP_403_FORBIDDEN,
            )

        refresh = RefreshToken.for_user(user)
        return Response(
            {
                "access": str(refresh.access_token),
                "refresh": str(refresh),
                # MeSerializer includes role_profile (is_super_admin,
                # branch_ids…) which clients need for role-based routing.
                "user": MeSerializer(user, context={"request": request}).data,
            }
        )


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        refresh_token = request.data.get("refresh")
        if not refresh_token:
            return Response(
                {"detail": "Refresh token required."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            RefreshToken(refresh_token).blacklist()
        except TokenError:
            return Response(
                {"detail": "Invalid or expired token."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        return Response({"detail": "Logged out successfully."})


# ---------------------------------------------------------------------------
# Profile
# ---------------------------------------------------------------------------


class MeView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response(MeSerializer(request.user, context={"request": request}).data)

    def patch(self, request):
        user = request.user
        # Profile picture arrives as a file upload (multipart).
        if "profile_pic" in request.FILES:
            user.profile_pic = request.FILES["profile_pic"]
        serializer = MeSerializer(
            user, data=request.data, partial=True, context={"request": request}
        )
        if serializer.is_valid():
            serializer.save()
            # Phone lives on the role profile, not CustomUser.
            if "phone" in request.data and str(user.user_type) == "3":
                try:
                    student = user.student
                    student.phone = str(request.data["phone"])[:20]
                    student.save(update_fields=["phone"])
                except Student.DoesNotExist:
                    pass
            return Response(MeSerializer(user, context={"request": request}).data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data, context={"request": request})
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        user = request.user
        if not user.check_password(serializer.validated_data["old_password"]):
            return Response(
                {"old_password": "Incorrect password."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        user.set_password(serializer.validated_data["new_password"])
        user.save()
        return Response({"detail": "Password changed successfully."})


class FcmTokenView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = FcmTokenSerializer(data=request.data)
        if serializer.is_valid():
            request.user.fcm_token = serializer.validated_data["token"]
            request.user.save(update_fields=["fcm_token"])
            return Response({"detail": "FCM token updated."})
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
