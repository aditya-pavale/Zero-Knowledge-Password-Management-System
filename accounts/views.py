import base64
import hashlib
import hmac
from datetime import timedelta

from django.conf import settings
from django.contrib.auth import authenticate
from django.db import transaction
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import generics, status
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken, OutstandingToken
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenRefreshView

from audit.models import AuditLog
from audit.service import log_event

from .models import User
from .permissions import IsAdminRole
from .serializers import (
    AdminUserSerializer,
    ChangeMasterPasswordSerializer,
    LoginSerializer,
    PreloginSerializer,
    ProfileSerializer,
    PublicKeysSerializer,
    RegisterSerializer,
    default_kdf_params,
)

LOCKOUT_THRESHOLD = 10
LOCKOUT_WINDOW = timedelta(minutes=15)


def _revoke_all_refresh_tokens(user):
    """Log out every other session (used when the master password changes)."""
    for token in OutstandingToken.objects.filter(user=user).exclude(blacklistedtoken__isnull=False):
        BlacklistedToken.objects.get_or_create(token=token)


def _tokens_for(user):
    refresh = RefreshToken.for_user(user)
    refresh["role"] = user.role
    return {"refresh": str(refresh), "access": str(refresh.access_token)}


class PreloginView(APIView):
    """Return the Argon2id salt/parameters the client needs to derive its keys.

    Unknown usernames get a deterministic fake salt so this endpoint can't be used
    to enumerate accounts.
    """

    permission_classes = [AllowAny]
    authentication_classes = []
    throttle_scope = "auth"

    def post(self, request):
        serializer = PreloginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        username = serializer.validated_data["username"]
        user = User.objects.filter(username=username).first()
        if user and user.kdf_salt:
            return Response(
                {
                    "kdf_algorithm": "argon2id",
                    "kdf_salt": user.kdf_salt,
                    "kdf_memory_kib": user.kdf_memory_kib,
                    "kdf_iterations": user.kdf_iterations,
                    "kdf_parallelism": user.kdf_parallelism,
                }
            )
        fake = hmac.new(settings.SECRET_KEY.encode(), f"prelogin:{username}".encode(), hashlib.sha256).digest()[:16]
        return Response({"kdf_algorithm": "argon2id", "kdf_salt": base64.b64encode(fake).decode(), **default_kdf_params()})


class KdfDefaultsView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []

    def get(self, request):
        return Response({"kdf_algorithm": "argon2id", **default_kdf_params()})


class RegisterView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []
    throttle_scope = "auth"

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        log_event(request, AuditLog.Event.REGISTER, user=user, target=user)
        return Response(
            {"user": ProfileSerializer(user).data, "tokens": _tokens_for(user)},
            status=status.HTTP_201_CREATED,
        )


class LoginView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []
    throttle_scope = "auth"

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        username = serializer.validated_data["username"]

        recent_failures = AuditLog.objects.filter(
            event=AuditLog.Event.LOGIN_FAILED,
            actor_username=username[:64],
            timestamp__gte=timezone.now() - LOCKOUT_WINDOW,
        ).count()
        if recent_failures >= LOCKOUT_THRESHOLD:
            log_event(request, AuditLog.Event.LOGIN_LOCKED, username=username, success=False)
            return Response(
                {"detail": "Too many failed attempts. Try again later."},
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )

        user = authenticate(request, username=username, password=serializer.validated_data["auth_hash"])
        if user is None:
            # Link the failure to the account (if it exists) so its owner sees it in "My activity".
            # The response is identical either way, so this reveals nothing to the caller.
            target = User.objects.filter(username=username).first()
            log_event(request, AuditLog.Event.LOGIN_FAILED, user=target, username=username, success=False)
            return Response({"detail": "Invalid username or master password."}, status=status.HTTP_401_UNAUTHORIZED)

        log_event(request, AuditLog.Event.LOGIN_SUCCESS, user=user)
        return Response({"user": ProfileSerializer(user).data, "tokens": _tokens_for(user)})


class RefreshView(TokenRefreshView):
    throttle_scope = "auth"


class LogoutView(APIView):
    def post(self, request):
        refresh = request.data.get("refresh")
        if refresh:
            try:
                token = RefreshToken(refresh)
                if str(token.get("user_id")) == str(request.user.pk):
                    token.blacklist()
            except TokenError:
                pass
        log_event(request, AuditLog.Event.LOGOUT)
        return Response(status=status.HTTP_204_NO_CONTENT)


class MeView(APIView):
    def get(self, request):
        return Response(ProfileSerializer(request.user).data)


class ChangeMasterPasswordView(APIView):
    throttle_scope = "auth"

    def post(self, request):
        serializer = ChangeMasterPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        user = request.user
        if not user.check_password(data["current_auth_hash"]):
            log_event(request, AuditLog.Event.PASSWORD_CHANGE, success=False)
            return Response({"detail": "Current master password is incorrect."}, status=status.HTTP_400_BAD_REQUEST)
        with transaction.atomic():
            user.set_password(data["new_auth_hash"])
            user.kdf_salt = data["kdf_salt"]
            user.kdf_memory_kib = data["kdf_memory_kib"]
            user.kdf_iterations = data["kdf_iterations"]
            user.kdf_parallelism = data["kdf_parallelism"]
            user.protected_vault_key = data["protected_vault_key"]
            user.save()
            _revoke_all_refresh_tokens(user)
        log_event(request, AuditLog.Event.PASSWORD_CHANGE)
        return Response({"user": ProfileSerializer(user).data, "tokens": _tokens_for(user)})


class PublicKeysView(generics.RetrieveAPIView):
    """Look up another user's public keys (needed to share with them)."""

    serializer_class = PublicKeysSerializer

    def get_object(self):
        return get_object_or_404(
            User.objects.filter(is_active=True).exclude(encryption_public_key=""),
            username=self.kwargs["username"],
        )


class AdminUserListView(generics.ListAPIView):
    serializer_class = AdminUserSerializer
    permission_classes = [IsAdminRole]
    queryset = User.objects.order_by("username")


class AdminUserDetailView(generics.RetrieveUpdateAPIView):
    """Admins can change role / active status. They can never see vault contents."""

    serializer_class = AdminUserSerializer
    permission_classes = [IsAdminRole]
    queryset = User.objects.all()
    http_method_names = ["get", "patch"]

    def perform_update(self, serializer):
        target = serializer.instance
        old_role, old_active = target.role, target.is_active
        if target.pk == self.request.user.pk and (
            serializer.validated_data.get("role", old_role) != old_role
            or serializer.validated_data.get("is_active", old_active) is False
        ):
            raise ValidationError("Admins cannot demote or deactivate themselves.")
        user = serializer.save()
        if user.role != old_role:
            log_event(
                self.request, AuditLog.Event.ROLE_CHANGE, target=user,
                metadata={"username": user.username, "from": old_role, "to": user.role},
            )
        if user.is_active != old_active:
            log_event(
                self.request, AuditLog.Event.USER_STATUS_CHANGE, target=user,
                metadata={"username": user.username, "is_active": user.is_active},
            )
