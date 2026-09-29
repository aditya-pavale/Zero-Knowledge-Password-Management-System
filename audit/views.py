from rest_framework import generics
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.permissions import IsAuditorOrAdmin

from .models import AuditLog
from .serializers import AuditLogSerializer
from .service import verify_chain


class AuditLogListView(generics.ListAPIView):
    """All events (auditor/admin only). Filters: ?event=...&username=...&success=true|false"""

    serializer_class = AuditLogSerializer
    permission_classes = [IsAuditorOrAdmin]

    def get_queryset(self):
        qs = AuditLog.objects.all()
        params = self.request.query_params
        if params.get("event"):
            qs = qs.filter(event=params["event"])
        if params.get("username"):
            qs = qs.filter(actor_username=params["username"])
        if params.get("success") in ("true", "false"):
            qs = qs.filter(success=params["success"] == "true")
        return qs


class MyAuditLogView(generics.ListAPIView):
    """A user's own security activity (logins, shares, ...)."""

    serializer_class = AuditLogSerializer

    def get_queryset(self):
        return AuditLog.objects.filter(actor=self.request.user)


class VerifyChainView(APIView):
    permission_classes = [IsAuditorOrAdmin]

    def get(self, request):
        ok, bad_id, count = verify_chain()
        return Response({"intact": ok, "first_tampered_id": bad_id, "entries_checked": count})
