from django.db.models import F
from rest_framework import viewsets

from audit.models import AuditLog
from audit.service import log_event

from .models import VaultItem
from .serializers import VaultItemSerializer


class VaultItemViewSet(viewsets.ModelViewSet):
    """CRUD on the caller's own encrypted items.

    The queryset is always scoped to request.user, so another user's item id simply
    returns 404 (no IDOR, and no hint that the id exists).
    """

    serializer_class = VaultItemSerializer
    http_method_names = ["get", "post", "put", "delete"]

    def get_queryset(self):
        return VaultItem.objects.filter(owner=self.request.user)

    def perform_create(self, serializer):
        item = serializer.save(owner=self.request.user)
        log_event(self.request, AuditLog.Event.VAULT_CREATE, target=item)

    def perform_update(self, serializer):
        item = serializer.save(version=F("version") + 1)
        item.refresh_from_db()
        log_event(self.request, AuditLog.Event.VAULT_UPDATE, target=item, metadata={"version": item.version})

    def perform_destroy(self, instance):
        log_event(self.request, AuditLog.Event.VAULT_DELETE, target=instance)
        instance.delete()
