import hashlib
import json

from django.conf import settings
from django.db import models


class AuditLog(models.Model):
    """Append-only, hash-chained security event log.

    Each entry stores sha256(previous_hash + canonical entry), so editing or deleting
    a row directly in the database breaks the chain and is detected by verify_chain().
    Entries never contain secrets, ciphertext or key material.
    """

    class Event(models.TextChoices):
        REGISTER = "register"
        LOGIN_SUCCESS = "login_success"
        LOGIN_FAILED = "login_failed"
        LOGIN_LOCKED = "login_locked"
        LOGOUT = "logout"
        PASSWORD_CHANGE = "password_change"  # event name, not a secret  # nosec B105
        VAULT_CREATE = "vault_create"
        VAULT_UPDATE = "vault_update"
        VAULT_DELETE = "vault_delete"
        SHARE_CREATE = "share_create"
        SHARE_REJECTED_SIGNATURE = "share_rejected_signature"
        SHARE_ACCEPT = "share_accept"
        SHARE_DELETE = "share_delete"
        ROLE_CHANGE = "role_change"
        USER_STATUS_CHANGE = "user_status_change"
        ACCESS_DENIED = "access_denied"
        ANALYZER_RUN = "analyzer_run"

    timestamp = models.DateTimeField(db_index=True)
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL)
    actor_username = models.CharField(max_length=64, blank=True, db_index=True)
    event = models.CharField(max_length=40, choices=Event.choices, db_index=True)
    success = models.BooleanField(default=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=256, blank=True)
    target_type = models.CharField(max_length=40, blank=True)
    target_id = models.CharField(max_length=64, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    prev_hash = models.CharField(max_length=64)
    entry_hash = models.CharField(max_length=64, unique=True)

    class Meta:
        ordering = ["-id"]

    def canonical(self):
        return json.dumps(
            {
                "timestamp": self.timestamp.isoformat(),
                "actor_username": self.actor_username,
                "event": self.event,
                "success": self.success,
                "ip_address": self.ip_address,
                "user_agent": self.user_agent,
                "target_type": self.target_type,
                "target_id": self.target_id,
                "metadata": self.metadata,
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    def compute_hash(self):
        return hashlib.sha256((self.prev_hash + self.canonical()).encode("utf-8")).hexdigest()

    def save(self, *args, **kwargs):
        if self.pk is not None:
            raise PermissionError("Audit log entries are immutable")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise PermissionError("Audit log entries cannot be deleted")

    def __str__(self):
        return f"{self.timestamp:%Y-%m-%d %H:%M:%S} {self.actor_username or '-'} {self.event}"
