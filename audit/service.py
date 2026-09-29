from django.db import connection, transaction
from django.utils import timezone

from .models import AuditLog

GENESIS_HASH = "0" * 64
# Keys that must never end up in the audit log, even by accident.
FORBIDDEN_METADATA_KEYS = {
    "password", "auth_hash", "ciphertext", "iv", "wrapped_key", "signature",
    "protected_vault_key", "private_key", "token", "refresh", "access",
}


def client_ip(request):
    # Only trust REMOTE_ADDR; X-Forwarded-For is attacker-controlled unless a trusted
    # proxy rewrites it (configure that at the proxy, not here).
    return request.META.get("REMOTE_ADDR") if request is not None else None


def log_event(request, event, *, user=None, username="", success=True, target=None, metadata=None):
    metadata = {k: v for k, v in (metadata or {}).items() if k not in FORBIDDEN_METADATA_KEYS}
    if user is None and request is not None and getattr(request, "user", None) is not None:
        if request.user.is_authenticated:
            user = request.user
    with transaction.atomic():
        if connection.vendor == "postgresql":
            # Serialize writers so two concurrent events can't both chain off the same row.
            with connection.cursor() as cursor:
                cursor.execute("LOCK TABLE audit_auditlog IN EXCLUSIVE MODE")
        last = AuditLog.objects.order_by("-id").first()
        entry = AuditLog(
            timestamp=timezone.now(),
            actor=user,
            actor_username=(user.username if user else username)[:64],
            event=event,
            success=success,
            ip_address=client_ip(request),
            user_agent=(request.META.get("HTTP_USER_AGENT", "") if request is not None else "")[:256],
            target_type=type(target).__name__ if target is not None else "",
            target_id=str(getattr(target, "pk", "") or "") if target is not None else "",
            metadata=metadata,
            prev_hash=last.entry_hash if last else GENESIS_HASH,
        )
        entry.entry_hash = entry.compute_hash()
        entry.save()
    return entry


def verify_chain():
    """Return (ok, first_bad_id, checked_count)."""
    prev = GENESIS_HASH
    count = 0
    for entry in AuditLog.objects.order_by("id").iterator():
        count += 1
        if entry.prev_hash != prev or entry.compute_hash() != entry.entry_hash:
            return False, entry.id, count
        prev = entry.entry_hash
    return True, None, count
