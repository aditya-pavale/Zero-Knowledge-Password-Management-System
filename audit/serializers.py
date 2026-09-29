from rest_framework import serializers

from .models import AuditLog


class AuditLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = AuditLog
        fields = [
            "id", "timestamp", "actor_username", "event", "success", "ip_address",
            "user_agent", "target_type", "target_id", "metadata", "entry_hash",
        ]
        read_only_fields = fields
