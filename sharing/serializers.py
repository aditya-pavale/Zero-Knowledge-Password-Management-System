from rest_framework import serializers

from accounts.models import User
from vault.serializers import validate_ciphertext, validate_iv
from vault_project.cryptoutils import CryptoValidationError, b64decode_strict, fingerprint

from .models import SharedItem


def _validate_b64(field, **limits):
    def run(value):
        try:
            b64decode_strict(value, field=field, **limits)
        except CryptoValidationError as exc:
            raise serializers.ValidationError(str(exc)) from exc
        return value

    return run


class CreateShareSerializer(serializers.Serializer):
    recipient = serializers.CharField(max_length=64)
    iv = serializers.CharField(max_length=24, validators=[validate_iv])
    ciphertext = serializers.CharField(max_length=128 * 1024, validators=[validate_ciphertext])
    wrapped_key = serializers.CharField(max_length=2048, validators=[_validate_b64("wrapped_key", min_len=256, max_len=1024)])
    signature = serializers.CharField(max_length=2048, validators=[_validate_b64("signature", min_len=256, max_len=1024)])

    def validate_recipient(self, value):
        user = User.objects.filter(username=value, is_active=True).exclude(encryption_public_key="").first()
        if user is None:
            raise serializers.ValidationError("Recipient not found.")
        if user == self.context["request"].user:
            raise serializers.ValidationError("You cannot share with yourself.")
        return user


class SharedItemSerializer(serializers.ModelSerializer):
    sender = serializers.CharField(source="sender.username", read_only=True)
    recipient = serializers.CharField(source="recipient.username", read_only=True)
    sender_signing_key_fingerprint = serializers.SerializerMethodField()

    class Meta:
        model = SharedItem
        fields = [
            "id", "sender", "recipient", "iv", "ciphertext", "wrapped_key", "signature",
            "sender_signing_public_key", "sender_signing_key_fingerprint",
            "status", "created_at", "accepted_at",
        ]
        read_only_fields = fields

    def get_sender_signing_key_fingerprint(self, obj):
        return fingerprint(obj.sender_signing_public_key)


class OutboxShareSerializer(serializers.ModelSerializer):
    """Senders only need metadata about what they sent (they can't decrypt it anyway)."""

    recipient = serializers.CharField(source="recipient.username", read_only=True)

    class Meta:
        model = SharedItem
        fields = ["id", "recipient", "status", "created_at", "accepted_at"]
        read_only_fields = fields
