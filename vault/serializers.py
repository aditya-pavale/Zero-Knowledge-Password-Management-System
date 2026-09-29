from rest_framework import serializers

from vault_project.cryptoutils import AES_GCM_IV_BYTES, AES_GCM_TAG_BYTES, CryptoValidationError, b64decode_strict

from .models import VaultItem

MAX_ITEM_BYTES = 64 * 1024


def validate_iv(value):
    try:
        b64decode_strict(value, field="iv", exact=AES_GCM_IV_BYTES)
    except CryptoValidationError as exc:
        raise serializers.ValidationError(str(exc)) from exc
    return value


def validate_ciphertext(value):
    try:
        b64decode_strict(value, field="ciphertext", min_len=AES_GCM_TAG_BYTES + 1, max_len=MAX_ITEM_BYTES)
    except CryptoValidationError as exc:
        raise serializers.ValidationError(str(exc)) from exc
    return value


class VaultItemSerializer(serializers.ModelSerializer):
    iv = serializers.CharField(max_length=24, validators=[validate_iv])
    ciphertext = serializers.CharField(max_length=MAX_ITEM_BYTES * 2, validators=[validate_ciphertext])

    class Meta:
        model = VaultItem
        fields = ["id", "iv", "ciphertext", "version", "created_at", "updated_at"]
        read_only_fields = ["id", "version", "created_at", "updated_at"]
