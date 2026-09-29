from django.conf import settings
from rest_framework import serializers

from vault_project.cryptoutils import (
    CryptoValidationError,
    b64decode_strict,
    fingerprint,
    load_rsa_public_key,
    validate_envelope,
)

from .models import USERNAME_VALIDATOR, User

AUTH_HASH_BYTES = 32
SALT_BYTES = 16
PRIVATE_KEY_ENVELOPE_MAX = 4096

# Lower bounds follow the OWASP Password Storage Cheat Sheet for Argon2id.
MIN_KDF_MEMORY_KIB = 19456
MAX_KDF_MEMORY_KIB = 1048576
MIN_KDF_ITERATIONS = 2
MAX_KDF_ITERATIONS = 20


def _crypto_field(validator):
    def run(value):
        try:
            validator(value)
        except CryptoValidationError as exc:
            raise serializers.ValidationError(str(exc)) from exc
        return value

    return run


def validate_auth_hash(value):
    return _crypto_field(lambda v: b64decode_strict(v, field="auth_hash", exact=AUTH_HASH_BYTES))(value)


class KdfParamsMixin(serializers.Serializer):
    kdf_salt = serializers.CharField(max_length=64)
    kdf_memory_kib = serializers.IntegerField(min_value=MIN_KDF_MEMORY_KIB, max_value=MAX_KDF_MEMORY_KIB)
    kdf_iterations = serializers.IntegerField(min_value=MIN_KDF_ITERATIONS, max_value=MAX_KDF_ITERATIONS)
    kdf_parallelism = serializers.IntegerField(min_value=1, max_value=8)

    def validate_kdf_salt(self, value):
        return _crypto_field(lambda v: b64decode_strict(v, field="kdf_salt", exact=SALT_BYTES))(value)


class RegisterSerializer(KdfParamsMixin):
    username = serializers.CharField(max_length=64, validators=[USERNAME_VALIDATOR])
    auth_hash = serializers.CharField(max_length=64, write_only=True)
    protected_vault_key = serializers.CharField(max_length=512)
    encryption_public_key = serializers.CharField(max_length=4096)
    encrypted_encryption_private_key = serializers.CharField(max_length=PRIVATE_KEY_ENVELOPE_MAX * 2)
    signing_public_key = serializers.CharField(max_length=4096)
    encrypted_signing_private_key = serializers.CharField(max_length=PRIVATE_KEY_ENVELOPE_MAX * 2)

    def validate_username(self, value):
        if User.objects.filter(username__iexact=value).exists():
            raise serializers.ValidationError("This username is not available.")
        return value

    def validate_auth_hash(self, value):
        return validate_auth_hash(value)

    def validate_protected_vault_key(self, value):
        return _crypto_field(lambda v: validate_envelope(v, field="protected_vault_key", max_len=64))(value)

    def validate_encryption_public_key(self, value):
        return _crypto_field(lambda v: load_rsa_public_key(v, field="encryption_public_key"))(value)

    def validate_signing_public_key(self, value):
        return _crypto_field(lambda v: load_rsa_public_key(v, field="signing_public_key"))(value)

    def validate_encrypted_encryption_private_key(self, value):
        return _crypto_field(
            lambda v: validate_envelope(v, field="encrypted_encryption_private_key", max_len=PRIVATE_KEY_ENVELOPE_MAX)
        )(value)

    def validate_encrypted_signing_private_key(self, value):
        return _crypto_field(
            lambda v: validate_envelope(v, field="encrypted_signing_private_key", max_len=PRIVATE_KEY_ENVELOPE_MAX)
        )(value)

    def validate(self, attrs):
        if attrs["encryption_public_key"] == attrs["signing_public_key"]:
            raise serializers.ValidationError("Encryption and signing keys must be different key pairs.")
        return attrs

    def create(self, validated_data):
        auth_hash = validated_data.pop("auth_hash")
        user = User(**validated_data)
        user.set_password(auth_hash)  # Argon2id(auth_hash) on the server side
        user.save()
        return user


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=64)
    auth_hash = serializers.CharField(max_length=64)


class PreloginSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=64)


class ProfileSerializer(serializers.ModelSerializer):
    """Everything the client needs to unlock its vault after login."""

    encryption_key_fingerprint = serializers.SerializerMethodField()
    signing_key_fingerprint = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = [
            "id", "username", "role", "date_joined",
            "kdf_salt", "kdf_memory_kib", "kdf_iterations", "kdf_parallelism",
            "protected_vault_key",
            "encryption_public_key", "encrypted_encryption_private_key",
            "signing_public_key", "encrypted_signing_private_key",
            "encryption_key_fingerprint", "signing_key_fingerprint",
        ]
        read_only_fields = fields

    def get_encryption_key_fingerprint(self, obj):
        return fingerprint(obj.encryption_public_key) if obj.encryption_public_key else ""

    def get_signing_key_fingerprint(self, obj):
        return fingerprint(obj.signing_public_key) if obj.signing_public_key else ""


class PublicKeysSerializer(serializers.ModelSerializer):
    encryption_key_fingerprint = serializers.SerializerMethodField()
    signing_key_fingerprint = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = [
            "username", "encryption_public_key", "signing_public_key",
            "encryption_key_fingerprint", "signing_key_fingerprint",
        ]
        read_only_fields = fields

    def get_encryption_key_fingerprint(self, obj):
        return fingerprint(obj.encryption_public_key)

    def get_signing_key_fingerprint(self, obj):
        return fingerprint(obj.signing_public_key)


class ChangeMasterPasswordSerializer(KdfParamsMixin):
    """Re-wrap the (unchanged) vault key under a new master password.

    Vault items and RSA private keys are encrypted with the vault key, so they don't
    need to be re-encrypted.
    """

    current_auth_hash = serializers.CharField(max_length=64)
    new_auth_hash = serializers.CharField(max_length=64)
    protected_vault_key = serializers.CharField(max_length=512)

    def validate_current_auth_hash(self, value):
        return validate_auth_hash(value)

    def validate_new_auth_hash(self, value):
        return validate_auth_hash(value)

    def validate_protected_vault_key(self, value):
        return _crypto_field(lambda v: validate_envelope(v, field="protected_vault_key", max_len=64))(value)


class AdminUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "username", "role", "is_active", "date_joined", "last_login"]
        read_only_fields = ["id", "username", "date_joined", "last_login"]


def default_kdf_params():
    kdf = settings.VAULT_KDF
    return {
        "kdf_memory_kib": kdf["memory_kib"],
        "kdf_iterations": kdf["iterations"],
        "kdf_parallelism": kdf["parallelism"],
    }
