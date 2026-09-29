from django.contrib.auth.models import AbstractUser
from django.core.validators import RegexValidator
from django.db import models

USERNAME_VALIDATOR = RegexValidator(
    r"^[A-Za-z0-9_.-]{3,64}$",
    "Username must be 3-64 characters: letters, digits, '_', '.' or '-'.",
)


class User(AbstractUser):
    """A vault user.

    Everything the server stores about a user's secrets is either public
    (RSA public keys, KDF salt/parameters) or encrypted client-side with a key
    the server never sees (vault key, RSA private keys).
    """

    class Role(models.TextChoices):
        USER = "user", "User"
        AUDITOR = "auditor", "Auditor"
        ADMIN = "admin", "Admin"

    username = models.CharField(max_length=64, unique=True, validators=[USERNAME_VALIDATOR])
    role = models.CharField(max_length=16, choices=Role.choices, default=Role.USER)

    # Client-side Argon2id parameters (public by design).
    kdf_salt = models.CharField(max_length=64, blank=True)
    kdf_memory_kib = models.PositiveIntegerField(default=65536)
    kdf_iterations = models.PositiveIntegerField(default=3)
    kdf_parallelism = models.PositiveSmallIntegerField(default=1)

    # Random 256-bit vault key, AES-256-GCM-wrapped with the Argon2id-derived key.
    protected_vault_key = models.TextField(blank=True)

    # RSA-OAEP key pair used to receive shared items.
    encryption_public_key = models.TextField(blank=True)
    encrypted_encryption_private_key = models.TextField(blank=True)

    # RSA-PSS key pair used to sign shared items.
    signing_public_key = models.TextField(blank=True)
    encrypted_signing_private_key = models.TextField(blank=True)

    REQUIRED_FIELDS = []

    @property
    def is_admin_role(self):
        return self.role == self.Role.ADMIN

    @property
    def is_auditor_role(self):
        return self.role in (self.Role.AUDITOR, self.Role.ADMIN)

    def __str__(self):
        return self.username
