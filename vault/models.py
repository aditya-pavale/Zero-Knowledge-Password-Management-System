from django.conf import settings
from django.db import models


class VaultItem(models.Model):
    """One encrypted vault entry.

    `ciphertext` is AES-256-GCM(vault_key, JSON{title, username, password, url, notes})
    produced in the browser. The server cannot see any of those fields, not even the title.
    """

    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="vault_items")
    iv = models.CharField(max_length=24)
    ciphertext = models.TextField()
    version = models.PositiveIntegerField(default=1)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-updated_at"]
        indexes = [models.Index(fields=["owner", "-updated_at"])]

    def __str__(self):
        return f"VaultItem #{self.pk} (owner={self.owner_id})"
