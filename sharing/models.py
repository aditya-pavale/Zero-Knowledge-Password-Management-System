from django.conf import settings
from django.db import models


class SharedItem(models.Model):
    """A password shared from one user to another with hybrid encryption.

    - ciphertext/iv:  AES-256-GCM(one-time key K, item JSON)
    - wrapped_key:    RSA-OAEP-SHA256(recipient public key, K)
    - signature:      RSA-PSS-SHA256(sender signing key, canonical message) over
                      sender, recipient, iv, ciphertext and wrapped_key
    """

    class Status(models.TextChoices):
        PENDING = "pending"
        ACCEPTED = "accepted"

    sender = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="shares_sent")
    recipient = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="shares_received")
    iv = models.CharField(max_length=24)
    ciphertext = models.TextField()
    wrapped_key = models.TextField()
    signature = models.TextField()
    # Snapshot of the signing key used, so later key rotation can't silently re-validate.
    sender_signing_public_key = models.TextField()
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.PENDING)
    created_at = models.DateTimeField(auto_now_add=True)
    accepted_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"Share #{self.pk} {self.sender_id}->{self.recipient_id}"
