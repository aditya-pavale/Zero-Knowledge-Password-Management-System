from django.conf import settings
from django.db import models


class AnalysisReport(models.Model):
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL)
    created_at = models.DateTimeField(auto_now_add=True)
    sources = models.JSONField(default=list)
    engine = models.CharField(max_length=64)  # model id, or "offline-knowledge-base"
    findings_count = models.PositiveIntegerField(default=0)
    summary = models.JSONField(default=dict)
    results = models.JSONField(default=list)

    class Meta:
        ordering = ["-created_at"]
