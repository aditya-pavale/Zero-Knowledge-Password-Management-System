from django.urls import path

from . import views

urlpatterns = [
    path("logs/", views.AuditLogListView.as_view(), name="audit-logs"),
    path("logs/mine/", views.MyAuditLogView.as_view(), name="audit-logs-mine"),
    path("verify/", views.VerifyChainView.as_view(), name="audit-verify"),
]
