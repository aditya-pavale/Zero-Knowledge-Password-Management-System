from django.urls import path

from . import views

urlpatterns = [
    path("analyze/", views.AnalyzeView.as_view(), name="analyzer-analyze"),
    path("reports/", views.ReportListView.as_view(), name="analyzer-reports"),
]
