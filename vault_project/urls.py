from django.http import JsonResponse
from django.urls import include, path
from django.templatetags.static import static
from django.views.generic import RedirectView, TemplateView


def health(_request):
    return JsonResponse({"status": "ok"})


urlpatterns = [
    path("", TemplateView.as_view(template_name="index.html"), name="home"),
    path("favicon.ico", RedirectView.as_view(url=static("favicon.svg"), permanent=True)),
    path("api/health/", health, name="health"),
    path("api/auth/", include("accounts.urls")),
    path("api/vault/", include("vault.urls")),
    path("api/shares/", include("sharing.urls")),
    path("api/audit/", include("audit.urls")),
    path("api/analyzer/", include("analyzer.urls")),
]
