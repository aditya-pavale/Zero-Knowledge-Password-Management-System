from rest_framework.routers import SimpleRouter

from .views import VaultItemViewSet

router = SimpleRouter()
router.register("items", VaultItemViewSet, basename="vault-item")

urlpatterns = router.urls
