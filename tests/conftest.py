import pytest
from django.core.cache import cache
from rest_framework.test import APIClient

from accounts.models import User

from .pyclient import VaultUser


@pytest.fixture(autouse=True)
def _no_https_redirect(settings):
    # Tests run with DEBUG=False (production settings) but over plain HTTP.
    settings.SECURE_SSL_REDIRECT = False


@pytest.fixture(autouse=True)
def _reset_throttles():
    cache.clear()
    yield
    cache.clear()


@pytest.fixture
def api():
    return APIClient()


@pytest.fixture
def register(api, db):
    """register("alice", role="admin") -> VaultUser with .tokens and .id set."""

    def _register(username, *, role=None, password="correct horse battery staple 42"):
        user = VaultUser(username, password)
        res = api.post("/api/auth/register/", user.registration_payload(), format="json")
        assert res.status_code == 201, res.json()
        user.id = res.json()["user"]["id"]
        user.tokens = res.json()["tokens"]
        if role:
            User.objects.filter(pk=user.id).update(role=role)
        return user

    return _register


@pytest.fixture
def client_for():
    def _client(user):
        c = APIClient()
        c.credentials(HTTP_AUTHORIZATION=f"Bearer {user.tokens['access']}")
        return c

    return _client
