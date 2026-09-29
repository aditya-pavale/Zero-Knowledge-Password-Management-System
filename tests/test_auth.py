import base64

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from accounts.models import User
from audit.models import AuditLog

from .pyclient import VaultUser, derive, spki

pytestmark = pytest.mark.django_db


def login(api, user, auth_hash=None):
    return api.post("/api/auth/login/", {"username": user.username, "auth_hash": auth_hash or user.auth_hash}, format="json")


def test_register_login_roundtrip_unwraps_vault_key(api, register):
    alice = register("alice")
    res = api.post("/api/auth/prelogin/", {"username": "alice"}, format="json")
    params = res.json()
    auth_hash, enc_key = derive(alice.password, params["kdf_salt"], params)
    assert auth_hash == alice.auth_hash

    res = login(api, alice, auth_hash)
    assert res.status_code == 200
    profile = res.json()["user"]
    from .pyclient import open_envelope

    assert open_envelope(enc_key, profile["protected_vault_key"], "vault-key-v1:alice") == alice.vault_key
    assert {"access", "refresh"} <= set(res.json()["tokens"])


def test_server_never_stores_master_password_or_raw_auth_hash(register):
    alice = register("alice")
    stored = User.objects.get(username="alice").password
    assert stored.startswith("argon2$argon2id$")
    assert alice.password not in stored
    assert alice.auth_hash not in stored


def test_wrong_password_rejected_and_logged(api, register):
    alice = register("alice")
    wrong, _ = derive("not my password at all!!", alice.salt, {"kdf_memory_kib": 19456, "kdf_iterations": 2, "kdf_parallelism": 1})
    assert login(api, alice, wrong).status_code == 401
    assert AuditLog.objects.filter(event="login_failed", actor_username="alice").count() == 1


def test_failed_logins_show_in_owners_activity(api, register, client_for):
    alice = register("alice")
    login(api, alice, VaultUser("x").auth_hash)
    events = [e["event"] for e in client_for(alice).get("/api/audit/logs/mine/").json()["results"]]
    assert "login_failed" in events


def test_prelogin_does_not_reveal_whether_user_exists(api, register):
    register("alice")
    real = api.post("/api/auth/prelogin/", {"username": "alice"}, format="json").json()
    fake1 = api.post("/api/auth/prelogin/", {"username": "mallory"}, format="json").json()
    fake2 = api.post("/api/auth/prelogin/", {"username": "mallory"}, format="json").json()
    assert set(real) == set(fake1)
    assert fake1 == fake2  # stable, so repeated probing can't distinguish it either
    assert len(base64.b64decode(fake1["kdf_salt"])) == 16


def test_unknown_user_and_wrong_password_look_the_same(api, register):
    alice = register("alice")
    ghost = VaultUser("ghost")
    wrong_pw = api.post("/api/auth/login/", {"username": "alice", "auth_hash": ghost.auth_hash}, format="json")
    no_user = login(api, ghost)
    assert wrong_pw.status_code == no_user.status_code == 401
    assert wrong_pw.json() == no_user.json()
    assert alice  # silence unused


def test_account_lockout_after_repeated_failures(api, register, settings):
    alice = register("alice")
    bogus = VaultUser("x").auth_hash
    for _ in range(10):
        assert login(api, alice, bogus).status_code == 401
    # Even the correct password is refused while locked.
    assert login(api, alice).status_code == 429
    assert AuditLog.objects.filter(event="login_locked").exists()


def test_logout_blacklists_refresh_token(api, register, client_for):
    alice = register("alice")
    c = client_for(alice)
    assert c.post("/api/auth/logout/", {"refresh": alice.tokens["refresh"]}, format="json").status_code == 204
    res = api.post("/api/auth/refresh/", {"refresh": alice.tokens["refresh"]}, format="json")
    assert res.status_code == 401


def test_endpoints_require_authentication(api):
    for path in ["/api/vault/items/", "/api/shares/inbox/", "/api/auth/me/", "/api/audit/logs/mine/"]:
        assert api.get(path).status_code == 401


@pytest.mark.parametrize(
    "field,value",
    [
        ("auth_hash", "short"),
        ("kdf_salt", base64.b64encode(b"tiny").decode()),
        ("kdf_memory_kib", 1024),  # weaker than OWASP minimum
        ("protected_vault_key", "not-an-envelope"),
        ("encryption_public_key", base64.b64encode(b"garbage" * 40).decode()),
        ("username", "bad name!"),
    ],
)
def test_register_rejects_malformed_material(api, db, field, value):
    payload = VaultUser("valid_user").registration_payload()
    payload[field] = value
    res = api.post("/api/auth/register/", payload, format="json")
    assert res.status_code == 400
    assert field in res.json()


def test_register_rejects_weak_rsa_keys(api, db):
    payload = VaultUser("weak").registration_payload()
    payload["encryption_public_key"] = spki(rsa.generate_private_key(public_exponent=65537, key_size=1024))
    res = api.post("/api/auth/register/", payload, format="json")
    assert res.status_code == 400


def test_duplicate_username_rejected(api, register):
    register("alice")
    res = api.post("/api/auth/register/", VaultUser("ALICE").registration_payload(), format="json")
    assert res.status_code == 400


def test_change_master_password(api, register, client_for):
    from .pyclient import KDF, b64, seal

    alice = register("alice")
    new_salt = b64(b"\x01" * 16)
    new_auth, new_enc = derive("a brand new master password!", new_salt, KDF)
    body = {
        "current_auth_hash": alice.auth_hash,
        "new_auth_hash": new_auth,
        "kdf_salt": new_salt,
        **KDF,
        "protected_vault_key": seal(new_enc, alice.vault_key, "vault-key-v1:alice"),
    }
    c = client_for(alice)
    bad = dict(body, current_auth_hash=new_auth)
    assert c.post("/api/auth/change-master-password/", bad, format="json").status_code == 400
    assert c.post("/api/auth/change-master-password/", body, format="json").status_code == 200
    assert login(api, alice).status_code == 401
    assert login(api, alice, new_auth).status_code == 200


def test_deactivated_user_token_rejected(register, client_for):
    alice = register("alice")
    User.objects.filter(pk=alice.id).update(is_active=False)
    assert client_for(alice).get("/api/auth/me/").status_code == 401


def _change_password(alice, client):
    from .pyclient import KDF, b64, seal

    new_salt = b64(b"\x02" * 16)
    new_auth, new_enc = derive("another brand new master password", new_salt, KDF)
    body = {
        "current_auth_hash": alice.auth_hash, "new_auth_hash": new_auth, "kdf_salt": new_salt, **KDF,
        "protected_vault_key": seal(new_enc, alice.vault_key, "vault-key-v1:alice"),
    }
    res = client.post("/api/auth/change-master-password/", body, format="json")
    assert res.status_code == 200
    return res.json()["tokens"]


def test_password_change_revokes_other_sessions(api, register, client_for):
    alice = register("alice")
    other_session = login(api, alice).json()["tokens"]["refresh"]  # e.g. a stolen/other device session
    new_tokens = _change_password(alice, client_for(alice))
    assert api.post("/api/auth/refresh/", {"refresh": other_session}, format="json").status_code == 401
    assert api.post("/api/auth/refresh/", {"refresh": alice.tokens["refresh"]}, format="json").status_code == 401
    # The session that performed the change keeps working with the freshly issued tokens.
    assert api.post("/api/auth/refresh/", {"refresh": new_tokens["refresh"]}, format="json").status_code == 200


def test_deactivated_user_cannot_refresh(api, register, client_for):
    admin, bob = register("root", role="admin"), register("bob")
    client_for(admin).patch(f"/api/auth/admin/users/{bob.id}/", {"is_active": False}, format="json")
    assert api.post("/api/auth/refresh/", {"refresh": bob.tokens["refresh"]}, format="json").status_code == 401
