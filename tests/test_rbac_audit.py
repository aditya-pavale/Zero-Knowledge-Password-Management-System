import pytest

from accounts.models import User
from audit.models import AuditLog
from audit.service import verify_chain

pytestmark = pytest.mark.django_db


def test_regular_user_blocked_from_privileged_endpoints(register, client_for):
    c = client_for(register("alice"))
    assert c.get("/api/audit/logs/").status_code == 403
    assert c.get("/api/audit/verify/").status_code == 403
    assert c.get("/api/auth/admin/users/").status_code == 403
    assert c.post("/api/analyzer/analyze/", {"findings": [{"title": "x"}]}, format="json").status_code == 403


def test_auditor_reads_logs_but_cannot_manage_users(register, client_for):
    c = client_for(register("aud", role="auditor"))
    assert c.get("/api/audit/logs/").status_code == 200
    assert c.get("/api/audit/verify/").json()["intact"] is True
    assert c.get("/api/auth/admin/users/").status_code == 403


def test_admin_changes_roles_and_it_is_audited(register, client_for):
    admin = register("root", role="admin")
    bob = register("bob")
    c = client_for(admin)
    res = c.patch(f"/api/auth/admin/users/{bob.id}/", {"role": "auditor"}, format="json")
    assert res.status_code == 200
    assert User.objects.get(pk=bob.id).role == "auditor"
    entry = AuditLog.objects.filter(event="role_change").first()
    assert entry.metadata == {"username": "bob", "from": "user", "to": "auditor"}
    # Username is read-only through this endpoint.
    c.patch(f"/api/auth/admin/users/{bob.id}/", {"username": "hacked"}, format="json")
    assert User.objects.get(pk=bob.id).username == "bob"


def test_admin_cannot_demote_self(register, client_for):
    admin = register("root", role="admin")
    res = client_for(admin).patch(f"/api/auth/admin/users/{admin.id}/", {"role": "user"}, format="json")
    assert res.status_code == 400


def test_role_is_read_from_db_not_token(register, client_for):
    """A token minted while admin stops working for admin endpoints once demoted."""
    admin = register("root", role="admin")
    c = client_for(admin)
    User.objects.filter(pk=admin.id).update(role="user")
    assert c.get("/api/auth/admin/users/").status_code == 403


def test_admin_cannot_read_other_users_vault(register, client_for):
    admin, alice = register("root", role="admin"), register("alice")
    item_id = client_for(alice).post("/api/vault/items/", alice.encrypt_item({"title": "t"}), format="json").json()["id"]
    assert client_for(admin).get(f"/api/vault/items/{item_id}/").status_code == 404


def test_audit_chain_detects_tampering(register, client_for):
    alice = register("alice")
    client_for(alice).post("/api/vault/items/", alice.encrypt_item({"title": "t"}), format="json")
    ok, _, count = verify_chain()
    assert ok and count >= 2
    # Bypass the model's immutability guard the way a DB-level attacker would.
    victim = AuditLog.objects.order_by("id").first()
    AuditLog.objects.filter(pk=victim.pk).update(actor_username="someone-else")
    ok, bad_id, _ = verify_chain()
    assert not ok and bad_id == victim.pk


def test_audit_entries_are_immutable(register):
    register("alice")
    entry = AuditLog.objects.first()
    entry.event = "logout"
    with pytest.raises(PermissionError):
        entry.save()
    with pytest.raises(PermissionError):
        entry.delete()


def test_audit_log_never_contains_secrets(register, client_for):
    alice = register("alice")
    c = client_for(alice)
    body = alice.encrypt_item({"title": "t", "password": "p"})
    c.post("/api/vault/items/", body, format="json")
    dump = str(list(AuditLog.objects.values()))
    assert alice.auth_hash not in dump
    assert body["ciphertext"] not in dump
    assert alice.tokens["access"] not in dump


def test_user_sees_only_own_activity(register, client_for):
    alice, bob = register("alice"), register("bob")
    logs = client_for(alice).get("/api/audit/logs/mine/").json()["results"]
    assert logs and all(l["actor_username"] == "alice" for l in logs)
    assert bob


def test_security_headers(api, db):
    res = api.get("/api/health/")
    assert "default-src 'self'" in res["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in res["Content-Security-Policy"]
    assert res["X-Frame-Options"] == "DENY"
    assert res["X-Content-Type-Options"] == "nosniff"
    assert res["Cache-Control"] == "no-store"
    page = api.get("/")
    assert page.status_code == 200
    assert "unsafe-inline" not in page["Content-Security-Policy"]
