import base64

import pytest

from audit.models import AuditLog
from sharing.models import SharedItem

pytestmark = pytest.mark.django_db

ITEM = {"title": "Team Wi-Fi", "username": "", "password": "correct-horse-wifi", "url": "", "notes": "2nd floor"}


def public_keys(client, username):
    res = client.get(f"/api/auth/users/{username}/public-keys/")
    assert res.status_code == 200
    return res.json()


def test_share_end_to_end(register, client_for):
    alice, bob = register("alice"), register("bob")
    a, b = client_for(alice), client_for(bob)
    keys = public_keys(a, "bob")
    res = a.post("/api/shares/", alice.create_share("bob", keys["encryption_public_key"], ITEM), format="json")
    assert res.status_code == 201, res.json()
    assert set(res.json()) == {"id", "recipient", "status", "created_at", "accepted_at"}  # no ciphertext echoed

    inbox = b.get("/api/shares/inbox/").json()["results"]
    assert len(inbox) == 1
    share = inbox[0]
    assert share["sender"] == "alice"
    assert bob.open_share(share) == ITEM

    assert b.post(f"/api/shares/{share['id']}/accept/").json()["status"] == "accepted"
    outbox = a.get("/api/shares/outbox/").json()["results"]
    assert outbox[0]["status"] == "accepted"
    assert "ciphertext" not in outbox[0]


def test_server_rejects_bad_signature(register, client_for):
    alice, bob = register("alice"), register("bob")
    a = client_for(alice)
    payload = alice.create_share("bob", public_keys(a, "bob")["encryption_public_key"], ITEM)
    ct = bytearray(base64.b64decode(payload["ciphertext"]))
    ct[0] ^= 1
    payload["ciphertext"] = base64.b64encode(bytes(ct)).decode()
    res = a.post("/api/shares/", payload, format="json")
    assert res.status_code == 400
    assert not SharedItem.objects.exists()
    assert AuditLog.objects.filter(event="share_rejected_signature").exists()
    assert bob


def test_cannot_forge_share_as_another_user(register, client_for):
    """Mallory signs with her own key but the server checks the authenticated sender (alice)."""
    alice, bob, mallory = register("alice"), register("bob"), register("mallory")
    a = client_for(alice)
    enc = public_keys(a, "bob")["encryption_public_key"]
    forged = alice.create_share("bob", enc, ITEM, signer=mallory.pss)
    assert a.post("/api/shares/", forged, format="json").status_code == 400

    # Mallory re-sending a payload signed for alice->bob also fails (sender is bound in the signature).
    m = client_for(mallory)
    legit = alice.create_share("bob", enc, ITEM)
    assert m.post("/api/shares/", legit, format="json").status_code == 400
    assert bob


def test_cannot_share_with_self_or_unknown(register, client_for):
    alice = register("alice")
    a = client_for(alice)
    enc = public_keys(a, "alice")["encryption_public_key"]
    assert a.post("/api/shares/", alice.create_share("alice", enc, ITEM), format="json").status_code == 400
    assert a.post("/api/shares/", alice.create_share("nobody", enc, ITEM), format="json").status_code == 400


def test_third_party_cannot_touch_share(register, client_for):
    alice, bob, eve = register("alice"), register("bob"), register("eve")
    a, e = client_for(alice), client_for(eve)
    share_id = a.post(
        "/api/shares/", alice.create_share("bob", public_keys(a, "bob")["encryption_public_key"], ITEM), format="json"
    ).json()["id"]
    assert e.get("/api/shares/inbox/").json()["count"] == 0
    assert e.post(f"/api/shares/{share_id}/accept/").status_code == 404
    assert e.delete(f"/api/shares/{share_id}/").status_code == 404
    # Sender can't accept on the recipient's behalf.
    assert a.post(f"/api/shares/{share_id}/accept/").status_code == 404
    # Sender can revoke.
    assert a.delete(f"/api/shares/{share_id}/").status_code == 204
    assert bob


def test_fingerprints_match_between_endpoints(register, client_for):
    alice = register("alice")
    register("bob")
    a = client_for(alice)
    me = client_for(alice).get("/api/auth/me/").json()
    assert public_keys(a, "alice")["signing_key_fingerprint"] == me["signing_key_fingerprint"]
