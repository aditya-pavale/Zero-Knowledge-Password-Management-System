import pytest
from django.db import connection

from vault.models import VaultItem

pytestmark = pytest.mark.django_db

ITEM = {"title": "Bank", "username": "alice@example.com", "password": "Sup3r-S3cret-Passw0rd!", "url": "https://bank.example", "notes": ""}


def test_crud_roundtrip(register, client_for):
    alice = register("alice")
    c = client_for(alice)
    res = c.post("/api/vault/items/", alice.encrypt_item(ITEM), format="json")
    assert res.status_code == 201
    item_id = res.json()["id"]

    listing = c.get("/api/vault/items/").json()["results"]
    assert [alice.decrypt_item(r) for r in listing] == [ITEM]

    updated = dict(ITEM, password="rotated-password-2")
    res = c.put(f"/api/vault/items/{item_id}/", alice.encrypt_item(updated), format="json")
    assert res.status_code == 200
    assert res.json()["version"] == 2
    assert alice.decrypt_item(c.get(f"/api/vault/items/{item_id}/").json()) == updated

    assert c.delete(f"/api/vault/items/{item_id}/").status_code == 204
    assert c.get("/api/vault/items/").json()["count"] == 0


def test_database_contains_only_ciphertext(register, client_for):
    alice = register("alice")
    client_for(alice).post("/api/vault/items/", alice.encrypt_item(ITEM), format="json")
    with connection.cursor() as cursor:
        cursor.execute("SELECT iv, ciphertext FROM vault_vaultitem")
        dump = " ".join(str(v) for row in cursor.fetchall() for v in row)
    for secret in ITEM.values():
        if secret:
            assert secret not in dump


def test_users_cannot_access_each_others_items(register, client_for):
    alice, bob = register("alice"), register("bob")
    item_id = client_for(alice).post("/api/vault/items/", alice.encrypt_item(ITEM), format="json").json()["id"]
    b = client_for(bob)
    assert b.get(f"/api/vault/items/{item_id}/").status_code == 404
    assert b.put(f"/api/vault/items/{item_id}/", bob.encrypt_item(ITEM), format="json").status_code == 404
    assert b.delete(f"/api/vault/items/{item_id}/").status_code == 404
    assert b.get("/api/vault/items/").json()["count"] == 0
    assert VaultItem.objects.filter(pk=item_id).exists()


def test_owner_cannot_be_spoofed_via_payload(register, client_for):
    alice, bob = register("alice"), register("bob")
    body = dict(bob.encrypt_item(ITEM), owner=alice.id)
    item_id = client_for(bob).post("/api/vault/items/", body, format="json").json()["id"]
    assert VaultItem.objects.get(pk=item_id).owner_id == bob.id


@pytest.mark.parametrize(
    "body",
    [
        {"iv": "AAAA", "ciphertext": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},  # IV not 12 bytes
        {"iv": "AAAAAAAAAAAAAAAA", "ciphertext": "AAAA"},  # shorter than a GCM tag
        {"iv": "AAAAAAAAAAAAAAAA", "ciphertext": "not base64 !!"},
        {"iv": "AAAAAAAAAAAAAAAA"},
    ],
)
def test_rejects_malformed_ciphertext(register, client_for, body):
    alice = register("alice")
    assert client_for(alice).post("/api/vault/items/", body, format="json").status_code == 400
