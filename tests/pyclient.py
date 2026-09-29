"""A Python re-implementation of frontend/static/js/crypto.js used to drive the API in tests.

It mirrors the browser exactly (Argon2id -> HKDF -> AES-GCM, RSA-OAEP, RSA-PSS), so the
tests exercise the real server-side validation and signature checks.
"""
import base64
import json
import os
from functools import lru_cache

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from vault_project.cryptoutils import share_signing_message

KDF = {"kdf_memory_kib": 19456, "kdf_iterations": 2, "kdf_parallelism": 1}
PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


def b64(data):
    return base64.b64encode(data).decode()


def unb64(s):
    return base64.b64decode(s)


def hkdf(master, info):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=bytes(32), info=info.encode()).derive(master)


def derive(password, salt_b64, params):
    master = hash_secret_raw(
        password.encode(), unb64(salt_b64),
        time_cost=params["kdf_iterations"], memory_cost=params["kdf_memory_kib"],
        parallelism=params["kdf_parallelism"], hash_len=32, type=Type.ID,
    )
    return b64(hkdf(master, "vault-auth-v1")), hkdf(master, "vault-enc-v1")


def seal(key, data, aad):
    iv = os.urandom(12)
    return f"v1.{b64(iv)}.{b64(AESGCM(key).encrypt(iv, data, aad.encode()))}"


def open_envelope(key, env, aad):
    _, iv, ct = env.split(".")
    return AESGCM(key).decrypt(unb64(iv), unb64(ct), aad.encode())


@lru_cache(maxsize=None)
def _rsa(name, purpose, bits=2048):
    # Cached per (user, purpose) so the suite doesn't generate dozens of RSA keys.
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def spki(private_key):
    return b64(private_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))


class VaultUser:
    def __init__(self, username, password="correct horse battery staple 42"):
        self.username = username
        self.password = password
        self.salt = b64(os.urandom(16))
        self.auth_hash, self.enc_key = derive(password, self.salt, KDF)
        self.vault_key = os.urandom(32)
        self.oaep = _rsa(username, "oaep")
        self.pss = _rsa(username, "pss")
        self.id = None
        self.tokens = None

    def registration_payload(self):
        pkcs8 = lambda k: k.private_bytes(  # noqa: E731
            serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        return {
            "username": self.username,
            "auth_hash": self.auth_hash,
            "kdf_salt": self.salt,
            **KDF,
            "protected_vault_key": seal(self.enc_key, self.vault_key, f"vault-key-v1:{self.username}"),
            "encryption_public_key": spki(self.oaep),
            "encrypted_encryption_private_key": seal(self.vault_key, pkcs8(self.oaep), f"rsa-oaep-priv-v1:{self.username}"),
            "signing_public_key": spki(self.pss),
            "encrypted_signing_private_key": seal(self.vault_key, pkcs8(self.pss), f"rsa-pss-priv-v1:{self.username}"),
        }

    # ---- vault items
    def encrypt_item(self, item):
        iv = os.urandom(12)
        ct = AESGCM(self.vault_key).encrypt(iv, json.dumps(item).encode(), f"vault-item-v1:{self.id}".encode())
        return {"iv": b64(iv), "ciphertext": b64(ct)}

    def decrypt_item(self, record):
        pt = AESGCM(self.vault_key).decrypt(
            unb64(record["iv"]), unb64(record["ciphertext"]), f"vault-item-v1:{self.id}".encode())
        return json.loads(pt)

    # ---- sharing
    def create_share(self, recipient_username, recipient_enc_pub_b64, item, signer=None):
        k = os.urandom(32)
        iv = os.urandom(12)
        ct = AESGCM(k).encrypt(iv, json.dumps(item).encode(),
                               f"vault-share-v1:{self.username}|{recipient_username}".encode())
        pub = serialization.load_der_public_key(unb64(recipient_enc_pub_b64))
        wrapped = pub.encrypt(k, OAEP)
        payload = {"recipient": recipient_username, "iv": b64(iv), "ciphertext": b64(ct), "wrapped_key": b64(wrapped)}
        msg = share_signing_message(sender=self.username, recipient=recipient_username, iv=payload["iv"],
                                    ciphertext=payload["ciphertext"], wrapped_key=payload["wrapped_key"])
        payload["signature"] = b64((signer or self.pss).sign(msg, PSS, hashes.SHA256()))
        return payload

    def open_share(self, share):
        k = self.oaep.decrypt(unb64(share["wrapped_key"]), OAEP)
        pt = AESGCM(k).decrypt(unb64(share["iv"]), unb64(share["ciphertext"]),
                               f"vault-share-v1:{share['sender']}|{share['recipient']}".encode())
        return json.loads(pt)
