"""Server-side helpers for *validating* client-produced crypto material.

The server never encrypts or decrypts vault data. It only checks that blobs are
well-formed, that public keys are sane, and that RSA-PSS signatures on shared items
verify against the sender's registered signing key.
"""
import base64
import binascii
import hashlib
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

MIN_RSA_BITS = 2048
PSS_SALT_LENGTH = 32
AES_GCM_IV_BYTES = 12
AES_GCM_TAG_BYTES = 16

# Wrapped keys are stored as "v1.<base64 iv>.<base64 ciphertext+tag>".
ENVELOPE_RE = re.compile(r"^v1\.([A-Za-z0-9+/=]+)\.([A-Za-z0-9+/=]+)$")


class CryptoValidationError(ValueError):
    pass


def b64decode_strict(value, *, field="value", exact=None, min_len=None, max_len=None):
    if not isinstance(value, str):
        raise CryptoValidationError(f"{field} must be a base64 string")
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise CryptoValidationError(f"{field} is not valid base64") from exc
    if exact is not None and len(raw) != exact:
        raise CryptoValidationError(f"{field} must decode to exactly {exact} bytes")
    if min_len is not None and len(raw) < min_len:
        raise CryptoValidationError(f"{field} is too short")
    if max_len is not None and len(raw) > max_len:
        raise CryptoValidationError(f"{field} is too long")
    return raw


def validate_envelope(value, *, field="value", max_len=8192):
    """Validate an AES-GCM envelope string without being able to decrypt it."""
    if not isinstance(value, str) or len(value) > max_len * 2:
        raise CryptoValidationError(f"{field} is not a valid encrypted envelope")
    match = ENVELOPE_RE.match(value)
    if not match:
        raise CryptoValidationError(f"{field} is not a valid encrypted envelope")
    b64decode_strict(match.group(1), field=f"{field}.iv", exact=AES_GCM_IV_BYTES)
    b64decode_strict(match.group(2), field=f"{field}.ciphertext", min_len=AES_GCM_TAG_BYTES + 1, max_len=max_len)
    return value


def load_rsa_public_key(value, *, field="public_key"):
    der = b64decode_strict(value, field=field, min_len=200, max_len=2048)
    try:
        key = serialization.load_der_public_key(der)
    except (ValueError, TypeError) as exc:
        raise CryptoValidationError(f"{field} is not a valid SPKI public key") from exc
    if not isinstance(key, rsa.RSAPublicKey):
        raise CryptoValidationError(f"{field} must be an RSA key")
    if key.key_size < MIN_RSA_BITS:
        raise CryptoValidationError(f"{field} must be at least {MIN_RSA_BITS} bits")
    return key


def fingerprint(public_key_b64):
    """Human-comparable SHA-256 fingerprint of an SPKI public key."""
    digest = hashlib.sha256(base64.b64decode(public_key_b64)).hexdigest()
    return ":".join(digest[i : i + 4] for i in range(0, 32, 4))


def share_signing_message(*, sender, recipient, iv, ciphertext, wrapped_key):
    """Canonical byte string signed by the sender (must match frontend/static/js/crypto.js)."""
    return "|".join(["vault-share-v1", sender, recipient, iv, ciphertext, wrapped_key]).encode("utf-8")


def verify_pss_signature(public_key_b64, signature_b64, message):
    key = load_rsa_public_key(public_key_b64, field="signing_public_key")
    signature = b64decode_strict(signature_b64, field="signature", min_len=128, max_len=1024)
    try:
        key.verify(
            signature,
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=PSS_SALT_LENGTH),
            hashes.SHA256(),
        )
    except InvalidSignature:
        return False
    return True
