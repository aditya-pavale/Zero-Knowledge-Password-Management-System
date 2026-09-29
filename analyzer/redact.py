"""Scrub anything that looks like a secret before findings leave the server.

This runs on every text field of every finding, after the parsers have already
dropped code snippets and HTTP evidence. It is a second line of defence.
"""
import math
import re
from collections import Counter

REDACTED = "[REDACTED]"

PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),  # JWT
    re.compile(r"\bsk-ant-[A-Za-z0-9_-]{10,}\b"),  # Anthropic keys
    re.compile(r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{10,}\b"),  # Stripe-style keys
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),  # AWS access key id
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),  # GitHub tokens
    re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s:/@]+:[^\s@/]+@", re.I),  # creds in URLs
    re.compile(
        r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|auth[_-]?hash|private[_-]?key|access[_-]?key)"
        r"(\s*[:=]\s*)(['\"]?)[^\s'\",;]+\3"
    ),
]


def _entropy(s):
    counts = Counter(s)
    return -sum(c / len(s) * math.log2(c / len(s)) for c in counts.values())


HIGH_ENTROPY = re.compile(r"[A-Za-z0-9+/=_-]{24,}")


def redact_text(text):
    if not text:
        return text
    for pattern in PATTERNS:
        if pattern.groups >= 2:
            text = pattern.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", text)
        else:
            text = pattern.sub(REDACTED, text)
    # Long random-looking tokens (base64 ciphertext, keys, hashes).
    return HIGH_ENTROPY.sub(lambda m: REDACTED if _looks_random(m.group(0)) else m.group(0), text)


def _looks_random(token):
    # Mixed case + digits + high entropy: base64 keys/ciphertext, not file paths or words.
    return (
        any(c.isdigit() for c in token)
        and any(c.isupper() for c in token)
        and any(c.islower() for c in token)
        and _entropy(token) > 4.0
    )


def redact_finding(finding):
    return {k: redact_text(v) if isinstance(v, str) else v for k, v in finding.items()}
