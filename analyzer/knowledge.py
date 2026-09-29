"""Offline explanations used when no LLM is configured (or the LLM call fails).

Keyed by CWE first, then by keywords in the rule id / title.
"""

KB = {
    "CWE-89": (
        "SQL injection: untrusted input is concatenated into a SQL query, letting an attacker "
        "read or modify data they shouldn't.",
        "Use the Django ORM or parameterized queries (cursor.execute(sql, params)); never build SQL with "
        "f-strings or %-formatting.",
    ),
    "CWE-79": (
        "Cross-site scripting (XSS): attacker-controlled data is rendered as HTML/JS in another user's "
        "browser, which in a password vault means stolen keys and plaintext.",
        "Render user data with textContent (never innerHTML), keep Django autoescaping on, and enforce a "
        "strict Content-Security-Policy without 'unsafe-inline'.",
    ),
    "CWE-798": (
        "Hard-coded credentials: a secret is committed in source code and can be read by anyone with repo "
        "access or from built images.",
        "Load secrets from environment variables or a secret manager, rotate the exposed secret, and add a "
        "secret scanner to CI.",
    ),
    "CWE-259": (
        "Hard-coded password in source.",
        "Move it to configuration/environment, rotate it, and make sure the default is not usable in production.",
    ),
    "CWE-327": (
        "Use of a broken or risky cryptographic algorithm (e.g. MD5, SHA1, DES, ECB mode).",
        "Use AES-256-GCM for encryption, SHA-256+ for hashing, Argon2id for password hashing, RSA-OAEP/PSS "
        "for asymmetric operations.",
    ),
    "CWE-330": (
        "Insufficiently random values: a non-cryptographic RNG (random module, Math.random) is used where "
        "unpredictability matters.",
        "Use secrets / os.urandom in Python and crypto.getRandomValues in the browser.",
    ),
    "CWE-295": (
        "Improper certificate validation: TLS verification is disabled, allowing man-in-the-middle attacks.",
        "Never pass verify=False; pin a CA bundle if you need a private CA.",
    ),
    "CWE-78": (
        "OS command injection: untrusted input reaches a shell command.",
        "Avoid shell=True, pass argument lists to subprocess, and validate input against an allow-list.",
    ),
    "CWE-502": (
        "Unsafe deserialization (pickle, yaml.load) of untrusted data can execute arbitrary code.",
        "Use JSON or yaml.safe_load; never unpickle data from users.",
    ),
    "CWE-352": (
        "Cross-site request forgery: a state-changing request can be triggered from another site using the "
        "victim's cookies.",
        "Keep CsrfViewMiddleware on for cookie-authenticated views; token (Bearer) auth is not sent "
        "automatically by browsers and avoids CSRF.",
    ),
    "CWE-693": (
        "Missing protection mechanism, typically a security header (CSP, X-Frame-Options, HSTS, nosniff).",
        "Add the missing header in middleware; see vault_project/middleware.py.",
    ),
    "CWE-1021": (
        "Clickjacking: the page can be framed by another origin.",
        "Send X-Frame-Options: DENY and CSP frame-ancestors 'none'.",
    ),
    "CWE-319": (
        "Cleartext transmission of sensitive data.",
        "Serve only over HTTPS, enable HSTS and SECURE_SSL_REDIRECT, set Secure on cookies.",
    ),
    "CWE-942": (
        "Overly permissive CORS policy: another origin may be allowed to read responses from this site.",
        "Only send Access-Control-Allow-Origin for trusted origins (CORS_ALLOWED_ORIGINS); never '*' on "
        "authenticated endpoints, and set WHITENOISE_ALLOW_ALL_ORIGINS = False for static files.",
    ),
    "CWE-311": (
        "Sensitive data is served without transport encryption, so it can be read or modified in transit.",
        "Terminate TLS in front of the app, keep SECURE_SSL_REDIRECT and HSTS enabled in production.",
    ),
    "CWE-209": (
        "Error messages leak internal details (stack traces, paths, SQL).",
        "Run with DEBUG=False in production and return generic error messages.",
    ),
    "CWE-200": (
        "Information exposure: the response reveals data (server versions, internal IPs, user existence) "
        "that helps an attacker.",
        "Remove version banners, return uniform errors, and avoid user enumeration.",
    ),
    "CWE-307": (
        "No limit on authentication attempts allows brute force.",
        "Throttle login endpoints and lock accounts after repeated failures (already done in accounts/views.py).",
    ),
    "CWE-605": (
        "Binding to all interfaces (0.0.0.0) exposes the service on every network interface.",
        "Bind to localhost in development; in containers this is expected and access is controlled by the "
        "network/firewall.",
    ),
    "CWE-703": (
        "Improper handling of exceptional conditions (e.g. assert used for security checks, bare except).",
        "Raise explicit exceptions; asserts are stripped with python -O.",
    ),
    "CWE-400": (
        "Uncontrolled resource consumption (e.g. HTTP requests without a timeout).",
        "Always pass timeout= to outbound requests and bound request body sizes.",
    ),
}

KEYWORDS = [
    ("sql", "CWE-89"), ("xss", "CWE-79"), ("innerhtml", "CWE-79"), ("script", "CWE-79"),
    ("hardcoded", "CWE-798"), ("hard-coded", "CWE-798"), ("password", "CWE-259"),
    ("md5", "CWE-327"), ("sha1", "CWE-327"), ("des", "CWE-327"), ("random", "CWE-330"),
    ("verify", "CWE-295"), ("subprocess", "CWE-78"), ("shell", "CWE-78"), ("pickle", "CWE-502"),
    ("yaml", "CWE-502"), ("csrf", "CWE-352"), ("content security policy", "CWE-693"),
    ("csp", "CWE-693"), ("header", "CWE-693"), ("frame", "CWE-1021"), ("clickjack", "CWE-1021"),
    ("cors", "CWE-942"), ("cross-domain", "CWE-942"), ("http only site", "CWE-311"),
    ("hsts", "CWE-319"), ("transport", "CWE-319"), ("debug", "CWE-209"), ("error", "CWE-209"),
    ("disclosure", "CWE-200"), ("leak", "CWE-200"), ("bind", "CWE-605"), ("assert", "CWE-703"),
    ("timeout", "CWE-400"),
]


ALIASES = {"CWE-264": "CWE-942"}  # ZAP files CORS issues under the old CWE-264 category


def lookup(finding):
    cwe = ALIASES.get(finding.get("cwe", ""), finding.get("cwe", ""))
    if cwe in KB:
        return cwe, KB[cwe]
    haystack = f"{finding.get('rule_id', '')} {finding.get('title', '')}".lower()
    for keyword, key in KEYWORDS:
        if keyword in haystack:
            return key, KB[key]
    return "", (
        finding.get("description") or "The scanner flagged a potential weakness in this location.",
        "Review the flagged code against the OWASP ASVS guidance for this category and add a regression test.",
    )
