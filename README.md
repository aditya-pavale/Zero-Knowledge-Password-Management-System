# Zero-Knowledge Secure Password Vault & AI-Assisted Security Platform

A multi-user password vault where every secret is encrypted **in the browser** before it is
uploaded. The Django server stores only ciphertext and can't read users' passwords, not even
their item titles. Users can share entries with hybrid RSA/AES encryption and RSA-PSS
signatures. The project ships with a DevSecOps pipeline (pytest, Bandit, Semgrep, OWASP ZAP)
and an AI analyzer that explains scanner findings without ever seeing secrets.

## Quick start (local)

```bash
git clone https://github.com/aditya-pavale/Zero-Knowledge-Password-Management-System.git
cd Zero-Knowledge-Password-Management-System
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
cp .env.example .env            # set DJANGO_SECRET_KEY; DATABASE_URL for PostgreSQL
.venv/bin/python manage.py migrate
.venv/bin/python manage.py runserver
# open http://127.0.0.1:8000 and create an account
.venv/bin/python manage.py set_role <username> admin   # bootstrap the first admin
```

`DATABASE_URL` selects PostgreSQL (`postgres://vault:vault@localhost:5432/vault`). If it isn't
set, SQLite is used for quick local development. One-time PostgreSQL setup:

```bash
sudo systemctl enable --now postgresql
sudo -u postgres psql -c "CREATE USER vault WITH PASSWORD 'vault';" -c "CREATE DATABASE vault OWNER vault;"
```

### Docker

```bash
cp .env.example .env    # set DJANGO_SECRET_KEY and POSTGRES_PASSWORD
docker compose up --build
```

The container runs as a non-root user with a read-only filesystem and all capabilities
dropped. PostgreSQL isn't exposed to the host.

## Architecture

```text
Browser (frontend/static/js)                           Django REST API                PostgreSQL
───────────────────────────────                        ──────────────                 ──────────
master password
  └─ Argon2id(salt, 64 MiB, t=3) ─► master key (never leaves the browser)
        ├─ HKDF "vault-auth-v1" ─► auth hash ──────►  Argon2id(auth hash) ────────►  users.password
        └─ HKDF "vault-enc-v1"  ─► enc key
              └─ AES-256-GCM unwrap ─► vault key (random, 256-bit)
                    ├─ AES-256-GCM ─► vault items ─►  /api/vault/items ───────────►  iv + ciphertext
                    └─ AES-256-GCM ─► RSA private keys (OAEP + PSS, 3072-bit)
```

* **Zero knowledge.** The server receives `HKDF(Argon2id(password))` for login and hashes it
  again with Argon2id. The encryption key comes from a different HKDF branch, so the value the
  server sees can't be turned into the key.
* **Key hierarchy.** Items are encrypted with a random *vault key*, and only the vault key is
  wrapped with the password-derived key. Changing the master password re-wraps one 32-byte key;
  no items need re-encrypting.
* **AAD binding.** GCM additional data binds each ciphertext to its owner and purpose
  (`vault-item-v1:<user id>`, `vault-key-v1:<username>`, …). The server therefore can't swap
  blobs between users or fields without detection.

### Secure sharing (hybrid encryption + signatures)

1. The sender fetches the recipient's RSA-OAEP public key and **compares the fingerprint
   out-of-band**. This defeats a malicious server swapping in its own key.
2. A random AES-256 key *K* encrypts the entry, and RSA-OAEP-SHA256 wraps *K* for the recipient.
3. The sender signs `vault-share-v1|sender|recipient|iv|ciphertext|wrapped_key` with RSA-PSS-SHA256.
4. The **server verifies the signature** against the authenticated sender's registered key and
   rejects forgeries. The **recipient verifies it again** in the browser before decrypting.
5. The recipient can save the entry, which re-encrypts it under their own vault key.

### Authorization & audit

* JWT access tokens (15 min) and rotating refresh tokens. Logout blacklists the session's refresh
  token, and changing the master password revokes every other session.
* Roles: `user`, `auditor` (reads audit logs), `admin` (manages roles and runs the AI analyzer).
  The role is read from the database on every request, never from the token. **No role can
  read another user's vault.** Querysets are scoped to the owner, so other users' IDs return 404.
* Brute-force protection: per-IP throttling on auth endpoints and a per-account lockout
  (10 failures in 15 min).
* User enumeration: `prelogin` returns a deterministic fake salt for unknown users, and login
  errors are identical in both cases.
* **Hash-chained audit log.** Each entry stores `sha256(prev_hash + entry)`, so edits made
  directly in the database are detected (`GET /api/audit/verify/`). Entries are append-only,
  and secrets are filtered out of metadata.
* Headers: strict CSP (no inline script or style), `frame-ancestors 'none'`, nosniff,
  no-referrer, HSTS + SSL redirect in production, and `Cache-Control: no-store` on the API.
* Frontend: every piece of user data is rendered with `textContent`. Keys are non-extractable
  WebCrypto keys held only in memory. The vault auto-locks after 10 minutes, and copied
  passwords are cleared from the clipboard after 30 s.

## API

| Method | Path | Who | Purpose |
|---|---|---|---|
| GET | `/api/auth/kdf-defaults/` | anyone | Argon2id parameters for new accounts |
| POST | `/api/auth/prelogin/` | anyone | salt + KDF params for a username |
| POST | `/api/auth/register/` | anyone | create account (auth hash, wrapped keys, public keys) |
| POST | `/api/auth/login/` | anyone | auth hash → JWTs + wrapped keys |
| POST | `/api/auth/refresh/`, `/api/auth/logout/` | user | rotate / revoke refresh token |
| GET | `/api/auth/me/` | user | own profile + key fingerprints |
| POST | `/api/auth/change-master-password/` | user | re-wrap vault key |
| GET | `/api/auth/users/<username>/public-keys/` | user | recipient keys for sharing |
| CRUD | `/api/vault/items/` | owner | encrypted items |
| POST | `/api/shares/` | user | create signed share (server verifies RSA-PSS) |
| GET | `/api/shares/inbox/`, `/api/shares/outbox/` | user | received / sent |
| POST | `/api/shares/<id>/accept/` | recipient | mark accepted |
| DELETE | `/api/shares/<id>/` | sender / recipient | revoke / dismiss |
| GET | `/api/audit/logs/mine/` | user | own security activity |
| GET | `/api/audit/logs/`, `/api/audit/verify/` | auditor, admin | all events, chain check |
| GET/PATCH | `/api/auth/admin/users/…` | admin | roles, activation |
| POST | `/api/analyzer/analyze/`, GET `/api/analyzer/reports/` | admin | AI analysis |

## Security testing

```bash
.venv/bin/pytest                      # 64 API/security tests (Python client mirrors the browser crypto)
node --test frontend/tests/           # WebCrypto + Argon2id tests of the real crypto.js
node scripts/e2e_smoke.mjs http://127.0.0.1:8000   # JS client ↔ live server interop
scripts/security_scan.sh              # Bandit + Semgrep (+ ZAP via Docker) → AI analysis in reports/
```

## AI security analyzer

`analyzer/` normalizes Bandit, Semgrep and ZAP JSON into one format, then:

1. **Drops code snippets and HTTP evidence** (the likeliest place for real secrets).
2. **Redacts** anything secret-looking: keys, JWTs, `password=…`, credentials in URLs, and
   high-entropy base64.
3. Sends only the redacted metadata to Claude (`claude-sonnet-5` by default via
   `ANTHROPIC_MODEL`, structured JSON output). Claude returns an
   explanation, its own severity, a false-positive flag and remediation.
4. Falls back to an offline CWE knowledge base when no `ANTHROPIC_API_KEY` is set or the call fails.

The analyzer never touches vault data: the server has no plaintext to give it.
Use it from the admin UI tab, or in CI:
`python manage.py analyze_findings --bandit b.json --semgrep s.json --zap z.json [--fail-on high]`.

## CI/CD (GitHub Actions)

`.github/workflows/vault-ci.yml` runs on every push and pull request:

```text
push ─► test (pytest on PostgreSQL 16, node crypto tests, migration + deploy checks)
     └► sast (Bandit, Semgrep; reports uploaded, medium+ findings fail the build)
          └► build (Docker image)
               └► dast (docker compose up + OWASP ZAP baseline)
                    └► ai-analysis (explains all findings; report in the job summary)
```

Add an `ANTHROPIC_API_KEY` repository secret to get LLM explanations in CI.

## Threat model notes / limitations

* The server delivers the JavaScript. A fully compromised server could serve malicious JS, a
  limitation shared by all web-based zero-knowledge vaults. The CSP, the absence of third-party
  scripts, and a vendored hash-wasm build reduce the risk; a browser extension or
  signed-bundle distribution would remove it.
* Public keys are trust-on-first-use unless users compare fingerprints (shown in Settings and
  in the share dialog).
* A forgotten master password can't be recovered. That's a direct consequence of zero knowledge.
* Account lockout can be abused to lock out a known username (a denial of service). Per-IP
  throttling limits the rate.
