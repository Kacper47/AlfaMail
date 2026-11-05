# AlfaMail

An end-to-end encrypted messenger with attachments, authenticated (signed) messages and mandatory two-factor authentication (TOTP), in the spirit of ProtonMail. Messages are encrypted and signed **in the browser**; the server only ever stores ciphertext.

## Contents

- [Architecture](#architecture)
- [Cryptographic design](#cryptographic-design)
- [Security measures](#security-measures)
- [Security model and limitations](#security-model-and-limitations)
- [Getting started](#getting-started)
- [Configuration](#configuration)
- [Running the tests](#running-the-tests)
- [API reference](#api-reference)
- [Project structure](#project-structure)

---

## Architecture

```
Browser (all cryptography happens here)
   │ HTTPS 443
   ▼
nginx ── TLS termination, rate limits, security headers, CSP
   ├──► static frontend (HTML / ES modules / CSS)
   └──► FastAPI backend :8000  (not published to the host)
              └──► SQLite (users, public keys, wrapped private keys, ciphertext)
```

The backend never receives a password, a private key or a plaintext message.

---

## Cryptographic design

Everything below is implemented in [`frontend/js/crypto.js`](frontend/js/crypto.js) using the browser's Web Crypto API.

### 1. One password, two independent secrets

```
password ──PBKDF2-HMAC-SHA256, 600 000 iterations, salt = SHA-256("alfamail-v1|" + username)──► 64 bytes
                                          ├─ bytes  0..31 → authSecret   sent to the server (login)
                                          └─ bytes 32..63 → wrapKey      never leaves the browser
```

The server cannot compute `wrapKey` from `authSecret` (they are independent halves of a KDF output), so knowing the login credential does not unlock anyone's keys. On the server `authSecret` is hashed again with **Argon2id** (random salt, RFC 9106 parameters), so a stolen database costs an attacker PBKDF2 *and* Argon2id per guess.

### 2. Per-user keys

Each user has two RSA-3072 key pairs, generated in the browser at registration:

| Key pair | Algorithm | Purpose |
|---|---|---|
| encryption | RSA-OAEP / SHA-256 | receive: unwraps message keys |
| signing | RSA-PSS / SHA-256 | prove authorship |

The public keys are uploaded as-is. The private keys are exported, encrypted with **AES-256-GCM** under `wrapKey`, and only that ciphertext is stored on the server. After login the browser decrypts them and re-imports them as **non-extractable** `CryptoKey` objects kept in IndexedDB: page scripts can use them but can never read the key bytes. The password is not stored anywhere (neither `sessionStorage` nor `localStorage`).

### 3. A message

```
envelope  = { m: <JSON: version, from, to[], timestamp, text, attachments[]>,
              s: RSA-PSS signature of m by the sender }
ciphertext = AES-256-GCM(random key K, random 96-bit IV, envelope)
for each recipient:  wrappedKey = RSA-OAEP(recipient's public key, K)
```

- **Attachments are part of `m`**, so they are covered by both the encryption and the signature.
- The signature is **inside** the encrypted envelope: the server cannot read it or use it to test guesses about the plaintext.
- `from` and `to[]` are signed. That binds a message to its sender *and* its audience, which stops a recipient from re-encrypting someone else's message to a third party and passing it off as addressed to them (the "surreptitious forwarding" attack). The receiving client rejects a message if the signature fails, the signed sender differs from the delivered sender, the signed recipient list does not include the reader, or the server lists a recipient that was not signed.
- The server stores `ciphertext`, `iv` and one `wrapped_key` per recipient.

### 4. Key authenticity

Public keys are served by the server, so a malicious server could try to substitute a key. The client therefore shows each sender's signing-key **fingerprint** and pins it on first sight (trust on first use). If a key later changes, the UI shows a warning and sending requires explicit confirmation. Comparing fingerprints through another channel is the strongest check.

---

## Security measures

- **Passwords**: never sent; see above. Strength meter + blocking of weak passwords at registration.
- **Authentication**: two-phase JWT (HS256). `pre_2fa_token` (5 min) is accepted only by `/login/verify-2fa`; `access_token` (30 min) only by the other endpoints. Token *type* is checked on every request.
- **TOTP**: ±1 time step accepted; a used time step cannot be reused (replay protection).
- **Brute force**: constant 1.5 s delay on failure, progressive account lockout (5, 10, 15 ... min) and a 5-minute 2FA lockout, both persisted in the database; nginx limits requests per IP (30/min for authentication endpoints, 10/s elsewhere).
- **Information leakage**: identical responses for unknown user / wrong secret / locked account; "message not found" and "not yours" are the same `404`; API docs are disabled.
- **Authorization**: a message copy is addressed by `(message, current user)`, so users can only read, mark or delete their own copies.
- **Output encoding**: message content, names and metadata are inserted with `textContent` only. Attachments are downloaded as `application/octet-stream` blobs with sanitized names and never rendered inline.
- **Headers**: strict CSP (`default-src 'none'; script-src 'self'; style-src 'self'; ...`), HSTS, `nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, COOP/CORP, `Permissions-Policy`; `Cache-Control: no-store` on API responses. The QR-code library is vendored (`frontend/vendor/`, SHA-256 `c541ef06…8f36`) instead of loaded from a CDN.
- **Containers**: backend runs as an unprivileged user without published ports; pinned Python dependencies and nginx image tag; `SECRET_KEY` is mandatory.
- **Audit log**: registration, successful/failed logins, failed 2FA, sent messages, with IP and User-Agent.

---

## Security model and limitations

Honest list of what this project does **not** protect against:

- **Web-delivered code.** The server delivers the JavaScript that does the encryption, so a compromised server could serve modified code. This is inherent to browser-based end-to-end encryption (the strict CSP and absence of third-party scripts reduce, but do not remove, the risk).
- **Key substitution.** Trust-on-first-use pinning detects a changed key, not a malicious key on first contact; verify fingerprints out of band for high-value contacts.
- **Password strength is enforced in the browser only**, because the server never sees the password. A modified client could register with a weak password; that only endangers that user's own account.
- **No password recovery.** The password protects the key material, so a forgotten password means the messages are unrecoverable. (A recovery e-mail flow is a possible extension but would require a separate recovery key to stay end-to-end.)
- **No sent folder**: the sender does not keep a copy of what they sent (add yourself as a recipient if you want one).
- **No forward secrecy; metadata is visible** to the server (who wrote to whom, when, and the size).
- The TOTP secret is stored in the database in clear text (the server needs it to verify codes).
- Access tokens cannot be revoked before they expire (30 minutes) and are kept in `sessionStorage`.
- A single-node design: SQLite and an unreplicated proxy.
- Behind Docker Desktop all clients may share one source IP, so nginx rate limits then apply to everyone together.

---

## Getting started

Requirements: [Docker](https://www.docker.com/) with Compose, and OpenSSL for the development certificate.

```bash
# 1. a signing secret for JWTs (required)
export SECRET_KEY=$(openssl rand -hex 64)

# 2. a self-signed TLS certificate for localhost (development only, once)
./scripts/generate-certs.sh

# 3. start
docker compose up --build
```

Open <https://localhost> and accept the self-signed certificate warning. To use the app you need an authenticator app (Google Authenticator, Aegis, ...).

Notes:

- Data lives in the `db_data` Docker volume. After upgrading from an older version that stored plaintext-capable keys, remove it (`docker compose down -v`): the data formats are not compatible.
- `nginx.crt` and `nginx.key` are generated locally and are git-ignored. Never reuse them outside local development.

---

## Configuration

| Environment variable | Description | Default |
|---|---|---|
| `SECRET_KEY` | Key used to sign JWTs. **Required** by `docker-compose.yml`; without it a random key is generated per process | - |
| `DATABASE_URL` | SQLAlchemy database URL | `sqlite:///./data/alfa_mail.db` |
| `AUTH_FAILURE_DELAY` | Seconds added to every failed authentication | `1.5` |

---

## Running the tests

```bash
# backend (API, authorization, lockouts, validation)
cd backend && pip install -r requirements-dev.txt && pytest

# browser-side cryptography (needs Node 20+; no dependencies)
node --test tests/frontend/crypto.test.mjs
```

The Node tests cover the full message protocol with the real `crypto.js`: round trips to several recipients, tampering, forged and relabelled senders, altered recipient lists, the forwarding attack, and wrong-password key unlock.

---

## API reference

All bodies are JSON. Protected endpoints need `Authorization: Bearer <access_token>`.

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `POST` | `/register` | - | Create account: username, `auth_secret`, public keys, wrapped private keys. Returns TOTP secret + `otpauth` URI |
| `POST` | `/2fa/enable` | secret + code | Activate the account with the first TOTP code |
| `POST` | `/login` | - | Phase 1: returns `pre_2fa_token` |
| `POST` | `/login/verify-2fa` | `pre_2fa_token` | Phase 2: TOTP code, returns `access_token` |
| `GET` | `/keys/me` | access | Own public keys and wrapped private keys |
| `GET` | `/users/{username}/public-keys` | access | Another user's public keys |
| `POST` | `/messages/send` | access | Store a ciphertext with one wrapped key per recipient |
| `GET` | `/messages` | access | Own message copies (ciphertext only) |
| `PATCH` | `/messages/{id}/read` | access | Mark own copy as read |
| `DELETE` | `/messages/{id}` | access | Delete own copy |
| `GET` | `/account/activity` | access | Recent sign-ins and failed attempts |
| `GET` | `/health` | - | Liveness probe (used by the Docker healthcheck; not proxied by nginx) |

---

## Project structure

```
AlfaMail/
├── backend/
│   ├── main.py            # FastAPI endpoints, lockouts, audit log
│   ├── auth.py            # Argon2id, JWT, TOTP (+ replay protection)
│   ├── crypto_utils.py    # validation of uploaded public keys (no message crypto here)
│   ├── models.py          # User, Message, MessageRecipient, AuditLog
│   ├── schemas.py         # strict request/response validation
│   ├── database.py        # engine/session (reads DATABASE_URL)
│   ├── tests/             # pytest suite
│   ├── requirements.txt   # pinned runtime dependencies
│   └── Dockerfile
├── frontend/
│   ├── index.html, register.html, messages.html
│   ├── css/style.css
│   ├── js/
│   │   ├── crypto.js      # ALL cryptography (key derivation, keys, encrypt/sign/verify)
│   │   ├── keystore.js    # non-extractable keys in IndexedDB
│   │   ├── api.js, dom.js, pins.js, strength.js
│   │   └── login.js, register.js, inbox.js
│   └── vendor/qrcode.min.js
├── nginx/
│   ├── nginx.conf         # TLS, rate limits, CSP and other headers, proxy rules
│   └── Dockerfile
├── scripts/generate-certs.sh
├── tests/frontend/crypto.test.mjs
└── docker-compose.yml
```
