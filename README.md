# AlfaMail

A secure messaging platform with end-to-end encryption, mandatory two-factor authentication (TOTP), and RSA digital signatures.

---

## Table of Contents

- [Architecture](#architecture)
- [Security Features](#security-features)
- [Requirements](#requirements)
- [Getting Started](#getting-started)
- [Configuration](#configuration)
- [User Flows](#user-flows)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [API Reference](#api-reference)

---

## Architecture

```
Browser
   │ HTTPS (443)
   ▼
Nginx (reverse proxy)
   │
   ├──► Frontend (static files: HTML/JS)
   │
   └──► Backend (FastAPI, port 8000)
             │
             └──► SQLite (users & messages)
```

All HTTP traffic is automatically redirected to HTTPS. Nginx serves the frontend as static files and proxies API requests to the FastAPI backend.

---

## Security Features

| Mechanism | Implementation |
|---|---|
| Password hashing | **Argon2id** |
| Two-factor authentication | **TOTP** (RFC 6238), mandatory for all accounts |
| Message encryption | Hybrid: **AES-256-GCM** (content) + **RSA-2048-OAEP** (key) |
| Digital signatures | **RSA-PSS** with SHA-256 |
| Session tokens | **JWT** (HS256), two-phase (`pre_2fa_token` → `access_token`) |
| Brute-force protection | Progressive account lockout after 5 failed login attempts |
| 2FA protection | 5-minute lockout after 5 incorrect TOTP codes |
| Transport security | **TLS/HTTPS** |
| HTTP headers | CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy |
| Audit logging | Login events recorded to the database |

### How message encryption works

1. The sender generates a one-time AES-256 key and encrypts the message content with it (AES-GCM).
2. The AES key is encrypted with the recipient's RSA public key (OAEP/SHA-256).
3. The sender signs the plaintext content with their RSA private key (RSA-PSS).
4. The server stores only ciphertext — it never has access to message content.
5. The recipient decrypts the AES key with their private key, decrypts the content, and verifies the sender's signature.

---

## Requirements

- [Docker](https://www.docker.com/) and [Docker Compose](https://docs.docker.com/compose/)
- A TLS certificate and private key (`nginx.crt`, `nginx.key`) placed in the project root

### Generating a self-signed certificate (development only)

```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout nginx.key -out nginx.crt \
  -subj "/CN=localhost"
```

---

## Getting Started

1. **Clone the repository** and navigate to the project directory.

2. **Set the `SECRET_KEY` environment variable** (used to sign JWT tokens):

   ```bash
   # Linux/macOS
   export SECRET_KEY=$(openssl rand -hex 64)

   # Windows (PowerShell)
   $env:SECRET_KEY = [System.Convert]::ToBase64String((1..64 | ForEach-Object { [byte](Get-Random -Max 256) }))
   ```

   Alternatively, create a `.env` file in the project root:

   ```env
   SECRET_KEY=your_very_secret_key_here
   ```

3. **Start the application:**

   ```bash
   docker compose up --build
   ```

4. **Open your browser** and go to `https://localhost`.

   > Your browser will show a warning for the self-signed certificate — you can safely accept it for local development.

---

## Configuration

| Environment Variable | Description | Default |
|---|---|---|
| `SECRET_KEY` | Key used to sign JWT tokens | Random (not recommended for production) |
| `DATABASE_URL` | SQLAlchemy database URL | `sqlite:///./data/alfa_mail.db` |

---

## User Flows

### Registration and 2FA activation

```
1. Register (POST /register)
       ↓
   Server returns TOTP secret + QR code URI
       ↓
2. User scans QR code in an authenticator app (Google Authenticator, Aegis, etc.)
       ↓
3. Enable 2FA (POST /2fa/enable) — verify the first TOTP code
       ↓
   Account activated
```

### Login (two-phase)

```
1. POST /login  (username + password)
       ↓
   Server returns `pre_2fa_token` (valid for 5 min)
       ↓
2. POST /login/verify-2fa  (TOTP code + pre_2fa_token)
       ↓
   Server returns `access_token` (valid for 30 min)
```

### Sending an encrypted message

```
1. Generate RSA keys (POST /keys/generate)
   — public key is stored on the server
   — private key (encrypted with the user's password) is stored locally or in the server vault
       ↓
2. Send message (POST /messages/send):
   — content encrypted with recipient's public key (AES-GCM + RSA-OAEP)
   — content signed with sender's private key (RSA-PSS)
       ↓
3. Read messages (POST /messages/my):
   — decrypt with own private key
   — verify sender's signature
```

---

## Tech Stack

### Backend
- **Python 3.11+**
- **FastAPI** — REST API framework
- **SQLAlchemy** — ORM with SQLite
- **Argon2-cffi** — password hashing (Argon2id)
- **python-jose** — JWT generation and verification
- **pyotp** — TOTP implementation (RFC 6238)
- **cryptography** — RSA, AES-GCM, digital signatures

### Frontend
- Vanilla HTML / CSS / JavaScript (no external frameworks)

### Infrastructure
- **Docker Compose** — container orchestration
- **Nginx** — reverse proxy, TLS termination, static file serving

---

## Project Structure

```
AlfaMail/
├── backend/
│   ├── main.py          # FastAPI endpoint definitions
│   ├── auth.py          # Passwords (Argon2), JWT, TOTP
│   ├── crypto_utils.py  # RSA, AES-GCM, digital signatures
│   ├── models.py        # SQLAlchemy models (User, Message, AuditLog)
│   ├── schemas.py       # Pydantic schemas (request/response validation)
│   ├── database.py      # Database session configuration
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   ├── index.html       # Login page
│   ├── register.html    # Registration page + 2FA setup
│   ├── messages.html    # Inbox
│   └── app.js           # Client-side logic (encryption, API calls)
├── nginx/
│   ├── nginx.conf       # Nginx config (HTTPS, proxy, CSP headers)
│   └── Dockerfile
├── nginx.crt            # TLS certificate (do not commit to repo!)
├── nginx.key            # TLS private key (do not commit to repo!)
└── docker-compose.yml
```

> **Note:** `nginx.crt` and `nginx.key` should not be stored in the Git repository — add them to `.gitignore`.

---

## API Reference

Interactive Swagger UI documentation is available at `https://localhost/docs` once the application is running.

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/register` | Register a new account + initialize TOTP |
| `POST` | `/2fa/enable` | Activate 2FA (verify the first TOTP code) |
| `POST` | `/login` | Login — phase 1 (returns `pre_2fa_token`) |
| `POST` | `/login/verify-2fa` | Login — phase 2 (verify TOTP, returns `access_token`) |
| `POST` | `/keys/generate` | Generate or restore RSA key pair |
| `POST` | `/messages/send` | Send an encrypted message |
| `POST` | `/messages/my` | Fetch and decrypt received messages |
| `PATCH` | `/messages/{id}/read` | Mark a message as read |
| `DELETE` | `/messages/{id}` | Delete a message |
