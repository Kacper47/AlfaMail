import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from jose import JWTError, jwt

# Read from env in production; fall back to a random per-process key (tokens then
# stop working after a restart) rather than ever using a hard-coded secret.
SECRET_KEY = os.getenv("SECRET_KEY") or secrets.token_urlsafe(64)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
PRE_2FA_TOKEN_EXPIRE_MINUTES = 5

# Argon2id with the library defaults (RFC 9106 "low memory" profile: t=3, m=64 MiB, p=4).
# A fresh random salt is generated for every hash and embedded in the encoded string.
ph = PasswordHasher()

# Verified against when the user does not exist, so that "unknown user" and
# "wrong password" take the same amount of time.
DUMMY_HASH = ph.hash(secrets.token_urlsafe(32))

TOTP_INTERVAL = 30
TOTP_WINDOW = 1  # accept the previous/next 30 s step to tolerate clock drift


def hash_secret(auth_secret: str) -> str:
    return ph.hash(auth_secret)


def verify_secret(auth_secret: str, hashed: str) -> bool:
    try:
        return ph.verify(hashed, auth_secret)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


# --- TOTP (RFC 6238) ---


def generate_totp_secret() -> str:
    return pyotp.random_base32()


def get_totp_uri(username: str, secret: str) -> str:
    return pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="AlfaMail")


def verify_totp_code(secret: str, code: str, last_used_step: Optional[int]) -> Optional[int]:
    """Return the matching 30 s time step, or None.

    A step that was already used (or is older than the last used one) is rejected,
    so an observed code cannot be replayed inside its validity window.
    """
    totp = pyotp.TOTP(secret, interval=TOTP_INTERVAL)
    now = datetime.now(timezone.utc)
    current_step = int(now.timestamp()) // TOTP_INTERVAL
    for step in range(current_step - TOTP_WINDOW, current_step + TOTP_WINDOW + 1):
        expected = totp.at(step * TOTP_INTERVAL)
        if hmac.compare_digest(expected, code):
            if last_used_step is not None and step <= last_used_step:
                return None
            return step
    return None


# --- JWT ---


def _encode(payload: dict, expires: timedelta) -> str:
    now = datetime.now(timezone.utc)
    claims = {**payload, "iat": now, "exp": now + expires}
    return jwt.encode(claims, SECRET_KEY, algorithm=ALGORITHM)


def create_access_token(username: str) -> str:
    return _encode(
        {"sub": username, "type": "access"}, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )


def create_pre_2fa_token(username: str) -> str:
    return _encode(
        {"sub": username, "type": "pre_2fa"}, timedelta(minutes=PRE_2FA_TOKEN_EXPIRE_MINUTES)
    )


def decode_token(token: str) -> Optional[dict]:
    try:
        return jwt.decode(
            token, SECRET_KEY, algorithms=[ALGORITHM], options={"require_exp": True}
        )
    except JWTError:
        return None
