import re
from datetime import datetime
from typing import Annotated, Optional

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

import crypto_utils

# --- Reusable, strict field types (validate everything with a "negative" mindset) ---

USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{2,31}$")

# Client-derived secret: 32 random-looking bytes, base64url without padding.
AuthSecret = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_-]{43}$")]
# Standard base64 alphabet only; sizes are bounded per field below.
Base64 = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9+/]+={0,2}$")]
TotpCode = Annotated[str, StringConstraints(pattern=r"^[0-9]{6}$")]

MAX_RECIPIENTS = 10
MAX_CIPHERTEXT_CHARS = 6_000_000  # ~4.5 MB of ciphertext; nginx caps the body at 8 MB


def _normalise_username(value: object) -> object:
    if isinstance(value, str):
        value = value.strip().lower()
        if not USERNAME_RE.fullmatch(value):
            raise ValueError("invalid username")
    return value


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


# --- Keys ---


class WrappedPrivateKeys(_Strict):
    iv: Annotated[Base64, Field(min_length=16, max_length=16)]  # 12 bytes
    ct: Annotated[Base64, Field(min_length=64, max_length=16_000)]


class PublicKeyPair(BaseModel):
    enc_public_key: str
    sig_public_key: str


# --- Auth ---


class UserCreate(_Strict):
    username: str
    auth_secret: AuthSecret
    enc_public_key: Annotated[Base64, Field(max_length=2_000)]
    sig_public_key: Annotated[Base64, Field(max_length=2_000)]
    wrapped_private_keys: WrappedPrivateKeys

    normalise_username = field_validator("username", mode="before")(_normalise_username)

    @field_validator("enc_public_key", "sig_public_key")
    @classmethod
    def check_public_key(cls, v: str) -> str:
        crypto_utils.validate_rsa_spki(v)
        return v


class UserLogin(_Strict):
    username: str
    auth_secret: AuthSecret

    normalise_username = field_validator("username", mode="before")(_normalise_username)


class TFAEnableRequest(UserLogin):
    code: TotpCode


class Login2FAVerifyRequest(_Strict):
    code: TotpCode


class RegisterResponse(BaseModel):
    message: str
    username: str
    secret: str
    otpauth_uri: str


class LoginResponse(BaseModel):
    requires_2fa: bool = True
    pre_2fa_token: str


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class KeyBundleResponse(BaseModel):
    enc_public_key: str
    sig_public_key: str
    wrapped_private_keys: WrappedPrivateKeys


# --- Messages ---


class RecipientKey(_Strict):
    username: str
    wrapped_key: Annotated[Base64, Field(min_length=300, max_length=1_100)]

    normalise_username = field_validator("username", mode="before")(_normalise_username)


class MessageSend(_Strict):
    recipients: Annotated[list[RecipientKey], Field(min_length=1, max_length=MAX_RECIPIENTS)]
    ciphertext: Annotated[Base64, Field(min_length=24, max_length=MAX_CIPHERTEXT_CHARS)]
    iv: Annotated[Base64, Field(min_length=16, max_length=16)]

    @field_validator("recipients")
    @classmethod
    def unique_recipients(cls, v: list[RecipientKey]) -> list[RecipientKey]:
        if len({r.username for r in v}) != len(v):
            raise ValueError("duplicate recipients")
        return v


class MessageSent(BaseModel):
    id: int
    created_at: datetime


class MessageOut(BaseModel):
    id: int
    sender_username: str
    recipients: list[str]
    ciphertext: str
    iv: str
    wrapped_key: str
    is_read: bool
    created_at: datetime


class ActivityEntry(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    event_type: str
    ip_address: Optional[str]
    timestamp: datetime
