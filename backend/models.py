import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship

from database import Base


def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(32), unique=True, index=True, nullable=False)

    # Argon2id hash of the *client-derived auth secret* (never of the password itself).
    auth_hash = Column(String, nullable=False)

    # TOTP (RFC 6238)
    totp_secret = Column(String, nullable=False)
    is_2fa_enabled = Column(Boolean, default=False, nullable=False)
    last_totp_step = Column(Integer, nullable=True)  # replay protection

    # Public keys (SPKI DER, base64) and the private keys wrapped in the browser
    # with a key the server never sees (JSON: {"iv": ..., "ct": ...}).
    enc_public_key = Column(Text, nullable=False)
    sig_public_key = Column(Text, nullable=False)
    wrapped_private_keys = Column(Text, nullable=False)

    # Brute-force protection (persisted, so it survives restarts)
    failed_attempts = Column(Integer, default=0, nullable=False)
    lockout_until = Column(DateTime, nullable=True)
    twofa_failed_attempts = Column(Integer, default=0, nullable=False)
    twofa_lockout_until = Column(DateTime, nullable=True)

    created_at = Column(DateTime, default=_utcnow, nullable=False)


class Message(Base):
    """An encrypted message. The server only ever stores ciphertext."""

    __tablename__ = "messages"

    id = Column(Integer, primary_key=True, index=True)
    sender_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    ciphertext = Column(Text, nullable=False)  # AES-256-GCM(envelope), base64
    iv = Column(String, nullable=False)  # 12-byte GCM nonce, base64
    created_at = Column(DateTime, default=_utcnow, nullable=False)

    sender = relationship("User", foreign_keys=[sender_id])
    recipients = relationship(
        "MessageRecipient", back_populates="message", cascade="all, delete-orphan"
    )


class MessageRecipient(Base):
    """Per-recipient copy of the message key, plus that recipient's own state."""

    __tablename__ = "message_recipients"
    __table_args__ = (UniqueConstraint("message_id", "recipient_id"),)

    id = Column(Integer, primary_key=True)
    message_id = Column(Integer, ForeignKey("messages.id"), nullable=False, index=True)
    recipient_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    wrapped_key = Column(Text, nullable=False)  # RSA-OAEP(recipient pubkey, AES key)
    is_read = Column(Boolean, default=False, nullable=False)

    message = relationship("Message", back_populates="recipients")
    recipient = relationship("User", foreign_keys=[recipient_id])


class AuditLog(Base):
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, index=True)
    event_type = Column(String(40), nullable=False)
    username = Column(String(32), index=True)
    ip_address = Column(String(64))
    user_agent = Column(String(200))
    timestamp = Column(DateTime, default=_utcnow, nullable=False)
