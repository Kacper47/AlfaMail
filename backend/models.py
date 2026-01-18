from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, DateTime, Text
from sqlalchemy.orm import relationship
import datetime
from database import Base

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String) # Argon2id hash
    
    # 2FA configuration
    is_2fa_enabled = Column(Boolean, default=False)
    totp_secret = Column(String, nullable=True) # Encrypted or raw TOTP secret
    
    # Brute-force protection attributes
    locked_until = Column(DateTime, nullable=True)
    
    # Cryptographic keys
    public_key = Column(Text, nullable=True) # RSA Public Key for verification

class Message(Base):
    __tablename__ = "messages"
    id = Column(Integer, primary_key=True, index=True)
    sender_id = Column(Integer, ForeignKey("users.id"))
    recipient_id = Column(Integer, ForeignKey("users.id"))
    
    # Encrypted message content (AES-GCM)
    ciphertext_body = Column(Text)
    nonce = Column(String) # Required for AES-GCM decryption
    
    # Digital signature (RSA-PSS) for authenticity and integrity
    signature = Column(Text)
    
    is_read = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

class AuditLog(Base):
    __tablename__ = "audit_log"
    id = Column(Integer, primary_key=True, index=True)
    event_type = Column(String) # e.g., login_attempt, signature_failure
    username = Column(String)
    ip_address = Column(String)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)