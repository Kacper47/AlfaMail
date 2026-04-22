from datetime import datetime, timedelta, timezone
from typing import Optional
import os
import secrets
from jose import JWTError, jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import pyotp
from sqlalchemy.orm import Session
import models

# Read from env in production; use random dev key if missing to avoid hardcoded secrets in code.
SECRET_KEY = os.getenv("SECRET_KEY") or secrets.token_urlsafe(64)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
PRE_2FA_TOKEN_EXPIRE_MINUTES = 5

ph = PasswordHasher()

def get_password_hash(password: str) -> str:
    return ph.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return ph.verify(hashed_password, plain_password)
    except VerifyMismatchError:
        return False

def authenticate_user(db: Session, username: str, password: str):
    """Verifies credentials and returns user object if valid."""
    user = db.query(models.User).filter(models.User.username == username).first()
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def generate_totp_secret():
    return pyotp.random_base32()

def get_totp_uri(username: str, secret: str):
    return pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="AlfaMail")

def verify_totp_code(secret: str, code: str):
    totp = pyotp.totp.TOTP(secret)
    return totp.verify(code)

def decode_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None

def create_pre_2fa_token(username: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=PRE_2FA_TOKEN_EXPIRE_MINUTES)
    payload = {"sub": username, "type": "pre_2fa", "exp": expire}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
