from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import pyotp
from sqlalchemy.orm import Session
import models

# SECRET_KEY should be stored in a .env file for production environments
SECRET_KEY = "very_secret_key_change_this_to_a_random_hex_in_production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

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
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    
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