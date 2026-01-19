from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import pyotp

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
    """Generates a random base32 secret for TOTP."""
    return pyotp.random_base32()

def get_totp_uri(username: str, secret: str):
    """Generates a provisioning URI for QR codes (compatible with Microsoft/Google Authenticator)."""
    return pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="AlfaMail")

def verify_totp_code(secret: str, code: str):
    """Verifies the 6-digit code provided by the user."""
    totp = pyotp.totp.TOTP(secret)
    return totp.verify(code)