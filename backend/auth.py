from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

# Initialize Argon2id hasher
ph = PasswordHasher()

def get_password_hash(password: str) -> str:
    """Hashes a password using Argon2id."""
    return ph.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a password against its hash."""
    try:
        return ph.verify(hashed_password, plain_password)
    except VerifyMismatchError:
        return False