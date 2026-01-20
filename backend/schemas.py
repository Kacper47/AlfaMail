from pydantic import BaseModel, Field, validator
import re
import datetime
from typing import Optional

class UserCreate(BaseModel):
    # Username constraints (e.g., min 3 chars)
    username: str = Field(..., min_length=3, max_length=50)
    # Password validation based on security requirements
    password: str = Field(..., min_length=12)

    @validator('password')
    def validate_password_strength(cls, v):
        # Check for at least one uppercase letter
        if not re.search(r"[A-Z]", v):
            raise ValueError('Password must contain at least one uppercase letter')
        # Check for at least one digit
        if not re.search(r"[0-9]", v):
            raise ValueError('Password must contain at least one digit')
        # Check for at least one special character
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", v):
            raise ValueError('Password must contain at least one special character')
        return v

class UserResponse(BaseModel):
    id: int
    username: str
    is_2fa_enabled: bool

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str

class LoginRequest(BaseModel):
    username: str
    password: str

class TFASecretResponse(BaseModel):
    secret: str
    otpauth_uri: str

class TFAVerifyRequest(BaseModel):
    code: str

class LoginResponse(BaseModel):
    access_token: Optional[str] = None
    token_type: Optional[str] = None
    requires_2fa: bool = False
    username: str

class KeyPairResponse(BaseModel):
    private_key: str
    public_key: str
    message: str

class MessageCreate(BaseModel):
    sender_username: str
    recipient_username: str
    content: str
    sender_private_key: str

class MessageResponse(BaseModel):
    id: int
    sender_id: int
    recipient_id: int
    ciphertext_body: str
    nonce: str
    signature: str
    created_at: datetime.datetime

    class Config:
        from_attributes = True

class DecryptedMessageResponse(BaseModel):
    id: int
    sender_username: str
    content: str
    signature_valid: bool
    is_read: bool 
    created_at: datetime.datetime

    class Config:
        from_attributes = True


class UserLogin(BaseModel):
    username: str
    password: str

class LoginResponse(BaseModel):
    access_token: Optional[str] = None
    token_type: Optional[str] = None
    requires_2fa: bool
    username: str
