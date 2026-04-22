from datetime import datetime, timedelta, timezone
import asyncio
from threading import Lock

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

import auth
import crypto_utils
import models
import schemas
from database import SessionLocal, engine

# Initialize database tables
models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="AlfaMail")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://localhost"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer(auto_error=False)

# Simple in-memory throttle for 2FA endpoints
TWO_FA_MAX_ATTEMPTS = 5
TWO_FA_LOCK_MINUTES = 5
_twofa_state: dict[str, dict] = {}
_twofa_lock = Lock()


# Dependency to get a database session per request
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _minutes_until_unlock(username: str) -> int:
    now = datetime.now(timezone.utc)
    with _twofa_lock:
        state = _twofa_state.get(username)
        if not state:
            return 0
        lockout_until = state.get("lockout_until")
        if not lockout_until:
            return 0
        if now >= lockout_until:
            state["attempts"] = 0
            state["lockout_until"] = None
            return 0
        return int((lockout_until - now).total_seconds() // 60) + 1


def _register_2fa_failure(username: str) -> None:
    now = datetime.now(timezone.utc)
    with _twofa_lock:
        state = _twofa_state.setdefault(username, {"attempts": 0, "lockout_until": None})
        state["attempts"] += 1
        if state["attempts"] >= TWO_FA_MAX_ATTEMPTS:
            state["lockout_until"] = now + timedelta(minutes=TWO_FA_LOCK_MINUTES)


def _reset_2fa_failures(username: str) -> None:
    with _twofa_lock:
        if username in _twofa_state:
            _twofa_state[username] = {"attempts": 0, "lockout_until": None}


def _extract_user_from_token(credentials: HTTPAuthorizationCredentials | None, token_type: str, db: Session | None = None):
    if not credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")

    payload = auth.decode_token(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")

    if payload.get("type") != token_type:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect token type")

    username = payload.get("sub")
    if not username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")

    if db is None:
        return username

    user = db.query(models.User).filter(models.User.username == username).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
    db: Session = Depends(get_db),
):
    return _extract_user_from_token(credentials, token_type="access", db=db)


def get_pre_2fa_username(credentials: HTTPAuthorizationCredentials | None = Depends(security)):
    return _extract_user_from_token(credentials, token_type="pre_2fa", db=None)


@app.get("/")
def read_root():
    return {"status": "Application running", "docs_url": "/docs"}


@app.post("/register")
def register_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(models.User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")

    hashed_password = auth.get_password_hash(user.password)
    totp_secret = auth.generate_totp_secret()

    new_user = models.User(
        username=user.username,
        hashed_password=hashed_password,
        totp_secret=totp_secret,
        is_2fa_enabled=False,
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {
        "message": "User created. 2FA setup required.",
        "username": new_user.username,
        "secret": totp_secret,
        "otpauth_uri": auth.get_totp_uri(new_user.username, totp_secret),
    }


@app.post("/login", response_model=schemas.LoginResponse)
async def login_for_access_token(user_data: schemas.UserLogin, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.username == user_data.username).first()

    if not user:
        await asyncio.sleep(2)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    now = datetime.now(timezone.utc)
    if user.lockout_until and now < user.lockout_until.replace(tzinfo=timezone.utc):
        remaining = (user.lockout_until.replace(tzinfo=timezone.utc) - now).seconds // 60
        raise HTTPException(status_code=403, detail=f"Account locked. Try again in {remaining + 1} min.")

    if not auth.verify_password(user_data.password, user.hashed_password):
        user.failed_attempts += 1

        if user.failed_attempts >= 5:
            minutes_to_lock = 5 * (user.failed_attempts - 4)
            user.lockout_until = now + timedelta(minutes=minutes_to_lock)

        db.commit()
        await asyncio.sleep(2)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    user.failed_attempts = 0
    user.lockout_until = None
    db.commit()

    if not getattr(user, "is_2fa_enabled", False):
        raise HTTPException(
            status_code=403,
            detail="Account not activated. Please verify your 2FA code first.",
        )

    pre_2fa_token = auth.create_pre_2fa_token(user.username)

    return {
        "access_token": None,
        "token_type": None,
        "requires_2fa": True,
        "pre_2fa_token": pre_2fa_token,
        "username": user.username,
    }


@app.get("/2fa/setup", response_model=schemas.TFASecretResponse)
def setup_2fa():
    raise HTTPException(
        status_code=410,
        detail="Endpoint disabled for security. Use /register flow to initialize 2FA.",
    )


@app.post("/2fa/enable")
def enable_2fa(data: schemas.TFAEnableRequest, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.username == data.username).first()
    if not user or not user.totp_secret:
        raise HTTPException(status_code=404, detail="User or TOTP setup not found")

    if not auth.verify_password(data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    remaining = _minutes_until_unlock(user.username)
    if remaining > 0:
        raise HTTPException(status_code=403, detail=f"2FA locked. Try again in {remaining} min.")

    if auth.verify_totp_code(user.totp_secret, data.code):
        user.is_2fa_enabled = True
        db.commit()
        _reset_2fa_failures(user.username)
        return {"message": f"2FA enabled successfully for {user.username}"}

    _register_2fa_failure(user.username)
    raise HTTPException(status_code=400, detail="Invalid 2FA code")


@app.post("/login/verify-2fa", response_model=schemas.Token)
def verify_login_2fa(
    data: schemas.Login2FAVerifyRequest,
    username: str = Depends(get_pre_2fa_username),
    db: Session = Depends(get_db),
):
    user = db.query(models.User).filter(models.User.username == username).first()

    if not user:
        raise HTTPException(status_code=401, detail="Invalid 2FA context")

    remaining = _minutes_until_unlock(user.username)
    if remaining > 0:
        raise HTTPException(status_code=403, detail=f"2FA locked. Try again in {remaining} min.")

    if not auth.verify_totp_code(user.totp_secret, data.code):
        _register_2fa_failure(user.username)
        raise HTTPException(status_code=401, detail="Invalid 2FA code")

    _reset_2fa_failures(user.username)
    access_token = auth.create_access_token(
        data={"sub": user.username, "type": "access"},
        expires_delta=timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES),
    )

    log_entry = models.AuditLog(
        event_type="login_success_2fa",
        username=user.username,
        timestamp=datetime.now(timezone.utc),
    )
    db.add(log_entry)
    db.commit()

    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/keys/generate", response_model=schemas.KeyPairResponse)
def generate_keys(
    key_data: schemas.KeyGenerateRequest,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not auth.verify_password(key_data.password, current_user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if current_user.public_key and current_user.encrypted_private_key:
        return {
            "private_key": current_user.encrypted_private_key,
            "public_key": current_user.public_key,
            "message": "Keys restored from server vault.",
        }

    priv_pem, pub_pem = crypto_utils.generate_rsa_key_pair(key_data.password)

    current_user.public_key = pub_pem
    current_user.encrypted_private_key = priv_pem
    db.commit()

    return {
        "private_key": priv_pem,
        "public_key": pub_pem,
        "message": "New keys generated and backed up to server.",
    }


@app.post("/messages/send", response_model=schemas.MessageResponse)
def send_secure_message(
    msg: schemas.MessageCreate,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if msg.sender_username and msg.sender_username != current_user.username:
        raise HTTPException(status_code=403, detail="Sender mismatch")

    if not auth.verify_password(msg.password, current_user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    clean_private_key = msg.sender_private_key.replace("\\n", "\n")
    recipient = db.query(models.User).filter(models.User.username == msg.recipient_username).first()

    if not recipient:
        raise HTTPException(status_code=404, detail="Recipient not found")

    if not recipient.public_key:
        raise HTTPException(status_code=400, detail="Recipient has not generated cryptographic keys")

    nonce, encrypted_body = crypto_utils.encrypt_message(msg.content, recipient.public_key)
    signature = crypto_utils.sign_data(msg.content, clean_private_key, msg.password)

    new_message = models.Message(
        sender_id=current_user.id,
        recipient_id=recipient.id,
        ciphertext_body=encrypted_body,
        nonce=nonce,
        signature=signature,
    )

    db.add(new_message)
    db.commit()
    db.refresh(new_message)

    return new_message


@app.post("/messages/my", response_model=list[schemas.DecryptedMessageResponse])
def get_my_messages(
    data: schemas.MessageReadRequest,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not auth.verify_password(data.password, current_user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    raw_key = data.private_key.strip()
    clean_private_key = raw_key.replace("\\n", "\n")

    if "\n" not in clean_private_key and "-----BEGIN" in clean_private_key:
        clean_private_key = clean_private_key.replace(
            "-----BEGIN ENCRYPTED PRIVATE KEY-----", "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
        )
        clean_private_key = clean_private_key.replace(
            "-----END ENCRYPTED PRIVATE KEY-----", "\n-----END ENCRYPTED PRIVATE KEY-----"
        )

    messages = db.query(models.Message).filter(models.Message.recipient_id == current_user.id).all()
    decrypted_list = []

    for msg in messages:
        try:
            decrypted_content = crypto_utils.decrypt_message(
                msg.ciphertext_body,
                msg.nonce,
                clean_private_key,
                data.password,
            )

            if not decrypted_content:
                continue

            sender = db.query(models.User).filter(models.User.id == msg.sender_id).first()
            is_signature_valid = False
            if sender and sender.public_key:
                is_signature_valid = crypto_utils.verify_signature(
                    decrypted_content,
                    msg.signature,
                    sender.public_key,
                )

            decrypted_list.append(
                {
                    "id": msg.id,
                    "sender_username": sender.username if sender else "Unknown",
                    "content": decrypted_content,
                    "signature_valid": is_signature_valid,
                    "is_read": msg.is_read,
                    "created_at": msg.created_at,
                }
            )
        except Exception:
            continue
    return decrypted_list


@app.delete("/messages/{message_id}")
def delete_message(
    message_id: int,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    msg = db.query(models.Message).filter(models.Message.id == message_id).first()
    if not msg:
        raise HTTPException(status_code=404, detail="Message not found")
    if msg.recipient_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not allowed")

    db.delete(msg)
    db.commit()
    return {"message": "Message deleted successfully"}


@app.patch("/messages/{message_id}/read")
def mark_message_as_read(
    message_id: int,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    msg = db.query(models.Message).filter(models.Message.id == message_id).first()
    if not msg:
        raise HTTPException(status_code=404, detail="Message not found")
    if msg.recipient_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not allowed")

    msg.is_read = True
    db.commit()
    return {"message": "Message marked as read"}
