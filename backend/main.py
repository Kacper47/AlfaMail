import asyncio
import json
import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Path, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, joinedload
from starlette.concurrency import run_in_threadpool

import auth
import models
import schemas
from database import SessionLocal, engine

models.Base.metadata.create_all(bind=engine)

# API docs are disabled: the API surface is documented in README.md and the
# interactive docs would only help an attacker.
app = FastAPI(title="AlfaMail", docs_url=None, redoc_url=None, openapi_url=None)

security = HTTPBearer(auto_error=False)

# --- Brute-force protection settings ---
MAX_LOGIN_ATTEMPTS = 5
MAX_2FA_ATTEMPTS = 5
TWO_FA_LOCK_MINUTES = 5
# Delay applied to every failed authentication (tests set it to 0).
FAILURE_DELAY = float(os.getenv("AUTH_FAILURE_DELAY", "1.5"))
# An account whose 2FA setup was never finished can be re-registered after this long.
UNACTIVATED_TTL = timedelta(minutes=15)

GENERIC_AUTH_ERROR = "Invalid credentials"
USERNAME_PATH = Path(pattern=r"^[a-z0-9][a-z0-9_.-]{2,31}$")


# --- Helpers ---


def _now() -> datetime:
    """Naive UTC 'now' (SQLite stores naive datetimes)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _client_ip(request: Request) -> str:
    # nginx overwrites X-Real-IP with the real peer address; the backend is not
    # reachable from outside the compose network.
    return (request.headers.get("x-real-ip") or (request.client.host if request.client else "") or "?")[:64]


def audit(db: Session, event: str, username: Optional[str], request: Request) -> None:
    db.add(
        models.AuditLog(
            event_type=event,
            username=username,
            ip_address=_client_ip(request),
            user_agent=(request.headers.get("user-agent") or "")[:200],
            timestamp=_now(),
        )
    )
    db.commit()


def _get_user(db: Session, username: str) -> Optional[models.User]:
    return db.query(models.User).filter(models.User.username == username).first()


async def authenticate(
    db: Session, request: Request, username: str, auth_secret: str
) -> models.User:
    """Verify (username, auth_secret).

    Every failure - unknown user, wrong secret, locked account - produces the same
    401 response after the same delay, and costs one Argon2 verification, so the
    caller cannot tell the cases apart.
    """
    user = _get_user(db, username)
    now = _now()
    locked = bool(user and user.lockout_until and now < user.lockout_until)

    target_hash = user.auth_hash if (user and not locked) else auth.DUMMY_HASH
    ok = await run_in_threadpool(auth.verify_secret, auth_secret, target_hash)

    if ok and user and not locked:
        user.failed_attempts = 0
        user.lockout_until = None
        db.commit()
        return user

    if user and not locked:
        user.failed_attempts += 1
        if user.failed_attempts >= MAX_LOGIN_ATTEMPTS:
            # progressive lockout: 5, 10, 15 ... minutes
            user.lockout_until = now + timedelta(minutes=5 * (user.failed_attempts - 4))
        db.commit()
        audit(db, "login_failed", user.username, request)
    else:
        audit(db, "login_failed", None, request)

    await asyncio.sleep(FAILURE_DELAY)
    raise HTTPException(status_code=401, detail=GENERIC_AUTH_ERROR)


def _check_2fa_lock(user: models.User) -> None:
    if user.twofa_lockout_until and _now() < user.twofa_lockout_until:
        raise HTTPException(status_code=429, detail="Too many attempts. Try again later.")


async def check_totp(
    db: Session, request: Request, user: models.User, code: str
) -> None:
    """Validate a TOTP code, enforcing lockout and replay protection."""
    _check_2fa_lock(user)
    step = auth.verify_totp_code(user.totp_secret, code, user.last_totp_step)
    if step is None:
        user.twofa_failed_attempts += 1
        if user.twofa_failed_attempts >= MAX_2FA_ATTEMPTS:
            user.twofa_lockout_until = _now() + timedelta(minutes=TWO_FA_LOCK_MINUTES)
            user.twofa_failed_attempts = 0
        db.commit()
        audit(db, "2fa_failed", user.username, request)
        await asyncio.sleep(FAILURE_DELAY)
        raise HTTPException(status_code=401, detail="Invalid code")
    user.last_totp_step = step
    user.twofa_failed_attempts = 0
    user.twofa_lockout_until = None
    db.commit()


def _user_from_token(
    credentials: Optional[HTTPAuthorizationCredentials], token_type: str, db: Session
) -> models.User:
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if not credentials:
        raise unauthorized
    payload = auth.decode_token(credentials.credentials)
    if not payload or payload.get("type") != token_type or not payload.get("sub"):
        raise unauthorized
    user = _get_user(db, payload["sub"])
    if not user:
        raise unauthorized
    return user


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: Session = Depends(get_db),
) -> models.User:
    user = _user_from_token(credentials, "access", db)
    if not user.is_2fa_enabled:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user


def get_pre_2fa_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: Session = Depends(get_db),
) -> models.User:
    return _user_from_token(credentials, "pre_2fa", db)


@app.middleware("http")
async def no_store(request: Request, call_next):
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    return response


# --- Endpoints ---


@app.get("/health", include_in_schema=False)
def health():
    return {"status": "ok"}


@app.post("/register", response_model=schemas.RegisterResponse, status_code=201)
async def register_user(
    data: schemas.UserCreate, request: Request, db: Session = Depends(get_db)
):
    existing = _get_user(db, data.username)
    if existing:
        stale = (
            not existing.is_2fa_enabled
            and _now() - existing.created_at > UNACTIVATED_TTL
        )
        if not stale:
            raise HTTPException(status_code=409, detail="Username unavailable")
        db.delete(existing)
        db.commit()

    totp_secret = auth.generate_totp_secret()
    user = models.User(
        username=data.username,
        auth_hash=await run_in_threadpool(auth.hash_secret, data.auth_secret),
        totp_secret=totp_secret,
        is_2fa_enabled=False,
        enc_public_key=data.enc_public_key,
        sig_public_key=data.sig_public_key,
        wrapped_private_keys=data.wrapped_private_keys.model_dump_json(),
    )
    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Username unavailable")

    audit(db, "register", user.username, request)
    return {
        "message": "User created. 2FA setup required.",
        "username": user.username,
        "secret": totp_secret,
        "otpauth_uri": auth.get_totp_uri(user.username, totp_secret),
    }


@app.post("/2fa/enable")
async def enable_2fa(
    data: schemas.TFAEnableRequest, request: Request, db: Session = Depends(get_db)
):
    user = await authenticate(db, request, data.username, data.auth_secret)
    if user.is_2fa_enabled:
        raise HTTPException(status_code=400, detail="Invalid request")

    await check_totp(db, request, user, data.code)
    user.is_2fa_enabled = True
    db.commit()
    audit(db, "2fa_enabled", user.username, request)
    return {"message": "2FA enabled"}


@app.post("/login", response_model=schemas.LoginResponse)
async def login(data: schemas.UserLogin, request: Request, db: Session = Depends(get_db)):
    user = await authenticate(db, request, data.username, data.auth_secret)
    if not user.is_2fa_enabled:
        # Only reachable with a correct secret, so this reveals nothing to a guesser.
        raise HTTPException(status_code=403, detail="Account not activated")
    return {"requires_2fa": True, "pre_2fa_token": auth.create_pre_2fa_token(user.username)}


@app.post("/login/verify-2fa", response_model=schemas.Token)
async def verify_login_2fa(
    data: schemas.Login2FAVerifyRequest,
    request: Request,
    user: models.User = Depends(get_pre_2fa_user),
    db: Session = Depends(get_db),
):
    await check_totp(db, request, user, data.code)
    audit(db, "login_success", user.username, request)
    return {"access_token": auth.create_access_token(user.username), "token_type": "bearer"}


@app.get("/keys/me", response_model=schemas.KeyBundleResponse)
def get_my_keys(current_user: models.User = Depends(get_current_user)):
    return {
        "enc_public_key": current_user.enc_public_key,
        "sig_public_key": current_user.sig_public_key,
        "wrapped_private_keys": json.loads(current_user.wrapped_private_keys),
    }


@app.get("/users/{username}/public-keys", response_model=schemas.PublicKeyPair)
def get_public_keys(
    username: str = USERNAME_PATH,
    _: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user = _get_user(db, username)
    if not user or not user.is_2fa_enabled:
        raise HTTPException(status_code=404, detail="User not found")
    return {"enc_public_key": user.enc_public_key, "sig_public_key": user.sig_public_key}


@app.post("/messages/send", response_model=schemas.MessageSent, status_code=201)
def send_message(
    msg: schemas.MessageSend,
    request: Request,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    names = [r.username for r in msg.recipients]
    users = {
        u.username: u
        for u in db.query(models.User)
        .filter(models.User.username.in_(names), models.User.is_2fa_enabled.is_(True))
        .all()
    }
    if len(users) != len(names):
        raise HTTPException(status_code=404, detail="Recipient not found")

    message = models.Message(
        sender_id=current_user.id, ciphertext=msg.ciphertext, iv=msg.iv, created_at=_now()
    )
    for r in msg.recipients:
        message.recipients.append(
            models.MessageRecipient(recipient_id=users[r.username].id, wrapped_key=r.wrapped_key)
        )
    db.add(message)
    db.commit()
    db.refresh(message)
    audit(db, "message_sent", current_user.username, request)
    return {"id": message.id, "created_at": message.created_at}


@app.get("/messages", response_model=list[schemas.MessageOut])
def list_my_messages(
    current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)
):
    rows = (
        db.query(models.MessageRecipient)
        .options(
            joinedload(models.MessageRecipient.message).joinedload(models.Message.sender),
            joinedload(models.MessageRecipient.message)
            .joinedload(models.Message.recipients)
            .joinedload(models.MessageRecipient.recipient),
        )
        .filter(models.MessageRecipient.recipient_id == current_user.id)
        .order_by(models.MessageRecipient.message_id.desc())
        .all()
    )
    return [
        {
            "id": row.message.id,
            "sender_username": row.message.sender.username,
            "recipients": sorted(r.recipient.username for r in row.message.recipients),
            "ciphertext": row.message.ciphertext,
            "iv": row.message.iv,
            "wrapped_key": row.wrapped_key,
            "is_read": row.is_read,
            "created_at": row.message.created_at,
        }
        for row in rows
    ]


def _my_copy(db: Session, user: models.User, message_id: int) -> models.MessageRecipient:
    # Same 404 whether the message does not exist or belongs to somebody else.
    row = (
        db.query(models.MessageRecipient)
        .filter(
            models.MessageRecipient.message_id == message_id,
            models.MessageRecipient.recipient_id == user.id,
        )
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="Message not found")
    return row


@app.patch("/messages/{message_id}/read")
def mark_message_as_read(
    message_id: int,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    row = _my_copy(db, current_user, message_id)
    row.is_read = True
    db.commit()
    return {"message": "Message marked as read"}


@app.delete("/messages/{message_id}")
def delete_message(
    message_id: int,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    row = _my_copy(db, current_user, message_id)
    message = row.message
    db.delete(row)
    db.flush()
    # Drop the message itself once nobody holds a copy any more.
    if not db.query(models.MessageRecipient).filter_by(message_id=message.id).count():
        db.delete(message)
    db.commit()
    return {"message": "Message deleted"}


@app.get("/account/activity", response_model=list[schemas.ActivityEntry])
def recent_activity(
    current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)
):
    """Recent security-relevant events for this account (lets users spot unknown logins)."""
    return (
        db.query(models.AuditLog)
        .filter(
            models.AuditLog.username == current_user.username,
            models.AuditLog.event_type.in_(["login_success", "login_failed", "2fa_failed"]),
        )
        .order_by(models.AuditLog.id.desc())
        .limit(20)
        .all()
    )
