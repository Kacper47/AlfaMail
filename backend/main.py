from fastapi import FastAPI, Depends, HTTPException, status, Request
from pydantic import BaseModel                
from sqlalchemy.orm import Session
import models
import schemas
import auth
from database import engine, SessionLocal                         
from datetime import datetime, timedelta, timezone
import crypto_utils
import asyncio                                
import time 
from fastapi.middleware.cors import CORSMiddleware

# Initialize database tables
models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="AlfaMail")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"], 
    allow_headers=["*"],
)

# Dependency to get a database session per request
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.get("/")
def read_root():
    return {"status": "Application running", "docs_url": "/docs"}


@app.post("/register")
def register_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    # 1. Check if username exists
    db_user = db.query(models.User).filter(models.User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")

    # 2. Hash password
    hashed_password = auth.get_password_hash(user.password)

    # 3. Generate TOTP Secret IMMEDIATELY
    totp_secret = auth.generate_totp_secret()

    # 4. Create User (is_2fa_enabled = False by default in models.py)
    new_user = models.User(
        username=user.username,
        hashed_password=hashed_password,
        totp_secret=totp_secret,     # Save secret now
        is_2fa_enabled=False         # Account is "Pending" until verified
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # 5. Return the secret so frontend can show it immediately
    return {
        "message": "User created. 2FA setup required.",
        "username": new_user.username,
        "secret": totp_secret,
        "otpauth_uri": auth.get_totp_uri(new_user.username, totp_secret)
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

    # 2. Check if 2FA is active (Atomic Registration check)
    if not getattr(user, 'is_2fa_enabled', False):
        raise HTTPException(
            status_code=403, 
            detail="Account not activated. Please verify your 2FA code first."
        )

    # 3. Phase 1 success: Server requests TOTP code
    return {
        "access_token": None,
        "token_type": None,
        "requires_2fa": True,
        "username": user.username
    }


# --- TWO-FACTOR AUTHENTICATION (2FA) MANAGEMENT ---
@app.get("/2fa/setup", response_model=schemas.TFASecretResponse)
def setup_2fa(username: str, db: Session = Depends(get_db)):
    # Find the specific user by username
    user = db.query(models.User).filter(models.User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Generate a new random TOTP secret key
    secret = auth.generate_totp_secret()
    
    # Associate the secret with the specific user
    user.totp_secret = secret
    db.commit()
        
    # Generate the URI for the QR code
    uri = auth.get_totp_uri(user.username, secret)
    return {"secret": secret, "otpauth_uri": uri}

@app.post("/2fa/enable")
def enable_2fa(username: str, data: schemas.TFAVerifyRequest, db: Session = Depends(get_db)):
    # Find the specific user
    user = db.query(models.User).filter(models.User.username == username).first()
    if not user or not user.totp_secret:
         raise HTTPException(status_code=404, detail="User or TOTP setup not found")

    # Verify the 6-digit TOTP code
    if auth.verify_totp_code(user.totp_secret, data.code):
        user.is_2fa_enabled = True
        db.commit()
        return {"message": f"2FA enabled successfully for {username}"}
    else:
        raise HTTPException(status_code=400, detail="Invalid 2FA code")

# --- USER LOGIN (PHASE 2: 2FA VERIFICATION) ---
@app.post("/login/verify-2fa", response_model=schemas.Token)
def verify_login_2fa(data: schemas.TFAVerifyRequest, username: str, db: Session = Depends(get_db)):
    # Fetch the user by username
    user = db.query(models.User).filter(models.User.username == username).first()
    
    # Verify the TOTP code
    if not user or not auth.verify_totp_code(user.totp_secret, data.code):
        raise HTTPException(status_code=401, detail="Invalid 2FA code")
    
    # If code is valid, issue final JWT access token and log success
    access_token = auth.create_access_token(data={"sub": user.username})
    
    log_entry = models.AuditLog(
        event_type="login_success_2fa",
        username=user.username,
        timestamp=datetime.now(timezone.utc)
    )
    db.add(log_entry)
    db.commit()
    
    return {"access_token": access_token, "token_type": "bearer"}

# --- CRYPTOGRAPHY & KEY MANAGEMENT ---
@app.post("/keys/generate", response_model=schemas.KeyPairResponse)
def generate_keys(username: str, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    if user.public_key and user.encrypted_private_key:
        return {
            "private_key": user.encrypted_private_key,
            "public_key": user.public_key,
            "message": "Keys restored from server vault."
        }

    priv_pem, pub_pem = crypto_utils.generate_rsa_key_pair()
    user.public_key = pub_pem
    user.encrypted_private_key = priv_pem 
    db.commit()
    
    return {
        "private_key": priv_pem,
        "public_key": pub_pem,
        "message": "New keys generated and backed up to server."
    }

# --- SECURE MESSAGING ENDPOINTS ---
@app.post("/messages/send", response_model=schemas.MessageResponse)
def send_secure_message(msg: schemas.MessageCreate, db: Session = Depends(get_db)):
    """
    Encrypts and signs a message before storing it in the database.
    Uses Recipient's Public Key for encryption and Sender's Private Key for signing.
    """
    clean_private_key = msg.sender_private_key.replace("\\n", "\n")
    # 1. Fetch Sender and Recipient from database
    sender = db.query(models.User).filter(models.User.username == msg.sender_username).first()
    recipient = db.query(models.User).filter(models.User.username == msg.recipient_username).first()
    
    if not sender or not recipient:
        raise HTTPException(status_code=404, detail="Sender or Recipient not found")
        
    if not recipient.public_key:
        raise HTTPException(status_code=400, detail="Recipient has not generated cryptographic keys")

    # 2. Encrypt the message using Recipient's Public Key (Hybrid AES + RSA)
    # This ensures only the recipient can read the content
    nonce, encrypted_body = crypto_utils.encrypt_message(msg.content, recipient.public_key)
    
    # 3. Sign the message using Sender's Private Key
    # This ensures integrity and authenticity (Non-repudiation)
    signature = crypto_utils.sign_data(msg.content, clean_private_key)
    
    # 4. Create and save the message record
    new_message = models.Message(
        sender_id=sender.id,
        recipient_id=recipient.id,
        ciphertext_body=encrypted_body,
        nonce=nonce,
        signature=signature
    )
    
    db.add(new_message)
    db.commit()
    db.refresh(new_message)
    
    return new_message

class MessageFetchRequest(BaseModel):
    username: str
    private_key: str

@app.post("/messages/my", response_model=list[schemas.DecryptedMessageResponse])
def get_my_messages(data: MessageFetchRequest, db: Session = Depends(get_db)):
    # 1. FIX: Naprawa klucza prywatnego (znaki nowej linii)
    clean_private_key = data.private_key.replace("\\n", "\n")
    
    user = db.query(models.User).filter(models.User.username == data.username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    messages = db.query(models.Message).filter(models.Message.recipient_id == user.id).all()
    decrypted_list = []

    for msg in messages:
        try:
            # 2. Używamy oczyszczonego klucza
            decrypted_content = crypto_utils.decrypt_message(
                msg.ciphertext_body, 
                msg.nonce, 
                clean_private_key
            )
            
            if not decrypted_content:
                continue

            sender = db.query(models.User).filter(models.User.id == msg.sender_id).first()
            is_signature_valid = False
            if sender and sender.public_key:
                is_signature_valid = crypto_utils.verify_signature(
                    decrypted_content, 
                    msg.signature, 
                    sender.public_key
                )

            decrypted_list.append({
                "id": msg.id,
                "sender_username": sender.username if sender else "Unknown",
                "content": decrypted_content,
                "signature_valid": is_signature_valid,
                "is_read": msg.is_read,
                "created_at": msg.created_at
            })
        except Exception:
            continue
    return decrypted_list


@app.delete("/messages/{message_id}")
def delete_message(message_id: int, db: Session = Depends(get_db)):
    """Deletes a specific message from the database."""
    msg = db.query(models.Message).filter(models.Message.id == message_id).first()
    if not msg:
        raise HTTPException(status_code=404, detail="Message not found")
    
    db.delete(msg)
    db.commit()
    return {"message": "Message deleted successfully"}

@app.patch("/messages/{message_id}/read")
def mark_message_as_read(message_id: int, db: Session = Depends(get_db)):
    """Marks a message as read in the database."""
    msg = db.query(models.Message).filter(models.Message.id == message_id).first()
    if not msg:
        raise HTTPException(status_code=404, detail="Message not found")
    
    msg.is_read = True
    db.commit()
    return {"message": "Message marked as read"}