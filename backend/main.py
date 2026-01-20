from fastapi import FastAPI, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
import models
import schemas
import auth
from database import engine, SessionLocal
import datetime
from datetime import timezone
import crypto_utils

# Initialize database tables
models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="AlfaMail")

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


# --- USER REGISTRATION ---
@app.post("/register", response_model=schemas.UserResponse, status_code=status.HTTP_201_CREATED)
def register_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    # 1. Check if the username is already taken
    db_user = db.query(models.User).filter(models.User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    # 2. Hash the password using the Argon2id algorithm
    hashed_pw = auth.get_password_hash(user.password)
    
    # 3. Create a new user record in the database
    new_user = models.User(
        username=user.username,
        hashed_password=hashed_pw
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    return new_user

# --- USER LOGIN (PHASE 1) ---

@app.post("/login", response_model=schemas.LoginResponse)
def login_for_access_token(
    form_data: schemas.LoginRequest, 
    request: Request, 
    db: Session = Depends(get_db)
):
    # Find user by username
    user = db.query(models.User).filter(models.User.username == form_data.username).first()
    
    # Audit Log preparation for the login attempt
    client_ip = request.client.host
    log_entry = models.AuditLog(
        event_type="login_attempt",
        username=form_data.username,
        ip_address=client_ip,
        timestamp=datetime.datetime.now(timezone.utc)
    )
    
    # Verify user existence and password validity
    if not user or not auth.verify_password(form_data.password, user.hashed_password):
        # Log failed attempt
        log_entry.event_type = "login_failed"
        db.add(log_entry)
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Check if 2FA is enabled for this user
    if user.is_2fa_enabled:
        # Do not issue JWT yet; inform that TOTP code is required
        return schemas.LoginResponse(
            username=user.username,
            requires_2fa=True
        )
    
    # Log successful login attempt (when 2FA is disabled)
    log_entry.event_type = "login_success"
    db.add(log_entry)
    db.commit()

    # Generate JWT access token
    access_token_expires = datetime.timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = auth.create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    
    return schemas.LoginResponse(
        access_token=access_token,
        token_type="bearer",
        username=user.username,
        requires_2fa=False
    )


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
        timestamp=datetime.datetime.now(timezone.utc)
    )
    db.add(log_entry)
    db.commit()
    
    return {"access_token": access_token, "token_type": "bearer"}

# --- CRYPTOGRAPHY & KEY MANAGEMENT ---
@app.post("/keys/generate", response_model=schemas.KeyPairResponse)
def generate_keys(username: str, db: Session = Depends(get_db)):
    """
    Generates a new RSA key pair for a user.
    The public key is stored in the database, while the private key is returned once.
    """
    user = db.query(models.User).filter(models.User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    # Generate RSA keys using crypto_utils
    priv_pem, pub_pem = crypto_utils.generate_rsa_key_pair()
    
    # Store the Public Key in the database for encryption by others
    user.public_key = pub_pem
    db.commit()
    
    # Return both keys. 
    # NOTE: In a real app, the server would NEVER see the private key (client-side generation).
    return {
        "private_key": priv_pem,
        "public_key": pub_pem,
        "message": "IMPORTANT: Store your private key securely. It is not saved on the server!"
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
    signature = crypto_utils.sign_data(msg.content, msg.sender_private_key)
    
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


@app.get("/messages/my", response_model=list[schemas.DecryptedMessageResponse])
def get_my_messages(username: str, private_key: str, db: Session = Depends(get_db)):
    """
    Retrieves and decrypts messages for a specific user.
    Handles potential decryption or signature verification errors gracefully.
    """
    user = db.query(models.User).filter(models.User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    messages = db.query(models.Message).filter(models.Message.recipient_id == user.id).all()
    decrypted_list = []

    for msg in messages:
        try:
            # 1. Attempt decryption
            decrypted_content = crypto_utils.decrypt_message(
                msg.ciphertext_body, 
                msg.nonce, 
                private_key
            )
            
            if not decrypted_content:
                continue

            # 2. Verify Sender's Signature
            sender = db.query(models.User).filter(models.User.id == msg.sender_id).first()
            
            # Safety check: Does sender have a public key?
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
                "created_at": msg.created_at
            })
        except Exception as e:
            # Log the error and skip this specific message
            print(f"Error processing message {msg.id}: {e}")
            continue

    return decrypted_list