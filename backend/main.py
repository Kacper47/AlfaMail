from fastapi import FastAPI, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
import models
import schemas
import auth
from database import engine, SessionLocal
import datetime
from datetime import timezone

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