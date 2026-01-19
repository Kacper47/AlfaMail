from fastapi import FastAPI, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordBearer
from datetime import datetime, timezone
import models, schemas, auth
from database import engine, SessionLocal
import datetime

# Create database tables
models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="AlfaMail")

# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.post("/register", response_model=schemas.UserResponse, status_code=status.HTTP_201_CREATED)
def register_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    # 1. Check if username already exists
    db_user = db.query(models.User).filter(models.User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    # 2. Hash the password using Argon2id
    hashed_pw = auth.get_password_hash(user.password)
    
    # 3. Create new user instance
    new_user = models.User(
        username=user.username,
        hashed_password=hashed_pw
    )
    
    # 4. Save to database
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    return new_user

@app.post("/login", response_model=schemas.Token)
def login_for_access_token(
    form_data: schemas.LoginRequest, 
    request: Request, 
    db: Session = Depends(get_db)
):
    # 1. Find user
    user = db.query(models.User).filter(models.User.username == form_data.username).first()
    
    # Prepare Audit Log entry
    client_ip = request.client.host
    log_entry = models.AuditLog(
        event_type="login_attempt",
        username=form_data.username,
        ip_address=client_ip,
        timestamp=datetime.datetime.now(datetime.timezone.utc)
    )
    
    # 2. Verify User and Password
    if not user or not auth.verify_password(form_data.password, user.hashed_password):
        # Log failure
        log_entry.event_type = "login_failed"
        db.add(log_entry)
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # 3. Log Success
    log_entry.event_type = "login_success"
    db.add(log_entry)
    db.commit()

    # 4. Generate Token
    access_token_expires = datetime.timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = auth.create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/")
def read_root():
    return {"status": "Application running", "docs_url": "/docs"}