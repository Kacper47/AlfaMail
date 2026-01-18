from fastapi import FastAPI
import models
from database import engine

# Automatically create database tables if they don't exist
models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="SecureMail")

@app.get("/")
def read_root():
    return {
        "status": "Success",
        "message": "Database models and tables initialized successfully"
    }