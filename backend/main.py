from fastapi import FastAPI

app = FastAPI(title="SecureMail")

@app.get("/")
def read_root():
    return {"status": "Application works", "info": "Connection with NGINX correct"}