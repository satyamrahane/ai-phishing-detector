import sys
import os
import csv
import io
import json
from datetime import datetime
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Response, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from authlib.integrations.starlette_client import OAuth
from starlette.middleware.sessions import SessionMiddleware
from pydantic import BaseModel
from typing import List

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# Add parent dir to path so we can import from database/
_current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(_current_dir)
sys.path.append(os.path.dirname(_current_dir))

from database.db import init_db, get_recent_scans, log_scan, clear_all_scans, create_user, get_user_by_email, get_db, User
from utils.cache import get_cached_result, cache_result
from backend.detector import analyze_url
from backend.auth import hash_password, verify_password, create_jwt_token, verify_jwt_token

limiter = Limiter(key_func=get_remote_address)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

def get_current_user(token: str = Depends(oauth2_scheme)):
    payload = verify_jwt_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return payload

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(title="AI Phishing Detection API", lifespan=lifespan)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    SessionMiddleware, 
    secret_key=os.getenv("JWT_SECRET", "phishguard-key")
)

oauth = OAuth()
oauth.register(
    name="google",
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"}
)

# Restrict CORS to allowed origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:8000", "http://localhost:8000", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    url: str

class ScanResponse(BaseModel):
    risk_score: int
    status: str
    reasons: List[str]
    ip_info: dict = None
    cached: bool = False

class RegisterRequest(BaseModel):
    name: str
    email: str
    password: str

class LoginRequest(BaseModel):
    email: str
    password: str

@app.post("/auth/register")
async def register(request: RegisterRequest, db=Depends(get_db)):
    existing = db.query(User).filter(
        User.email == request.email
    ).first()
    if existing:
        raise HTTPException(
            status_code=400, 
            detail="Email already registered"
        )
    hashed = hash_password(request.password)
    user = User(
        name=request.name,
        email=request.email,
        hashed_password=hashed,
        created_at=json.dumps(datetime.utcnow().isoformat(timespec='seconds')) # Keep consistency if needed, or just isoformat
    )
    # Actually looking at db.py, created_at is a String.
    user.created_at = datetime.utcnow().isoformat(timespec='seconds')
    
    db.add(user)
    db.commit()
    db.refresh(user)
    token = create_jwt_token(user.id, user.email)
    return {"token": token, "email": user.email, "access_token": token, "token_type": "bearer"} # Added access_token for frontend compatibility

@app.post("/auth/login")
async def login(request: LoginRequest, db=Depends(get_db)):
    user = db.query(User).filter(
        User.email == request.email
    ).first()
    if not user or not verify_password(
        request.password, user.hashed_password
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
        )
    token = create_jwt_token(user.id, user.email)
    return {"token": token, "email": user.email, "access_token": token, "token_type": "bearer"} # Added access_token for frontend compatibility

@app.get("/auth/google")
async def google_login(request: Request):
    redirect_uri = "http://127.0.0.1:5000/auth/google/callback"
    return await oauth.google.authorize_redirect(
        request, redirect_uri
    )

@app.get("/auth/google/callback")
async def google_callback(request: Request, db=Depends(get_db)):
    try:
        token = await oauth.google.authorize_access_token(request)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Google auth failed: {str(e)}")
        
    userinfo = token.get("userinfo")
    if not userinfo:
        raise HTTPException(status_code=400, detail="Could not get user info from Google")
        
    email = userinfo["email"]
    name = userinfo.get("name", email)
    user = db.query(User).filter(User.email == email).first()
    if not user:
        user = User(
            name=name,
            email=email,
            hashed_password=hash_password(
                os.urandom(32).hex()
            ),
            created_at=datetime.utcnow().isoformat(timespec='seconds')
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        
    jwt_token = create_jwt_token(user.id, user.email)
    frontend_url = os.getenv("FRONTEND_URL", "http://127.0.0.1:8000")
    return RedirectResponse(
        url=f"{frontend_url}/dashboard.html?token={jwt_token}"
    )

@app.get("/auth/github") 
async def github_login():
    return {"message": "GitHub OAuth portal coming soon. For now, please use manual login."}

@app.post("/scan", response_model=ScanResponse)
@limiter.limit("30/minute")
def scan(request: Request, body: ScanRequest, user: dict = Depends(get_current_user)):
    url = body.url
    
    if len(url) > 2000:
        raise HTTPException(status_code=400, detail="URL exceeds maximum length of 2000 characters")

    cached = get_cached_result(url)
    if cached:
        cached["cached"] = True
        return cached

    result = analyze_url(url)
    
    # Save to Redis
    cache_result(url, result)

    # Log to PostgreSQL database
    log_scan(url, result["risk_score"], result["status"], result["reasons"])

    result["cached"] = False
    return result

@app.get("/logs")
@limiter.limit("60/minute")
def get_logs(request: Request, user: dict = Depends(get_current_user)):
    scans = get_recent_scans(limit=50)
    total = len(scans)
    phishing = sum(1 for s in scans if s["status"] == "Phishing")
    suspicious = sum(1 for s in scans if s["status"] == "Suspicious")
    safe = sum(1 for s in scans if s["status"] == "Safe")

    return {
        "total_scans": total,
        "phishing_count": phishing,
        "suspicious_count": suspicious,
        "safe_count": safe,
        "scans": scans
    }

@app.get("/export")
@limiter.limit("20/minute")
def export_csv(request: Request):
    scans = get_recent_scans(limit=10000)
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "url", "risk_score", "status", "reasons", "timestamp"])
    
    for s in scans:
        writer.writerow([
            s["id"], 
            s["url"], 
            s["risk_score"], 
            s["status"], 
            json.dumps(s["reasons"]), 
            s["timestamp"]
        ])
        
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment;filename=scans_export.csv"}
    )

@app.delete("/logs")
def clear_logs(request: Request):
    clear_all_scans()
    return {"message": "Scan logs cleared successfully"}
