import sys
import os
import csv
import io
import json
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# Add parent dir to path so we can import from database/
_current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(_current_dir)
sys.path.append(os.path.dirname(_current_dir))

from database.db import init_db, get_recent_scans, log_scan, clear_all_scans
from utils.cache import get_cached_result, cache_result
from backend.detector import analyze_url

limiter = Limiter(key_func=get_remote_address)

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(title="AI Phishing Detection API", lifespan=lifespan)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Restrict CORS to allowed origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:5500"],
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
    cached: bool = False

@app.post("/scan", response_model=ScanResponse)
@limiter.limit("30/minute")
def scan(request: Request, body: ScanRequest):
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
def get_logs(request: Request):
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
