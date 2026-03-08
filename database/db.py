import json
from datetime import datetime
import os
from sqlalchemy import create_engine, Column, Integer, String, Boolean
from sqlalchemy.orm import declarative_base, sessionmaker

# Import load_dotenv to get DATABASE_URL if not set
from dotenv import load_dotenv
load_dotenv()

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://localhost/phishing_db")

if DATABASE_URL.startswith("sqlite"):
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
else:
    engine = create_engine(DATABASE_URL)
    
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    url = Column(String, nullable=False)
    risk_score = Column(Integer, nullable=False)
    status = Column(String, nullable=False)
    reasons = Column(String, nullable=False)  # Stored as JSON string
    timestamp = Column(String, nullable=False)

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    created_at = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)

def init_db():
    Base.metadata.create_all(bind=engine)

def log_scan(url, risk_score, status, reasons):
    session = SessionLocal()
    try:
        new_scan = Scan(
            url=url,
            risk_score=risk_score,
            status=status,
            reasons=json.dumps(reasons),
            timestamp=datetime.utcnow().isoformat(timespec='seconds')
        )
        session.add(new_scan)
        session.commit()
    finally:
        session.close()

def get_recent_scans(limit=50):
    session = SessionLocal()
    try:
        rows = session.query(Scan).order_by(Scan.id.desc()).limit(limit).all()
        return [
            {
                "id": r.id,
                "url": r.url,
                "risk_score": r.risk_score,
                "status": r.status,
                "reasons": json.loads(r.reasons),
                "timestamp": r.timestamp
            }
            for r in rows
        ]
    finally:
        session.close()

def clear_all_scans():
    session = SessionLocal()
    try:
        session.query(Scan).delete()
        session.commit()
    finally:
        session.close()

def create_user(name, email, hashed_password):
    session = SessionLocal()
    try:
        new_user = User(
            name=name,
            email=email,
            hashed_password=hashed_password,
            created_at=datetime.utcnow().isoformat(timespec='seconds'),
            is_active=True
        )
        session.add(new_user)
        session.commit()
        return new_user.id
    finally:
        session.close()

def get_user_by_email(email):
    session = SessionLocal()
    try:
        # We need to eagerly load or just return a dict, but returning the object will detach it.
        # Actually returning a dictionary is safer in a sessionless context.
        user = session.query(User).filter(User.email == email).first()
        if user:
            return {
                "id": user.id,
                "name": user.name,
                "email": user.email,
                "hashed_password": user.hashed_password,
                "created_at": user.created_at,
                "is_active": user.is_active
            }
        return None
    finally:
        session.close()
