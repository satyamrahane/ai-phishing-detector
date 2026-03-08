import json
from datetime import datetime
import os
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import declarative_base, sessionmaker

# Import load_dotenv to get DATABASE_URL if not set
from dotenv import load_dotenv
load_dotenv()

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://localhost/phishing_db")

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
