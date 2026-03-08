import os
import json
import redis
from dotenv import load_dotenv

load_dotenv()

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

# Attempt to connect to Redis
try:
    _redis_client = redis.from_url(REDIS_URL, decode_responses=True)
    # Ping to check if available
    _redis_client.ping()
except Exception as e:
    _redis_client = None
    print(f"[cache] \u26a0\ufe0f Redis unavailable: {e}. Caching is disabled.")

def get_cached_result(url: str):
    """
    Checks if URL was scanned before.
    Returns parsed dictionary result or None.
    """
    if not _redis_client:
        return None
    try:
        cached = _redis_client.get(f"scan:{url}")
        if cached:
            return json.loads(cached)
    except Exception:
        pass
    return None

def cache_result(url: str, result: dict):
    """
    Saves result with 24 hour expiry.
    """
    if not _redis_client:
        return
    try:
        # 24 hours = 86400 seconds
        _redis_client.setex(f"scan:{url}", 86400, json.dumps(result))
    except Exception:
        pass
