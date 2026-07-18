"""
session_store.py
────────────────
Centralised session state shared between the existing frontend API (main.py)
and the new v1 remote API (api_v1.py).

Design rules:
  • One session  = one EFT.  Sessions must never overlap.
  • Sessions expire after SESSION_TTL_SECONDS (default 3600 = 1 hour).
  • A background asyncio task purges expired sessions automatically.
"""

import os
import shutil
import asyncio
import time
import uuid
from typing import Dict, Any

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Try /app/temp (Docker), fallback to ./temp (local development)
TMP_DIR: str = "/app/temp"
try:
    os.makedirs(TMP_DIR, exist_ok=True)
    # Test writability
    test_file = os.path.join(TMP_DIR, ".write_test")
    with open(test_file, "w") as f:
        f.write("test")
    os.remove(test_file)
except OSError:
    TMP_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "temp"))

SESSION_TTL_SECONDS: int = 3600  # 1 hour

# ---------------------------------------------------------------------------
# In-memory session store
# Each entry:  session_id (str) -> { ...session_data..., "_created_at": float }
# ---------------------------------------------------------------------------

SESSIONS: Dict[str, Any] = {}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def new_session_id() -> str:
    """Generate a new UUID4 session ID."""
    return str(uuid.uuid4())


def validate_session_id(session_id: str) -> bool:
    """Return True if session_id is a valid UUID4 string."""
    try:
        uuid.UUID(session_id, version=4)
        return True
    except ValueError:
        return False


def session_dir(session_id: str) -> str:
    """Return the filesystem path for a session's temp directory."""
    return os.path.join(TMP_DIR, session_id)


def create_session(data: Dict[str, Any]) -> str:
    """
    Create a new session with the supplied data dict and return the session_id.
    Automatically stamps _created_at for TTL tracking.
    """
    sid = new_session_id()
    sdir = session_dir(sid)
    os.makedirs(sdir, exist_ok=True)
    SESSIONS[sid] = {**data, "_created_at": time.monotonic()}
    return sid


def get_session(session_id: str) -> Dict[str, Any] | None:
    """Return the session dict or None if not found."""
    return SESSIONS.get(session_id)


def delete_session(session_id: str) -> bool:
    """
    Remove session from memory and delete its temp directory.
    Returns True if the session existed, False otherwise.
    """
    if session_id not in SESSIONS:
        return False
    del SESSIONS[session_id]
    sdir = session_dir(session_id)
    if os.path.exists(sdir):
        shutil.rmtree(sdir, ignore_errors=True)
    return True


# ---------------------------------------------------------------------------
# Background cleanup task
# ---------------------------------------------------------------------------

async def _cleanup_expired_sessions() -> None:
    """
    Asyncio background task: runs every 5 minutes and removes sessions that
    have exceeded SESSION_TTL_SECONDS.
    """
    while True:
        await asyncio.sleep(300)  # check every 5 minutes
        now = time.monotonic()
        expired = [
            sid
            for sid, data in list(SESSIONS.items())
            if now - data.get("_created_at", now) > SESSION_TTL_SECONDS
        ]
        for sid in expired:
            print(f"[session_store] Expiring session {sid}")
            delete_session(sid)


def start_cleanup_task() -> None:
    """
    Schedule the background cleanup coroutine onto the running event loop.
    Call this once from a FastAPI startup event.
    """
    loop = asyncio.get_event_loop()
    loop.create_task(_cleanup_expired_sessions())
