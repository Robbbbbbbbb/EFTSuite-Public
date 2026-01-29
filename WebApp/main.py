"""
EFTSuite Web Application - Secure Version

A secure web application for converting fingerprint cards (FD-258) to digital EFT files.
Includes user authentication, session management, rate limiting, and secure data handling.
"""

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Request, Depends, Cookie, Header
from fastapi.exceptions import RequestValidationError
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse, FileResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, validator, Field
from starlette.middleware.base import BaseHTTPMiddleware
from contextlib import asynccontextmanager
import shutil
import os
import re
import uuid
import json
import base64
import asyncio
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any, Union

try:
    import cv2
except ImportError:
    cv2 = None
try:
    import fitz  # PyMuPDF
except ImportError:
    fitz = None

# Rate limiting
try:
    from slowapi import Limiter, _rate_limit_exceeded_handler
    from slowapi.util import get_remote_address
    from slowapi.errors import RateLimitExceeded
    RATE_LIMITING_AVAILABLE = True
except ImportError:
    RATE_LIMITING_AVAILABLE = False

from services.image_processing import align_image, get_default_boxes, apply_crop_and_rotate
from services.eft_generator import generate_eft
from services.fingerprint import Fingerprint
from services.eft_parser import EFTParser
from services.eft_editor import EFTEditor
from services.fd258_generator import FD258Generator
from services.nbis_helper import convert_wsq_to_raw
from services.auth import AuthManager, AuthSession
from services.secure_delete import SecureDelete, SessionCleaner


# =============================================================================
# Configuration
# =============================================================================

# Environment-based configuration
DEBUG = os.environ.get("DEBUG", "false").lower() == "true"
REQUIRE_AUTH = os.environ.get("REQUIRE_AUTH", "true").lower() == "true"
ALLOW_REGISTRATION = os.environ.get("ALLOW_REGISTRATION", "true").lower() == "true"
MAX_UPLOAD_SIZE_MB = int(os.environ.get("MAX_UPLOAD_SIZE_MB", "50"))
SESSION_TIMEOUT_HOURS = int(os.environ.get("SESSION_TIMEOUT_HOURS", "2"))

# Paths
TMP_DIR = "/app/temp"
DATA_DIR = "/app/data"
os.makedirs(TMP_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)


# =============================================================================
# Rate Limiting Setup
# =============================================================================

if RATE_LIMITING_AVAILABLE:
    limiter = Limiter(key_func=get_remote_address)
else:
    limiter = None


# =============================================================================
# Lifecycle Management
# =============================================================================

# Initialize auth manager
auth_manager = AuthManager(db_path=os.path.join(DATA_DIR, "users.db"))

# Initialize secure delete
secure_delete = SecureDelete(passes=3)
session_cleaner = SessionCleaner(TMP_DIR, secure_delete)

# In-memory session store (for EFT processing, not auth)
SESSIONS = {}

# Background task for session cleanup
async def cleanup_expired_sessions():
    """Periodically clean up expired sessions"""
    while True:
        await asyncio.sleep(300)  # Every 5 minutes
        try:
            # Clean expired auth sessions
            auth_manager.cleanup_expired_sessions()

            # Clean expired data sessions
            now = datetime.utcnow()
            expired = []
            for session_id, session_data in list(SESSIONS.items()):
                created = session_data.get("created_at")
                if created:
                    age = now - created
                    if age > timedelta(hours=SESSION_TIMEOUT_HOURS):
                        expired.append(session_id)

            for session_id in expired:
                # Securely delete session data
                session_cleaner.cleanup_session(session_id)
                if session_id in SESSIONS:
                    del SESSIONS[session_id]

            if expired:
                print(f"Cleaned up {len(expired)} expired sessions")
        except Exception as e:
            print(f"Error in cleanup task: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan management"""
    # Startup
    print("Starting EFTSuite with security features enabled")
    print(f"  - Authentication required: {REQUIRE_AUTH}")
    print(f"  - Registration allowed: {ALLOW_REGISTRATION}")
    print(f"  - Session timeout: {SESSION_TIMEOUT_HOURS} hours")

    # Create default admin if no users exist
    if auth_manager.get_user_count() == 0:
        default_password = os.environ.get("DEFAULT_ADMIN_PASSWORD", "ChangeMe123!")
        success, msg = auth_manager.create_user("admin", default_password, is_admin=True)
        if success:
            print(f"  - Created default admin user (password: {default_password})")
            print("  - IMPORTANT: Change the default password immediately!")
        else:
            print(f"  - Failed to create default admin: {msg}")

    # Start cleanup task
    cleanup_task = asyncio.create_task(cleanup_expired_sessions())

    yield

    # Shutdown
    cleanup_task.cancel()
    try:
        await cleanup_task
    except asyncio.CancelledError:
        pass


# =============================================================================
# FastAPI App
# =============================================================================

app = FastAPI(
    title="EFTSuite",
    description="Secure fingerprint card to EFT converter",
    version="2.1.0",
    lifespan=lifespan
)

# Add rate limiting if available
if RATE_LIMITING_AVAILABLE:
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


# =============================================================================
# Security Middleware
# =============================================================================

class SecurityMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses"""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        # Security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"

        # Cache control for sensitive endpoints
        if "/api/" in request.url.path:
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
            response.headers["Pragma"] = "no-cache"

        return response


app.add_middleware(SecurityMiddleware)

# CORS configuration (restrictive by default)
ALLOWED_ORIGINS = os.environ.get("ALLOWED_ORIGINS", "").split(",")
ALLOWED_ORIGINS = [o.strip() for o in ALLOWED_ORIGINS if o.strip()]

if ALLOWED_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["*"],
    )


# =============================================================================
# Error Handlers
# =============================================================================

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handle validation errors without exposing sensitive data"""
    # Log details server-side only
    if DEBUG:
        print(f"Validation Error: {exc.errors()}")

    # Return sanitized response
    return JSONResponse(
        status_code=422,
        content={"detail": "Invalid request data", "errors": [
            {"field": err.get("loc", [])[-1] if err.get("loc") else "unknown",
             "message": err.get("msg", "Invalid value")}
            for err in exc.errors()
        ]},
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle unexpected errors without exposing stack traces"""
    if DEBUG:
        print(f"Unhandled error: {exc}")
        import traceback
        traceback.print_exc()

    return JSONResponse(
        status_code=500,
        content={"detail": "An internal error occurred"},
    )


# =============================================================================
# Authentication Dependencies
# =============================================================================

def get_client_ip(request: Request) -> str:
    """Get client IP, considering proxy headers"""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


async def get_auth_token(
    request: Request,
    authorization: Optional[str] = Header(None),
    auth_token: Optional[str] = Cookie(None)
) -> Optional[str]:
    """Extract auth token from header or cookie"""
    # Try Authorization header first
    if authorization:
        if authorization.startswith("Bearer "):
            return authorization[7:]
        return authorization

    # Fall back to cookie
    return auth_token


async def require_auth(
    request: Request,
    token: Optional[str] = Depends(get_auth_token)
) -> AuthSession:
    """Dependency that requires valid authentication"""
    if not REQUIRE_AUTH:
        # Return a dummy session for unauthenticated mode
        return AuthSession(
            token="",
            user_id=0,
            username="anonymous",
            created_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(days=365),
            data_sessions=list(SESSIONS.keys())
        )

    if not token:
        raise HTTPException(
            status_code=401,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"}
        )

    session = auth_manager.validate_token(token)
    if not session:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"}
        )

    return session


async def optional_auth(
    request: Request,
    token: Optional[str] = Depends(get_auth_token)
) -> Optional[AuthSession]:
    """Dependency that optionally authenticates"""
    if not token:
        return None
    return auth_manager.validate_token(token)


# =============================================================================
# Input Validation Helpers
# =============================================================================

def validate_session_id(session_id: str) -> str:
    """Validate session ID is a valid UUID"""
    try:
        uuid.UUID(session_id)
        return session_id
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid session ID format")


def validate_filename(filename: str) -> str:
    """Validate and sanitize filename to prevent path traversal"""
    # Remove any path components
    filename = os.path.basename(filename)

    # Check for dangerous patterns
    if not filename or filename.startswith('.') or '..' in filename:
        raise HTTPException(status_code=400, detail="Invalid filename")

    # Only allow safe characters
    if not re.match(r'^[\w\-. ]+$', filename):
        raise HTTPException(status_code=400, detail="Invalid filename characters")

    return filename


def validate_path_safety(base_dir: str, file_path: str) -> str:
    """Ensure file path stays within base directory"""
    abs_base = os.path.abspath(base_dir)
    abs_path = os.path.abspath(file_path)

    if not abs_path.startswith(abs_base + os.sep):
        raise HTTPException(status_code=403, detail="Access denied")

    return abs_path


def sanitize_text(text: str, max_length: int = 100, allow_spaces: bool = True) -> str:
    """Sanitize text input"""
    if not text:
        return ""

    # Basic sanitation
    text = text.strip()

    # Remove control characters
    text = ''.join(c for c in text if ord(c) >= 32 or c in '\n\r\t')

    # Limit length
    text = text[:max_length]

    if not allow_spaces:
        text = ''.join(c for c in text if not c.isspace())

    return text


# =============================================================================
# Request Models (with validation)
# =============================================================================

class Box(BaseModel):
    id: str
    fp_number: int = Field(..., ge=1, le=15)
    x: float = Field(..., ge=0)
    y: float = Field(..., ge=0)
    w: float = Field(..., ge=0)
    h: float = Field(..., ge=0)


class CropRequest(BaseModel):
    session_id: str
    rotation: int = Field(..., ge=-360, le=360)
    x: int = Field(..., ge=0)
    y: int = Field(..., ge=0)
    w: int = Field(..., ge=1)
    h: int = Field(..., ge=1)

    @validator('session_id')
    def validate_session(cls, v):
        validate_session_id(v)
        return v


class GenerateRequest(BaseModel):
    session_id: str
    boxes: List[Box]
    type2_data: Dict[str, Any]
    bypass_ssn: Optional[bool] = False
    mode: Optional[str] = "rolled"

    @validator('session_id')
    def validate_session(cls, v):
        validate_session_id(v)
        return v

    @validator('mode')
    def validate_mode(cls, v):
        if v not in ['atf', 'rolled']:
            raise ValueError('Mode must be atf or rolled')
        return v


class CaptureSessionRequest(BaseModel):
    l_slap: Optional[str] = None
    r_slap: Optional[str] = None
    thumbs: Optional[str] = None
    prints: Optional[Dict[str, str]] = None


class SaveEFTRequest(BaseModel):
    session_id: str
    type2_data: Dict[str, Any]

    @validator('session_id')
    def validate_session(cls, v):
        validate_session_id(v)
        return v


class SelectPageRequest(BaseModel):
    session_id: str
    page_index: int = Field(..., ge=0)

    @validator('session_id')
    def validate_session(cls, v):
        validate_session_id(v)
        return v


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=1)


class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8)

    @validator('username')
    def validate_username(cls, v):
        if not v[0].isalpha():
            raise ValueError('Username must start with a letter')
        if not all(c.isalnum() or c in '_-' for c in v):
            raise ValueError('Username can only contain letters, numbers, underscores, and hyphens')
        return v.lower()


class ChangePasswordRequest(BaseModel):
    old_password: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=8)


# =============================================================================
# Static Files and Main Page
# =============================================================================

# Serve static files
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/")
async def read_index(auth: Optional[AuthSession] = Depends(optional_auth)):
    """Serve the main page or redirect to login"""
    if REQUIRE_AUTH and not auth:
        return RedirectResponse(url="/login")
    return FileResponse("static/index.html")


@app.get("/login")
async def login_page():
    """Serve the login page"""
    return FileResponse("static/login.html")


# =============================================================================
# Authentication Endpoints
# =============================================================================

@app.post("/api/auth/login")
async def login(request: Request, data: LoginRequest):
    """Authenticate user and return token"""
    if RATE_LIMITING_AVAILABLE:
        # Rate limit: 5 attempts per minute per IP
        pass  # Handled by decorator when available

    ip_address = get_client_ip(request)
    user_agent = request.headers.get("User-Agent", "")

    success, message, token = auth_manager.authenticate(
        data.username,
        data.password,
        ip_address,
        user_agent
    )

    if not success:
        raise HTTPException(status_code=401, detail=message)

    response = JSONResponse(content={"message": message, "token": token})

    # Set secure cookie
    response.set_cookie(
        key="auth_token",
        value=token,
        httponly=True,
        secure=not DEBUG,  # Require HTTPS in production
        samesite="strict",
        max_age=SESSION_TIMEOUT_HOURS * 3600
    )

    return response


@app.post("/api/auth/register")
async def register(request: Request, data: RegisterRequest):
    """Register a new user"""
    if not ALLOW_REGISTRATION:
        raise HTTPException(status_code=403, detail="Registration is disabled")

    ip_address = get_client_ip(request)

    # Rate limit registration
    if RATE_LIMITING_AVAILABLE:
        pass  # Handled by decorator

    success, message = auth_manager.create_user(data.username, data.password)

    if not success:
        raise HTTPException(status_code=400, detail=message)

    # Log the registration
    auth_manager.log_action(None, "REGISTER", f"New user: {data.username}", ip_address)

    return {"message": message}


@app.post("/api/auth/logout")
async def logout(
    request: Request,
    auth: AuthSession = Depends(require_auth)
):
    """Logout and invalidate session"""
    ip_address = get_client_ip(request)
    auth_manager.logout(auth.token, ip_address)

    response = JSONResponse(content={"message": "Logged out successfully"})
    response.delete_cookie("auth_token")

    return response


@app.get("/api/auth/me")
async def get_current_user(auth: AuthSession = Depends(require_auth)):
    """Get current user info"""
    return {
        "user_id": auth.user_id,
        "username": auth.username,
        "expires_at": auth.expires_at.isoformat()
    }


@app.post("/api/auth/change-password")
async def change_password(
    request: Request,
    data: ChangePasswordRequest,
    auth: AuthSession = Depends(require_auth)
):
    """Change user password"""
    success, message = auth_manager.change_password(
        auth.token,
        data.old_password,
        data.new_password
    )

    if not success:
        raise HTTPException(status_code=400, detail=message)

    return {"message": message}


# =============================================================================
# Health Check
# =============================================================================

@app.get("/health")
async def health_check():
    """Health check endpoint for Docker/load balancer"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "auth_required": REQUIRE_AUTH
    }


# =============================================================================
# Session Management Helpers
# =============================================================================

def create_session(auth: AuthSession) -> str:
    """Create a new data processing session"""
    session_id = str(uuid.uuid4())
    session_dir = os.path.join(TMP_DIR, session_id)
    os.makedirs(session_dir, exist_ok=True)

    SESSIONS[session_id] = {
        "created_at": datetime.utcnow(),
        "user_id": auth.user_id,
        "boxes": []
    }

    # Register with auth system
    if auth.token:
        auth_manager.register_data_session(auth.token, session_id)

    return session_id


def get_session(session_id: str, auth: AuthSession) -> dict:
    """Get session data, verifying ownership"""
    session_id = validate_session_id(session_id)

    if session_id not in SESSIONS:
        raise HTTPException(status_code=404, detail="Session not found")

    session = SESSIONS[session_id]

    # Verify ownership
    if REQUIRE_AUTH and session.get("user_id") != auth.user_id:
        if not auth_manager.owns_data_session(auth.token, session_id):
            raise HTTPException(status_code=403, detail="Access denied")

    # Update last accessed
    session["last_accessed"] = datetime.utcnow()

    return session


def get_session_dir(session_id: str) -> str:
    """Get session directory path"""
    session_id = validate_session_id(session_id)
    session_dir = os.path.join(TMP_DIR, session_id)
    validate_path_safety(TMP_DIR, session_dir)
    return session_dir


# =============================================================================
# Upload Endpoints
# =============================================================================

@app.post("/api/upload")
async def upload_image(
    request: Request,
    file: UploadFile = File(...),
    auth: AuthSession = Depends(require_auth)
):
    """Upload a fingerprint card image"""
    # Validate file size
    content = await file.read()
    if len(content) > MAX_UPLOAD_SIZE_MB * 1024 * 1024:
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Maximum size is {MAX_UPLOAD_SIZE_MB}MB"
        )

    # Validate file type
    ext = os.path.splitext(file.filename or "")[1].lower()
    allowed_extensions = {'.jpg', '.jpeg', '.png', '.bmp', '.tiff', '.tif', '.pdf'}
    if ext not in allowed_extensions:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid file type. Allowed: {', '.join(allowed_extensions)}"
        )

    # Create session
    session_id = create_session(auth)
    session_dir = get_session_dir(session_id)

    if not ext:
        ext = ".jpg"

    file_path = os.path.join(session_dir, "original" + ext)
    with open(file_path, "wb") as buffer:
        buffer.write(content)

    try:
        # Check if PDF
        if ext == ".pdf":
            if fitz is None:
                raise HTTPException(status_code=500, detail="PDF processing not available")

            doc = fitz.open(file_path)
            page_count = doc.page_count

            if page_count == 1:
                # Auto-convert single page
                page = doc.load_page(0)
                zoom = 500 / 72
                mat = fitz.Matrix(zoom, zoom)
                pix = page.get_pixmap(matrix=mat)

                img_path = os.path.join(session_dir, "original.png")
                pix.save(img_path)
                file_path = img_path

                with open(file_path, "rb") as f:
                    img_bytes = f.read()
                    img_base64 = base64.b64encode(img_bytes).decode('utf-8')

                SESSIONS[session_id]["image_path"] = file_path

                return {
                    "session_id": session_id,
                    "image_base64": img_base64
                }
            else:
                # Multi-page PDF
                previews = []
                for i in range(min(page_count, 20)):  # Limit pages
                    page = doc.load_page(i)
                    zoom = 0.5
                    mat = fitz.Matrix(zoom, zoom)
                    pix = page.get_pixmap(matrix=mat)
                    img_data = pix.tobytes("png")
                    b64 = base64.b64encode(img_data).decode('utf-8')
                    previews.append(b64)

                SESSIONS[session_id]["mode"] = "pdf_select"
                SESSIONS[session_id]["pdf_path"] = file_path
                SESSIONS[session_id]["page_count"] = page_count

                return {
                    "session_id": session_id,
                    "type": "pdf_selection",
                    "pages": previews
                }

        # Normal image processing
        warning = None
        if cv2 is not None:
            img = cv2.imread(file_path)
            if img is not None:
                h, w = img.shape[:2]
                ppi = w / 8.0
                if ppi < 490:
                    warning = f"Low resolution detected (~{int(ppi)} PPI). Minimum 500 PPI required for valid EFTs."

        with open(file_path, "rb") as f:
            img_bytes = f.read()
            img_base64 = base64.b64encode(img_bytes).decode('utf-8')

        SESSIONS[session_id]["image_path"] = file_path

        # Log the upload
        auth_manager.log_action(
            auth.token, "UPLOAD",
            f"Session {session_id}, file size {len(content)} bytes",
            get_client_ip(request)
        )

        return {
            "session_id": session_id,
            "image_base64": img_base64,
            "warning": warning
        }

    except HTTPException:
        raise
    except Exception as e:
        # Clean up on error
        session_cleaner.cleanup_session(session_id)
        if session_id in SESSIONS:
            del SESSIONS[session_id]
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/select_pdf_page")
async def select_pdf_page(
    data: SelectPageRequest,
    auth: AuthSession = Depends(require_auth)
):
    """Select a page from multi-page PDF"""
    session = get_session(data.session_id, auth)

    if session.get("mode") != "pdf_select":
        raise HTTPException(status_code=400, detail="Invalid session mode")

    pdf_path = session["pdf_path"]
    page_idx = data.page_index

    try:
        doc = fitz.open(pdf_path)
        if page_idx < 0 or page_idx >= doc.page_count:
            raise HTTPException(status_code=400, detail="Invalid page index")

        page = doc.load_page(page_idx)
        zoom = 500 / 72
        mat = fitz.Matrix(zoom, zoom)
        pix = page.get_pixmap(matrix=mat)

        session_dir = get_session_dir(data.session_id)
        img_path = os.path.join(session_dir, "original.png")
        pix.save(img_path)

        # Update session
        SESSIONS[data.session_id] = {
            **session,
            "image_path": img_path,
            "mode": None,
            "boxes": []
        }

        with open(img_path, "rb") as f:
            b64 = base64.b64encode(f.read()).decode('utf-8')

        return {
            "session_id": data.session_id,
            "image_base64": b64
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/start_capture_session")
async def start_capture_session(
    request: Request,
    data: CaptureSessionRequest,
    auth: AuthSession = Depends(require_auth)
):
    """Create session from live scanner capture"""
    session_id = create_session(auth)
    session_dir = get_session_dir(session_id)

    images_map = {}

    try:
        def save_b64(b64_str, name):
            # Validate base64
            try:
                decoded = base64.b64decode(b64_str)
            except Exception:
                raise HTTPException(status_code=400, detail="Invalid base64 data")

            path = os.path.join(session_dir, name)
            with open(path, "wb") as f:
                f.write(decoded)
            return path

        if data.l_slap:
            images_map[14] = save_b64(data.l_slap, "14.png")
        if data.r_slap:
            images_map[13] = save_b64(data.r_slap, "13.png")
        if data.thumbs:
            images_map[15] = save_b64(data.thumbs, "15.png")

        if data.prints:
            for k, b64 in data.prints.items():
                try:
                    fp_num = int(k)
                    if fp_num < 1 or fp_num > 15:
                        continue

                    if b64 == "SKIP":
                        fname = f"{k}.jp2"
                        dest_path = os.path.join(session_dir, fname)

                        unprintable_path = os.path.abspath("./static/img/unprintable.jp2")
                        if os.path.exists(unprintable_path):
                            shutil.copy(unprintable_path, dest_path)
                        elif cv2 is not None:
                            import numpy as np
                            blank_img = np.ones((500, 500, 3), dtype=np.uint8) * 255
                            cv2.imwrite(dest_path, blank_img)

                        images_map[fp_num] = dest_path
                    else:
                        images_map[fp_num] = save_b64(b64, f"{k}.png")
                except ValueError:
                    continue

        SESSIONS[session_id]["mode"] = "capture"
        SESSIONS[session_id]["images"] = images_map

        auth_manager.log_action(
            auth.token, "CAPTURE_SESSION",
            f"Session {session_id}, {len(images_map)} images",
            get_client_ip(request)
        )

        return {"session_id": session_id}

    except HTTPException:
        raise
    except Exception as e:
        session_cleaner.cleanup_session(session_id)
        if session_id in SESSIONS:
            del SESSIONS[session_id]
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# Processing Endpoints
# =============================================================================

@app.post("/api/process_crop")
async def process_crop(
    data: CropRequest,
    auth: AuthSession = Depends(require_auth)
):
    """Apply crop and rotation to uploaded image"""
    session = get_session(data.session_id, auth)
    session_dir = get_session_dir(data.session_id)

    if "image_path" in session:
        original_path = session["image_path"]
    else:
        original_path = os.path.join(session_dir, "original.jpg")

    if not os.path.exists(original_path):
        raise HTTPException(status_code=404, detail="Original image not found")

    try:
        crop_rect = {'x': data.x, 'y': data.y, 'w': data.w, 'h': data.h}
        processed_img = apply_crop_and_rotate(original_path, data.rotation, crop_rect)

        aligned_path = os.path.join(session_dir, "aligned.png")
        cv2.imwrite(aligned_path, processed_img)

        SESSIONS[data.session_id]["image_path"] = aligned_path

        boxes = get_default_boxes(processed_img.shape)
        SESSIONS[data.session_id]["boxes"] = boxes

        _, buffer = cv2.imencode('.png', processed_img)
        img_base64 = base64.b64encode(buffer).decode('utf-8')

        return {
            "image_base64": img_base64,
            "boxes": boxes
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/preview")
async def preview_crops(
    data: GenerateRequest,
    auth: AuthSession = Depends(require_auth)
):
    """Generate preview crops for verification"""
    session = get_session(data.session_id, auth)

    img_path = session.get("image_path")
    if not img_path or not os.path.exists(img_path):
        raise HTTPException(status_code=404, detail="Image not found")

    img = cv2.imread(img_path)
    previews = {}

    target_fps = list(range(1, 11)) if data.mode == "rolled" else [13, 14, 15]

    for box in data.boxes:
        if box.fp_number not in target_fps:
            continue

        x, y, w, h = int(box.x), int(box.y), int(box.w), int(box.h)
        x = max(0, x)
        y = max(0, y)
        w = min(w, img.shape[1] - x)
        h = min(h, img.shape[0] - y)

        if w <= 0 or h <= 0:
            continue

        crop = img[y:y+h, x:x+w]
        _, buffer = cv2.imencode('.jpg', crop)
        b64 = base64.b64encode(buffer).decode('utf-8')
        previews[box.id] = b64

    return {"previews": previews}


@app.post("/api/generate")
async def generate_eft_endpoint(
    request: Request,
    data: GenerateRequest,
    auth: AuthSession = Depends(require_auth)
):
    """Generate EFT file from fingerprints"""
    session = get_session(data.session_id, auth)
    session_dir = get_session_dir(data.session_id)

    if cv2 is None:
        raise HTTPException(status_code=500, detail="OpenCV not available")

    prints_map = {}
    fp_objects = []

    if session.get("mode") == "capture":
        images_map = session["images"]
        for box in data.boxes:
            target_path = images_map.get(box.fp_number) or images_map.get(str(box.fp_number))

            if target_path:
                img = cv2.imread(target_path)
                if img is None:
                    continue

                fp = Fingerprint(img, box.fp_number, session_dir, data.session_id)
                fp_objects.append(fp)

                if data.mode == "rolled":
                    result_path = fp.process_and_convert_raw(type4=True)
                else:
                    result_path = fp.process_and_convert_raw()

                if result_path:
                    prints_map[box.fp_number] = fp
    else:
        img_path = session.get("image_path")
        if not img_path or not os.path.exists(img_path):
            raise HTTPException(status_code=404, detail="Image not found")

        img = cv2.imread(img_path)

        for box in data.boxes:
            x, y, w, h = int(box.x), int(box.y), int(box.w), int(box.h)

            if w <= 0 or h <= 0:
                continue

            y = max(0, y)
            x = max(0, x)
            h = min(h, img.shape[0] - y)
            w = min(w, img.shape[1] - x)

            if w <= 0 or h <= 0:
                continue

            crop = img[y:y+h, x:x+w]

            fp = Fingerprint(crop, box.fp_number, session_dir, data.session_id)
            fp_objects.append(fp)

            if data.mode == "rolled":
                result_path = fp.process_and_convert_raw(type4=True)
            else:
                result_path = fp.process_and_convert_raw()

            if result_path:
                prints_map[box.fp_number] = fp

    if not fp_objects:
        raise HTTPException(status_code=400, detail="No valid fingerprints found")

    try:
        gen_data = data.type2_data.copy()
        gen_data["bypass_ssn"] = data.bypass_ssn

        eft_path = generate_eft(
            gen_data, data.session_id,
            {fp.fp_number: fp for fp in fp_objects},
            mode=data.mode
        )

        # Handle size limits
        max_size = 11.8 * 1024 * 1024
        current_size = os.path.getsize(eft_path)

        bitrates = [2.25, 1.75, 1.25, 0.75]
        retries = 0

        while current_size > max_size and retries < len(bitrates):
            for fp in fp_objects:
                if data.mode == "rolled":
                    fp.process_and_convert_wsq(bitrate=bitrates[retries], type4=True)
                else:
                    fp.process_and_convert_wsq(bitrate=bitrates[retries])

            eft_path = generate_eft(
                gen_data, data.session_id,
                {fp.fp_number: fp for fp in fp_objects},
                mode=data.mode
            )
            current_size = os.path.getsize(eft_path)
            retries += 1

        if current_size > max_size:
            raise HTTPException(
                status_code=400,
                detail=f"EFT size ({current_size} bytes) exceeds limit after compression"
            )

        # Generate safe filename
        fname = sanitize_text(data.type2_data.get("fname", "Unknown"), 50, False)
        lname = sanitize_text(data.type2_data.get("lname", "Unknown"), 50, False)

        safe_fname = "".join(c for c in fname if c.isalnum() or c in '-_')
        safe_lname = "".join(c for c in lname if c.isalnum() or c in '-_')

        filename = f"EFT-{safe_fname}-{safe_lname}.eft"
        new_path = os.path.join(session_dir, filename)
        shutil.move(eft_path, new_path)

        # Log the generation
        auth_manager.log_action(
            auth.token, "GENERATE_EFT",
            f"Session {data.session_id}, size {current_size} bytes",
            get_client_ip(request)
        )

        return {
            "download_url": f"/api/download/{data.session_id}/{filename}",
            "filename": filename
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"EFT generation failed: {str(e)}")


# =============================================================================
# EFT View/Edit Endpoints
# =============================================================================

@app.post("/api/upload_eft")
async def upload_eft(
    request: Request,
    file: UploadFile = File(...),
    auth: AuthSession = Depends(require_auth)
):
    """Upload existing EFT for viewing/editing"""
    content = await file.read()

    if len(content) > MAX_UPLOAD_SIZE_MB * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File too large")

    session_id = create_session(auth)
    session_dir = get_session_dir(session_id)

    file_path = os.path.join(session_dir, "original.eft")
    with open(file_path, "wb") as buffer:
        buffer.write(content)

    SESSIONS[session_id]["eft_path"] = file_path
    SESSIONS[session_id]["mode"] = "view_edit"

    auth_manager.log_action(
        auth.token, "UPLOAD_EFT",
        f"Session {session_id}, size {len(content)} bytes",
        get_client_ip(request)
    )

    return {"session_id": session_id}


@app.get("/api/eft_session/{session_id}")
async def get_eft_session(
    session_id: str,
    auth: AuthSession = Depends(require_auth)
):
    """Parse and return EFT data for viewing"""
    session = get_session(session_id, auth)

    if "eft_path" not in session:
        raise HTTPException(status_code=404, detail="EFT not found in session")

    session_dir = get_session_dir(session_id)
    eft_path = session["eft_path"]

    try:
        parser = EFTParser(eft_path)

        type2_data = parser.get_type2_data()

        images_dir = os.path.join(session_dir, "images")
        images = parser.extract_images(images_dir)

        image_data = []
        for img in images:
            image_data.append({
                "fgp": img["fgp"],
                "url": f"/api/image/{session_id}/{os.path.basename(img['display_path'])}" if img['display_path'] else None,
                "width": img["width"],
                "height": img["height"]
            })

        text_dump = parser.get_text_dump()

        return {
            "type2_data": type2_data,
            "images": image_data,
            "text_dump": text_dump
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to parse EFT: {str(e)}")


@app.get("/api/image/{session_id}/{filename}")
async def get_image(
    session_id: str,
    filename: str,
    auth: AuthSession = Depends(require_auth)
):
    """Get extracted image from EFT"""
    get_session(session_id, auth)  # Verify ownership

    # Validate filename
    filename = validate_filename(filename)

    session_dir = get_session_dir(session_id)
    file_path = os.path.join(session_dir, "images", filename)

    # Validate path stays within session directory
    validate_path_safety(session_dir, file_path)

    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Image not found")

    return FileResponse(file_path)


@app.post("/api/save_eft")
async def save_eft(
    request: Request,
    data: SaveEFTRequest,
    auth: AuthSession = Depends(require_auth)
):
    """Save edited EFT"""
    session = get_session(data.session_id, auth)

    if "eft_path" not in session:
        raise HTTPException(status_code=404, detail="EFT not found in session")

    session_dir = get_session_dir(data.session_id)
    eft_path = session["eft_path"]
    output_path = os.path.join(session_dir, "edited.eft")

    try:
        editor = EFTEditor(eft_path, output_path)
        editor.save(data.type2_data)

        fname = sanitize_text(data.type2_data.get("2.018", "edited"), 50, False)
        safe_fname = "".join(c for c in fname if c.isalnum() or c in '-_,')
        final_name = f"edited-{safe_fname}.eft"

        final_path = os.path.join(session_dir, final_name)
        shutil.move(output_path, final_path)

        auth_manager.log_action(
            auth.token, "SAVE_EFT",
            f"Session {data.session_id}",
            get_client_ip(request)
        )

        return {
            "download_url": f"/api/download/{data.session_id}/{final_name}",
            "filename": final_name
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save EFT: {str(e)}")


# =============================================================================
# Download and Delete Endpoints
# =============================================================================

@app.get("/api/download/{session_id}/{filename}")
async def download_file(
    request: Request,
    session_id: str,
    filename: str,
    auth: AuthSession = Depends(require_auth)
):
    """Download generated file"""
    get_session(session_id, auth)  # Verify ownership

    # Validate filename to prevent path traversal
    filename = validate_filename(filename)

    session_dir = get_session_dir(session_id)
    file_path = os.path.join(session_dir, filename)

    # Validate path stays within session directory
    validate_path_safety(session_dir, file_path)

    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")

    auth_manager.log_action(
        auth.token, "DOWNLOAD",
        f"Session {session_id}, file {filename}",
        get_client_ip(request)
    )

    return FileResponse(file_path, filename=filename)


@app.delete("/api/delete/{session_id}")
async def delete_session(
    request: Request,
    session_id: str,
    auth: AuthSession = Depends(require_auth)
):
    """Securely delete a session and all its data"""
    get_session(session_id, auth)  # Verify ownership

    session_dir = get_session_dir(session_id)

    # Securely delete files
    success = session_cleaner.cleanup_session(session_id)

    # Remove from memory
    if session_id in SESSIONS:
        del SESSIONS[session_id]

    auth_manager.log_action(
        auth.token, "DELETE_SESSION",
        f"Session {session_id}, secure_delete={success}",
        get_client_ip(request)
    )

    return {"message": "Session deleted securely", "secure": success}


@app.delete("/api/delete-all-data")
async def delete_all_user_data(
    request: Request,
    auth: AuthSession = Depends(require_auth)
):
    """Securely delete all data for current user"""
    # Get all sessions for this user
    user_sessions = auth_manager.get_user_data_sessions(auth.token)

    deleted_count = 0
    for session_info in user_sessions:
        session_id = session_info["session_id"]
        if session_cleaner.cleanup_session(session_id):
            deleted_count += 1
        if session_id in SESSIONS:
            del SESSIONS[session_id]

    # Clear from database
    auth_manager.delete_user_data_sessions(auth.token)

    auth_manager.log_action(
        auth.token, "DELETE_ALL_DATA",
        f"Deleted {deleted_count} sessions",
        get_client_ip(request)
    )

    return {
        "message": f"Securely deleted {deleted_count} sessions",
        "count": deleted_count
    }


# =============================================================================
# FD-258 Generation
# =============================================================================

class RawFP:
    def __init__(self, p, w=0, h=0, is_raw=False):
        self.img_path = p
        self.w = w
        self.h = h
        self.is_raw = is_raw


@app.post("/api/generate_fd258")
async def generate_fd258(
    request: Request,
    data: GenerateRequest,
    auth: AuthSession = Depends(require_auth)
):
    """Generate printable FD-258 card"""
    session = get_session(data.session_id, auth)
    session_dir = get_session_dir(data.session_id)

    if session.get("mode") != "capture":
        raise HTTPException(status_code=400, detail="Only available for capture sessions")

    images_map = session["images"]
    prints_map = {}

    # Map individual images
    for i in range(1, 15):
        fp_num = i
        target_path = images_map.get(fp_num) or images_map.get(str(fp_num))

        if target_path and os.path.exists(target_path):
            sfp = RawFP(target_path)
            prints_map[fp_num] = sfp

    # Legacy fallback for slaps
    if len(prints_map) < 4:
        for fp_num in [13, 14, 15]:
            target_path = images_map.get(fp_num) or images_map.get(str(fp_num))

            if not target_path:
                continue

            fp = Fingerprint(cv2.imread(target_path), fp_num, session_dir, data.session_id)
            fp.process_and_convert(10)
            if not fp.fingers:
                fp.segment()

            if fp_num == 13:
                prints_map[13] = fp
            elif fp_num == 14:
                prints_map[14] = fp

            for finger in fp.fingers:
                try:
                    fn = int(finger.n)
                    seg_path = os.path.join(session_dir, finger.name)

                    if fp.fp_number == 14:
                        if fn == 7:
                            fn = 10
                        elif fn == 10:
                            fn = 7
                        elif fn == 8:
                            fn = 9
                        elif fn == 9:
                            fn = 8

                    sfp = RawFP(seg_path, finger.sw, finger.sh)
                    if 1 <= fn <= 10:
                        prints_map[fn] = sfp

                    if fn == 11 and 11 not in prints_map:
                        prints_map[11] = sfp
                        prints_map[1] = sfp
                    elif fn == 12 and 12 not in prints_map:
                        prints_map[12] = sfp
                        prints_map[6] = sfp

                    if fn == 1 and 11 not in prints_map:
                        prints_map[11] = sfp
                    if fn == 6 and 12 not in prints_map:
                        prints_map[12] = sfp

                except Exception:
                    continue

    try:
        generator = FD258Generator("static/img/fd258-blank.jpg")
        img_bytes = generator.generate(data.type2_data, prints_map)

        filename = f"fd258-{data.session_id}.jpg"
        out_path = os.path.join(session_dir, filename)
        with open(out_path, "wb") as f:
            f.write(img_bytes)

        auth_manager.log_action(
            auth.token, "GENERATE_FD258",
            f"Session {data.session_id}",
            get_client_ip(request)
        )

        return {
            "download_url": f"/api/download/{data.session_id}/{filename}",
            "filename": filename
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"FD258 generation failed: {str(e)}")


# =============================================================================
# User Data Management
# =============================================================================

@app.get("/api/my-sessions")
async def list_my_sessions(auth: AuthSession = Depends(require_auth)):
    """List all sessions for current user"""
    sessions = auth_manager.get_user_data_sessions(auth.token)

    # Add size information
    for session_info in sessions:
        session_info["size_bytes"] = session_cleaner.get_session_size(session_info["session_id"])

    return {"sessions": sessions}


@app.get("/api/storage-usage")
async def get_storage_usage(auth: AuthSession = Depends(require_auth)):
    """Get storage usage for current user"""
    sessions = auth_manager.get_user_data_sessions(auth.token)
    total_size = sum(
        session_cleaner.get_session_size(s["session_id"])
        for s in sessions
    )

    return {
        "session_count": len(sessions),
        "total_bytes": total_size,
        "total_mb": round(total_size / (1024 * 1024), 2)
    }
