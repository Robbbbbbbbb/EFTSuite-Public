"""
api_v1.py
──────────
EFTSuite Remote API — v1 Router
Prefix: /api/v1

"""

from __future__ import annotations

import base64
import os
import shutil
import uuid
from typing import Any, Dict, List, Optional

import cv2

try:
    import fitz  # PyMuPDF
except ImportError:
    fitz = None

from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, field_validator

from services.session_store import (
    SESSIONS,
    TMP_DIR,
    create_session,
    delete_session,
    get_session,
    session_dir,
    validate_session_id,
)
from services.image_processing import apply_crop_and_rotate, get_default_boxes
from services.eft_generator import generate_eft
from services.fingerprint import Fingerprint

# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

router = APIRouter(prefix="/api/v1", tags=["EFTSuite API v1"])

API_VERSION = "1.0"

# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class Box(BaseModel):
    id: str
    fp_number: int
    x: float
    y: float
    w: float
    h: float


class RotateCropRequest(BaseModel):
    session_id: str
    rotation: int
    x: int
    y: int
    w: int
    h: int

    @field_validator("rotation")
    @classmethod
    def validate_rotation(cls, v: int) -> int:
        if v not in (0, 90, 180, 270):
            raise ValueError("rotation must be 0, 90, 180 or 270")
        return v


class SelectPdfPageRequest(BaseModel):
    session_id: str
    page_index: int


class PreviewRequest(BaseModel):
    session_id: str
    boxes: List[Box]
    mode: str = "rolled"

    @field_validator("mode")
    @classmethod
    def validate_mode(cls, v: str) -> str:
        if v not in ("rolled", "atf"):
            raise ValueError("mode must be 'rolled' or 'atf'")
        return v


class GenerateRequest(BaseModel):
    session_id: str
    boxes: List[Box]
    type2_data: Dict[str, Any]
    bypass_ssn: Optional[bool] = False
    mode: Optional[str] = "rolled"

    @field_validator("mode")
    @classmethod
    def validate_mode(cls, v: Optional[str]) -> Optional[str]:
        if v not in (None, "rolled", "atf"):
            raise ValueError("mode must be 'rolled' or 'atf'")
        return v


# ---------------------------------------------------------------------------
# Error helpers
# ---------------------------------------------------------------------------

def api_error(detail: str, code: str, status: int = 400) -> HTTPException:
    """Return a structured HTTPException with our standard error shape."""
    return HTTPException(
        status_code=status,
        detail={"error": True, "detail": detail, "code": code},
    )


def require_session(session_id: str) -> Dict[str, Any]:
    """Validate UUID format and existence; raise api_error on failure."""
    if not validate_session_id(session_id):
        raise api_error("Invalid session ID format", "INVALID_SESSION_ID", 400)
    data = get_session(session_id)
    if data is None:
        raise api_error("Session not found", "SESSION_NOT_FOUND", 404)
    return data


# ---------------------------------------------------------------------------
# Allowed upload extensions
# ---------------------------------------------------------------------------

ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".bmp", ".tiff", ".tif", ".pdf"}
ALLOWED_MIME_PREFIXES = ("image/", "application/pdf")


def _validate_upload(file: UploadFile) -> str:
    """Return the lowercased extension or raise api_error."""
    ext = os.path.splitext(file.filename or "")[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise api_error(
            f"Unsupported file type '{ext}'. Allowed: {', '.join(ALLOWED_EXTENSIONS)}",
            "UNSUPPORTED_FILE_TYPE",
            415,
        )
    return ext


# ---------------------------------------------------------------------------
# Phase 1 — Health check
# ---------------------------------------------------------------------------


@router.get("/health")
async def health_check():
    """Returns API status and version."""
    return {"status": "ok", "version": API_VERSION}


# ---------------------------------------------------------------------------
# Phase 2 — Upload
# ---------------------------------------------------------------------------


@router.post("/upload")
async def api_upload(file: UploadFile = File(...)):
    """
    Step 1: Upload a fingerprint card image (JPEG/PNG/BMP/TIFF/PDF).

    Returns:
        session_id, image_base64, optional warning, optional type='pdf_selection'
    """
    ext = _validate_upload(file)

    # Create session
    sid = str(uuid.uuid4())
    sdir = os.path.join(TMP_DIR, sid)
    os.makedirs(sdir, exist_ok=True)

    file_path = os.path.join(sdir, "original" + ext)
    with open(file_path, "wb") as buf:
        shutil.copyfileobj(file.file, buf)

    try:
        # ── PDF handling ──────────────────────────────────────────────────
        if ext == ".pdf":
            if fitz is None:
                raise api_error("PyMuPDF is not installed on this server", "PDF_NOT_SUPPORTED", 500)

            doc = fitz.open(file_path)
            page_count = doc.page_count

            if page_count == 1:
                # Single page — auto-convert to PNG at 500 DPI
                pix = doc.load_page(0).get_pixmap(matrix=fitz.Matrix(500 / 72, 500 / 72))
                img_path = os.path.join(sdir, "original.png")
                pix.save(img_path)
                file_path = img_path

                with open(file_path, "rb") as f:
                    img_b64 = base64.b64encode(f.read()).decode()

                SESSIONS[sid] = {"image_path": file_path, "boxes": [], "_created_at": __import__("time").monotonic()}
                return {"session_id": sid, "image_base64": img_b64}

            else:
                # Multi-page — return thumbnails for selection
                previews = []
                for i in range(page_count):
                    pix = doc.load_page(i).get_pixmap(matrix=fitz.Matrix(0.5, 0.5))
                    previews.append(base64.b64encode(pix.tobytes("png")).decode())

                SESSIONS[sid] = {
                    "mode": "pdf_select",
                    "pdf_path": file_path,
                    "page_count": page_count,
                    "_created_at": __import__("time").monotonic(),
                }
                return {"session_id": sid, "type": "pdf_selection", "pages": previews}

        # ── Image handling ────────────────────────────────────────────────
        warning = None
        if cv2 is not None:
            img = cv2.imread(file_path)
            if img is not None:
                h, w = img.shape[:2]
                ppi = w / 8.0
                if ppi < 490:
                    warning = (
                        f"Low resolution detected (~{int(ppi)} PPI). "
                        "Minimum 500 PPI (4000px width) is required for valid EFTs."
                    )

        with open(file_path, "rb") as f:
            img_b64 = base64.b64encode(f.read()).decode()

        SESSIONS[sid] = {"image_path": file_path, "boxes": [], "_created_at": __import__("time").monotonic()}
        return {"session_id": sid, "image_base64": img_b64, "warning": warning}

    except HTTPException:
        raise
    except Exception as e:
        import traceback; traceback.print_exc()
        raise api_error(str(e), "UPLOAD_FAILED", 500)


@router.post("/select_pdf_page")
async def api_select_pdf_page(data: SelectPdfPageRequest):
    """
    For multi-page PDFs: select which page to use as the fingerprint card.
    Must be called after /upload returns type='pdf_selection'.
    """
    session_data = require_session(data.session_id)
    if session_data.get("mode") != "pdf_select":
        raise api_error("Session is not in PDF page-selection mode", "WRONG_SESSION_MODE", 400)

    pdf_path = session_data["pdf_path"]
    sid = data.session_id
    sdir = session_dir(sid)

    try:
        doc = fitz.open(pdf_path)
        if data.page_index < 0 or data.page_index >= doc.page_count:
            raise api_error("page_index out of range", "INVALID_PAGE_INDEX", 400)

        pix = doc.load_page(data.page_index).get_pixmap(matrix=fitz.Matrix(500 / 72, 500 / 72))
        img_path = os.path.join(sdir, "original.png")
        pix.save(img_path)

        SESSIONS[sid] = {"image_path": img_path, "boxes": [], "_created_at": session_data["_created_at"]}

        with open(img_path, "rb") as f:
            b64 = base64.b64encode(f.read()).decode()

        return {"session_id": sid, "image_base64": b64}

    except HTTPException:
        raise
    except Exception as e:
        import traceback; traceback.print_exc()
        raise api_error(str(e), "PDF_PAGE_SELECT_FAILED", 500)


# ---------------------------------------------------------------------------
# Phase 3 — Rotate & Crop
# ---------------------------------------------------------------------------


@router.post("/rotate_crop")
async def api_rotate_crop(data: RotateCropRequest):
    """
    Step 2: Apply rotation and crop to the uploaded image.
    Returns the aligned image (base64) and computed default fingerprint boxes.
    """
    session_data = require_session(data.session_id)
    sid = data.session_id
    sdir = session_dir(sid)

    if "image_path" not in session_data:
        raise api_error("Session has no image. Call /upload first.", "NO_IMAGE_IN_SESSION", 400)

    original_path = session_data["image_path"]
    if not os.path.exists(original_path):
        raise api_error("Source image not found on disk", "IMAGE_NOT_FOUND", 404)

    try:
        crop_rect = {"x": data.x, "y": data.y, "w": data.w, "h": data.h}
        processed = apply_crop_and_rotate(original_path, data.rotation, crop_rect)

        aligned_path = os.path.join(sdir, "aligned.png")
        cv2.imwrite(aligned_path, processed)

        SESSIONS[sid]["image_path"] = aligned_path

        boxes = get_default_boxes(processed.shape)
        SESSIONS[sid]["boxes"] = boxes

        _, buf = cv2.imencode(".png", processed)
        img_b64 = base64.b64encode(buf).decode()

        return {"image_base64": img_b64, "boxes": boxes}

    except HTTPException:
        raise
    except Exception as e:
        import traceback; traceback.print_exc()
        raise api_error(str(e), "ROTATE_CROP_FAILED", 500)


# ---------------------------------------------------------------------------
# Phase 4 — Preview
# ---------------------------------------------------------------------------


@router.post("/preview")
async def api_preview(data: PreviewRequest):
    """
    Optional: Return base64-cropped previews of each fingerprint region
    so the WP plugin can show the user what will be captured.
    """
    session_data = require_session(data.session_id)

    if "image_path" not in session_data:
        raise api_error("No image in session. Call /rotate_crop first.", "NO_IMAGE_IN_SESSION", 400)

    img_path = session_data["image_path"]
    img = cv2.imread(img_path)
    if img is None:
        raise api_error("Could not read image from disk", "IMAGE_READ_FAILED", 500)

    target_fps = list(range(1, 11)) if data.mode == "rolled" else [13, 14, 15]
    previews: Dict[str, str] = {}

    for box in data.boxes:
        if box.fp_number not in target_fps:
            continue
        x, y, w, h = (
            max(0, int(box.x)),
            max(0, int(box.y)),
            int(box.w),
            int(box.h),
        )
        w = min(w, img.shape[1] - x)
        h = min(h, img.shape[0] - y)
        if w <= 0 or h <= 0:
            continue
        crop = img[y : y + h, x : x + w]
        _, buf = cv2.imencode(".jpg", crop)
        previews[box.id] = base64.b64encode(buf).decode()

    return {"previews": previews}


# ---------------------------------------------------------------------------
# Shared fingerprint processing helper
# ---------------------------------------------------------------------------


def _process_fingerprints(
    session_data: Dict[str, Any],
    boxes: List[Box],
    mode: str,
    sid: str,
    sdir: str,
):
    """
    Crop each fingerprint region from the aligned image and return a
    (fp_objects, prints_map) tuple.
    """
    img_path = session_data.get("image_path")
    if not img_path or not os.path.exists(img_path):
        raise api_error("Aligned image not found. Call /rotate_crop first.", "NO_IMAGE_IN_SESSION", 400)

    img = cv2.imread(img_path)
    if img is None:
        raise api_error("Could not read aligned image", "IMAGE_READ_FAILED", 500)

    fp_objects: List[Fingerprint] = []
    prints_map: Dict[int, Fingerprint] = {}

    for box in boxes:
        x, y, w, h = int(box.x), int(box.y), int(box.w), int(box.h)
        if w <= 0 or h <= 0:
            continue
        y = max(0, y)
        x = max(0, x)
        h = min(h, img.shape[0] - y)
        w = min(w, img.shape[1] - x)
        if w <= 0 or h <= 0:
            continue

        crop = img[y : y + h, x : x + w]
        fp = Fingerprint(crop, box.fp_number, sdir, sid)
        fp_objects.append(fp)

        if mode == "rolled":
            result = fp.process_and_convert_raw(type4=True)
        else:
            result = fp.process_and_convert_raw()

        if result:
            prints_map[box.fp_number] = fp

    return fp_objects, prints_map


# ---------------------------------------------------------------------------
# Phase 6 helper — generate reduced EFT
# ---------------------------------------------------------------------------

FULL_MAX_BYTES = 12.0 * 1024 * 1024
REDUCED_MAX_BYTES = 5.0 * 1024 * 1024
WSQ_FLOOR = 0.75  # FBI minimum — hard floor, never go below


def _generate_full_and_reduced(
    gen_data: Dict[str, Any],
    sid: str,
    prints_map: Dict[int, Fingerprint],
    fp_objects: List[Fingerprint],
    mode: str,
    safe_fname: str,
    safe_lname: str,
    sdir: str,
):
    """
    Generate the full-size EFT (≤11.0 MB) and optionally a reduced-size EFT
    (≤5 MB) using the parametric compression pipeline in generate_eft.

    Returns a dict with keys:
      download_url, filename, reduced_download_url (optional), reduced_filename (optional),
      reduced_warning (optional — if 5 MB could not be achieved)
    """
    # ── Full-size generation ─────────────────────────────────────────────
    eft_path = generate_eft(
        gen_data, sid, {fp.fp_number: fp for fp in fp_objects},
        mode=mode, max_size_bytes=11.0 * 1024 * 1024
    )

    current_size = os.path.getsize(eft_path)
    if current_size > FULL_MAX_BYTES:
        raise api_error(
            f"EFT size ({current_size} bytes) exceeds 12.0 MB limit even after compression.",
            "EFT_TOO_LARGE",
            400,
        )

    # Rename full-size file
    full_filename = f"EFT-{safe_fname}-{safe_lname}.eft"
    full_path = os.path.join(sdir, full_filename)
    shutil.move(eft_path, full_path)

    result = {
        "download_url": f"/api/v1/download/{sid}/{full_filename}",
        "filename": full_filename,
    }

    # ── Reduced-size generation (≤5 MB) ──────────────────────────────────
    full_size_bytes = os.path.getsize(full_path)
    if full_size_bytes <= REDUCED_MAX_BYTES:
        # Full file already fits — no separate reduced copy needed
        return result

    reduced_filename = f"EFT-{safe_fname}-{safe_lname}-reduced.eft"
    reduced_full_path = os.path.join(sdir, reduced_filename)

    candidate = generate_eft(
        gen_data, sid, {fp.fp_number: fp for fp in fp_objects},
        mode=mode, max_size_bytes=REDUCED_MAX_BYTES,
        allow_scale_down=True
    )
    candidate_size = os.path.getsize(candidate)
    shutil.move(candidate, reduced_full_path)

    reduced_warning = None
    if candidate_size > REDUCED_MAX_BYTES:
        reduced_warning = (
            f"Could not achieve ≤5 MB even at minimum WSQ bitrate ({WSQ_FLOOR}). "
            f"Reduced file is {candidate_size / (1024*1024):.1f} MB."
        )

    result["reduced_download_url"] = f"/api/v1/download/{sid}/{reduced_filename}"
    result["reduced_filename"] = reduced_filename
    if reduced_warning:
        result["reduced_warning"] = reduced_warning

    return result


# ---------------------------------------------------------------------------
# Phase 5 — Generate EFT
# ---------------------------------------------------------------------------


@router.post("/generate")
async def api_generate(data: GenerateRequest):
    """
    Step 3 (Final): Generate the EFT file.

    Produces a full-size EFT (≤11.0 MB) and, if the full file exceeds 5 MB,
    also a reduced-size EFT (≤5 MB, WSQ floor 0.75).

    Returns download URLs for both.
    """
    session_data = require_session(data.session_id)
    sid = data.session_id
    sdir = session_dir(sid)

    if cv2 is None:
        raise api_error("OpenCV (cv2) is not installed", "CV2_NOT_INSTALLED", 500)

    try:
        fp_objects, prints_map = _process_fingerprints(
            session_data, data.boxes, data.mode, sid, sdir
        )
    except HTTPException:
        raise
    except Exception as e:
        import traceback; traceback.print_exc()
        raise api_error(str(e), "FINGERPRINT_PROCESSING_FAILED", 500)

    if not fp_objects:
        raise api_error("No valid fingerprints found.", "NO_VALID_FINGERPRINTS", 400)

    try:
        gen_data = data.type2_data.copy()
        gen_data["bypass_ssn"] = data.bypass_ssn

        fname = data.type2_data.get("fname", data.type2_data.get("2.018", "Unknown")).split(",")[0]
        lname = data.type2_data.get("lname", "Unknown")
        safe_fname = "".join(c for c in fname if c.isalnum() or c in ("-", "_"))
        safe_lname = "".join(c for c in lname if c.isalnum() or c in ("-", "_"))

        return _generate_full_and_reduced(
            gen_data, sid, prints_map, fp_objects, data.mode, safe_fname, safe_lname, sdir
        )

    except HTTPException:
        raise
    except Exception as e:
        import traceback; traceback.print_exc()
        raise api_error(f"EFT generation failed: {e}", "EFT_GENERATION_FAILED", 500)


# ---------------------------------------------------------------------------
# Phase 7 — Download & Session Cleanup
# ---------------------------------------------------------------------------


@router.get("/download/{session_id}/{filename}")
async def api_download(session_id: str, filename: str):
    """Download a generated EFT file by session ID and filename."""
    if not validate_session_id(session_id):
        raise api_error("Invalid session ID", "INVALID_SESSION_ID", 400)

    # Directory traversal protection
    safe_sdir = os.path.abspath(os.path.join(TMP_DIR, session_id))
    if not safe_sdir.startswith(os.path.abspath(TMP_DIR)):
        raise api_error("Access denied", "ACCESS_DENIED", 403)

    file_path = os.path.join(safe_sdir, filename)
    if not os.path.exists(file_path):
        raise api_error("File not found", "FILE_NOT_FOUND", 404)

    return FileResponse(file_path, filename=filename)


@router.delete("/session/{session_id}")
async def api_delete_session(session_id: str):
    """Destroy a session and all associated temp files."""
    if not validate_session_id(session_id):
        raise api_error("Invalid session ID", "INVALID_SESSION_ID", 400)

    if not delete_session(session_id):
        raise api_error("Session not found", "SESSION_NOT_FOUND", 404)

    return {"message": "Deleted"}


# ---------------------------------------------------------------------------
# Phase 8 — All-In-One Convenience Endpoint
# ---------------------------------------------------------------------------


@router.post("/process")
async def api_process(
    file: UploadFile = File(...),
    # Type-2 demographic fields (Form)
    name: str = Form(..., description="Full name in format: Surname,First,Middle"),
    dob: str = Form(..., description="Date of birth YYYYMMDD"),
    ssn: Optional[str] = Form(default=""),
    bypass_ssn: bool = Form(default=False),
    sex: Optional[str] = Form(default=""),
    race: Optional[str] = Form(default=""),
    height: Optional[str] = Form(default="000"),
    weight: Optional[str] = Form(default="000"),
    eye: Optional[str] = Form(default=""),
    hair: Optional[str] = Form(default=""),
    pob: Optional[str] = Form(default=""),
    ctz: Optional[str] = Form(default=""),
    addr: Optional[str] = Form(default=""),
    mode: str = Form(default="rolled"),
):
    """
    All-in-one endpoint for API usage.

    Upload a fingerprint card image + demographic data in a single multipart
    request. The app will:
      1. Save and decode the image
      2. Auto-crop (no rotation, full image)
      3. Compute default fingerprint boxes
      4. Generate full-size EFT (≤11.0 MB)
      5. Generate reduced-size EFT (≤5 MB) if needed
      6. Return both download URLs + session_id

    The session_id is returned so the client can later call DELETE /session/{id}
    to clean up, or simply let it expire after 1 hour.
    """
    if mode not in ("rolled", "atf"):
        raise api_error("mode must be 'rolled' or 'atf'", "INVALID_MODE", 400)

    ext = _validate_upload(file)

    # ── Save uploaded file ─────────────────────────────────────────────────
    sid = str(uuid.uuid4())
    sdir = os.path.join(TMP_DIR, sid)
    os.makedirs(sdir, exist_ok=True)

    file_path = os.path.join(sdir, "original" + ext)
    with open(file_path, "wb") as buf:
        shutil.copyfileobj(file.file, buf)

    import time as _time
    SESSIONS[sid] = {"_created_at": _time.monotonic()}

    try:
        # ── PDF → PNG conversion ───────────────────────────────────────────
        if ext == ".pdf":
            if fitz is None:
                raise api_error("PyMuPDF not installed", "PDF_NOT_SUPPORTED", 500)
            doc = fitz.open(file_path)
            pix = doc.load_page(0).get_pixmap(matrix=fitz.Matrix(500 / 72, 500 / 72))
            img_path = os.path.join(sdir, "original.png")
            pix.save(img_path)
            file_path = img_path
        else:
            img_path = file_path

        # ── Load image ────────────────────────────────────────────────────
        if cv2 is None:
            raise api_error("OpenCV not installed", "CV2_NOT_INSTALLED", 500)

        img = cv2.imread(img_path)
        if img is None:
            raise api_error("Could not read uploaded image", "IMAGE_READ_FAILED", 400)

        # ── Auto-crop = full image, no rotation ───────────────────────────
        aligned_path = os.path.join(sdir, "aligned.png")
        cv2.imwrite(aligned_path, img)
        SESSIONS[sid]["image_path"] = aligned_path

        boxes_raw = get_default_boxes(img.shape)
        boxes = [Box(**b) for b in boxes_raw]

        # ── Build Type-2 data dict ────────────────────────────────────────
        type2_data: Dict[str, Any] = {
            "2.018": name,
            "2.022": dob,
            "2.016": ssn or "",
            "2.024": sex or "",
            "2.025": race or "",
            "2.027": height or "000",
            "2.029": weight or "000",
            "2.031": eye or "",
            "2.032": hair or "",
            "2.020": pob or "",
            "2.021": ctz or "",
            "2.041": addr or "",
            "2.037": "Firearms",
            "bypass_ssn": bypass_ssn,
        }

        # ── Parse name for filename ───────────────────────────────────────
        name_parts = name.replace(",", " ").split()
        safe_fname = "".join(c for c in (name_parts[1] if len(name_parts) > 1 else "Unknown") if c.isalnum() or c in ("-", "_"))
        safe_lname = "".join(c for c in (name_parts[0] if name_parts else "Unknown") if c.isalnum() or c in ("-", "_"))

        # ── Process fingerprints ──────────────────────────────────────────
        fp_objects, prints_map = _process_fingerprints(
            SESSIONS[sid], boxes, mode, sid, sdir
        )

        if not fp_objects:
            raise api_error("No valid fingerprints found.", "NO_VALID_FINGERPRINTS", 400)

        # ── Generate EFTs ─────────────────────────────────────────────────
        result = _generate_full_and_reduced(
            type2_data, sid, prints_map, fp_objects, mode, safe_fname, safe_lname, sdir
        )
        result["session_id"] = sid
        return result

    except HTTPException:
        raise
    except Exception as e:
        import traceback; traceback.print_exc()
        raise api_error(f"Processing failed: {e}", "PROCESS_FAILED", 500)
