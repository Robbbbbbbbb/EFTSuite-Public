from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel
import shutil
import os
import uuid
import json
import base64
try:
    import cv2
except ImportError:
    cv2 = None
try:
    import fitz # PyMuPDF
except ImportError:
    fitz = None

from typing import List, Dict, Optional, Any, Union

from services.image_processing import align_image, get_default_boxes, apply_crop_and_rotate
from services.eft_generator import generate_eft
from services.fingerprint import Fingerprint
from services.eft_parser import EFTParser
from services.eft_editor import EFTEditor
from services.fd258_generator import FD258Generator
from services.nbis_helper import convert_wsq_to_raw


app = FastAPI()

# Logging handler for validation errors
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    print(f"Validation Error: {exc.errors()}")
    print(f"Body: {await request.body()}")
    return JSONResponse(
        status_code=422,
        content={"detail": exc.errors(), "body": str(exc.body)},
    )

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Temp storage
TMP_DIR = "/app/temp"
os.makedirs(TMP_DIR, exist_ok=True)

# In-memory session store
SESSIONS = {}

# Model selection box on the fingerprint card image.
class Box(BaseModel):
    id: str
    fp_number: int
    x: float
    y: float
    w: float
    h: float

# Request model for the initial crop and rotate step.
class CropRequest(BaseModel):
    session_id: str
    rotation: int
    x: int
    y: int
    w: int
    h: int

# Request model for the final EFT generation step.
class GenerateRequest(BaseModel):
    session_id: str
    boxes: List[Box]
    type2_data: Dict[str, Any]
    bypass_ssn: Optional[bool] = False
    mode: Optional[str] = "rolled" # 'atf' or 'rolled'

class CaptureSessionRequest(BaseModel):
    l_slap: Optional[str] = None
    r_slap: Optional[str] = None
    thumbs: Optional[str] = None
    prints: Optional[Dict[str, str]] = None

# Request model for saving edited EFT.
class SaveEFTRequest(BaseModel):
    session_id: str
    type2_data: Dict[str, Any]

class SelectPageRequest(BaseModel):
    session_id: str
    page_index: int

# Serves the main SPA.
@app.get("/")
async def read_index():
    return FileResponse("static/index.html")

# Step 1: Uploads the raw fingerprint card image.
# Creates a new session and saves the original image.

@app.post("/api/upload")
async def upload_image(file: UploadFile = File(...)):
    session_id = str(uuid.uuid4())
    session_dir = os.path.join(TMP_DIR, session_id)
    os.makedirs(session_dir, exist_ok=True)
    
    # Determine extension
    ext = os.path.splitext(file.filename)[1].lower()
    if not ext:
        ext = ".jpg"

    file_path = os.path.join(session_dir, "original" + ext)
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
        
    try:
        # Check if PDF
        if ext == ".pdf":
            if fitz is None:
                raise HTTPException(status_code=500, detail="PyMuPDF (fitz) is not installed")
            
            doc = fitz.open(file_path)
            page_count = doc.page_count
            
            if page_count == 1:
                # Auto-convert single page
                page = doc.load_page(0)
                # Render at high resolution (500 DPI)
                zoom = 500 / 72
                mat = fitz.Matrix(zoom, zoom)
                pix = page.get_pixmap(matrix=mat)
                
                img_path = os.path.join(session_dir, "original.png") # Convert to PNG
                pix.save(img_path)
                
                # Update session path to point to the image
                file_path = img_path
                
                # Continue as normal image upload...
                with open(file_path, "rb") as f:
                    img_bytes = f.read()
                    img_base64 = base64.b64encode(img_bytes).decode('utf-8')
                
                SESSIONS[session_id] = {
                    "image_path": file_path,
                    "boxes": []
                }
                
                return {
                    "session_id": session_id,
                    "image_base64": img_base64
                }
            else:
                # Multi-page PDF - Request selection
                previews = []
                for i in range(page_count):
                    page = doc.load_page(i)
                    # Render thumbnail (low res)
                    zoom = 0.5 
                    mat = fitz.Matrix(zoom, zoom)
                    pix = page.get_pixmap(matrix=mat)
                    
                    # Get base64
                    img_data = pix.tobytes("png")
                    b64 = base64.b64encode(img_data).decode('utf-8')
                    previews.append(b64)
                
                # Save session state
                SESSIONS[session_id] = {
                    "mode": "pdf_select",
                    "pdf_path": file_path,
                    "page_count": page_count
                }
                
                return {
                    "session_id": session_id,
                    "type": "pdf_selection",
                    "pages": previews
                }

        # Normal Image Processing
        # If we are here, it's not a PDF or it was converted already
        
        # Check Resolution (PPI)
        # Standard FD-258 is 8 inches wide. 500 PPI = 4000 pixels.
        warning = None
        if cv2 is not None:
            img = cv2.imread(file_path)
            if img is not None:
                h, w = img.shape[:2]
                ppi = w / 8.0
                if ppi < 490: # Allow slight buffer
                    warning = f"Low resolution detected (~{int(ppi)} PPI). Minimum 500 PPI (4000px width) is required for valid EFTs."

        # Read the image to get base64
        with open(file_path, "rb") as f:
            img_bytes = f.read()
            img_base64 = base64.b64encode(img_bytes).decode('utf-8')
        
        SESSIONS[session_id] = {
            "image_path": file_path, # Temporary path pointing to original uploaded image
            "boxes": []
        }
        
        return {
            "session_id": session_id,
            "image_base64": img_base64,
            "warning": warning
        }
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/select_pdf_page")
async def select_pdf_page(data: SelectPageRequest):
    session_id = data.session_id
    if session_id not in SESSIONS:
        raise HTTPException(status_code=404, detail="Session not found")
        
    session_data = SESSIONS[session_id]
    if session_data.get("mode") != "pdf_select":
        raise HTTPException(status_code=400, detail="Invalid session mode")
        
    pdf_path = session_data["pdf_path"]
    page_idx = data.page_index
    
    try:
        doc = fitz.open(pdf_path)
        if page_idx < 0 or page_idx >= doc.page_count:
             raise HTTPException(status_code=400, detail="Invalid page index")
             
        page = doc.load_page(page_idx)
        # Render high res (500 DPI)
        zoom = 500 / 72
        mat = fitz.Matrix(zoom, zoom)
        pix = page.get_pixmap(matrix=mat)
        
        session_dir = os.path.dirname(pdf_path)
        img_path = os.path.join(session_dir, "original.png")
        pix.save(img_path)
        
        # Update session
        SESSIONS[session_id] = {
            "image_path": img_path,
            "boxes": []
        }
        
        # Return base64
        with open(img_path, "rb") as f:
            b64 = base64.b64encode(f.read()).decode('utf-8')
            
        return {
            "session_id": session_id,
            "image_base64": b64
        }
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

# Creates a session from captured live scans.
@app.post("/api/start_capture_session")
async def start_capture_session(data: CaptureSessionRequest):
    session_id = str(uuid.uuid4())
    session_dir = os.path.join(TMP_DIR, session_id)
    os.makedirs(session_dir, exist_ok=True)
    
    images_map = {}
    
    # Save print images
    try:
        def save_b64(b64_str, name):
            path = os.path.join(session_dir, name)
            with open(path, "wb") as f:
                f.write(base64.b64decode(b64_str))
            return path
        
        # 14 = L_SLAP, 13 = R_SLAP, 15 = THUMBS
        if data.l_slap: images_map[14] = save_b64(data.l_slap, "14.png")
        if data.r_slap: images_map[13] = save_b64(data.r_slap, "13.png")
        if data.thumbs: images_map[15] = save_b64(data.thumbs, "15.png")

        # Handle Generic Prints
        if data.prints:
            for k, b64 in data.prints.items():
                fname = f"{k}.png"
                # Ensure key is int for internal map
                try:
                    fp_num = int(k)
                    if b64 == "SKIP":
                        # Load placeholder if available, otherwise create blank
                        fname = f"{k}.jp2" # User requested JP2
                        dest_path = os.path.join(session_dir, fname)
                        
                        # Correct Path based on user request
                        if os.path.exists("./static/img/unprintable.jp2"):
                            unprintable_path = os.path.abspath("./static/img/unprintable.jp2")
                        else:
                            # Fallback 
                            unprintable_path = os.path.abspath("unprintable.jp2")

                        if os.path.exists(unprintable_path):
                            shutil.copy(unprintable_path, dest_path)
                        else:
                            print(f"Warning: unprintable.jp2 not found for skipped finger {k}. Using blank fallback.")
                            # Create a blank white image (500x500)
                            if cv2 is not None:
                                import numpy as np
                                blank_img = np.ones((500, 500, 3), dtype=np.uint8) * 255
                                cv2.imwrite(dest_path, blank_img)
                            else:
                                # Fallback if no cv2 (unlikely but safe)
                                with open(dest_path, "wb") as f:
                                    f.write(b"") # Empty file better than crash? 
                        
                        images_map[fp_num] = dest_path
                    else:
                        images_map[fp_num] = save_b64(b64, fname)
                except ValueError:
                    print(f"Skipping invalid key {k}")
        
        # Save session and return session id
        SESSIONS[session_id] = {
            "mode": "capture",
            "images": images_map
        }
        
        return {"session_id": session_id}
    
    # Exception handling in case of an error
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

# Step 2: Applies user-defined crop and rotation to the original image.
# Calculates default fingerprint boxes for the newly aligned image.
@app.post("/api/process_crop")
async def process_crop(data: CropRequest):

    # Get session
    session_id = data.session_id
    if session_id not in SESSIONS:
        raise HTTPException(status_code=404, detail="Session not found")
        
    # Get session directory
    session_dir = os.path.join(TMP_DIR, session_id)
    
    # Use image path from session if available (handles png from pdfs)
    if "image_path" in SESSIONS[session_id]:
        original_path = SESSIONS[session_id]["image_path"]
    else:
        original_path = os.path.join(session_dir, "original.jpg")
    
    # Process crop
    try:
        crop_rect = {'x': data.x, 'y': data.y, 'w': data.w, 'h': data.h}
        processed_img = apply_crop_and_rotate(original_path, data.rotation, crop_rect)
        
        # Save as aligned.png
        aligned_path = os.path.join(session_dir, "aligned.png")
        cv2.imwrite(aligned_path, processed_img)
        
        # Update session
        SESSIONS[session_id]["image_path"] = aligned_path
        
        # Get default boxes based on new image
        boxes = get_default_boxes(processed_img.shape)
        SESSIONS[session_id]["boxes"] = boxes
        
        # Return new base64 and boxes
        _, buffer = cv2.imencode('.png', processed_img)
        img_base64 = base64.b64encode(buffer).decode('utf-8')
        
        return {
            "image_base64": img_base64,
            "boxes": boxes
        }
    
    # Exception handling in case of an error
    except Exception as e:
        print(e)
        raise HTTPException(status_code=500, detail=str(e))


# Returns cropped images for the given boxes so the user can verify.
@app.post("/api/preview")
async def preview_crops(data: GenerateRequest):
    session_id = data.session_id
    if session_id not in SESSIONS:
        raise HTTPException(status_code=404, detail="Session not found")
    
    # Get session directory
    img_path = SESSIONS[session_id]["image_path"]
    img = cv2.imread(img_path)
    
    # Generate print previews
    previews = {}
    
    # Filter boxes based on mode
    target_fps = []
    if data.mode == "rolled":
        target_fps = list(range(1, 11)) # 1-10
    else:
        target_fps = [13, 14, 15] # 13, 14, 15 (Slaps)

    for box in data.boxes:
        if box.fp_number not in target_fps:
            continue
            
        # Crop
        x, y, w, h = box.x, box.y, box.w, box.h
        # Ensure bounds
        x = max(0, x)
        y = max(0, y)
        w = min(w, img.shape[1] - x)
        h = min(h, img.shape[0] - y)
        
        crop = img[y:y+h, x:x+w]
        _, buffer = cv2.imencode('.jpg', crop)
        b64 = base64.b64encode(buffer).decode('utf-8')
        previews[box.id] = b64
        
    return {"previews": previews}
    
"""
> Step 3 (Final): Processes individual fingerprint images and generates the EFT file.

This endpoint does the following:
    1. Crops each finger based on the user-adjusted boxes.
    2. Converts/segments the images (RGB -> Gray -> JP2).
    3. Assembles the EFT file.
    4. Handles re-compression if the file exceeds the 11MB size limit.
"""

@app.post("/api/generate")
async def generate_eft_endpoint(data: GenerateRequest):

    # Get session
    session_id = data.session_id
    if session_id not in SESSIONS:
        raise HTTPException(status_code=404, detail="Session not found")
    
    # Get session data
    session_data = SESSIONS[session_id]
    session_dir = os.path.join(TMP_DIR, session_id)
    
    # Check if cv2 is installed, handle error if not
    if cv2 is None:
        raise HTTPException(status_code=500, detail="cv2 not installed")

    # Initialize variables
    prints_map = {}
    fp_objects = [] 

    # Check session mode (Capture or Upload)
    if session_data.get("mode") == "capture":

        # If Capture Mode: Load individual images based on box.fp_number
        images_map = session_data["images"]
        for box in data.boxes:
            # Handle key type differences (int vs str)
            target_path = None
            if box.fp_number in images_map:
                target_path = images_map[box.fp_number]
            elif str(box.fp_number) in images_map:
                target_path = images_map[str(box.fp_number)]
                
            if target_path:
                img_path = target_path
                img = cv2.imread(img_path)
                
                if img is None:
                    print(f"Error: Failed to load image at {img_path}")
                    continue


                # Create Fingerprint object
                fp = Fingerprint(img, box.fp_number, session_dir, session_id)
                fp_objects.append(fp)

                # Capture mode processing
                if data.mode == "rolled":
                    result_path = fp.process_and_convert_raw(type4=True)
                else: 
                    # Default Type-14 Capture
                    result_path = fp.process_and_convert_raw()

                if result_path:
                    prints_map[box.fp_number] = fp
    else:
        # Upload Mode: Crop from master image
        img_path = session_data["image_path"]
        img = cv2.imread(img_path)
        
        for box in data.boxes:
            # Cast to int for slicing
            x, y, w, h = int(box.x), int(box.y), int(box.w), int(box.h)
            
            # Validate bounds
            if w <= 0 or h <= 0:
                print(f"Skipping invalid box {box.fp_number}: w={w}, h={h}")
                continue
                
            # Ensure within image dimensions
            y = max(0, y)
            x = max(0, x)
            h = min(h, img.shape[0] - y)
            w = min(w, img.shape[1] - x)
            
            if w <= 0 or h <= 0:
                 print(f"Skipping empty crop for FP {box.fp_number}")
                 continue

            crop = img[y:y+h, x:x+w]
            
            fp = Fingerprint(crop, box.fp_number, session_dir, session_id)
            fp_objects.append(fp)
            
            # Select processing method based on requested mode (rolled or flat)
            if data.mode == "rolled":
                result_path = fp.process_and_convert_raw(type4=True)
            else:
                result_path = fp.process_and_convert_raw() # Default raw
            
            # Add processed fingerprint to prints_map
            if result_path:
                size = os.path.getsize(result_path)
                print(f"Processed FP {box.fp_number}: {result_path} ({size} bytes)")
                if size == 0:
                    print(f"WARNING: FP {box.fp_number} is 0 bytes!")
                prints_map[box.fp_number] = fp
            else:
                 print(f"ERROR: Failed to process FP {box.fp_number}")
            
    # Check if we have any valid objects
    if not fp_objects:
        raise HTTPException(status_code=400, detail="No valid fingerprints found to generate EFT.")

    # Generate EFT with size safeguard
    try:
        # Inject bypass flag into type2_data for the generator
        gen_data = data.type2_data.copy()
        gen_data["bypass_ssn"] = data.bypass_ssn

        # Initial generation with NO compression (Raw)
        eft_path = generate_eft(gen_data, session_id, {fp.fp_number: fp for fp in fp_objects}, mode=data.mode)
        
        # Check size (Max 11.8 MB)
        max_size = 11.8 * 1024 * 1024
        current_size = os.path.getsize(eft_path)
        
        retries = 0
        # WSQ Bitrates: Start high (2.25) and decrease by 0.5
        bitrates = [2.25, 1.75, 1.25, 0.75] 
        
        # Re-compress and re-generate EFT if file exceeds limit
        while current_size > max_size and retries < len(bitrates):
            print(f"EFT size {current_size} exceeds limit. Re-compressing with WSQ bitrate {bitrates[retries]}...")
            
            # Re-compress all images
            for fp in fp_objects:
                if data.mode == "rolled":
                    fp.process_and_convert_wsq(bitrate=bitrates[retries], type4=True)
                else:
                    fp.process_and_convert_wsq(bitrate=bitrates[retries])
            
            # Re-generate EFT
            eft_path = generate_eft(gen_data, session_id, {fp.fp_number: fp for fp in fp_objects}, mode=data.mode)
            current_size = os.path.getsize(eft_path)
            retries += 1
        
        # If file still exceeds limit after all retries, raise error
        if current_size > max_size:
            raise HTTPException(status_code=400, detail=f"EFT size ({current_size} bytes) exceeds 11.8MB limit even after compression.")
        
        # Determine Filename
        fname = data.type2_data.get("fname", "Unknown")
        lname = data.type2_data.get("lname", "Unknown")

        # Sanitize
        safe_fname = "".join(c for c in fname if c.isalnum() or c in ('-', '_'))
        safe_lname = "".join(c for c in lname if c.isalnum() or c in ('-', '_'))
        
        # Generate filename
        filename = f"EFT-{safe_fname}-{safe_lname}.eft"
        
        # Rename the generated file to the user-friendly name
        new_path = os.path.join(session_dir, filename)
        shutil.move(eft_path, new_path)
        
        # Return download URL with session path and filename
        return {"download_url": f"/api/download/{session_id}/{filename}", "filename": filename}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"EFT Generation failed: {str(e)}")

# View/Edit EFT Endpoints
# Upload an existing EFT file for viewing/editing
@app.post("/api/upload_eft")
async def upload_eft(file: UploadFile = File(...)):
    session_id = str(uuid.uuid4())
    session_dir = os.path.join(TMP_DIR, session_id)
    # Create session directory
    os.makedirs(session_dir, exist_ok=True)

    # Save uploaded file to session directory
    file_path = os.path.join(session_dir, "original.eft")
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
        
    # Store session data
    SESSIONS[session_id] = {
        "eft_path": file_path,
        "mode": "view_edit"
    }
    
    # Return session ID
    return {"session_id": session_id}

# Parse the uploaded EFT and return data for the UI
@app.get("/api/eft_session/{session_id}")
async def get_eft_session(session_id: str):
    # Check if session exists
    if session_id not in SESSIONS or "eft_path" not in SESSIONS[session_id]:
        raise HTTPException(status_code=404, detail="Session not found")
        
    # Get session directory and EFT path
    session_dir = os.path.join(TMP_DIR, session_id)
    eft_path = SESSIONS[session_id]["eft_path"]
    
    # Parse EFT
    try:
        parser = EFTParser(eft_path)
        
        # 1. Type 2 Data
        type2_data = parser.get_type2_data()
        
        # 2. Extract Images
        images_dir = os.path.join(session_dir, "images")
        images = parser.extract_images(images_dir)
        
        # Prepare image URLs by mapping raw local path to endpoint        
        image_data = []
        for img in images:
            image_data.append({
                "fgp": img["fgp"],
                "url": f"/api/image/{session_id}/{os.path.basename(img['display_path'])}" if img['display_path'] else None,
                "width": img["width"],
                "height": img["height"]
            })
            
        # 3. Text Dump
        text_dump = parser.get_text_dump()
        return {
            "type2_data": type2_data,
            "images": image_data,
            "text_dump": text_dump
        }
    # Catch any errors and throw console message if present
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Failed to parse EFT: {str(e)}")

@app.get("/api/image/{session_id}/{filename}")
async def get_image(session_id: str, filename: str):
    file_path = os.path.join(TMP_DIR, session_id, "images", filename)
    if os.path.exists(file_path):
        return FileResponse(file_path)
    raise HTTPException(status_code=404, detail="Image not found")

# Reconstruct the EFT with updated Type 2 data.
@app.post("/api/save_eft")
async def save_eft(data: SaveEFTRequest):
    # Get session ID and throw error if not present
    session_id = data.session_id
    if session_id not in SESSIONS or "eft_path" not in SESSIONS[session_id]:
        raise HTTPException(status_code=404, detail="Session not found")
        
    session_dir = os.path.join(TMP_DIR, session_id)
    eft_path = SESSIONS[session_id]["eft_path"]
    
    # Generate new filename
    output_path = os.path.join(session_dir, "edited.eft")
    
    try:
        editor = EFTEditor(eft_path, output_path)
        editor.save(data.type2_data)
        
        # Determine nicer filename if possible
        fname = data.type2_data.get("2.018", "edited")
        # Sanitize filename
        safe_fname = "".join(c for c in fname if c.isalnum() or c in ('-', '_', ','))
        final_name = f"edited-{safe_fname}.eft"
        
        final_path = os.path.join(session_dir, final_name)
        shutil.move(output_path, final_path)
        # Create download URL for edited EFT
        return {"download_url": f"/api/download/{session_id}/{final_name}", "filename": final_name}
    
    # Throw error if EFT can't be saved
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Failed to save EFT: {str(e)}")

# Create download endpoint
@app.get("/api/download/{session_id}/{filename}")
async def download_file(session_id: str, filename: str):
    file_path = os.path.join(TMP_DIR, session_id, filename)
    if os.path.exists(file_path):
        return FileResponse(file_path, filename=filename)
    raise HTTPException(status_code=404, detail="File not found")

# Destroy session
@app.delete("/api/delete/{session_id}")
async def delete_session(session_id: str):
    # Validate session_id is a valid UUID to prevent directory traversal
    try:
        uuid.UUID(session_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid session ID format")

    session_dir = os.path.join(TMP_DIR, session_id)
    # Double check path safety
    if not os.path.abspath(session_dir).startswith(os.path.abspath(TMP_DIR)):
         raise HTTPException(status_code=403, detail="Access denied")

    if os.path.exists(session_dir):
        shutil.rmtree(session_dir)
        if session_id in SESSIONS:
            del SESSIONS[session_id]
        return {"message": "Deleted"}
    raise HTTPException(status_code=404, detail="Session not found")

class RawFP:
    def __init__(self, p, w=0, h=0, is_raw=False):
        self.img_path = p
        self.w = w
        self.h = h
        self.is_raw = is_raw

class SimpleFP:
    def __init__(self, p, w=0, h=0): 
        self.img_path = p
        self.w = w
        self.h = h


@app.post("/api/generate_fd258")
async def generate_fd258(data: GenerateRequest):
    # Get session
    session_id = data.session_id
    if session_id not in SESSIONS:
        raise HTTPException(status_code=404, detail="Session not found")
    
    session_data = SESSIONS[session_id]
    session_dir = os.path.join(TMP_DIR, session_id)
    
    # FD258 generation is only available for capture mode
    if session_data.get("mode") != "capture":
        raise HTTPException(status_code=400, detail="Only available for capture sessions")

    # Load images_map
    images_map = session_data["images"]
    print(f"DEBUG: images_map keys: {list(images_map.keys())}")
    
    # Collect printable images
    prints_map = {}
    
    # NEW: Directly map individual images if available (e.g. Type-4 Flat Capture)
    # Check for IDs 1-10 and 11-14 in images_map
    for i in range(1, 15):
        fp_num = i
        # Check string or int key
        target_path = None
        if fp_num in images_map: target_path = images_map[fp_num]
        elif str(fp_num) in images_map: target_path = images_map[str(fp_num)]
        
        if target_path and os.path.exists(target_path):
            print(f"DEBUG: Found direct print for FP {fp_num}")
            # Map to FD258 layout
            # 1-10 map directly
            # 11-14:
            # 14 -> 14 (P_L4)
            # 13 -> 13 (P_R4)
            # 11 -> Plain R Thumb (usually ID 11 in our capture, but specs say 11 is P_RT)
            # 12 -> Plain L Thumb 
            
            # SimpleFP wrapper
            sfp = RawFP(target_path) 
            prints_map[fp_num] = sfp
            
            # Special handling for capture IDs 11 and 12 (Thumbs)
            # In captureSequence: 11='R Thumb (Plain)', 12='L Thumb (Plain)'
            # FD258 Generator expects '11' for R Thumb Plain, '12' for L Thumb Plain.
            # This matches.
            
    # If we have prints_map filled with 1-14, we are good.
    # Legacy Fallback: Only if we lack data, try to extract from Slaps (13, 14, 15)
    
    if len(prints_map) < 4: # Arbitrary check, if we have very few prints, try legacy logic for slaps
        print("DEBUG: Low print count, attempting legacy slap segmentation...")
        for fp_num in [13, 14, 15]:
            # ... existing logic ...
            target_path = None
            if fp_num in images_map: target_path = images_map[fp_num]
            elif str(fp_num) in images_map: target_path = images_map[str(fp_num)]

            if not target_path: continue
            
            fp = Fingerprint(cv2.imread(target_path), fp_num, session_dir, session_id)
            fp.process_and_convert(10)
            if not fp.fingers: fp.segment()
            
            # Map Slaps themselves
            if fp_num == 13: prints_map[13] = fp
            elif fp_num == 14: prints_map[14] = fp
            
            # Map segments
            for finger in fp.fingers:
                try: 
                    fn = int(finger.n)
                    seg_path = os.path.join(session_dir, finger.name)
                    
                    if fp.fp_number == 14:
                         if fn == 7: fn = 10
                         elif fn == 10: fn = 7
                         elif fn == 8: fn = 9
                         elif fn == 9: fn = 8
                    
                    sfp = RawFP(seg_path, finger.sw, finger.sh) # simplified
                    if 1 <= fn <= 10: prints_map[fn] = sfp
                    
                    # Map Segments to Plain Thumbs 11/12
                    # Note: If we already have 11/12 from direct capture, don't overwrite?
                    if fn == 11 and 11 not in prints_map: 
                        prints_map[11] = sfp # Plain R Thumb
                        prints_map[1] = sfp  # Also use for rolled if missing?
                    elif fn == 12 and 12 not in prints_map: 
                        prints_map[12] = sfp # Plain L Thumb
                        prints_map[6] = sfp
                        
                    # Fix: If we extracted Rolled Thumb (1 or 6) from slap, map to Plain as well if plain missing
                    if fn == 1 and 11 not in prints_map: prints_map[11] = sfp
                    if fn == 6 and 12 not in prints_map: prints_map[12] = sfp

                except Exception as e:
                    print(f"Error mapping segment: {e}")

    print(f"DEBUG: Final prints_map keys: {list(prints_map.keys())}")



                 
    # Generate FD258
    try:
        generator = FD258Generator("static/img/fd258-blank.jpg")
        img_bytes = generator.generate(data.type2_data, prints_map)
        
        # Save
        filename = f"fd258-{session_id}.jpg"
        out_path = os.path.join(session_dir, filename)
        with open(out_path, "wb") as f:
            f.write(img_bytes)
            
        return {"download_url": f"/api/download/{session_id}/{filename}", "filename": filename}
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"FD258 Generation failed: {str(e)}")

