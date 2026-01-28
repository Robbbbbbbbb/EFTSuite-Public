
// Global State
let sessionId = null;
let image = new Image(); // For verification/box selection (Step 1)
let cropImage = new Image(); // For crop step (Step 1)
let boxes = []; // Array of fingerprint boxes
let activeBoxIndex = -1;
let isCaptureSession = false; // Track if session is from capture
let pendingImageData = null;

// Crop State
let cropRotation = 0;
let cropBox = null;
let isCropDragging = false;
let cropStart = null;
let cropScaleFactor = 1;

// Box Selection State
let isDragging = false;
let isResizing = false;
let resizeHandle = null;
let scaleFactor = 1;
let selectedGenMode = 'rolled'; // 'atf' or 'rolled'

// Edit/View State
let isEditMode = false;
let editSessionId = null;

// UI References
const pStep1 = document.getElementById('p-step-1');
const pStep2 = document.getElementById('p-step-2');
const pStep3 = document.getElementById('p-step-3');
const wizardProgressBar = document.getElementById('wizard-progress-bar');

const panelStep1 = document.getElementById('step-1-panel');
const panelStep2 = document.getElementById('step-2-panel');
const panelStep3 = document.getElementById('step-3-panel');
const panelDownload = document.getElementById('step-download-panel');

const viewUpload = document.getElementById('view-upload');
const viewCrop = document.getElementById('view-crop');
const viewModeSelect = document.getElementById('view-mode-select');
const viewBox = document.getElementById('view-box');
const viewPdfSelect = document.getElementById('view-pdf-select');
const viewWarning = document.getElementById('view-warning');

// New Section References
const sectionNewEft = document.getElementById('section-new-eft');
const sectionCapture = document.getElementById('section-capture-prints');
const sectionEditEft = document.getElementById('section-edit-eft');
const sectionDynamic = document.getElementById('section-dynamic-content');
const editViewUpload = document.getElementById('edit-view-upload');
const editViewMode = document.getElementById('edit-view-mode');
const editViewMain = document.getElementById('edit-view-main');

const btnBack = document.getElementById('btn-back');
const btnNext = document.getElementById('btn-next');
const btnSubmit = document.getElementById('btn-submit');
const loading = document.getElementById('loading');

const navNew = document.querySelector('.nav-links li:first-child');
const navCapture = document.getElementById('nav-capture');
const navEdit = document.getElementById('nav-edit');
const navInfo = document.getElementById('nav-info');
const navAbout = document.getElementById('nav-about');

const dynamicTitle = document.getElementById('dynamic-title');
const dynamicBody = document.getElementById('dynamic-content-body');

// Canvases
const cropCanvas = document.getElementById('crop-canvas');
const cropCtx = cropCanvas.getContext('2d');
const verifyCanvas = document.getElementById('editor-canvas');
const verifyCtx = verifyCanvas.getContext('2d');

// Navigation Wizard
let currentAppMode = 'new'; // 'new' or 'edit'
let currentStep = 1; // 1, 2, 3
let currentSubStep = 'upload'; // 'upload', 'crop', 'mode', 'box'

// Navigation Handling
navEdit.onclick = () => {
    currentAppMode = 'edit';
    updateAppMode();
};

navCapture.onclick = () => {
    currentAppMode = 'capture';
    updateAppMode();
};

navInfo.onclick = () => {
    currentAppMode = 'info';
    updateAppMode();
};

navAbout.onclick = () => {
    currentAppMode = 'about';
    updateAppMode();
};

function updateAppMode() {
    navNew.classList.remove('active');
    navEdit.classList.remove('active');
    navCapture.classList.remove('active');
    navInfo.classList.remove('active');
    navAbout.classList.remove('active');

    // Reset Views
    sectionNewEft.classList.add('hidden');
    sectionCapture.classList.add('hidden');
    sectionEditEft.classList.add('hidden');
    sectionDynamic.classList.add('hidden');
    wizardProgressBar.classList.add('hidden');
    document.getElementById('main-footer').classList.add('hidden');

    if (currentAppMode === 'new') {
        navNew.classList.add('active');
        sectionNewEft.classList.remove('hidden');
        wizardProgressBar.classList.remove('hidden');
        document.getElementById('main-footer').classList.remove('hidden');
        updateWizardUI();
    } else if (currentAppMode === 'capture') {
        navCapture.classList.add('active');
        sectionCapture.classList.remove('hidden');
        initCaptureMode();
    } else if (currentAppMode === 'edit') {
        navEdit.classList.add('active');
        sectionEditEft.classList.remove('hidden');
        // Reset Edit Flow
        editViewUpload.classList.remove('hidden');
        editViewMode.classList.add('hidden');
        editViewMain.classList.add('hidden');
        panelDownload.classList.add('hidden');
    } else if (currentAppMode === 'info') {
        navInfo.classList.add('active');
        sectionDynamic.classList.remove('hidden');
        loadDynamicContent('https://raw.githubusercontent.com/Robbbbbbbbb/EFTSuite-Public/main/dynamic/info.md', 'Info');
    } else if (currentAppMode === 'about') {
        navAbout.classList.add('active');
        sectionDynamic.classList.remove('hidden');
        loadDynamicContent('https://raw.githubusercontent.com/Robbbbbbbbb/EFTSuite-Public/main/dynamic/about.md', 'About');
    }
}

async function loadDynamicContent(url, title) {
    dynamicTitle.textContent = title;
    dynamicBody.innerHTML = '';
    showLoading(true);

    try {
        // Append timestamp to prevent caching
        const res = await fetch(url + "?t=" + new Date().getTime(), {
            cache: "no-store"
        });
        if (res.ok) {
            const text = await res.text();
            dynamicBody.innerHTML = marked.parse(text);

            // Open links in new tab
            dynamicBody.querySelectorAll('a').forEach(a => {
                a.setAttribute('target', '_blank');
                a.setAttribute('rel', 'noopener noreferrer');
            });
        } else {
            throw new Error("Content unavailable");
        }
    } catch (e) { // If the dynamic content from GitHub can't be displayed, link the repo instead
        dynamicBody.innerHTML = `
            <div style="text-align:center; padding: 20px;">
                <p>Content unavailable.</p>
                <p><a href="https://github.com/Robbbbbbbbb/EFTSuite-Public/" target="_blank" style="color:var(--accent-color)">Visit Repository</a></p>
            </div>
        `;
    } finally {
        showLoading(false);
    }
}

// NEW EFT LOGIC

function updateWizardUI() {
    if (currentAppMode !== 'new') return;

    // Hide all panels
    [panelStep1, panelStep2, panelStep3, panelDownload].forEach(p => p.classList.add('hidden'));

    // Update Progress Bar
    [pStep1, pStep2, pStep3].forEach((el, idx) => {
        el.classList.remove('active', 'completed');
        if (idx + 1 < currentStep) el.classList.add('completed');
        if (idx + 1 === currentStep) el.classList.add('active');
    });

    // Update Bar Fill
    const fill = document.getElementById('progress-fill');
    if (fill) {
        let pct = 0;
        if (currentStep === 1) pct = 33;
        else if (currentStep === 2) pct = 66;
        else if (currentStep >= 3) pct = 100;
        fill.style.width = pct + "%";
    }

    // Reset Buttons
    btnBack.classList.add('hidden');
    btnNext.classList.add('hidden');
    btnSubmit.classList.add('hidden');

    if (currentStep === 1) {
        panelStep1.classList.remove('hidden');

        // Sub-step logic
        [viewUpload, viewCrop, viewModeSelect, viewBox, viewPdfSelect, viewWarning].forEach(v => v.classList.add('hidden'));

        if (currentSubStep === 'upload') {
            viewUpload.classList.remove('hidden');
            // No buttons (upload is action)
        } else if (currentSubStep === 'crop') {
            viewCrop.classList.remove('hidden');
            btnNext.classList.remove('hidden');
            btnNext.textContent = "Confirm Crop";
            btnBack.classList.remove('hidden');
            btnBack.onclick = () => window.location.reload();
        } else if (currentSubStep === 'mode') {
            viewModeSelect.classList.remove('hidden');
            btnBack.classList.remove('hidden');
            btnBack.onclick = () => { currentSubStep = 'crop'; updateWizardUI(); };
        } else if (currentSubStep === 'box') {
            viewBox.classList.remove('hidden');
            btnBack.classList.remove('hidden');
            btnBack.onclick = () => { currentSubStep = 'mode'; updateWizardUI(); };
            btnNext.classList.remove('hidden');
            btnNext.textContent = "Next Step";
        } else if (currentSubStep === 'pdf_select') {
            viewPdfSelect.classList.remove('hidden');
            btnBack.classList.remove('hidden');
            btnBack.onclick = () => { window.location.reload(); };
        } else if (currentSubStep === 'warning') {
            viewWarning.classList.remove('hidden');
        }

    } else if (currentStep === 2) {
        panelStep2.classList.remove('hidden');
        btnBack.classList.remove('hidden');
        btnNext.classList.remove('hidden');
        btnNext.textContent = "Review";

        btnBack.onclick = () => {
            currentStep = 1;
            currentSubStep = 'box';
            updateWizardUI();
            requestAnimationFrame(initVerifyStep); // Redraw canvas
        };

    } else if (currentStep === 3) {
        panelStep3.classList.remove('hidden');
        btnBack.classList.remove('hidden');
        btnSubmit.classList.remove('hidden');

        btnBack.onclick = () => {
            currentStep = 2;
            updateWizardUI();
        };

        populateReview();

    } else if (currentStep === 4) { // Download
        panelDownload.classList.remove('hidden');
        document.getElementById('main-footer').classList.add('hidden');
        loadSupportInfo();
    }
}

async function loadSupportInfo() {
    const el = document.getElementById('support-content');
    el.innerHTML = '<div style="text-align:center; color:#aaa;">Loading info...</div>';

    const url = "https://raw.githubusercontent.com/Robbbbbbbbb/EFTSuite-Public/refs/heads/main/dynamic/supportme.md";

    try {
        const res = await fetch(url + "?t=" + new Date().getTime());
        if (res.ok) {
            const text = await res.text();
            el.innerHTML = marked.parse(text);

            // Style links
            el.querySelectorAll('a').forEach(a => {
                a.setAttribute('target', '_blank');
                a.setAttribute('rel', 'noopener noreferrer');
                a.style.color = 'var(--accent-color)';
                a.style.textDecoration = 'none';
            });
        } else {
            throw new Error("Content unavailable");
        }
    } catch (e) {
        el.innerHTML = `
            <div style="text-align:center;">
                <h3>EFTSuite-Public</h3>
                <p>Check out the project on GitHub:</p>
                <p><a href="https://github.com/Robbbbbbbbb/EFTSuite-Public/" target="_blank" style="color:var(--accent-color); text-decoration:none;">https://github.com/Robbbbbbbbb/EFTSuite-Public/</a></p>
            </div>
        `;
    }
}



// Next Button Logic
btnNext.onclick = async () => {
    if (currentStep === 1) {
        if (currentSubStep === 'crop') {
            await confirmCrop();
        } else if (currentSubStep === 'box') {
            currentStep = 2;
            updateWizardUI();
        }
    } else if (currentStep === 2) {
        // Validate Form
        const form = document.getElementById('type2-form');
        if (form.checkValidity()) {
            currentStep = 3;
            updateWizardUI();
        } else {
            form.reportValidity();
        }
    }
};

// Mode Selection Handlers
document.getElementById('btn-gen-atf').onclick = () => {
    // Type-14 is disabled
    return;
};
document.getElementById('btn-gen-rolled').onclick = () => {
    selectedGenMode = 'rolled';
    boxes = getBoxesForMode('rolled');
    currentSubStep = 'box';
    updateWizardUI();
    requestAnimationFrame(initVerifyStep);
};

// STEP 1: Upload
// SSN Bypass Logic
const bypassChk = document.getElementById('bypass-ssn');
if (bypassChk) {
    bypassChk.onchange = (e) => {
        const ssnInput = document.querySelector('input[name="2.016"]');
        if (e.target.checked) {
            ssnInput.value = '';
            ssnInput.disabled = true;
            ssnInput.required = false;
        } else {
            ssnInput.disabled = false;
            ssnInput.required = true;
        }
    };
}

// STEP 1: Upload
const fileInput = document.getElementById('file-input');
const uploadArea = document.querySelector('#view-upload .upload-area');

function setupUploadZone(area, input, handler) {
    if (!area || !input) return;

    // Click to upload (delegation)
    area.onclick = (e) => {
        // Ignroe if clicking the button (it has its own handler/behavior) or the input itself
        if (e.target.tagName === 'BUTTON' || e.target === input) return;
        input.click();
    };

    // Drag & Drop
    area.addEventListener('dragover', (e) => {
        e.preventDefault();
        area.classList.add('dragover');
    });

    area.addEventListener('dragleave', (e) => {
        e.preventDefault();
        area.classList.remove('dragover');
    });

    area.addEventListener('drop', (e) => {
        e.preventDefault();
        area.classList.remove('dragover');
        if (e.dataTransfer.files.length > 0) {
            handler(e.dataTransfer.files[0]);
        }
    });

    // Input Change
    input.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            const f = e.target.files[0];
            e.target.value = '';
            handler(f);
        }
    });
}

// Setup New EFT Upload
setupUploadZone(uploadArea, fileInput, handleFileUpload);

async function handleFileUpload(file) {
    const formData = new FormData();
    formData.append("file", file);

    showLoading(true);
    try {
        const res = await fetch('/api/upload', { method: 'POST', body: formData });
        if (!res.ok) throw new Error("Upload failed");
        const data = await res.json();

        sessionId = data.session_id;
        isCaptureSession = false;

        // Check for PPI Warning
        if (data.warning) {
            document.getElementById('warning-text').textContent = data.warning;
            currentSubStep = 'warning';
            updateWizardUI();

            // Store data for proceeding
            pendingImageData = data;
            return;
        }

        if (data.type === 'pdf_selection') {
            currentSubStep = 'pdf_select';
            renderPdfSelection(data.pages);
            updateWizardUI();
            return;
        }

        cropImage.onload = () => {
            currentSubStep = 'crop';
            updateWizardUI();
            requestAnimationFrame(initCropStep);
        };
        cropImage.src = "data:image/png;base64," + data.image_base64;

    } catch (e) {
        alert(e.message);
    } finally {
        showLoading(false);
    }
}

// STEP 1.5: Crop Logic
function initCropStep() {
    cropRotation = 0;
    cropBox = null;
    drawCropCanvas();
}

function getRotatedDimensions() {
    if (cropRotation % 180 === 0) {
        return { w: cropImage.naturalWidth, h: cropImage.naturalHeight };
    } else {
        return { w: cropImage.naturalHeight, h: cropImage.naturalWidth };
    }
}

function drawCropCanvas() {
    const container = cropCanvas.parentElement;
    const maxWidth = container.clientWidth;
    const maxHeight = container.clientHeight;

    const dims = getRotatedDimensions();

    const scaleX = maxWidth / dims.w;
    const scaleY = maxHeight / dims.h;

    cropScaleFactor = Math.min(scaleX, scaleY);

    cropCanvas.width = dims.w * cropScaleFactor;
    cropCanvas.height = dims.h * cropScaleFactor;

    cropCtx.save();
    cropCtx.clearRect(0, 0, cropCanvas.width, cropCanvas.height);
    cropCtx.scale(cropScaleFactor, cropScaleFactor);

    cropCtx.translate(dims.w / 2, dims.h / 2);
    cropCtx.rotate(cropRotation * Math.PI / 180);
    cropCtx.drawImage(cropImage, -cropImage.naturalWidth / 2, -cropImage.naturalHeight / 2);

    cropCtx.restore();

    // Draw Boxes
    if (cropBox) {
        cropCtx.strokeStyle = '#bada55';
        cropCtx.lineWidth = 2;
        cropCtx.strokeRect(
            cropBox.x * cropScaleFactor,
            cropBox.y * cropScaleFactor,
            cropBox.w * cropScaleFactor,
            cropBox.h * cropScaleFactor
        );

        cropCtx.fillStyle = 'rgba(0,0,0,0.7)';
        cropCtx.fillRect(0, 0, cropCanvas.width, cropBox.y * cropScaleFactor); // Top
        cropCtx.fillRect(0, (cropBox.y + cropBox.h) * cropScaleFactor, cropCanvas.width, cropCanvas.height - (cropBox.y + cropBox.h) * cropScaleFactor); // Bottom
        cropCtx.fillRect(0, cropBox.y * cropScaleFactor, cropBox.x * cropScaleFactor, cropBox.h * cropScaleFactor); // Left
        cropCtx.fillRect((cropBox.x + cropBox.w) * cropScaleFactor, cropBox.y * cropScaleFactor, cropCanvas.width - (cropBox.x + cropBox.w) * cropScaleFactor, cropBox.h * cropScaleFactor); // Right
    }
}

// Crop Controls
document.getElementById('btn-rotate-left').onclick = () => { cropRotation = (cropRotation - 90) % 360; cropBox = null; drawCropCanvas(); };
document.getElementById('btn-rotate-right').onclick = () => { cropRotation = (cropRotation + 90) % 360; cropBox = null; drawCropCanvas(); };
document.getElementById('btn-reset-crop').onclick = initCropStep;

cropCanvas.onmousedown = (e) => {
    const rect = cropCanvas.getBoundingClientRect();
    const x = (e.clientX - rect.left) / cropScaleFactor;
    const y = (e.clientY - rect.top) / cropScaleFactor;
    isCropDragging = true;
    cropStart = { x, y };
    cropBox = { x, y, w: 0, h: 0 };
    drawCropCanvas();
};

cropCanvas.onmousemove = (e) => {
    if (!isCropDragging) return;
    const rect = cropCanvas.getBoundingClientRect();
    const x = (e.clientX - rect.left) / cropScaleFactor;
    const y = (e.clientY - rect.top) / cropScaleFactor;

    const w = x - cropStart.x;
    const h = y - cropStart.y;

    cropBox = {
        x: w > 0 ? cropStart.x : x,
        y: h > 0 ? cropStart.y : y,
        w: Math.abs(w),
        h: Math.abs(h)
    };
    drawCropCanvas();
};

cropCanvas.onmouseup = () => isCropDragging = false;

async function confirmCrop() {
    const dims = getRotatedDimensions();
    const finalCrop = cropBox || { x: 0, y: 0, w: dims.w, h: dims.h };

    if (finalCrop.w < 100 || finalCrop.h < 100) return alert("Selection too small");

    showLoading(true);
    try {
        const payload = {
            session_id: sessionId,
            rotation: cropRotation,
            x: Math.round(finalCrop.x),
            y: Math.round(finalCrop.y),
            w: Math.round(finalCrop.w),
            h: Math.round(finalCrop.h)
        };

        const res = await fetch('/api/process_crop', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (!res.ok) throw new Error("Processing failed");
        const data = await res.json();

        // boxes = data.boxes; // Do not use default boxes from backend

        image.onload = () => {
            currentSubStep = 'mode';
            updateWizardUI();
            // requestAnimationFrame(initVerifyStep);
        };
        image.src = "data:image/png;base64," + data.image_base64;

    } catch (e) {
        alert(e.message);
    } finally {
        showLoading(false);
    }
}


// Box Selection Logic
function initVerifyStep() {
    const container = verifyCanvas.parentElement;
    const maxWidth = container.clientWidth;
    const maxHeight = container.clientHeight;

    const scaleX = maxWidth / image.width;
    const scaleY = maxHeight / image.height;

    scaleFactor = Math.min(scaleX, scaleY);

    verifyCanvas.width = image.width * scaleFactor;
    verifyCanvas.height = image.height * scaleFactor;

    drawVerifyCanvas();
}

function getVerifyMousePos(evt) {
    const rect = verifyCanvas.getBoundingClientRect();
    const scaleX = verifyCanvas.width / rect.width;
    const scaleY = verifyCanvas.height / rect.height;
    const cvsX = (evt.clientX - rect.left) * scaleX;
    const cvsY = (evt.clientY - rect.top) * scaleY;
    return { x: cvsX / scaleFactor, y: cvsY / scaleFactor };
}

function getBoxesForMode(mode) {
    const w = image.width;
    const h = image.height;

    if (mode === 'atf') {
        // Legacy mode
        return [
            { id: 'Left Slap', fp_number: 14, x: w * 0.05, y: h * 0.45, w: w * 0.3, h: h * 0.4 },
            { id: 'Right Slap', fp_number: 13, x: w * 0.65, y: h * 0.45, w: w * 0.3, h: h * 0.4 },
            { id: 'Thumbs', fp_number: 15, x: w * 0.3, y: h * 0.75, w: w * 0.4, h: h * 0.2 },
        ];
    } else {
        // Updated Specs (FD-258 8x8)
        // Rolls: 0.2w, 0.1875h
        // Slaps: 0.375w, 0.25h
        // Plain Thumbs: 0.125w, 0.25h

        const w_roll = w * 0.18;      // Reduced 10%
        const h_roll = h * 0.16875;   // Reduced 10%
        const w_plain = w * 0.10;     // Reduced 20%
        const h_plain = h * 0.20;     // Reduced 20%
        const w_slap = w * 0.375;
        const h_slap = h * 0.25;

        const y1 = h * 0.33; // Row 1
        const y2 = h * 0.53; // Row 2
        const y3 = h * 0.74; // Row 3

        const list = [];
        const fingerNames = ["Thumb", "Index", "Middle", "Ring", "Little"];

        // Row 1 (Right Hand Rolled) 1-5
        // x = 0.0, 0.2, 0.4, 0.6, 0.8
        for (let i = 0; i < 5; i++) {
            list.push({
                id: `Right ${fingerNames[i]}`,
                fp_number: i + 1,
                x: i * (w * 0.2),
                y: y1,
                w: w_roll,
                h: h_roll
            });
        }

        // Row 2 (Left Hand Rolled) 6-10
        // x = 0.0, 0.2, 0.4, 0.6, 0.8
        for (let i = 0; i < 5; i++) {
            list.push({
                id: `Left ${fingerNames[i]}`,
                fp_number: i + 6,
                x: i * (w * 0.2),
                y: y2,
                w: w_roll,
                h: h_roll
            });
        }

        // Row 3 (Plain)
        // Positions matches backend:
        // L4: x=0.0
        // LT: x=0.375
        // RT: x=0.50
        // R4: x=0.625

        list.push({ id: 'Left 4 Fingers', fp_number: 14, x: 0, y: y3, w: w_slap, h: h_slap });
        list.push({ id: 'Left Thumb Plain', fp_number: 12, x: w * 0.375, y: y3, w: w_plain, h: h_slap });
        list.push({ id: 'Right Thumb Plain', fp_number: 11, x: w * 0.50, y: y3, w: w_plain, h: h_slap });
        list.push({ id: 'Right 4 Fingers', fp_number: 13, x: w * 0.625, y: y3, w: w_slap, h: h_slap });

        return list;
    }
}

function drawVerifyCanvas() {
    verifyCtx.clearRect(0, 0, verifyCanvas.width, verifyCanvas.height);
    verifyCtx.save();
    verifyCtx.scale(scaleFactor, scaleFactor);
    verifyCtx.drawImage(image, 0, 0);
    verifyCtx.lineWidth = 10;

    boxes.forEach((box, index) => {
        // High contrast colors: Active=Magenta (#FF00FF), Inactive=Cyan (#00FFFF) or Lime (#00FF00)
        // User requested high contrast, not blue/black.
        const isActive = index === activeBoxIndex;
        verifyCtx.strokeStyle = isActive ? '#FF00FF' : '#00FF00';
        verifyCtx.strokeRect(box.x, box.y, box.w, box.h);
        verifyCtx.fillStyle = verifyCtx.strokeStyle;
        verifyCtx.font = 'bold 40px Arial';
        verifyCtx.fillText(box.id, box.x, box.y - 10);

        if (isActive) {
            // Drag Handles: Bright Yellow/Orange for contrast
            verifyCtx.fillStyle = '#FFD700'; // Gold
            const handleSize = 40;
            verifyCtx.fillRect(box.x - handleSize / 2, box.y - handleSize / 2, handleSize, handleSize);
            verifyCtx.fillRect(box.x + box.w - handleSize / 2, box.y - handleSize / 2, handleSize, handleSize);
            verifyCtx.fillRect(box.x - handleSize / 2, box.y + box.h - handleSize / 2, handleSize, handleSize);
            verifyCtx.fillRect(box.x + box.w - handleSize / 2, box.y + box.h - handleSize / 2, handleSize, handleSize);
        }
    });

    verifyCtx.restore();
}


verifyCanvas.onmousedown = (e) => {
    const { x, y } = getVerifyMousePos(e);
    if (activeBoxIndex !== -1) {
        const handle = getResizeHandle(boxes[activeBoxIndex], x, y);
        if (handle) {
            isResizing = true;
            resizeHandle = handle;
            return;
        }
    }
    for (let i = boxes.length - 1; i >= 0; i--) {
        if (isInside(boxes[i], x, y)) {
            activeBoxIndex = i;
            isDragging = true;
            drawVerifyCanvas();
            return;
        }
    }
    activeBoxIndex = -1;
    drawVerifyCanvas();
};

verifyCanvas.onmousemove = (e) => {
    const { x, y } = getVerifyMousePos(e);
    if (isResizing && activeBoxIndex !== -1) {
        resizeBox(boxes[activeBoxIndex], resizeHandle, x, y);
        drawVerifyCanvas();
    } else if (isDragging && activeBoxIndex !== -1) {
        const box = boxes[activeBoxIndex];
        box.x += e.movementX / scaleFactor;
        box.y += e.movementY / scaleFactor;
        drawVerifyCanvas();
    } else {
        if (activeBoxIndex !== -1) {
            const handle = getResizeHandle(boxes[activeBoxIndex], x, y);
            if (handle) {
                verifyCanvas.style.cursor = getCursorForHandle(handle);
                return;
            }
        }
        verifyCanvas.style.cursor = 'default';
    }
};

verifyCanvas.onmouseup = () => { isDragging = false; isResizing = false; };

function isInside(box, x, y) {
    return x >= box.x && x <= box.x + box.w && y >= box.y && y <= box.y + box.h;
}

function getResizeHandle(box, x, y) {
    const d = 40;
    if (Math.abs(x - box.x) < d && Math.abs(y - box.y) < d) return 'tl';
    if (Math.abs(x - (box.x + box.w)) < d && Math.abs(y - box.y) < d) return 'tr';
    if (Math.abs(x - box.x) < d && Math.abs(y - (box.y + box.h)) < d) return 'bl';
    if (Math.abs(x - (box.x + box.w)) < d && Math.abs(y - (box.y + box.h)) < d) return 'br';
    return null;
}

function resizeBox(box, handle, mx, my) {
    if (handle === 'tl') {
        const newW = (box.x + box.w) - mx;
        const newH = (box.y + box.h) - my;
        if (newW > 10 && newH > 10) { box.x = mx; box.y = my; box.w = newW; box.h = newH; }
    } else if (handle === 'tr') {
        const newW = mx - box.x;
        const newH = (box.y + box.h) - my;
        if (newW > 10 && newH > 10) { box.y = my; box.w = newW; box.h = newH; }
    } else if (handle === 'bl') {
        const newW = (box.x + box.w) - mx;
        const newH = my - box.y;
        if (newW > 10 && newH > 10) { box.x = mx; box.w = newW; box.h = newH; }
    } else if (handle === 'br') {
        const newW = mx - box.x;
        const newH = my - box.y;
        if (newW > 10 && newH > 10) { box.w = newW; box.h = newH; }
    }
}


function getCursorForHandle(handle) {
    return (handle === 'tl' || handle === 'br') ? 'nwse-resize' : 'nesw-resize';
}


// STEP 3: Review Logic
function populateReview() {
    const summary = document.getElementById('summary-content');
    const form = document.getElementById('type2-form');
    const formData = new FormData(form);
    const data = Object.fromEntries(formData.entries());

    const noMn = document.getElementById('no-mn').checked;
    let mname = data.mname || "";
    if (noMn) mname = "NMN";
    const fullName = `${data.lname}, ${data.fname} ${mname}`;

    const cleanAddr = [data.addr_street, data.addr_city, data.addr_state, data.addr_zip]
        .map(s => (s || "").trim())
        .filter(s => s)
        .join(" ");

    const displayFields = [
        { num: "2.018", name: "NAM", val: fullName },
        { num: "2.022", name: "DOB", val: data["dob"] },
        { num: "2.016", name: "SOC", val: data["2.016"] },
        { num: "2.024", name: "SEX", val: data["2.024"] },
        { num: "2.025", name: "RAC", val: data["2.025"] },
        { num: "2.027", name: "HGT", val: data["2.027"] },
        { num: "2.029", name: "WGT", val: data["2.029"] },
        { num: "2.031", name: "EYE", val: data["2.031"] },
        { num: "2.032", name: "HAI", val: data["2.032"] },
        { num: "2.020", name: "POB", val: data["2.020"] },
        { num: "2.021", name: "CTZ", val: data["2.021"] },
        { num: "2.041", name: "RES", val: cleanAddr },
    ];

    let html = '<ul style="list-style:none; padding:0;">';
    displayFields.forEach(f => {
        if (f.val) {
            html += `<li><strong style="color:var(--text-muted)">${f.num} - ${f.name}:</strong> <span style="color:var(--text-color)">${f.val}</span></li>`;
        }
    });
    html += '</ul>';
    summary.innerHTML = html;

    // Check if we have captured images in session, otherwise crop from card
    const container = document.getElementById('review-dynamic-container');
    container.innerHTML = '';

    if (isCaptureSession) {
        // Dynamic display of captured prints
        // Sort keys to display in logical order
        const keys = Object.keys(capturedPrints).sort((a, b) => parseInt(a) - parseInt(b));

        // Helper to label
        const getLabel = (k) => {
            // Try to find in captureSequence first if it exists
            // But captureSequence might be reset if we reloaded? No, global var.
            // If captureSequence is empty (e.g. reload), fallback to known IDs
            if (captureSequence && captureSequence.length > 0) {
                const item = captureSequence.find(i => i.id === k);
                if (item) return item.label;
            }
            const map = {
                '14': 'Left Slap', '13': 'Right Slap', '15': 'Thumbs',
                '1': 'R Thumb', '2': 'R Index', '3': 'R Middle', '4': 'R Ring', '5': 'R Little',
                '6': 'L Thumb', '7': 'L Index', '8': 'L Middle', '9': 'L Ring', '10': 'L Little',
                '11': 'Plain R Thumb', '12': 'Plain L Thumb'
            };
            return map[k] || `FP ${k}`;
        };

        const row = document.createElement('div');
        row.style.display = 'flex';
        row.style.flexWrap = 'wrap';
        row.style.gap = '10px';
        container.appendChild(row);

        keys.forEach(k => {
            row.appendChild(createReviewCard(getLabel(k), capturedPrints[k], true));
        });

    } else {
        if (selectedGenMode === 'rolled') {
            const labels = {
                1: "Thumb", 2: "Index", 3: "Middle", 4: "Ring", 5: "Little",
                6: "Thumb", 7: "Index", 8: "Middle", 9: "Ring", 10: "Little"
            };

            // Helper to create a section
            const createHandSection = (title, rangeStart, rangeEnd) => {
                const sectDiv = document.createElement('div');
                sectDiv.style.width = '100%';
                sectDiv.style.marginBottom = '15px';

                const hdr = document.createElement('h4');
                hdr.textContent = title;
                hdr.style.margin = '0 0 10px 0';
                hdr.style.color = '#aaa';
                hdr.style.borderBottom = '1px solid #444';
                hdr.style.paddingBottom = '5px';
                sectDiv.appendChild(hdr);

                const row = document.createElement('div');
                row.style.display = 'flex';
                row.style.gap = '10px';
                row.style.justifyContent = 'center';
                row.style.flexWrap = 'wrap';
                sectDiv.appendChild(row);

                // Filter and Sort boxes
                const handBoxes = boxes.filter(b => b.fp_number >= rangeStart && b.fp_number <= rangeEnd)
                    .sort((a, b) => a.fp_number - b.fp_number);

                handBoxes.forEach(box => {
                    const label = labels[box.fp_number] || `FP ${box.fp_number}`;
                    row.appendChild(createReviewCard(label, image, false, box));
                });

                return sectDiv;
            };

            // ROW 1: Right Hand (1-5)
            container.appendChild(createHandSection("Right Hand", 1, 5));

            // ROW 2: Left Hand (6-10)
            container.appendChild(createHandSection("Left Hand", 6, 10));

        } else {
            // ATF Mode: L_SLAP (14), R_SLAP (13), THUMBS (15)
            const slapMap = { 14: "Left Slap", 13: "Right Slap", 15: "Thumbs" };
            [14, 13, 15].forEach(num => {
                const box = boxes.find(b => b.fp_number === num);
                if (box) container.appendChild(createReviewCard(slapMap[num], image, false, box));
            });
        }
    }
}

function createReviewCard(label, source, isBase64 = false, box = null) {
    const div = document.createElement('div');
    div.className = 'review-img-card';

    const lbl = document.createElement('label');
    lbl.textContent = label;
    div.appendChild(lbl);

    if (isBase64 && source === 'SKIP') {
        const ph = document.createElement('div');
        ph.style.width = '150px';
        ph.style.height = '100px';
        ph.style.background = '#333';
        ph.style.color = '#e74c3c';
        ph.style.display = 'flex';
        ph.style.alignItems = 'center';
        ph.style.justifyContent = 'center';
        ph.style.fontSize = '2rem';
        ph.style.fontWeight = 'bold';
        ph.textContent = '❌';
        div.appendChild(ph);
    } else if (isBase64) {
        const img = document.createElement('img');
        img.src = "data:image/png;base64," + source;
        img.style.maxWidth = '150px';
        img.style.maxHeight = '100px';
        img.style.height = 'auto';
        img.style.objectFit = 'contain';
        div.appendChild(img);
    } else if (box) { // source is global 'image' (HTMLImageElement)
        const cvs = document.createElement('canvas');
        cvs.width = box.w;
        cvs.height = box.h;
        // Limit display size
        cvs.style.maxWidth = '150px';
        cvs.style.maxHeight = '100px';
        cvs.style.objectFit = 'contain';

        const ctx = cvs.getContext('2d');
        ctx.drawImage(source, box.x, box.y, box.w, box.h, 0, 0, box.w, box.h);
        div.appendChild(cvs);
    }

    return div;
}

// Submit (New EFT)
btnSubmit.onclick = async () => {
    const formData = new FormData(document.getElementById('type2-form'));
    const data = Object.fromEntries(formData.entries());

    const noMn = document.getElementById('no-mn').checked;
    let mname = data.mname || "";
    if (noMn) mname = "NMN";

    const fullName = `${data.lname},${data.fname},${mname}`;
    data["2.018"] = fullName;

    const cleanAddr = [data.addr_street, data.addr_city, data.addr_state, data.addr_zip]
        .map(s => s.replace(/[^a-zA-Z0-9\s]/g, "").trim())
        .join(" ");
    data["2.041"] = cleanAddr;

    const dobInput = document.getElementById('dob-input').value;
    if (dobInput) data["2.022"] = dobInput.replace(/-/g, "");

    const payload = {
        session_id: sessionId,
        boxes: boxes,
        type2_data: data,
        bypass_ssn: document.getElementById('bypass-ssn').checked,
        mode: selectedGenMode
    };

    showLoading(true);
    try {
        const res = await fetch('/api/generate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (!res.ok) throw new Error((await res.json()).detail || "Generation failed");

        const result = await res.json();
        const link = document.getElementById('download-link');
        link.href = result.download_url;
        link.setAttribute('download', result.filename);

        currentStep = 4;
        updateWizardUI();

        // Show FD258 button if capture session
        if (isCaptureSession) {
            document.getElementById('btn-dl-fd258').classList.remove('hidden');
        } else {
            document.getElementById('btn-dl-fd258').classList.add('hidden');
        }

    } catch (e) {
        alert(e.message);
    } finally {
        showLoading(false);
    }
};


document.getElementById('btn-dl-fd258').onclick = async () => {

    const formData = new FormData(document.getElementById('type2-form'));
    const data = Object.fromEntries(formData.entries());

    const noMn = document.getElementById('no-mn').checked;
    let mname = data.mname || "";
    if (noMn) mname = "NMN";

    const fullName = `${data.lname},${data.fname},${mname}`;
    data["2.018"] = fullName;

    const cleanAddr = [data.addr_street, data.addr_city, data.addr_state, data.addr_zip]
        .map(s => s.replace(/[^a-zA-Z0-9\s]/g, "").trim())
        .join(" ");
    data["2.041"] = cleanAddr;

    const dobInput = document.getElementById('dob-input').value;
    if (dobInput) data["2.022"] = dobInput.replace(/-/g, "");

    const payload = {
        session_id: sessionId,
        boxes: boxes,
        type2_data: data,
        bypass_ssn: document.getElementById('bypass-ssn').checked,
        mode: selectedGenMode
    };

    showLoading(true);
    try {
        const res = await fetch('/api/generate_fd258', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (!res.ok) throw new Error((await res.json()).detail || "Generation failed");

        const result = await res.json();
        // Trigger download
        const a = document.createElement('a');
        a.href = result.download_url;
        a.download = result.filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);

    } catch (e) {
        alert(e.message);
    } finally {
        showLoading(false);
    }
}

document.getElementById('btn-restart').onclick = () => window.location.reload();


// CAPTURE PRINTS LOGIC
let ws = null;
let captureMode = 'slaps'; // 'slaps' or 'full'
let captureSequence = [];
let captureStepIndex = 0;
let capturedPrints = {}; // Map of ID -> Base64
let currentCaptureImage = null;
let reconnectTimer = null;

// Settings
let scannerIP = localStorage.getItem('scanner_ip') || 'localhost';
let scannerPort = localStorage.getItem('scanner_port') || '8888';

function initCaptureMode() {
    const statusEl = document.getElementById('scanner-status');
    const previewEl = document.getElementById('scanner-preview');

    // Show Mode Selection, Hide Wizard
    document.getElementById('capture-mode-select').classList.remove('hidden');
    document.getElementById('capture-wizard').classList.add('hidden');

    // Setup Mode Buttons
    // document.getElementById('btn-cap-mode-slaps').onclick = () => startCaptureSession('slaps'); // REMOVED
    document.getElementById('btn-cap-mode-full').onclick = () => startCaptureSession('full');

    if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) return;

    logToConsole(`Connecting to Scanner Helper at ws://${scannerIP}:${scannerPort}/ ...`);
    ws = new WebSocket(`ws://${scannerIP}:${scannerPort}/`);

    ws.onopen = () => {
        logToConsole("WS Connected");
        statusEl.textContent = '🟢 Scanner Helper Connected';
        statusEl.style.background = '#27ae60';
        if (reconnectTimer) { clearInterval(reconnectTimer); reconnectTimer = null; }
    };

    ws.onclose = () => {
        logToConsole("WS Disconnected");
        statusEl.textContent = '⚪ Scanner Disconnected (Is Helper Running?)';
        statusEl.style.background = '#e74c3c';
        ws = null;
        if (!reconnectTimer) {
            reconnectTimer = setInterval(initCaptureMode, 3000);
        }
    };

    ws.onerror = (e) => logToConsole("WS Error");

    ws.onmessage = async (evt) => {
        const msg = JSON.parse(evt.data);

        if (msg.type === 'log') {
            logToConsole("[HELPER]: " + msg.message);
        } else if (msg.type === 'preview') {
            previewEl.src = "data:image/png;base64," + msg.image;
        } else if (msg.type === 'status') {
            logToConsole("STATUS: " + msg.message);
        } else if (msg.type === 'result') {
            logToConsole("Image Captured");

            let finalImg = msg.image;
            const currentItem = captureSequence[captureStepIndex];
            // Mirror Slaps (13, 14) due to scanner reversing them
            if (currentItem && ['13', '14'].includes(currentItem.id)) {
                logToConsole("Correcting mirrored slap...");
                finalImg = await mirrorBase64(msg.image);
            }

            currentCaptureImage = finalImg;

            // Check Express Mode
            const isExpress = document.getElementById('chk-express-mode').checked;
            if (isExpress) {
                acceptCapture();
            } else {
                showCaptureResult(finalImg);
            }
        }
    };

    // Bind Controls
    document.getElementById('btn-cap-start').onclick = startCapture;
    document.getElementById('btn-cap-skip').onclick = skipCapture; // NEW
    document.getElementById('btn-cap-cancel').onclick = cancelCapture;
    document.getElementById('btn-cap-retry').onclick = retryCapture;
    document.getElementById('btn-cap-reset').onclick = resetCapture;
    document.getElementById('btn-cap-accept').onclick = acceptCapture;
    document.getElementById('btn-cap-finalize').onclick = finalizeCapture;

    // Settings Handlers
    document.getElementById('btn-scanner-settings').onclick = () => {
        document.getElementById('scanner-settings-modal').classList.remove('hidden');
        document.getElementById('setting-scanner-ip').value = scannerIP;
        document.getElementById('setting-scanner-port').value = scannerPort;
    };

    document.getElementById('btn-cancel-settings').onclick = () => {
        document.getElementById('scanner-settings-modal').classList.add('hidden');
    };

    document.getElementById('btn-reset-settings').onclick = () => {
        document.getElementById('setting-scanner-ip').value = 'localhost';
        document.getElementById('setting-scanner-port').value = '8888';
    };

    document.getElementById('btn-save-settings').onclick = () => {
        const ip = document.getElementById('setting-scanner-ip').value.trim();
        const port = document.getElementById('setting-scanner-port').value.trim();

        if (ip && port) {
            scannerIP = ip;
            scannerPort = port;
            localStorage.setItem('scanner_ip', scannerIP);
            localStorage.setItem('scanner_port', scannerPort);

            document.getElementById('scanner-settings-modal').classList.add('hidden');

            // Reconnect
            if (ws) {
                ws.close();
                ws = null;
            }
            if (reconnectTimer) { clearInterval(reconnectTimer); reconnectTimer = null; }
            initCaptureMode();
        } else {
            alert("Please enter valid IP and Port");
        }
    };
}

function startCaptureSession(mode) {
    captureMode = mode;
    capturedPrints = {};
    captureStepIndex = 0;

    if (mode === 'slaps') {
        // REMOVED SLAPS LOGIC
        captureSequence = [];
    } else {
        // Full Type-4 Sequence
        captureSequence = [
            // Right Hand Rolled
            { id: '1', label: 'R Thumb' },
            { id: '2', label: 'R Index' },
            { id: '3', label: 'R Middle' },
            { id: '4', label: 'R Ring' },
            { id: '5', label: 'R Little' },
            // Left Hand Rolled
            { id: '6', label: 'L Thumb' },
            { id: '7', label: 'L Index' },
            { id: '8', label: 'L Middle' },
            { id: '9', label: 'L Ring' },
            { id: '10', label: 'L Little' },
            // Plains
            { id: '14', label: 'Left 4 (Plain)' },
            { id: '13', label: 'Right 4 (Plain)' },
            { id: '12', label: 'L Thumb (Plain)' },
            { id: '11', label: 'R Thumb (Plain)' }
        ];
    }

    document.getElementById('capture-mode-select').classList.add('hidden');
    document.getElementById('capture-wizard').classList.remove('hidden');
    updateCaptureUI();
}

function updateCaptureUI() {
    const listContainer = document.getElementById('capture-progress-labels');
    listContainer.innerHTML = ''; // Clear

    // Progress Labels/Bubbles (Simplified for robustness)

    // Only show current step active
    const currentItem = captureSequence[captureStepIndex];

    if (!currentItem) {
        // Done
        listContainer.innerHTML = '<div class="progress-step completed">Capture Complete!</div>';
        document.getElementById('capture-instruction').textContent = "All images captured.";
        resetCaptureButtons(false);
        document.getElementById('btn-cap-finalize').classList.remove('hidden');
        document.getElementById('scanner-preview').src = "";
        return;
    }

    // Render Steps (Simplified view if too many)
    if (captureMode === 'slaps') {
        captureSequence.forEach((item, idx) => {
            const div = document.createElement('div');
            div.className = 'progress-step';
            if (idx < captureStepIndex) div.classList.add('completed');
            if (idx === captureStepIndex) div.classList.add('active');
            div.textContent = `${idx + 1}. ${item.label}`;
            listContainer.appendChild(div);
        });
    } else {
        // Compact view for Full Mode
        const div = document.createElement('div');
        div.className = 'progress-step active';
        div.textContent = `Step ${captureStepIndex + 1} / ${captureSequence.length}: ${currentItem.label}`;
        listContainer.appendChild(div);
    }

    document.getElementById('capture-instruction').textContent = "Place " + currentItem.label;
    resetCaptureButtons(true);

    // Update Gallery
    renderCaptureGallery();
}

function renderCaptureGallery() {
    const container = document.getElementById('capture-gallery-container');
    // Keep the "Done" button at the bottom, so clear only the top part or re-append
    // We'll clear and re-append everything.
    container.innerHTML = '';

    Object.keys(capturedPrints).forEach(k => {
        // Find label
        const item = captureSequence.find(i => i.id === k);
        const label = item ? item.label : `ID ${k}`;

        const div = document.createElement('div');
        div.className = 'review-img-card';
        // div.innerHTML = `<label>${label}</label><img src="data:image/png;base64,${capturedPrints[k]}" style="width:100%; height:80px; object-fit:contain; background:#000;">`;

        const lbl = document.createElement('label');
        lbl.textContent = label;
        div.appendChild(lbl);

        // Handle Skipped vs Image
        if (capturedPrints[k] === 'SKIP') {
            const ph = document.createElement('div');
            ph.style.width = '100%';
            ph.style.height = '80px';
            ph.style.background = '#333';
            ph.style.color = '#e67e22';
            ph.style.display = 'flex';
            ph.style.alignItems = 'center';
            ph.style.justifyContent = 'center';
            ph.style.fontSize = '0.8rem';
            ph.textContent = 'Skipped (Unprintable)';
            div.appendChild(ph);
        } else {
            const img = document.createElement('img');
            img.src = "data:image/png;base64," + capturedPrints[k];
            img.style.width = '100%';
            img.style.height = '80px';
            img.style.objectFit = 'contain';
            img.style.backgroundColor = '#000';
            div.appendChild(img);
        }

        container.appendChild(div);
    });

    const btn = document.getElementById('btn-cap-finalize');
    if (btn) {
        if (captureStepIndex >= captureSequence.length) {
            btn.classList.remove('hidden');
        } else {
            btn.classList.add('hidden');
        }
    }
}

function resetCaptureButtons(readyToStart) {
    document.getElementById('btn-cap-start').classList.toggle('hidden', !readyToStart);
    document.getElementById('btn-cap-skip').classList.toggle('hidden', !readyToStart); // Toggle Skip
    document.getElementById('btn-cap-cancel').classList.add('hidden');
    document.getElementById('btn-cap-accept').classList.add('hidden');
    document.getElementById('btn-cap-retry').classList.add('hidden');

    // Reset All only if at start? Or let them reset anytime?
    // User can reset if they want to start over
    document.getElementById('btn-cap-reset').classList.remove('hidden');

    document.getElementById('scanner-preview').style.opacity = '0.5';
}

function skipCapture() {
    const currentItem = captureSequence[captureStepIndex];
    if (currentItem) {
        // Mark as SKIPPED
        capturedPrints[currentItem.id] = "SKIP";
        captureStepIndex++;
        updateCaptureUI();
        checkExpressAutoAdvance();
    }
}

function startCapture() {
    if (!ws) return;

    document.getElementById('btn-cap-start').classList.add('hidden');
    document.getElementById('btn-cap-skip').classList.add('hidden'); // NEW
    document.getElementById('btn-cap-reset').classList.add('hidden');
    document.getElementById('btn-cap-cancel').classList.remove('hidden');
    document.getElementById('scanner-preview').style.opacity = '1.0';

    const currentItem = captureSequence[captureStepIndex];
    if (!currentItem) return;

    // Send generic START_CAPTURE. 
    // The param usually tells the scanner what to expect (e.g. flat vs roll). 
    // If we want "flat scans" for everything (as user requested), we send "FLAT" or similar?
    // Existing code sent "L_SLAP", "R_SLAP". The helper probably decides based on that.
    // If we send raw expectation, maybe we need to update Helper? 
    // Assuming Helper just takes a string title or mode.
    // Ideally we pass "FLAT" for all because user said "capture as flat scans".
    // But passing legacy "L_SLAP" might trigger specific auto-capture logic.
    // For Rolled fingers (1-10), we might want to capture as flats.
    // I'll send the ID or Label.

    ws.send(JSON.stringify({ action: "START_CAPTURE", param: currentItem.id }));
}

function cancelCapture() {
    ws.send(JSON.stringify({ action: "CANCEL" }));
    resetCaptureButtons(true);
}

function showCaptureResult(base64) {
    document.getElementById('scanner-preview').src = "data:image/png;base64," + base64;
    document.getElementById('btn-cap-cancel').classList.add('hidden');
    document.getElementById('btn-cap-accept').classList.remove('hidden');
    document.getElementById('btn-cap-retry').classList.remove('hidden');
}

function retryCapture() {
    currentCaptureImage = null;
    startCapture();
}

function resetCapture() {
    // Go back to mode selection
    document.getElementById('capture-wizard').classList.add('hidden');
    document.getElementById('capture-mode-select').classList.remove('hidden');
    capturedPrints = {};
    captureStepIndex = 0;
}

function acceptCapture() {
    const currentItem = captureSequence[captureStepIndex];
    if (currentItem && currentCaptureImage) {
        capturedPrints[currentItem.id] = currentCaptureImage;
        captureStepIndex++;
        updateCaptureUI();
        checkExpressAutoAdvance();
    }
}

function checkExpressAutoAdvance() {
    const isExpress = document.getElementById('chk-express-mode').checked;
    if (isExpress && captureStepIndex < captureSequence.length) {
        // Auto-start next capture after a short delay
        setTimeout(() => startCapture(), 500);
    }
}

function logToConsole(msg) {
    const el = document.getElementById('console-output');
    if (el) {
        const line = document.createElement('div');
        line.textContent = `[${new Date().toLocaleTimeString()}] ${msg}`;
        el.appendChild(line);
        el.parentElement.scrollTop = el.parentElement.scrollHeight;
    }
}

async function finalizeCapture() {
    showLoading(true);
    try {
        const payload = {
            prints: capturedPrints // Send all prints as generic map
            // legacy fields can be omitted or filled if desired
        };

        // Populate legacy for backward compat if simple slaps
        if (capturedPrints['14']) payload.l_slap = capturedPrints['14'];
        if (capturedPrints['13']) payload.r_slap = capturedPrints['13'];
        if (capturedPrints['15']) payload.thumbs = capturedPrints['15'];

        const res = await fetch('/api/start_capture_session', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (!res.ok) throw new Error("Failed to start session");
        const data = await res.json();
        sessionId = data.session_id;
        isCaptureSession = true;

        // Populate boxes for generator (New EFT Step 2)
        // We need to set 'boxes' based on what we captured so the Review step knows what to show.
        // Actually, 'boxes' is used for extracting images from the "master" image in Step 1.
        // But here we have individual images.
        // We should construct mock boxes or just use the IDs.
        // The Review logic in populateReview() iterates capturedPrints if isCaptureSession is true.
        // Update populateReview() might be needed for Full mode?
        // Let's check populateReview() in next step if needed. 
        // But first set selectedGenMode.

        if (captureMode === 'full') {
            selectedGenMode = 'rolled';
            // Create mock boxes for 1-10, 11-14
            boxes = captureSequence.map(item => ({ id: item.id, fp_number: parseInt(item.id), x: 0, y: 0, w: 0, h: 0 }));
        } else {
            // Fallback / Default to Rolled if somehow here
            selectedGenMode = 'rolled';
            boxes = captureSequence.map(item => ({ id: item.id, fp_number: parseInt(item.id), x: 0, y: 0, w: 0, h: 0 }));
        }

        currentAppMode = 'new';
        currentStep = 2;

        navCapture.classList.remove('active');
        sectionCapture.classList.add('hidden');

        navNew.classList.add('active');
        sectionNewEft.classList.remove('hidden');
        wizardProgressBar.classList.remove('hidden');
        document.getElementById('main-footer').classList.remove('hidden');

        updateWizardUI();

    } catch (e) {
        alert(e.message);
    } finally {
        showLoading(false);
    }
}

// EDIT/VIEW EFT LOGIC

// 1. Upload EFT
const eftFileInput = document.getElementById('eft-file-input');
const eftUploadArea = document.querySelector('#edit-view-upload .upload-area');

setupUploadZone(eftUploadArea, eftFileInput, handleEftUpload);

async function handleEftUpload(file) {
    const formData = new FormData();
    formData.append("file", file);

    showLoading(true);
    try {
        const res = await fetch('/api/upload_eft', { method: 'POST', body: formData });
        if (!res.ok) throw new Error("Upload failed");
        const data = await res.json();

        editSessionId = data.session_id;

        // Move to mode selection
        editViewUpload.classList.add('hidden');
        editViewMode.classList.remove('hidden');

    } catch (e) {
        alert(e.message);
    } finally {
        showLoading(false);
    }
}

// 2. Mode Selection
document.getElementById('btn-mode-read').onclick = () => loadEFT(false);
document.getElementById('btn-mode-edit').onclick = () => loadEFT(true);

async function loadEFT(editMode) {
    isEditMode = editMode;

    showLoading(true);
    try {
        const res = await fetch(`/api/eft_session/${editSessionId}`);
        if (!res.ok) throw new Error("Failed to load EFT data");
        const data = await res.json();

        renderEFTData(data, editMode);

        editViewMode.classList.add('hidden');
        editViewMain.classList.remove('hidden');

    } catch (e) {
        alert(e.message);
    } finally {
        showLoading(false);
    }
}

function renderEFTData(data, editMode) {
    // 1. Raw Dump
    document.getElementById('raw-content').textContent = data.text_dump || "No raw data available.";

    // 2. Form Fields (Type 2)
    const formGrid = document.getElementById('edit-form-grid');
    formGrid.innerHTML = '';

    const t2 = data.type2_data;

    // Common fields to show with labels (others at bottom)
    // Map field number to label
    const fieldLabels = {
        "2.018": "Name",
        "2.016": "SSN",
        "2.022": "DOB",
        "2.024": "Sex",
        "2.025": "Race",
        "2.027": "Height",
        "2.029": "Weight",
        "2.031": "Eye Color",
        "2.032": "Hair Color",
        "2.020": "Place of Birth",
        "2.021": "Citizenship",
        "2.041": "Address",
    };

    // Hiding certain Type-2 fields from being editable
    const hiddenFields = ["2.002", "2.005", "2.037", "2.038", "2.073"];

    // Sort keys: Known first, then others
    const keys = Object.keys(t2).sort();
    const knownKeys = Object.keys(fieldLabels);
    let orderedKeys = [...knownKeys.filter(k => t2[k] !== undefined), ...keys.filter(k => !knownKeys.includes(k))];

    // Filter hidden
    orderedKeys = orderedKeys.filter(k => !hiddenFields.includes(k));

    orderedKeys.forEach(k => {
        const val = t2[k];
        const label = fieldLabels[k] ? `${k} - ${fieldLabels[k]}` : k;

        const div = document.createElement('div');
        div.className = 'form-group';

        const lbl = document.createElement('label');
        lbl.textContent = label;
        div.appendChild(lbl);

        const inp = document.createElement('input');
        inp.type = 'text';
        inp.name = k;
        inp.value = val;
        inp.readOnly = !editMode;

        // Validation Warnings in Edit Mode
        if (editMode) {
            inp.onblur = () => {
                // Check simple validations
                if (k === '2.027') { // Height
                    if (val < 400 || val > 711) showWarning(inp, "Height typically 400-711");
                    else clearWarning(inp);
                }
                // Add more if needed
            };
        }

        div.appendChild(inp);
        formGrid.appendChild(div);
    });

    document.getElementById('editor-title').textContent = editMode ? "Edit Mode (Advanced)" : "Read Only Mode";
    const btnSave = document.getElementById('btn-save-eft');
    if (editMode) {
        btnSave.classList.remove('hidden');
        btnSave.onclick = saveEFTChanges;
    } else {
        btnSave.classList.add('hidden');
    }

    // 3. Images
    const imgContainer = document.getElementById('edit-img-container');
    imgContainer.innerHTML = '';

    // Convert and Sort
    const cleanImages = data.images.map(img => {
        return { ...img, fgpInt: parseInt(img.fgp) };
    });

    // Check for Rolled (1-10)
    const rolled = cleanImages.filter(img => img.fgpInt >= 1 && img.fgpInt <= 10).sort((a, b) => a.fgpInt - b.fgpInt);

    // Check for Slaps (13-15)
    // 14: L Slap, 13: R Slap, 15: Thumbs
    const slaps = cleanImages.filter(img => [13, 14, 15].includes(img.fgpInt));

    const createEditCard = (label, url) => {
        const div = document.createElement('div');
        div.className = 'review-img-card';
        div.style.margin = '5px';

        const lbl = document.createElement('label');
        lbl.textContent = label;
        div.appendChild(lbl);

        const img = document.createElement('img');
        img.src = url;
        img.style.maxWidth = '150px';
        img.style.maxHeight = '100px';
        img.style.height = 'auto';
        img.style.objectFit = 'contain';
        img.style.border = '1px solid #555';
        img.onclick = () => window.open(url, '_blank'); // Click to zoom
        img.style.cursor = 'pointer';
        div.appendChild(img);

        return div;
    };

    if (rolled.length > 0) {
        // Render Rolled Layout
        const labels = {
            1: "Thumb", 2: "Index", 3: "Middle", 4: "Ring", 5: "Little",
            6: "Thumb", 7: "Index", 8: "Middle", 9: "Ring", 10: "Little"
        };

        const createHandSection = (title, imgs) => {
            const sectDiv = document.createElement('div');
            sectDiv.style.width = '100%';
            sectDiv.style.marginBottom = '15px';

            const hdr = document.createElement('h4');
            hdr.textContent = title;
            hdr.style.margin = '0 0 10px 0';
            hdr.style.color = '#aaa';
            hdr.style.borderBottom = '1px solid #444';
            hdr.style.paddingBottom = '5px';
            sectDiv.appendChild(hdr);

            const row = document.createElement('div');
            row.style.display = 'flex';
            row.style.gap = '10px';
            row.style.justifyContent = 'center';
            row.style.flexWrap = 'wrap';
            sectDiv.appendChild(row);

            imgs.forEach(img => {
                const label = labels[img.fgpInt] || `FP ${img.fgp}`;
                row.appendChild(createEditCard(label, img.url));
            });
            return sectDiv;
        };

        const rightHand = rolled.filter(i => i.fgpInt >= 1 && i.fgpInt <= 5);
        if (rightHand.length > 0) imgContainer.appendChild(createHandSection("Right Hand", rightHand));

        const leftHand = rolled.filter(i => i.fgpInt >= 6 && i.fgpInt <= 10);
        if (leftHand.length > 0) imgContainer.appendChild(createHandSection("Left Hand", leftHand));

        // Hide Slaps/Others if Rolled are present, per user request.

    } else {
        // If NO Rolled prints, show Slaps and Others (e.g. Type 14 upload)

        if (slaps.length > 0) {
            // Render Slaps
            // Sort order: 14 (L), 13 (R), 15 (Thumbs)
            const slapOrder = { 14: 1, 13: 2, 11: 2.1, 12: 2.2, 15: 3 };
            // Standard Type 14 is 13, 14, 15.

            const sortedSlaps = slaps.sort((a, b) => (slapOrder[a.fgpInt] || 99) - (slapOrder[b.fgpInt] || 99));

            const sectDiv = document.createElement('div');
            sectDiv.style.width = '100%';
            sectDiv.style.marginTop = '15px';

            const hdr = document.createElement('h4');
            hdr.textContent = "Plain / Slap Impressions";
            hdr.style.margin = '0 0 10px 0';
            hdr.style.color = '#aaa';
            hdr.style.borderBottom = '1px solid #444';
            hdr.style.paddingBottom = '5px';
            sectDiv.appendChild(hdr);

            const row = document.createElement('div');
            row.style.display = 'flex';
            row.style.gap = '10px';
            row.style.justifyContent = 'center';
            row.style.flexWrap = 'wrap';
            sectDiv.appendChild(row);

            const slapLabels = { 14: "Left Slap", 13: "Right Slap", 15: "Thumbs" };

            sortedSlaps.forEach(img => {
                const label = slapLabels[img.fgpInt] || `FP ${img.fgp}`;
                row.appendChild(createEditCard(label, img.url));
            });

            imgContainer.appendChild(sectDiv);
        }

        // Fallback for others (e.g. Palm or unknown)
        const others = cleanImages.filter(img => {
            const i = img.fgpInt;
            const isRolled = (i >= 1 && i <= 10);
            const isSlap = [13, 14, 15].includes(i);
            return !isRolled && !isSlap;
        });

        if (others.length > 0) {
            const sectDiv = document.createElement('div');
            sectDiv.style.width = '100%';
            sectDiv.style.marginTop = '15px';

            const hdr = document.createElement('h4');
            hdr.textContent = "Other Images";
            hdr.style.margin = '0 0 10px 0';
            hdr.style.color = '#aaa';
            hdr.style.borderBottom = '1px solid #444';
            sectDiv.appendChild(hdr);

            const row = document.createElement('div');
            row.style.display = 'flex';
            row.style.gap = '10px';
            row.style.justifyContent = 'center';
            row.style.flexWrap = 'wrap';
            sectDiv.appendChild(row);

            others.forEach(img => {
                row.appendChild(createEditCard(`FP ${img.fgp}`, img.url));
            });
            imgContainer.appendChild(sectDiv);
        }
    }
}

function showWarning(input, msg) {
    // Check if warning already exists
    let w = input.nextElementSibling;
    if (w && w.classList.contains('warning-text')) {
        w.textContent = msg;
    } else {
        w = document.createElement('small');
        w.className = 'warning-text';
        w.style.color = '#f39c12';
        w.textContent = msg;
        input.parentNode.appendChild(w);
    }
}

function clearWarning(input) {
    let w = input.nextElementSibling;
    if (w && w.classList.contains('warning-text')) {
        w.remove();
    }
}

async function saveEFTChanges() {
    const form = document.getElementById('edit-form');
    const formData = new FormData(form);
    const data = Object.fromEntries(formData.entries());

    showLoading(true);
    try {
        const payload = {
            session_id: editSessionId,
            type2_data: data
        };

        const res = await fetch('/api/save_eft', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (!res.ok) throw new Error("Save failed");
        const result = await res.json();

        // Show Download Panel
        editViewMain.classList.add('hidden');
        panelDownload.classList.remove('hidden');
        document.getElementById('main-footer').classList.add('hidden');

        const link = document.getElementById('download-link');
        link.href = result.download_url;
        link.setAttribute('download', result.filename);

    } catch (e) {
        alert(e.message);
    } finally {
        showLoading(false);
    }
}


// Init Dropdowns
async function initDropdowns() {
    try {
        const response = await fetch('/static/codes.js');
        const text = await response.text();
        const parseList = (str) => {
            str = str.trim().replace(/,$/, "");
            if (!str) return [];
            return eval(`[${str}]`);
        };

        let match = text.match(/const US_STATES = \[\s*([\s\S]*?)\];/);
        const usStates = match ? parseList(match[1]) : [];
        match = text.match(/const COUNTRIES = \[\s*([\s\S]*?)\];/);
        const countries = match ? parseList(match[1]) : [];

        const allPob = [...usStates, ...countries];
        const allCtz = [...usStates, ...countries];

        const pobSelect = document.getElementById('pob-select');
        const ctzSelect = document.getElementById('ctz-select');
        const addrStateSelect = document.getElementById('addr-state');

        const addOpts = (sel, list) => {
            list.forEach(obj => {
                const key = Object.keys(obj)[0];
                const val = obj[key];
                sel.add(new Option(`${val} (${key})`, key));
            });
        };

        addOpts(pobSelect, allPob);
        addOpts(ctzSelect, allCtz);
        ctzSelect.value = "US";
        addOpts(addrStateSelect, usStates);

        const hSelect = document.getElementById('height-select');
        for (let h = 400; h <= 711; h++) {
            let s = h.toString();
            let ft = s[0];
            let inch = parseInt(s.substring(1));
            if (inch <= 11) hSelect.add(new Option(`${ft}' ${inch}"`, h));
        }

    } catch (e) { console.error(e); }
}

const sentenceCase = (str) => {
    return str.replace(/[a-zA-Z]+/g, function (txt) {
        return txt.charAt(0).toUpperCase() + txt.substr(1).toLowerCase();
    });
};

document.querySelectorAll('.sentence-case').forEach(input => {
    input.addEventListener('blur', (e) => {
        let val = e.target.value.replace(/[^a-zA-Z\s\-]/g, "");
        e.target.value = sentenceCase(val);
    });
    input.addEventListener('input', (e) => {
        e.target.value = e.target.value.replace(/[^a-zA-Z\s\-]/g, "");
    });
});

document.getElementById('no-mn').addEventListener('change', (e) => {
    const mname = document.getElementById('mname');
    if (e.target.checked) {
        mname.value = "";
        mname.disabled = true;
    } else {
        mname.disabled = false;
    }
});

function showLoading(show) {
    if (show) loading.classList.remove('hidden');
    else loading.classList.add('hidden');
}

// Start
initDropdowns();
updateWizardUI();
checkLatestVersion();

async function checkLatestVersion() {
    const el = document.getElementById('latest-version-text');
    if (!el) return;

    try {
        const url = 'https://raw.githubusercontent.com/Robbbbbbbbb/EFTSuite-Public/refs/heads/main/dynamic/version.md';
        const res = await fetch(url + "?t=" + new Date().getTime(), { cache: "no-store" });
        if (res.ok) {
            const ver = (await res.text()).trim();
            // Parse Markdown and remove wrapping <p> tags if present
            const html = marked.parse(ver);
            // marked.parse wraps inline content in <p> by default, which breaks layout in the footer span.
            // We strip the <p> tags to keep it inline.
            el.innerHTML = html.replace(/^<p>|<\/p>\s*$/g, "");

            // Open links in new tab
            el.querySelectorAll('a').forEach(a => {
                a.setAttribute('target', '_blank');
                a.setAttribute('rel', 'noopener noreferrer');
            });
        } else {
            el.textContent = "Unknown";
        }
    } catch (e) {
        el.textContent = "Error";
    }
}

// PDF Selection Logic
function renderPdfSelection(pages) {
    const container = document.getElementById('pdf-pages-container');
    container.innerHTML = '';

    pages.forEach((b64, index) => {
        const wrapper = document.createElement('div');
        wrapper.className = 'mode-selection-card'; // Reuse style
        wrapper.style.padding = '10px';
        wrapper.style.width = '150px';

        const img = document.createElement('img');
        img.src = "data:image/png;base64," + b64;
        img.style.width = '100%';
        img.style.height = 'auto';
        img.style.border = '1px solid #555';
        img.style.marginBottom = '10px';

        const label = document.createElement('div');
        label.innerText = `Page ${index + 1}`;

        wrapper.appendChild(img);
        wrapper.appendChild(label);

        wrapper.onclick = () => selectPdfPage(index);

        container.appendChild(wrapper);
    });
}

document.getElementById('btn-cancel-pdf').onclick = () => {
    window.location.reload();
};

async function selectPdfPage(index) {
    showLoading(true);
    try {
        const res = await fetch('/api/select_pdf_page', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ session_id: sessionId, page_index: index })
        });

        if (!res.ok) throw new Error("Page selection failed");
        const data = await res.json();

        cropImage.onload = () => {
            currentSubStep = 'crop';
            updateWizardUI();
            requestAnimationFrame(initCropStep);
        };
        cropImage.src = "data:image/png;base64," + data.image_base64;

    } catch (e) {
        alert(e.message);
    } finally {
        showLoading(false);
    }
}


// Warning Handlers
document.getElementById('btn-warn-back').onclick = () => {
    window.location.reload();
};

document.getElementById('btn-warn-proceed').onclick = () => {
    if (pendingImageData) {
        const data = pendingImageData;

        if (data.type === 'pdf_selection') {
            currentSubStep = 'pdf_select';
            renderPdfSelection(data.pages);
            updateWizardUI();
            return;
        }

        cropImage.onload = () => {
            currentSubStep = 'crop';
            updateWizardUI();
            requestAnimationFrame(initCropStep);
        };
        cropImage.src = "data:image/png;base64," + data.image_base64;
    }
};

function mirrorBase64(b64) {
    return new Promise((resolve) => {
        const img = new Image();
        img.onload = () => {
            const canvas = document.createElement('canvas');
            canvas.width = img.width;
            canvas.height = img.height;
            const ctx = canvas.getContext('2d');
            ctx.translate(canvas.width, 0);
            ctx.scale(-1, 1);
            ctx.drawImage(img, 0, 0);
            resolve(canvas.toDataURL().split(',')[1]);
        };
        img.src = "data:image/png;base64," + b64;
    });
}
