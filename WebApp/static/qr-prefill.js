/* ============================================================================
 * qr-prefill.js  —  EFT Suite "Scan QR to Prefill" (operator side)
 * ----------------------------------------------------------------------------
 * Adds a button to the data-entry step that reads an applicant's pre-fill QR
 * (produced by intake.html) and populates #type2-form. Nothing is sent to the
 * server here — it only fills the existing form, then the operator clicks the
 * normal Generate button as usual. No backend or Docker changes required.
 *
 * INSTALL (one-time):
 *   1. Drop this file in WebApp/static/qr-prefill.js
 *   2. Drop the decoder library in WebApp/static/ (for offline use, vendor it):
 *        curl -L -o WebApp/static/html5-qrcode.min.js \
 *          https://cdn.jsdelivr.net/npm/html5-qrcode@2.3.8/html5-qrcode.min.js
 *   3. In WebApp/static/index.html, just before </body> add:
 *        <script src="/static/html5-qrcode.min.js"></script>
 *        <script src="/static/qr-prefill.js"></script>
 *
 * The Dockerfile does `COPY . /app`, so these static files are included
 * automatically on the next `docker build` -- no other changes needed.
 *
 * CAMERA NOTE: getUserMedia (live camera) only works on a "secure context":
 * http://localhost is fine, but a plain http:// LAN IP is not. The "Scan from
 * image" fallback (upload a photo of the QR) always works regardless.
 * ==========================================================================*/

(function () {
  "use strict";

  // ---- Helpers ------------------------------------------------------------
  const fromB64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

  // Expand single-char field names back to the form's name="" attributes
  const FEXPAND = {
    'n':'fname','m':'mname','l':'lname','d':'dob',
    'p':'2.020','c':'2.021','s':'2.016',
    'a':'addr_street','b':'addr_city','e':'addr_state','z':'addr_zip',
    'x':'2.024','r':'2.025','h':'2.027','w':'2.029','o':'2.031','i':'2.032'
  };
  function expandFields(compact) {
    if (!compact) return {};
    return Object.fromEntries(
      Object.entries(compact).map(([k, v]) => [FEXPAND[k] !== undefined ? FEXPAND[k] : k, v])
    );
  }
  function expandFlags(g) {
    if (!g) return {};
    // compact: nm=1 → no_mn:true, bs=1 → bypass_ssn:true
    const out = {};
    if (g.nm || g.no_mn)       out.no_mn = true;
    if (g.bs || g.bypass_ssn)  out.bypass_ssn = true;
    return out;
  }

  function setField(name, value) {
    const el = document.querySelector(`#type2-form [name="${CSS.escape(name)}"]`);
    if (!el) return;
    if (el.tagName === "SELECT") {
      const exists = Array.from(el.options).some((o) => o.value === String(value));
      if (!exists && value !== "" && value != null) {
        el.add(new Option(String(value), String(value)));
      }
    }
    el.value = value == null ? "" : value;
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  }

  function applyToForm(fields, flags) {
    Object.entries(fields || {}).forEach(([k, v]) => setField(k, v));
    flags = flags || {};
    const noMn = document.getElementById("no-mn");
    if (noMn) {
      noMn.checked = !!flags.no_mn;
      noMn.dispatchEvent(new Event("change", { bubbles: true }));
    }
    const bypass = document.getElementById("bypass-ssn");
    if (bypass) {
      bypass.checked = !!flags.bypass_ssn;
      bypass.dispatchEvent(new Event("change", { bubbles: true }));
    }
  }

  // ---- Decryption ---------------------------------------------------------
  async function decryptPayload(obj, passphrase) {
    const enc = new TextEncoder();
    const baseKey = await crypto.subtle.importKey(
      "raw", enc.encode(passphrase), "PBKDF2", false, ["deriveKey"]
    );
    const key = await crypto.subtle.deriveKey(
      { name: "PBKDF2", salt: fromB64(obj.salt), iterations: 150000, hash: "SHA-256" },
      baseKey, { name: "AES-GCM", length: 256 }, false, ["decrypt"]
    );
    const pt = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: fromB64(obj.iv) }, key, fromB64(obj.ct)
    );
    return JSON.parse(new TextDecoder().decode(pt));
  }

  // ---- Process decoded QR text --------------------------------------------
  async function handleDecodedText(text) {
    let obj;
    try { obj = JSON.parse(text); } catch (e) {
      alert("That QR code isn't an EFT Suite pre-fill code.");
      return;
    }
    // Accept both legacy "eftsuite-intake" and compact "ei" type strings
    if (!obj || (obj.t !== "eftsuite-intake" && obj.t !== "ei")) {
      alert("That QR code isn't an EFT Suite pre-fill code.");
      return;
    }

    if (obj.enc === "AESGCM") {
      const MAX = 3;
      for (let attempt = 1; attempt <= MAX; attempt++) {
        const left = MAX - attempt + 1;
        const msg = attempt === 1
          ? "This pre-fill code is encrypted. Enter the applicant's passphrase:"
          : "Incorrect passphrase. " + left + " attempt" + (left === 1 ? "" : "s") +
            " left. Enter the passphrase:";
        const pass = prompt(msg);
        if (pass === null) return;
        try {
          const data = await decryptPayload(obj, pass);
          // Support both compact {f,g} and legacy {fields,flags} inner formats
          applyToForm(expandFields(data.f || data.fields), expandFlags(data.g || data.flags));
          closeScanner();
          flashStatus("Form pre-filled from QR. Please verify every field before generating.");
          return;
        } catch (e) {
          if (attempt === MAX) {
            alert("Incorrect passphrase -- all " + MAX + " attempts used. Scan or upload the code again to retry.");
            return;
          }
        }
      }
      return;
    }

    try {
      // Support both compact {f,g} and legacy {fields,flags} formats
      applyToForm(expandFields(obj.f || obj.fields), expandFlags(obj.g || obj.flags));
      closeScanner();
      flashStatus("Form pre-filled from QR. Please verify every field before generating.");
    } catch (e) {
      alert("Could not read the code.");
    }
  }

  // ---- Scanner UI ---------------------------------------------------------
  let overlay = null;
  let cameraStream = null;   // active getUserMedia stream

  function flashStatus(msg) {
    const n = document.createElement("div");
    n.textContent = msg;
    n.style.cssText =
      "position:fixed;bottom:20px;left:50%;transform:translateX(-50%);" +
      "background:#1f6f3f;color:#fff;padding:12px 18px;border-radius:6px;" +
      "z-index:10000;max-width:90%;text-align:center;box-shadow:0 2px 12px rgba(0,0,0,.4)";
    document.body.appendChild(n);
    setTimeout(() => n.remove(), 6000);
  }

  function closeScanner() {
    if (cameraStream) {
      cameraStream.getTracks().forEach((t) => t.stop());
      cameraStream = null;
    }
    if (overlay) { overlay.remove(); overlay = null; }
  }

  function openScanner() {
    const hasBD = ('BarcodeDetector' in window);

    overlay = document.createElement("div");
    overlay.style.cssText =
      "position:fixed;inset:0;background:rgba(0,0,0,.9);z-index:9999;" +
      "display:flex;flex-direction:column;align-items:center;justify-content:center;gap:14px;padding:20px;";
    overlay.innerHTML = `
      <div style="color:#fff;font-size:1.1rem;font-weight:bold;">Scan Applicant QR Code</div>

      <div style="position:relative;width:min(460px,92vw);background:#000;border-radius:8px;overflow:hidden;">
        <video id="qr-video" autoplay playsinline muted style="width:100%;display:block;"></video>
        <div style="position:absolute;inset:0;display:flex;align-items:center;justify-content:center;pointer-events:none;">
          <div id="qr-aim-ring" style="width:260px;height:260px;border:2px solid rgba(186,218,85,.8);border-radius:10px;
                      box-shadow:0 0 0 9999px rgba(0,0,0,.35);transition:border-color .15s;"></div>
        </div>
      </div>

      <div id="qr-decode-tmp" style="display:none;"></div>
      <canvas id="qr-snap-canvas" style="display:none;max-width:320px;border:2px solid #bada55;border-radius:4px;"></canvas>
      <canvas id="qr-crop-canvas" style="display:none;"></canvas>

      <div style="display:flex;gap:10px;flex-wrap:wrap;justify-content:center;">
        <button type="button" id="qr-snap-btn" class="btn"
                style="font-size:1rem;padding:12px 28px;">📸 Capture &amp; Decode</button>
        <label class="btn btn-secondary" style="cursor:pointer;margin:0;padding:12px 20px;">
          Upload image
          <input type="file" accept="image/*" id="qr-file-input" style="display:none;">
        </label>
        <button type="button" class="btn btn-secondary" id="qr-close-btn">Cancel</button>
      </div>

      <div id="qr-status" style="color:#bada55;font-size:.9rem;max-width:380px;text-align:center;min-height:1.4em;">
        Starting camera…
      </div>`;
    document.body.appendChild(overlay);

    const video      = document.getElementById("qr-video");
    const canvas     = document.getElementById("qr-snap-canvas");
    const cropCanvas = document.getElementById("qr-crop-canvas");
    const snapBtn    = document.getElementById("qr-snap-btn");
    const aimRing    = document.getElementById("qr-aim-ring");

    const setStatus = (msg, isError) => {
      const el = document.getElementById("qr-status");
      if (el) { el.textContent = msg; el.style.color = isError ? "#ffb4b4" : "#bada55"; }
    };

    function stopCamera() {
      if (cameraStream) {
        if (cameraStream._stopScan) cameraStream._stopScan();
        cameraStream.getTracks().forEach((t) => t.stop());
        cameraStream = null;
      }
    }

    // Decode a File/Blob: BarcodeDetector → ZXing fallback
    async function decodeFileObj(file) {
      if (hasBD) {
        try {
          const detector = new BarcodeDetector({ formats: ['qr_code'] });
          const bitmap = await createImageBitmap(file);
          const codes = await detector.detect(bitmap);
          if (codes.length > 0) return codes[0].rawValue;
        } catch (_) {}
      }
      if (typeof Html5Qrcode !== "undefined") {
        const reader = new Html5Qrcode("qr-decode-tmp");
        return reader.scanFile(file, false)
          .finally(() => { try { reader.clear(); } catch (_) {} });
      }
      throw new Error("No decoder available");
    }

    // ---- close ----
    document.getElementById("qr-close-btn").onclick = () => { stopCamera(); closeScanner(); };

    // ---- upload fallback ----
    document.getElementById("qr-file-input").onchange = (e) => {
      const file = e.target.files && e.target.files[0];
      if (!file) return;
      setStatus("Decoding image…", false);
      decodeFileObj(file)
        .then((decoded) => { stopCamera(); handleDecodedText(decoded); })
        .catch(() => setStatus("No QR code found — try a clearer image.", true))
        .finally(() => { e.target.value = ""; });
    };

    // ---- snap: always capture frame to canvas first so user sees what was grabbed ----
    snapBtn.onclick = async () => {
      if (!cameraStream || video.videoWidth === 0) {
        setStatus("Camera not ready yet — wait a moment.", true);
        return;
      }
      setStatus("Capturing frame…", false);
      snapBtn.disabled = true;

      try {
        // ALWAYS draw the current video frame to canvas so user can see what was captured
        canvas.width  = video.videoWidth;
        canvas.height = video.videoHeight;
        canvas.getContext("2d").drawImage(video, 0, 0);
        canvas.style.display = "block";
        window._qrCanvas = canvas; // debug handle

        let result = null;

        // Helper: decode a canvas element with all available decoders
        async function tryDecodeCanvas(src, label) {
          // A. jsQR — direct pixel data, excellent for screen QR codes
          if (typeof jsQR !== "undefined") {
            const ctx = src.getContext("2d");
            const id = ctx.getImageData(0, 0, src.width, src.height);
            console.log(`[QR:${label}] jsQR attempt ${src.width}x${src.height}`);
            const code = jsQR(id.data, id.width, id.height, { inversionAttempts: "attemptBoth" });
            console.log(`[QR:${label}] jsQR result:`, code ? code.data.substring(0,40) : null);
            if (code) return code.data;
          }

          // B. BarcodeDetector (Chrome flag or Android/Mac)
          if (hasBD) {
            try {
              const detector = new BarcodeDetector({ formats: ['qr_code'] });
              const codes = await detector.detect(src);
              if (codes.length) return codes[0].rawValue;
            } catch (_) {}
          }

          // C. ZXing via Html5Qrcode scanFile
          if (typeof Html5Qrcode !== "undefined") {
            return new Promise((resolve, reject) => {
              src.toBlob((blob) => {
                if (!blob) { reject(new Error("toBlob null")); return; }
                const reader = new Html5Qrcode("qr-decode-tmp");
                reader.scanFile(new File([blob], label + ".png", { type: "image/png" }), false)
                  .then(resolve).catch(reject)
                  .finally(() => { try { reader.clear(); } catch (_) {} });
              }, "image/png");
            });
          }

          return null;
        }

        // Helper: draw scaled copy of canvas into a new canvas of given max width
        function scaledCanvas(src, maxW) {
          const scale = Math.min(1, maxW / src.width);
          const c = document.createElement("canvas");
          c.width  = Math.round(src.width  * scale);
          c.height = Math.round(src.height * scale);
          c.getContext("2d").drawImage(src, 0, 0, c.width, c.height);
          return c;
        }

        // Helper: apply image preprocessing to fight moire/blur from screen→camera
        // blur (px) removes moire bands; contrast multiplier binarizes modules
        function preprocessCanvas(src, blurPx, contrast) {
          const c = document.createElement("canvas");
          c.width = src.width; c.height = src.height;
          const ctx = c.getContext("2d");
          ctx.filter = `grayscale(1) blur(${blurPx}px) contrast(${contrast})`;
          ctx.drawImage(src, 0, 0);
          ctx.filter = "none";
          return c;
        }

        // 1. Try ImageCapture.grabFrame() with BarcodeDetector (highest quality, no canvas taint)
        if (result === null && hasBD && 'ImageCapture' in window && cameraStream.getVideoTracks().length) {
          try {
            const ic = new ImageCapture(cameraStream.getVideoTracks()[0]);
            const bitmap = await ic.grabFrame();
            const codes = await new BarcodeDetector({ formats: ['qr_code'] }).detect(bitmap);
            if (codes.length) result = codes[0].rawValue;
          } catch (_) {}
        }

        // 2. Full-resolution canvas — raw
        if (result === null) {
          setStatus("Trying full-res decode…", false);
          try { result = await tryDecodeCanvas(canvas, "full"); } catch (_) {}
        }

        // 3. Downscaled to 1280px
        if (result === null) {
          setStatus("Trying 1280px scale…", false);
          try { result = await tryDecodeCanvas(scaledCanvas(canvas, 1280), "1280"); } catch (_) {}
        }

        // 4. Downscaled to 800px
        if (result === null) {
          setStatus("Trying 800px scale…", false);
          try { result = await tryDecodeCanvas(scaledCanvas(canvas, 800), "800"); } catch (_) {}
        }

        // 5. Center-square crop at 512px
        if (result === null) {
          setStatus("Trying center crop…", false);
          const sq = Math.min(canvas.width, canvas.height);
          cropCanvas.width  = 512;
          cropCanvas.height = 512;
          cropCanvas.getContext("2d").drawImage(
            canvas,
            (canvas.width - sq) / 2, (canvas.height - sq) / 2, sq, sq,
            0, 0, 512, 512
          );
          try { result = await tryDecodeCanvas(cropCanvas, "crop"); } catch (_) {}
        }

        // 6. Preprocessed 800px: light blur + contrast 4 (mild moire removal)
        if (result === null) {
          setStatus("Trying preprocessed (light)…", false);
          try { result = await tryDecodeCanvas(preprocessCanvas(scaledCanvas(canvas, 800), 1, 4), "pre-light"); } catch (_) {}
        }

        // 7. Preprocessed 600px: stronger blur + contrast 8 (heavy moire removal)
        if (result === null) {
          setStatus("Trying preprocessed (strong)…", false);
          try { result = await tryDecodeCanvas(preprocessCanvas(scaledCanvas(canvas, 600), 2, 8), "pre-strong"); } catch (_) {}
        }

        // 8. Preprocessed center crop 512px: blur + high contrast (best for screen QR)
        if (result === null) {
          setStatus("Trying preprocessed crop…", false);
          try { result = await tryDecodeCanvas(preprocessCanvas(cropCanvas, 1.5, 6), "pre-crop"); } catch (_) {}
        }

        if (!result) throw new Error("QR code not detected — check the preview above and re-aim");
        canvas.style.display = "none";
        stopCamera();
        handleDecodedText(result);
      } catch (err) {
        const msg = (err && (err.message || err.name)) || "unknown";
        setStatus(`No QR code found — check the captured preview above to verify the QR is in frame.`, true);
        snapBtn.disabled = false;
      }
    };

    // ---- camera ----
    if (!window.isSecureContext || !navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      setStatus("Camera unavailable (needs https:// or localhost). Use 'Upload image'.", true);
      snapBtn.disabled = true;
      return;
    }

    navigator.mediaDevices.getUserMedia({
      video: { facingMode: { ideal: "environment" }, width: { ideal: 1920 }, height: { ideal: 1080 } }
    })
    .then((stream) => {
      cameraStream = stream;
      video.srcObject = stream;

      if (hasBD) {
        // ── AUTO-SCAN in background — also keep Capture button visible ──
        setStatus("Auto-scanning… or press Capture to force a decode.", false);
        const detector = new BarcodeDetector({ formats: ['qr_code'] });
        let active = true;
        let lastTs = 0;
        cameraStream._stopScan = () => { active = false; };

        // Use ImageCapture.grabFrame() if available — no canvas, no taint issues
        const videoTrack = stream.getVideoTracks()[0];
        const ic = ('ImageCapture' in window && videoTrack) ? new ImageCapture(videoTrack) : null;

        function scanTick(ts) {
          if (!active || !cameraStream) return;
          if (ts - lastTs >= 400 && video.readyState >= 2 && video.videoWidth > 0) {
            lastTs = ts;
            const grab = ic
              ? ic.grabFrame().then((bmp) => detector.detect(bmp))
              : Promise.resolve([]);
            grab.then((codes) => {
              if (!active) return;
              if (codes.length > 0) {
                active = false;
                if (aimRing) aimRing.style.borderColor = "#55ff55";
                stopCamera();
                handleDecodedText(codes[0].rawValue);
              } else {
                requestAnimationFrame(scanTick);
              }
            }).catch(() => { if (active) requestAnimationFrame(scanTick); });
          } else {
            requestAnimationFrame(scanTick);
          }
        }
        requestAnimationFrame(scanTick);

      } else {
        setStatus("Aim the QR code in the box, then press Capture.", false);
      }
    })
    .catch((err) => {
      const n = (err && err.name) || "";
      const msg = /NotAllowedError|Permission/i.test(n)
        ? "Camera permission denied — allow access and reopen, or use 'Upload image'."
        : /NotFoundError/i.test(n) ? "No camera found. Use 'Upload image'."
        : "Camera error (" + (err.message || n) + "). Use 'Upload image'.";
      setStatus(msg, true);
      snapBtn.disabled = true;
    });
  }

  // ---- Phone scan (Option 3): show QR of /scan URL, poll for result --------
  let _phonePolling = null;

  function openPhoneScanner() {
    if (_phonePolling) clearInterval(_phonePolling);

    // Build the overlay
    const ov = document.createElement("div");
    ov.id = "phone-scan-overlay";
    ov.style.cssText =
      "position:fixed;inset:0;background:rgba(0,0,0,.92);z-index:9999;" +
      "display:flex;flex-direction:column;align-items:center;justify-content:center;gap:14px;padding:20px;";
    ov.innerHTML = `
      <div style="color:#fff;font-size:1.1rem;font-weight:bold;">Phone Camera Scan</div>
      <div style="color:#aaa;font-size:.85rem;text-align:center;max-width:320px;">
        Scan the QR below with your phone, then use your phone camera to scan the patient's QR.
      </div>
      <div id="phone-qr-holder" style="background:#fff;padding:12px;border-radius:8px;"></div>
      <div id="phone-scan-url" style="color:#bada55;font-size:.8rem;word-break:break-all;max-width:320px;text-align:center;"></div>
      <div id="phone-scan-status" style="color:#bada55;font-size:.9rem;text-align:center;min-height:1.4em;">
        Waiting for phone scan…
      </div>
      <button type="button" class="btn btn-secondary" id="phone-scan-cancel">Cancel</button>`;
    document.body.appendChild(ov);

    document.getElementById("phone-scan-cancel").onclick = () => {
      if (_phonePolling) { clearInterval(_phonePolling); _phonePolling = null; }
      ov.remove();
    };

    // Detect real LAN IP via WebRTC
    // Score: 192.168.x = 0 (best), 10.x = 1, 172.x = 3 (Docker bridge lives here), loopback = 4
    function scoreIP(ip) {
      if (/^192\.168\./.test(ip)) return 0;
      if (/^10\./.test(ip))       return 1;
      if (/^172\./.test(ip))      return 3; // Docker bridge (172.17.x.x) — avoid
      if (/^127\./.test(ip))      return 4;
      return 2;
    }

    function getAllLanIPs() {
      return new Promise((resolve) => {
        try {
          const pc = new RTCPeerConnection({ iceServers: [] });
          pc.createDataChannel("");
          pc.createOffer().then(o => pc.setLocalDescription(o));
          const found = new Set();
          pc.onicecandidate = (e) => {
            if (!e.candidate) {
              pc.close();
              resolve([...found].sort((a, b) => scoreIP(a) - scoreIP(b)));
            } else {
              const m = e.candidate.candidate.match(/(\d+\.\d+\.\d+\.\d+)/);
              if (m && m[1] !== "0.0.0.0") found.add(m[1]);
            }
          };
          setTimeout(() => { try { pc.close(); } catch(_){} resolve([...found]); }, 3000);
        } catch (_) { resolve([]); }
      });
    }

    function buildPhoneQR(url) {
      const holder = document.getElementById("phone-qr-holder");
      const urlEl  = document.getElementById("phone-scan-url");
      if (!holder) return;
      // Clear previous content
      holder.innerHTML = "";
      urlEl.textContent = url;
      if (typeof QRCode !== "undefined") {
        new QRCode(holder, { text: url, width: 200, height: 200, correctLevel: QRCode.CorrectLevel.M });
      } else {
        holder.innerHTML = `<p style="color:#111;font-size:.75rem;word-break:break-all;">${url}</p>`;
      }
    }
    // Make buildPhoneQR accessible from inline onclick
    window._buildPhoneQR = buildPhoneQR;

    getAllLanIPs().then(ips => {
      const port = 8080;
      const holder = document.getElementById("phone-qr-holder");

      // Best candidate: first IP that isn't 172.x and isn't loopback
      const best = ips.find(ip => scoreIP(ip) <= 1);

      if (best) {
        buildPhoneQR(`http://${best}:${port}/scan`);
        // If there are other candidates, show them as alternates below the QR
        const others = ips.filter(ip => ip !== best && scoreIP(ip) <= 2);
        if (others.length) {
          const altDiv = document.createElement("div");
          altDiv.style.cssText = "margin-top:10px;font-size:.75rem;color:#555;text-align:center;";
          altDiv.innerHTML = "Wrong IP? Try: " + others.map(ip =>
            `<a href="#" style="color:#0066cc;margin:0 4px;" onclick="event.preventDefault();window._buildPhoneQR('http://${ip}:${port}/scan');">${ip}</a>`
          ).join("");
          holder.appendChild(altDiv);
        }
      } else {
        // No good IP found — show manual input + any detected IPs as hints
        const hint = ips.length ? `<br><small style="color:#888">Detected: ${ips.join(", ")}</small>` : "";
        holder.innerHTML = `
          <div style="color:#333;font-size:.85rem;padding:10px;text-align:center;">
            Enter your computer's LAN IP:${hint}<br>
            <input id="manual-ip" type="text" placeholder="e.g. 192.168.1.50"
              style="margin-top:8px;padding:6px;font-size:1rem;border-radius:4px;border:1px solid #aaa;width:180px;">
            <br>
            <button onclick="const v=document.getElementById('manual-ip').value.trim();if(v)window._buildPhoneQR('http://'+v+':${port}/scan');"
              style="margin-top:8px;padding:6px 14px;cursor:pointer;">Generate QR</button>
          </div>`;
      }
    });

    // Poll for incoming prefill data
    _phonePolling = setInterval(() => {
      fetch("/api/prefill-pending")
        .then(r => r.json())
        .then(({ data }) => {
          if (data) {
            clearInterval(_phonePolling);
            _phonePolling = null;
            document.getElementById("phone-scan-status").textContent = "✓ Received! Filling form…";
            setTimeout(() => {
              ov.remove();
              handleDecodedText(data);
            }, 600);
          }
        })
        .catch(() => {});
    }, 2000);
  }

  // ---- USB barcode scanner (Option 4): focused text input ----------------
  function openUsbScanner() {
    const form = document.getElementById("type2-form");
    if (!form) return;

    const ov = document.createElement("div");
    ov.id = "usb-scan-overlay";
    ov.style.cssText =
      "position:fixed;inset:0;background:rgba(0,0,0,.92);z-index:9999;" +
      "display:flex;flex-direction:column;align-items:center;justify-content:center;gap:14px;padding:20px;";
    ov.innerHTML = `
      <div style="color:#fff;font-size:1.1rem;font-weight:bold;">USB Barcode Scanner</div>
      <div style="color:#aaa;font-size:.85rem;text-align:center;max-width:360px;">
        Click the field below to focus it, then scan the QR code with your USB scanner.
      </div>
      <input id="usb-scan-input" type="text" autocomplete="off"
        placeholder="Scanner input — click here then scan"
        style="width:min(400px,90vw);padding:14px;font-size:1rem;border-radius:8px;border:2px solid #bada55;
               background:#1a1a1a;color:#fff;outline:none;text-align:center;">
      <div id="usb-scan-status" style="color:#bada55;font-size:.9rem;min-height:1.4em;text-align:center;">
        Ready — scan a QR code
      </div>
      <button type="button" class="btn btn-secondary" id="usb-scan-cancel">Cancel</button>`;
    document.body.appendChild(ov);

    const inp = document.getElementById("usb-scan-input");
    inp.focus();

    document.getElementById("usb-scan-cancel").onclick = () => ov.remove();

    // USB scanners typically finish with Enter (\n or \r)
    inp.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        const val = inp.value.trim();
        if (!val) return;
        document.getElementById("usb-scan-status").textContent = "Decoding…";
        inp.value = "";
        ov.remove();
        handleDecodedText(val);
      }
    });

    // Also handle paste + auto-detect (some scanners paste instead of typing)
    inp.addEventListener("paste", () => {
      setTimeout(() => {
        const val = inp.value.trim();
        if (val.startsWith("{")) {
          inp.value = "";
          ov.remove();
          handleDecodedText(val);
        }
      }, 100);
    });
  }

  // ---- Upload QR image (Option: patient shares image file) ----------------
  function openUploadScanner() {
    const ov = document.createElement("div");
    ov.id = "upload-scan-overlay";
    ov.style.cssText =
      "position:fixed;inset:0;background:rgba(0,0,0,.92);z-index:9999;" +
      "display:flex;flex-direction:column;align-items:center;justify-content:center;gap:14px;padding:20px;";
    ov.innerHTML = `
      <div style="color:#fff;font-size:1.1rem;font-weight:bold;">Upload QR Image</div>
      <div style="color:#aaa;font-size:.85rem;text-align:center;max-width:320px;">
        Patient screenshots their QR code and shares the image file. Select it below.
      </div>
      <label style="display:inline-block;padding:14px 28px;background:#2c6e49;color:#fff;
                    border-radius:10px;font-size:1rem;cursor:pointer;" for="qr-upload-input">
        📁 Choose Image File
      </label>
      <input id="qr-upload-input" type="file" accept="image/*" style="display:none;">
      <div id="upload-scan-status" style="color:#bada55;font-size:.9rem;text-align:center;min-height:1.4em;"></div>
      <button type="button" class="btn btn-secondary" id="upload-scan-cancel">Cancel</button>`;
    document.body.appendChild(ov);

    document.getElementById("upload-scan-cancel").onclick = () => ov.remove();

    document.getElementById("qr-upload-input").addEventListener("change", async function() {
      const file = this.files[0];
      if (!file) return;
      document.getElementById("upload-scan-status").textContent = "Uploading…";
      const form = new FormData();
      form.append("file", file);
      try {
        const res  = await fetch("/api/decode-qr", { method: "POST", body: form });
        const json = await res.json();
        if (json.ok) {
          document.getElementById("upload-scan-status").textContent = "✓ Decoded! Filling form…";
          setTimeout(() => { ov.remove(); handleDecodedText(json.data); }, 500);
        } else {
          document.getElementById("upload-scan-status").textContent =
            "No QR found in image. Make sure you selected the QR screenshot.";
          document.getElementById("upload-scan-status").style.color = "#ff7070";
        }
      } catch (e) {
        document.getElementById("upload-scan-status").textContent = "Server error — try again.";
        document.getElementById("upload-scan-status").style.color = "#ff7070";
      }
    });
  }

  // ---- Inject buttons -----------------------------------------------------
  function injectButton() {
    const form = document.getElementById("type2-form");
    if (!form || document.getElementById("btn-usb-scan")) return;
    const bar = document.createElement("div");
    bar.style.cssText = "margin-bottom:16px;display:flex;gap:6px;";
    bar.innerHTML = `
      <button type="button" id="btn-usb-scan" class="btn btn-secondary" style="flex:1;">
        🔌 USB Scanner
      </button>
      <button type="button" id="btn-upload-scan" class="btn btn-secondary" style="flex:1;">
        📁 Upload QR
      </button>
      <button type="button" id="btn-phone-scan" class="btn btn-secondary" style="flex:1;">
        📷 Photo of Print
      </button>`;
    form.parentNode.insertBefore(bar, form);
    document.getElementById("btn-usb-scan").onclick    = openUsbScanner;
    document.getElementById("btn-upload-scan").onclick  = openUploadScanner;
    document.getElementById("btn-phone-scan").onclick   = openPhoneScanner;
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", injectButton);
  } else {
    injectButton();
  }
})();
