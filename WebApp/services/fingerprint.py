import os
import cv2
import math
import numpy as np
from services.eft_helper import US_CHAR
from services.nbis_helper import segment_fingerprints, get_nfiq_quality, convert_to_wsq

class Finger:
    """
    Represents a single segmented fingerprint (usually from a slap image).
    
    Attributes:
        orgID (str): Vendor ID for the quality algorithm (defaults to "15" for NFIQv1).
        algID (str): Algorithm ID (defaults to "14205" for NFIQv1).
        str_data (str): The raw output string from `nfseg` describing the segment.
        n (str): Finger position number (1-10).
        sw, sh (int): Width and height of the segment.
        sx, sy (int): Top-left coordinates of the segment relative to the original image.
        t (float): Rotation angle (theta) in degrees.
        score (str): NFIQ quality score (1-5).
        tmpdir (str): Directory where the segment file resides.
    """
    def __init__(self, str_data, tmpdir):
        self.orgID = "15" # Vendor ID for NFIQv1
        self.algID = "14205" # Algorithm ID for NFIQv1
        self.str = str_data
        self.tmpdir = tmpdir
        self.n = "0"
        self.sw = 0
        self.sh = 0
        self.sx = 0
        self.sy = 0
        self.t = 0.0
        self.readString()
        self.computeBox()
        self.segmentQuality()

    def readString(self):
        """
        Parses the output string from `nfseg` to populate attributes.
        Example input: 'FILE lfour_10.raw e 3 sw 168 sh 280 sx 120 sy 256 th -28.3'
        """
        vals = self.str.split(' ')
        try:
            self.name = vals[1]
            # Try to infer finger number from filename if possible
            # Usually nfseg output: basename_XX.ext
            # We will default to 0 if unknown
            base = os.path.splitext(self.name)[0]
            if '_' in base:
                parts = base.split('_')
                if parts[-1].isdigit():
                    self.n = str(int(parts[-1]))
            
            if 'sw' in vals:
                idx_sw = vals.index('sw') + 1
                self.sw = int(vals[idx_sw])
            if 'sh' in vals:
                idx_sh = vals.index('sh') + 1
                self.sh = int(vals[idx_sh])
            if 'sx' in vals:
                idx_sx = vals.index('sx') + 1
                self.sx = int(vals[idx_sx])
            if 'sy' in vals:
                idx_sy = vals.index('sy') + 1
                self.sy = int(vals[idx_sy])
            if 'th' in vals:
                idx_th = vals.index('th') + 1
                self.t = float(vals[idx_th])
            
        except Exception as e:
            print(f"Error parsing Finger string: {e}")

    def computeBox(self):
        """
        Calculates the bounding box coordinates based on dimensions and rotation.
        """
        self.x1 = str(abs(int((self.sw / 2) * math.cos(self.t) - (self.sh / 2)))) 
        self.y1 = str(abs(int((self.sh / 2) * math.cos(self.t) - (self.sw / 2)))) 
        self.x2 = str(abs(int((self.sw / 2) * math.cos(self.t) + (self.sh / 2)))) 
        self.y2 = str(abs(int((self.sh / 2) * math.cos(self.t) - (self.sw / 2)))) 

    def segmentQuality(self):
        """
        Computes the NFIQ quality score for this finger segment.
        """
        try:
            # Pass full path to nfiq
            full_path = os.path.join(self.tmpdir, self.name)
            self.score = str(get_nfiq_quality(full_path))
        except Exception as e:
            # print(f"NFIQ failed: {e}") # Silent fail
            self.score = "255"

    def getScoreString(self):
        """
        Returns the formatted score string for Type-14 record.
        Maps plain thumb positions (11, 12) to standard finger positions (1, 6) for quality scoring.
        """
        n_val = self.n
        if self.n == "11":
            n_val = "1"
        elif self.n == "12":
            n_val = "6"
            
        return n_val + chr(US_CHAR) + self.score + chr(US_CHAR) + self.orgID + chr(US_CHAR) + self.algID

    def getPosString(self):
        """Returns the formatted position string for Type-14 record."""
        return self.n + chr(US_CHAR) + self.x1 + chr(US_CHAR) + self.x2 + chr(US_CHAR) + self.y1 + chr(US_CHAR) + self.y2


class Fingerprint:
    """
    Represents a source fingerprint image (e.g., a slap or a thumb) to be processed.
    
    Attributes:
        img (numpy.ndarray): The image data in grayscale.
        fp_number (int): The FBI finger position code (13=R Slap, 14=L Slap, 15=Thumbs).
        name (str): Unique identifier for this fingerprint instance.
        fingers (List[Finger]): List of segmented `Finger` objects if this is a slap image.
        converted (str): Path to the converted JP2 file.
    """
    def __init__(self, src_img, fp_number, tmpdir, session_id):
        self.tmpdir = tmpdir
        self.session_id = session_id
        self.fp_number = fp_number
        self.name = f"{session_id}_{fp_number}"
        self.encoding = 'png'
        self.converted = ""
        
        # Validate Image
        if src_img is None or src_img.size == 0:
             raise ValueError(f"Invalid image for FP {fp_number}")

        # Force 8-bit Grayscale
        if len(src_img.shape) == 3 and src_img.shape[2] == 3:
            print(f"Converting FP {fp_number} from RGB {src_img.shape} to Grayscale")
            self.img = cv2.cvtColor(src_img, cv2.COLOR_BGR2GRAY)
        else:
            self.img = src_img
            
        print(f"FP {fp_number} Image Shape: {self.img.shape}")
        self.fingers = []
        
        # Attributes required by Type14 Record
        self.hll = str(self.img.shape[1]) # Width
        self.vll = str(self.img.shape[0]) # Height
        self.fgp = str(self.fp_number)    # Finger Position
        self.slc = "1"                    # Scale Units (Pixels per inch)
        
        # Fixed constants as per FBI EFT Specification
        self.hps = "2400"                 # Horizontal Pixel Scale
        self.vps = "2400"                 # Vertical Pixel Scale
        self.cga = "NONE"                 # Compression Algorithm (Default None)
        self.bpx = "8"                    # Bits Per Pixel

    def _prepare_type4_dimensions(self):
        """
        Resizes the image to meet Type-4 strict dimension requirements.
        """
        target_w, target_h = 0, 0
        fp_num = int(self.fp_number)
        
        if 1 <= fp_num <= 10:
            target_w, target_h = 800, 750
        elif 11 <= fp_num <= 12:
            target_w, target_h = 400, 572
        elif 13 <= fp_num <= 14:
            target_w, target_h = 1600, 1000
        else:
            return # No resize needed
            
        print(f"Resizing FP {fp_num} to {target_w}x{target_h} for Type-4")
        resized_img = cv2.resize(self.img, (target_w, target_h), interpolation=cv2.INTER_AREA)
        
        self.img = resized_img
        self.hll = str(target_w)
        self.vll = str(target_h)

    def process_and_convert_raw(self, type4=False):
        """
        Saves the image as raw bytes (uncompressed).
        """
        if type4:
            self._prepare_type4_dimensions()

        raw_path = os.path.join(self.tmpdir, self.name + ".raw")
        with open(raw_path, "wb") as f:
            f.write(self.img.tobytes())
            
        self.converted = raw_path
        self.cga = "NONE"
        print(f"FP {self.fp_number} Saved Raw: {raw_path}")
        
        # Segment slaps if Type-14 (Type-4 usually doesn't segment slaps in this context)
        if not type4 and int(self.fp_number) >= 13:
            # For segmentation we need a PNG usually because nfseg works on image files
            # But we can save a temp png
            png_path = os.path.join(self.tmpdir, self.name + ".png")
            cv2.imwrite(png_path, self.img)
            self.segment()
            
        return self.converted

    def process_and_convert_wsq(self, bitrate=2.25, type4=False):
        """
        Compresses the image using WSQ.
        """
        if type4:
            self._prepare_type4_dimensions()

        # Save Raw first (needed for cwsq)
        raw_path = os.path.join(self.tmpdir, self.name + ".raw")
        with open(raw_path, "wb") as f:
            f.write(self.img.tobytes())
            
        wsq_path = os.path.join(self.tmpdir, self.name + ".wsq")
        
        try:
            convert_to_wsq(
                raw_path, 
                wsq_path, 
                int(self.hll), 
                int(self.vll), 
                bitrate=bitrate
            )
            self.converted = wsq_path
            self.cga = "WSQ20" # For Type-14. Type-4 will map this to 1.
            print(f"FP {self.fp_number} Converted to WSQ: {wsq_path} (Rate: {bitrate})")
        except Exception as e:
            print(f"WSQ Conversion failed: {e}")
            return None

        if not type4 and int(self.fp_number) >= 13:
            # Segment needs PNG
            png_path = os.path.join(self.tmpdir, self.name + ".png")
            if not os.path.exists(png_path):
                cv2.imwrite(png_path, self.img)
            self.segment()

        return self.converted

    def process_and_convert(self, compression_ratio=10):
        """
        Legacy method for JP2 conversion (kept for backward compatibility if needed, 
        but we are moving to WSQ/Raw).
        """
        png_path = os.path.join(self.tmpdir, self.name + ".png")
        if not os.path.exists(png_path):
            cv2.imwrite(png_path, self.img)
            
        jp2_path = os.path.join(self.tmpdir, self.name + ".jp2")
        
        # Command: opj_compress -i input.png -o output.jp2 -r ratio -n 2
        cmd = ["opj_compress", "-i", png_path, "-o", jp2_path, "-r", str(compression_ratio), "-n", "2"]
        
        try:
            import subprocess
            res = subprocess.run(cmd, capture_output=True, text=True)
            if res.returncode != 0:
                print(f"opj_compress failed for FP {self.fp_number}: {res.stderr}")
                return None
            
            self.converted = jp2_path
            self.cga = "JP2"
        except Exception as e:
            print(f"Conversion failed: {e}")
            return None

        if int(self.fp_number) >= 13:
            self.segment()
            
        return self.converted

    def process_and_convert_type4(self, compression_ratio=10):
        """
        Legacy Type-4 JP2 conversion.
        """
        self._prepare_type4_dimensions()
        return self.process_and_convert(compression_ratio)

    def segment(self):
        """
        Segments the slap image into individual fingers using `nfseg`.
        Populates the `self.fingers` list with `Finger` objects.
        """
        png_path = os.path.join(self.tmpdir, self.name + ".png")
        try:
            segments = segment_fingerprints(png_path, self.fp_number)
            for segment in segments:
                # The Finger class expects a string, so we need to reconstruct it
                line = f"FILE {segment['file']} e 3 sw {segment['sw']} sh {segment['sh']} sx {segment['sx']} sy {segment['sy']} th {segment['th']}"
                self.fingers.append(Finger(line, self.tmpdir))
        except Exception as e:
            print(f"Segmentation failed: {e}")
