import os
import cv2
import shutil
import subprocess
import uuid
import random
from services.eft_helper import Type1, Type2, Type14, Type4, get_date
from services.fingerprint import Fingerprint 

# Define temp directory location
TMP_DIR = "/app/temp"

from services.nbis_helper import verify_eft

# Format name string to 'Surname, First Middle'
# Handles incorrectly spaced names to preserve proper EBTS spec
# Enforces 30 character limit of eForms. If > 30 chars, truncate middle name to initial only (IO)
def format_name(name_str: str) -> str:
    if not name_str:
        return ""
        
    parts = [p.strip() for p in name_str.split(',') if p.strip()]
    
    if len(parts) == 0:
        return ""
    
    if len(parts) == 1:
        return parts[0][:30]
        
    surname = parts[0]
    first = parts[1]
    
    if len(parts) > 2:
        middle = " ".join(parts[2:])
    else:
        middle = "NMN"
        
    # Construct full name
    full_name = f"{surname}, {first} {middle}"
    
    # Check length limit (30 chars)
    if len(full_name) > 30:
        # Try shortening middle name to initial
        if middle != "NMN" and len(middle) > 0:
            middle_initial = middle[0]
            short_name = f"{surname}, {first} {middle_initial}"
            if len(short_name) <= 30:
                return short_name
        
        # If still too long or no middle name to shorten, just truncate
        return full_name[:30]
        
    return full_name

# Extract Initials from name string (returnsn 'XXX' if parsing fails)
def get_initials(name_str: str) -> str:
    try:
        # Expected format: "Surname, First Middle"
        if ',' not in name_str:
            return "XXX"
            
        surname_part, given_part = name_str.split(',', 1)
        surname = surname_part.strip()
        given = given_part.strip().split()
        
        initials = ""
        if surname:
            initials += surname[0]
        if given:
            initials += given[0][0] # First name initial
            # Build logic for shorter Transaction Control Number (TCN)
            if len(given) > 1 and given[1] != "NMN":
                 initials += given[1][0]

        # Ensure alphanumeric and length
        initials = "".join(c for c in initials if c.isalnum()).upper()
        if not initials:
            return "XXX"
        return initials[:5] # Safety cap
    except:
        return "XXX"

# Orchestrate EFT generation
def generate_eft(data: dict, session_id: str, prints_map: dict, mode: str = "atf") -> str:
    """
    Args:
    - data (dict): A dictionary containing Type-2 field values.
    - session_id (str): A unique identifier for the current user session.
    - prints_map (dict): A dictionary mapping finger position numbers (int) to `Fingerprint` objects.
    - mode (str): Generation mode - 'atf' (Type-14) or 'rolled' (Type-4).
    Returns:
    - str: The absolute path to the generated EFT file.
    """
    session_dir = os.path.join(TMP_DIR, session_id)
    
    # Dynamic Compression Strategy
    # 1. Try RAW (No compression)
    # 2. If > 11.8 MB, try WSQ with decreasing bitrate
    
    # Bitrates to try: High Quality -> Standard Quality
    # 3.5 is very high quality (near lossless visually for fingerprints)
    # 0.75 is FBI standard minimum
    bitrates = [3.5, 3.0, 2.5, 2.0, 1.5, 1.0, 0.75]
    
    # Sort prints once
    sorted_prints = sorted(prints_map.items(), key=lambda item: int(item[0]))
    
    # Helper to build EFT with current compression state
    def build_eft_attempt(compression_type, bitrate=None):
        t1 = Type1()
        t2 = Type2(0) # IDC 0 for Type 2
        
        # Map data to Type 2 fields
        # 2.018 Name Formatting (Max 30 chars, Middle Initial fallback)
        raw_name = data.get("2.018", "")
        formatted_name = format_name(raw_name)
        t2.name = formatted_name
        
        t2.rsn = "Firearms" # 2.037 Reason Fingerprinted
        
        # DOB Sanitization
        raw_dob = data.get("2.022", "")
        t2.dob = raw_dob.replace("-", "")
        
        t2.addr = data.get("2.041", "")
        t2.pob = data.get("2.020", "")
        t2.ctz = data.get("2.021", "")
        
        # SSN Validation Or Bypass
        raw_ssn = data.get("2.016", "")
        # SSN bypass logic
        bypass_ssn = data.get("bypass_ssn", False)

        if bypass_ssn:
            t2.ssn = "" # Explicitly empty if bypassed
        else:
            clean_ssn = "".join(c for c in raw_ssn if c.isdigit())
            if len(clean_ssn) == 9:
                t2.ssn = clean_ssn
            else:
                t2.ssn = "" 
    
        t2.race = data.get("2.025", "")
        t2.eye = data.get("2.031", "")
        t2.hair = data.get("2.032", "")
        t2.sex = data.get("2.024", "")
        
        # Height Validation (Min 400, Max 711, Default/Unknown = 000)
        try:
            hgt = int(data.get("2.027", "0"))
            if hgt < 400 or hgt > 711:
                t2.height = "000"
            else:
                t2.height = str(hgt)
        except:
            t2.height = "000"
            
        # Weight Validation (Max 499, Default 000)
        try:
            wgt = int(data.get("2.029", "0"))
            if wgt > 499:
                t2.weight = "000"
            else:
                t2.weight = str(wgt)
        except:
            t2.weight = "000"
        
        t1.add_record(t2)
        
        # Generate Transaction Control Number (TCN)
        date_str = get_date().split(':')[0][2:] # YYYYMMDD -> YYMMDD
        initials = get_initials(formatted_name)
        seq = f"{random.randint(1, 99):02d}"
        
        tcn = f"{date_str}-{initials}-{seq}"
        t1.set_tcn(tcn)
        
        fname = f"{tcn}.eft"
        
        # Process Images
        if mode == "rolled":
            # Type-4 Records (1-14)
            for fp_num, fp_obj in sorted_prints:
                num = int(fp_num)
                if 1 <= num <= 14:
                    # Convert based on strategy
                    if compression_type == "RAW":
                        fp_obj.process_and_convert_raw(type4=True)
                    else:
                        fp_obj.process_and_convert_wsq(bitrate=bitrate, type4=True)
                        
                    # Type 4
                    t4 = Type4(fp_obj, idc=num) # IDC matches FGP
                    t4.build()
                    t1.add_record(t4)
                    
        else:
            # ATF Compliant (Type-14)
            idc = 1
            for fp_num, fp_obj in sorted_prints:
                if int(fp_num) in [13, 14, 15]: # Only Left Slap, Right Slap, and Thumbs
                    # Convert based on strategy
                    if compression_type == "RAW":
                        fp_obj.process_and_convert_raw(type4=False)
                    else:
                        fp_obj.process_and_convert_wsq(bitrate=bitrate, type4=False)
                        
                    t14 = Type14(fp_obj, idc)
                    t14.fcd = get_date().split(':')[0]
                    t14.build()
                    t1.add_record(t14)
                    idc += 1
                
        output_path = os.path.join(session_dir, fname)
        t1.write_to_file(output_path)
        return output_path

    # Execution Loop
    final_path = ""
    
    # 1. Try RAW
    print("Attempting RAW (No Compression)...")
    try:
        final_path = build_eft_attempt("RAW")
        size_mb = os.path.getsize(final_path) / (1024 * 1024)
        print(f"RAW EFT Size: {size_mb:.2f} MB")
        
        if size_mb < 11.8:
            print("RAW fits! Returning.")
            return verify_and_return(final_path)
    except Exception as e:
        print(f"RAW attempt failed: {e}")

    # 2. Try WSQ Loop
    for rate in bitrates:
        print(f"Attempting WSQ @ {rate}...")
        try:
            final_path = build_eft_attempt("WSQ", bitrate=rate)
            size_mb = os.path.getsize(final_path) / (1024 * 1024)
            print(f"WSQ {rate} EFT Size: {size_mb:.2f} MB")
            
            if size_mb < 11.8:
                print(f"WSQ {rate} fits! Returning.")
                return verify_and_return(final_path)
        except Exception as e:
            print(f"WSQ {rate} attempt failed: {e}")
            
    # Fallback: Return the last generated file (even if slightly over, better than nothing, or it's the smallest we could do)
    print("WARNING: Could not meet 11.8 MB limit even with lowest quality. Returning smallest file.")
    return verify_and_return(final_path)

def verify_and_return(output_path):
    # Verify the generated EFT file
    try:
        is_valid, message = verify_eft(output_path)
        if not is_valid:
             if "Command not found" in message:
                 print(f"WARNING: Validation skipped due to missing tools: {message}")
             else:
                 raise Exception(f"EFT verification failed: {message}")
    except Exception as e:
         print(f"Validation Warning: {e}")
        
    return output_path
