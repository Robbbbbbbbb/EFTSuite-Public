import os
import subprocess
from typing import List, Tuple

def run_command(command: List[str], cwd: str = None) -> Tuple[str, str, int]:
    """
    A wrapper function to securely run external command-line tools.

    This function captures standard output, standard error, and the return code,
    providing a consistent way to interact with the NBIS binaries. Using `subprocess.run`
    with `check=True` helps catch errors early.

    Args:
        command: A list of strings representing the command and its arguments.
        cwd: The working directory where the command should be executed. This is
             critical for tools that generate output files in the current directory.

    Returns:
        A tuple containing the standard output (str), standard error (str), and
        the exit code (int) of the command.
    """
    try:
        process = subprocess.run(
            command,
            cwd=cwd,
            capture_output=True,
            text=True,
            check=True
        )
        return process.stdout, process.stderr, process.returncode
    except subprocess.CalledProcessError as e:
        # This handles cases where the command returns a non-zero exit code.
        return e.stdout, e.stderr, e.returncode
    except FileNotFoundError:
        # This handles cases where the command itself is not found in the PATH.
        return "", f"Command not found: {command[0]}", 1

def verify_eft(eft_path: str) -> Tuple[bool, str]:
    """
    Verifies the integrity of a generated EFT file using the `chkan2k` tool.

    The `chkan2k` tool performs a validation check on the ANSI/NIST file 
    structure and content, ensuring it meets the format specifications.
    We check for an empty stderr as success, or return code 0.

    Args:
        eft_path: The absolute path to the EFT file to be verified.

    Returns:
        A tuple containing a boolean (True if valid, False otherwise) and a
        descriptive message.
    """
    if not os.path.exists(eft_path):
        return False, "EFT file not found."

    # `chkan2k <file>` validates the structure of the ANSI/NIST file.
    command = ["chkan2k", eft_path]
    stdout, stderr, returncode = run_command(command)

    if returncode == 0:
        return True, "EFT file is valid."
    else:
        # stderr from `chkan2k` provides detailed error messages.
        return False, f"EFT file is invalid:\n{stderr}"

def segment_fingerprints(image_path: str, finger_position: int) -> List[dict]:
    """
    Segments a slap fingerprint image into individual fingers using `nfseg`.

    `nfseg` is a specialized tool designed to find and separate individual
    fingerprint images from a larger slap image (e.g., a four-finger slap).

    Args:
        image_path: Path to the slap image (e.g., "left_slap.png").
        finger_position: The FBI/IAFIS code for the slap type.
                         13 = Right Slap, 14 = Left Slap, 15 = Thumbs.

    Returns:
        A list of dictionaries, where each dictionary contains the segmentation
        data for a single finger found in the slap image.
    """
    # Command structure: nfseg <slap_code> <other_params> <image_file>
    # The other parameters are legacy and are typically set to '1 1 1 0'.
    command = ["nfseg", str(finger_position), "1", "1", "1", "0", os.path.basename(image_path)]
    stdout, stderr, returncode = run_command(command, cwd=os.path.dirname(image_path))

    if returncode != 0:
        raise Exception(f"nfseg failed:\n{stderr}")

    segments = []
    # `nfseg` outputs structured text with details for each segmented finger.
    for line in stdout.splitlines():
        if "FILE" in line:
            parts = line.split()
            # This parsing is based on the specific output format of `nfseg`.
            segments.append({
                "file": parts[1],
                "sw": int(parts[parts.index("sw") + 1]),
                "sh": int(parts[parts.index("sh") + 1]),
                "sx": int(parts[parts.index("sx") + 1]),
                "sy": int(parts[parts.index("sy") + 1]),
                "th": float(parts[parts.index("th") + 1]),
            })

    return segments

def get_nfiq_quality(image_path: str) -> int:
    """
    Calculates the NIST Fingerprint Image Quality (NFIQ) score for an image.

    NFIQ is an algorithm that assesses the quality of a fingerprint image,
    assigning a score from 1 (best) to 5 (worst). This score helps determine
    if an image is likely to be usable for matching.

    Args:
        image_path: Path to the fingerprint image to be scored.

    Returns:
        An integer representing the NFIQ score (1-5). Returns 255 on failure.
    """
    command = ["nfiq", image_path]
    stdout, stderr, returncode = run_command(command)

    if returncode != 0:
        # In case of failure, returning a non-standard NFIQ score like 255 to indicate error in calling function
        print(f"nfiq failed for {image_path}:\n{stderr}")
        return 255

    try:
        # `nfiq` prints the quality score to standard output.
        return int(stdout.strip())
    except (ValueError, IndexError):
        print(f"Could not parse nfiq output for {image_path}: {stdout}")
        return 255

def convert_wsq_to_raw(wsq_path: str) -> str:
    """
    Decodes a WSQ file to a raw file using `dwsq`.
    
    Args:
        wsq_path: Path to the WSQ file.
        
    Returns:
        Path to the decoded raw file.
    """
    # dwsq <file> creates <file>.raw (stripping extension if present? No, usually adds .raw)
    # Actually dwsq usuall takes input.wsq and outputs input.raw if no args?
    # Or dwsq <input> [-raw] ...
    # From help: dwsq decompresses...
    # Usage usually: dwsq file.wsq  -> produces file.raw in same dir.
    
    # Check if raw already exists
    base = os.path.splitext(wsq_path)[0]
    raw_path = base + ".raw"
    
    if os.path.exists(raw_path):
        return raw_path
        
    # Run dwsq
    # Try 1: dwsq raw <file>
    command = ["dwsq", "raw", os.path.basename(wsq_path)]
    stdout, stderr, returncode = run_command(command, cwd=os.path.dirname(wsq_path))
    
    if os.path.exists(raw_path):
        return raw_path
        
    # Try 2: dwsq <file> (defaults to .raw output often)
    command = ["dwsq", os.path.basename(wsq_path)]
    stdout, stderr, returncode = run_command(command, cwd=os.path.dirname(wsq_path))
    
    if os.path.exists(raw_path):
        return raw_path
        
    # Try 3: Append -raw flag if supported
    command = ["dwsq", "-raw", os.path.basename(wsq_path)]
    stdout, stderr, returncode = run_command(command, cwd=os.path.dirname(wsq_path))

    if os.path.exists(raw_path):
        return raw_path

    # Check for file.wsq.raw pattern in case tool appended
    if os.path.exists(wsq_path + ".raw"):
         return wsq_path + ".raw"

    raise Exception(f"dwsq failed to produce raw file. Last error: {stderr}")
             
    # Verify result
    if os.path.exists(raw_path):
        return raw_path
        
    # Fallback check for different naming convention
    # e.g. file.wsq.raw
    if os.path.exists(wsq_path + ".raw"):
        return wsq_path + ".raw"
        
    raise Exception(f"dwsq ran but output file not found for {wsq_path}")

def convert_to_wsq(raw_path: str, output_path: str, width: int, height: int, bitrate: float = 2.25, depth: int = 8, ppi: int = 500) -> str:
    """
    Compresses a raw image to WSQ using `cwsq`.
    
    Args:
        raw_path: Path to the input raw image.
        output_path: Path to the output WSQ file.
        width: Image width.
        height: Image height.
        bitrate: Compression bitrate (e.g. 0.75, 2.25).
        depth: Bit depth (default 8).
        ppi: Pixels per inch (default 500).
        
    Returns:
        Path to the generated WSQ file.
    """
    # cwsq <rate> wsq <outfile> -r <infile> <w> <h> <depth> <ppi>
    # Note: cwsq arguments might vary by version, but this is the standard NBIS usage.
    
    command = [
        "cwsq", 
        str(bitrate), 
        "wsq", 
        output_path, 
        "-r", 
        raw_path, 
        str(width), 
        str(height), 
        str(depth), 
        str(ppi)
    ]
    
    stdout, stderr, returncode = run_command(command, cwd=os.path.dirname(raw_path))
    
    if returncode != 0:
        raise Exception(f"cwsq failed: {stderr}")
        
    if not os.path.exists(output_path):
        raise Exception(f"cwsq failed to create output file: {stderr}")
        
    return output_path

