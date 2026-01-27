from datetime import datetime, timedelta
from hashlib import sha256
import struct

FS_CHAR = 0x1C # Record
GS_CHAR = 0x1D # Field
RS_CHAR = 0x1E # Subfield 
US_CHAR = 0x1F # Item

# EZ defaults
VERSION = "0200"
ORI = "WVATF0800"
DAI = "WVIAFIS0Z" # FBI/CJIS
TOT = "FAUF" # Type of transactions

def join(iterable, sep=":"):
    return ':'.join([str(x) for x in iterable])


def join_dict(d, sep=GS_CHAR, endsep=FS_CHAR):
    """
    Serializes a dictionary of fields into the EFT binary format.
    Format: KEY:VALUE<SEP>...KEY:VALUE<ENDSEP>
    
    Args:
        d (dict): Dictionary of fields (Key -> Value).
        sep (int): Separator char code (default GS).
        endsep (int): End separator char code (default FS).
        
    Returns:
        bytearray: Serialized data.
    """
    x = bytearray()
    
    # Robust numeric sort to ensure X.001 is first and X.010 > X.002
    def sort_key(k):
        try:
            parts = k.split('.')
            return (int(parts[0]), int(parts[1]))
        except:
            return (99, 99) # fallback to end
            
    keys = sorted(d.keys(), key=sort_key)
    numKeys = len(keys)
    
    i = 0
    for key in keys:
        val = d[key]
        
        # Determine separator
        is_last = (i == numKeys - 1)
        separator = endsep if is_last else sep
        
        # Encode Key
        x = x + bytearray(key, 'ascii') + bytes(":", 'ascii')
        
        # Encode Value
        if isinstance(val, bytes):
            # Already bytes
            x = x + val
        else:
            # Convert to string first
            x = x + bytearray(str(val), 'ascii')
            
        # Append Separator
        x = x + bytes(chr(separator), 'ascii')
        
        i += 1
        
    return x


def get_date():
    # YYYYMMdd
    # eForms seems to be working on GMT. Subtracting 1 day to make sure we don't get too close to the current date
    d = datetime.now() - timedelta(days=1)
    return d.strftime("%Y%m%d:%H%M%S")


class Record:
    def __init__(self, rtype="0", idc=0):
        self.rtype = rtype
        self.len = "1"  # Type-1 header record length
        self.idc = idc
        self.full_time = get_date()
        self.dat = self.full_time.split(':')[0]
        self.cnt = []

    def _get_len(self):
        # Iteratively calculate length to account for the digits added by the length field itself
        # Initial guess (minimal length "1")
        self.len = "1"
        for _ in range(5): # Loop to stabilize
            d = self._get_dict()
            serialized = join_dict(d)
            curr_size = len(serialized)
            if str(curr_size) == str(self.len):
                break
            self.len = curr_size
        return self.len

    def _get_dict(self):  # Overrideable if needed
        return {self.rtype + ".001": self.len}

    def repr(self):
        self._get_len()
        return join_dict(self._get_dict())

    def __cnt__(self):
        tmp = self.idc
        # Ensure tmp is int
        try:
            tmp = int(tmp)
        except:
            tmp = 0
            
        if tmp >= 0 and tmp < 10:
            tmp = "0" + str(tmp)
        else:
            tmp = str(tmp)
        return self.rtype + chr(US_CHAR) + tmp

    def write_to_file(self, fname):
        print(f"Writing EFT to {fname}...")
        with open(fname, 'wb') as f:
            # Write Type-1 header
            print("Serializing Type 1 Header...")
            f.write(self.repr())
            
            # Write Children
            for idx, record in enumerate(self.cnt):
                print(f"Serializing Record {idx+2} (Type {record.rtype}, IDC {record.idc})...")
                try:
                    f.write(record.repr())
                except Exception as e:
                    print(f"ERROR serializing record {record.rtype}: {e}")
                    # Log the dict content for debug
                    try:
                        print(f"Record Data: {record._get_dict()}")
                    except:
                        pass
                    raise e


class Type1(Record):
    def __init__(self):
        super().__init__()
        self.ver = VERSION
        self.cnt = []
        self.cnt_total = 1  # Pointer to self.cnt
        self.tot = TOT
        self.pry = 5  # Priority (1-10, default: 5, response in 2 hours)
        self.dai = DAI  # Destination, CJIS
        self.ori = ORI  # Source, ATF
        self.tcn = self.ori + self.full_time.replace(':','-') + "-EFTC-"
        self.nsr = "00.00"  # Only for type 4
        self.ntr = "00.00"  # Only for type 4
        self.record_string = ""

    def get_len(self):
        tmp = 0
        for record in self.cnt:
            tmp += record._get_len()
        tmp += self._get_len()
        self.len = tmp

    # CNT is sum of Type-2 records and the count of remaining subfields.
    # Using len(self.cnt) which contains all non-Type-1 records.

    def get_count_string(self):
        total_records = len(self.cnt)
        x = "1" + chr(US_CHAR) + str(total_records)
        if len(self.cnt) > 0:
            x = x + chr(RS_CHAR) + ','.join([str(x.__cnt__())
                                             for x in self.cnt]).replace(',', chr(RS_CHAR))
        return x

    def set_tcn(self, name):
        # Overwrite TCN with the specific value provided
        self.tcn = name

    def add_record(self, record):
        self.cnt.append(record)
    
    def from_dict(self, d):
        """Populate fields from a dictionary (e.g. parsed from file)"""
        if "1.002" in d: self.ver = d["1.002"]
        if "1.004" in d: self.tot = d["1.004"]
        if "1.005" in d: self.dat = d["1.005"]
        if "1.006" in d: self.pry = d["1.006"]
        if "1.007" in d: self.dai = d["1.007"]
        if "1.008" in d: self.ori = d["1.008"]
        if "1.009" in d: self.tcn = d["1.009"]
        if "1.011" in d: self.nsr = d["1.011"]
        if "1.012" in d: self.ntr = d["1.012"]

    def _get_dict(self):
        return {
            "1.001": self.len,
            "1.002": self.ver,
            "1.003": self.get_count_string(),
            "1.004": self.tot,
            "1.005": self.dat,
            "1.006": self.pry,
            "1.007": self.dai,
            "1.008": self.ori,
            "1.009": self.tcn,
            "1.011": self.nsr,
            "1.012": self.ntr
        }


class Type2(Record):
    def __init__(self, idc=0):
        super().__init__("2", idc)
        self.aka = ""
        self.pob = ""
        self.ctz = ""
        self.dob = ""
        self.race = ""
        self.eye = ""
        self.hair = ""
        self.rsn = ""
        self.dfp = get_date().split(':')[0]
        self.name = ""
        self.residence = ""
        self.birth = ""
        self.height = ""
        self.weight = ""
        self.amp = ""
        self.ssn=""
        self.sex = ""
        self.stateBorn = ""
        self.addr = ""
        self.extra_fields = {} # Store unsupported fields

    # Populate fields from a dictionary
    def from_dict(self, d):
        mapping = {
            "2.016": "ssn", "2.018": "name", "2.019": "aka", "2.020": "pob",
            "2.021": "ctz", "2.022": "dob", "2.024": "sex", "2.025": "race",
            "2.027": "height", "2.029": "weight", "2.031": "eye", "2.032": "hair",
            "2.037": "rsn", "2.038": "dfp", "2.041": "addr", "2.084": "amp"
        }
        for k, v in d.items():
            if k == "2.002": self.idc = v
            elif k in mapping:
                setattr(self, mapping[k], v)
            elif k.startswith("2.") and k != "2.001" and k != "2.005" and k != "2.073":
                # Preserve non-structural extra fields
                self.extra_fields[k] = v
    
    def _clean_dict(self, d):
        out = {}
        for key, value in d.items():
            if value != None:
                if len(str(value)) > 0:
                    out[key]=value
        return out

    def _get_dict(self):
        if len(str(self.idc)) == 1:
            self.idc = "0" + str(self.idc)
        x = {
            "2.001": self.len,
            "2.002": self.idc,
            "2.005": "N",
            #"2.015": self.stateID, # Disable for now
            "2.016": self.ssn,
            "2.018": self.name,
            "2.019": self.aka,
            "2.020": self.pob,
            "2.021": self.ctz,
            "2.022": self.dob,
            "2.024": self.sex,
            "2.025": self.race,
            "2.027": self.height,
            "2.029": self.weight,
            "2.031": self.eye,
            "2.032": self.hair,
            "2.037": self.rsn,
            "2.038": self.dfp,
            "2.041": self.addr,
            "2.073": ORI,
            "2.084": self.amp,
        }
        # Merge extra fields
        x.update(self.extra_fields)
        a = self._clean_dict(x)
        return a

"""
>> Type-4 High-Resolution Grayscale Image Record. <<
This is a Binary Record (image), not a Tagged Field Record.
Structure: (18 bytes header + Data):
- LEN (4B)
- IDC (1B)
- IMP (1B)
- FGP (6B)
- ISR (1B)
- HLL (2B)
- VLL (2B)
- CGA (1B)
- DATA
"""
class Type4(Record):
    def __init__(self, f, idc=0):
        # Don't use the base Record init fully because this is binary
        self.rtype = "4"
        self.idc = int(idc) # Ensure int
        self.fgp = int(f.fgp) # Ensure int
        """
        Impression Type Logic:
        - Type-4: 1-10=Rolled(1)
        - Type-14: 11-14=Plain(0)
        """
        if 1 <= self.fgp <= 10:
            self.imp = 1
        else:
            self.imp = 0
            
        self.isr = 0 # Image scanning resolution (0=Native)
        self.hll = int(f.hll)
        self.vll = int(f.vll)
        
        # Determine CGA based on Fingerprint object
        if hasattr(f, 'cga'):
            if f.cga == "NONE":
                self.cga = 0
            elif f.cga == "WSQ20" or f.cga == "WSQ":
                self.cga = 1
            elif f.cga == "JP2":
                self.cga = 4
            elif f.cga == "PNG":
                self.cga = 5
            else:
                self.cga = 1 # Default to WSQ if unknown (legacy behavior)
        else:
            self.cga = 1 # Default
        
        if hasattr(f, 'converted'):
            self.file = f.converted
        else:
             self.file = None
             
        self.dat = b""

    def build(self):
        self.dat = self.read_data()

    def read_data(self):
        with open(self.file, 'rb') as f:
            return f.read()

    def _get_len(self):
        # Header is 18 bytes
        return 18 + len(self.dat)

    def repr(self):
        # Calculate Length
        total_len = self._get_len()
        """
        Pack Header (Big endian)
        - >I (4B Len)
        - B (1B IDC)
        - B (1B IMP)
        - 6B (6B FGP: [fgp, 255, 255, 255, 255, 255])
        - B (1B ISR)
        - H (2B HLL)
        - H (2B VLL)
        - B (1B CGA)
        """
        header = struct.pack(
            '>I B B 6B B H H B',
            total_len,
            self.idc,
            self.imp,
            self.fgp, 255, 255, 255, 255, 255, # FGP Array
            self.isr,
            self.hll,
            self.vll,
            self.cga
        )
        
        return header + self.dat

class Type14(Record):
    def __init__(self, f, idc=0):
        super().__init__("14", idc)
        self.isc = "1"  # Default for FD-258
        self.scu = "1"  # Pixels per inch = 1, pixels per cm = 2
        self.imp = "1"  # Impression type, default=1 (rolled)
        self.src = ORI # "WVATF0900" - Source agency, ATF
        self.fcd = "" # Fingerprint capture date (YYYYMMDD, less one day)
        self.hll = f.hll  # Horizontal line length
        self.vll = f.vll  # Vertical line length
        self.slc = f.slc  # Scale units
        self.thps = f.hps  # Transmitted horizontal pixel scale
        self.tvps = f.vps  # Transmitted verical pixel scale
        self.cga = f.cga  # Compression algorithm (default WSQ20)
        self.bpx = f.bpx  # Bits per pixel
        #self.ppd = ""  # Print position descriptors (Not mandatory, not including)
        self.file = f.converted
        #self.score = "" # Not mandatory, not including
        self.fgp = f.fgp # Finger position
        self.dat=""
        self.hash=""
        self.fingerprints = f.fingers

    def build(self):
        self.dat = self.read_data()
        try:
            self.hash = sha256(self.dat).hexdigest()
            # print(self.hash)
        except Exception as e:
            print("ERROR WHILE HASHING!: {}".format(e))

    def read_data(self):
        x = b''
        # "14.999": self.dat -> Image Data.
        with open(self.file, 'rb') as f:
            x = f.read()
        return x

    def _get_dict(self):
        return {
            "14.001": self.len,
            "14.002": self.idc,
            "14.003": self.imp,
            "14.004": self.src,
            "14.005": get_date().split(':')[0],
            "14.006": self.hll,
            "14.007": self.vll,
            "14.008": self.scu,
            "14.009": self.thps,
            "14.010": self.tvps,
            "14.011": self.cga,
            "14.012": self.bpx,
            "14.013": self.fgp,
            "14.021": self.getFingerprintPos(),
            "14.023": self.getFingerprintQuality(),
            "14.024": self.getFingerprintQuality(), # Not even going to attempt to grade fingerprints, assume default value
            #"14.014": self.ppd, # Not mandatory, not including
            #"14.022": self.score # Not mandatory, not including
            "14.999": self.dat
        }
    
    def getFingerprintPos(self):
        x = ""
        for i in range(len(self.fingerprints)):
            x += self.fingerprints[i].getPosString()
            if i+1 != len(self.fingerprints):
                x += chr(RS_CHAR)
        return x

    def getFingerprintQuality(self):
        x = ""
        for i in range(len(self.fingerprints)):
            x += self.fingerprints[i].getScoreString()
            if i+1 != len(self.fingerprints):
                x += chr(RS_CHAR)
        return x

# Use `Type14Raw` class to handle existing Type 14 records where image data is already bytes and we have metadata fields, bypassing the need for a Fingerprint object.
# (This is used for reading existing Type 14 records from a file)
class Type14Raw(Record):
    """

    """
    def __init__(self, data: dict, idc=0):
        super().__init__("14", idc)
        self.fields = data.copy()
        
        # Ensure structural fields are correct
        # Remove LEN (14.001) as it will need to be recalculated later anyway
        if "14.001" in self.fields: del self.fields["14.001"]
        
        # Update IDC
        if idc > 0:
            self.fields["14.002"] = str(idc)
            
    def _get_dict(self):
        # Ensure 14.001 header record is positioned first
        # Create a new dictionary starting with 14.001
        # Get sorted keys from self.fields to ensure determinism for other fields
        
        d = {}
        d["14.001"] = self.len
        
        # Add remaining fields
        # Note: self.fields contains everything else. Sort fields to ensure determinism.
        
        def sort_key(k):
            try:
                parts = k.split('.')
                return (int(parts[0]), int(parts[1]))
            except:
                return (99, 99) # fallback
                
        sorted_keys = sorted(self.fields.keys(), key=sort_key)
        for k in sorted_keys:
            d[k] = self.fields[k]
            
        return d

class Type4Raw(Record):
    """
    Handles existing Type 4 records (Binary) where image data is already bytes.
    Used for reading/preserving existing Type 4 records.
    """
    def __init__(self, data: dict, idc=0):
        # Don't use the base Record init fully
        self.rtype = "4"
        self.fields = data.copy()
        
        # Parse IDC
        self.idc = int(idc)
        if "4.002" in self.fields:
             try: self.idc = int(self.fields["4.002"])
             except: pass
             
        # Parse FGP
        self.fgp = 0
        if "4.004" in self.fields:
             try: self.fgp = int(self.fields["4.004"])
             except: pass
        
        # Parse IMP (Implicit logic or explicit field if we stored it)
        # If not present, derive from FGP
        if "4.003" in self.fields:
             try: self.imp = int(self.fields["4.003"])
             except: self.imp = 1 if (1 <= self.fgp <= 10) else 0
        else:
             self.imp = 1 if (1 <= self.fgp <= 10) else 0

        # Parse ISR
        self.isr = 0
        if "4.005" in self.fields:
             try: self.isr = int(self.fields["4.005"])
             except: pass

        # Parse HLL
        self.hll = 0
        if "4.006" in self.fields:
             try: self.hll = int(self.fields["4.006"])
             except: pass
             
        # Parse VLL
        self.vll = 0
        if "4.007" in self.fields:
             try: self.vll = int(self.fields["4.007"])
             except: pass

        # Parse CGA
        self.cga = 1
        if "4.008" in self.fields:
             try: self.cga = int(self.fields["4.008"])
             except: pass

        # Image Data
        self.dat = b""
        if "4.999" in self.fields:
             self.dat = self.fields["4.999"]
             
    def _get_len(self):
        return 18 + len(self.dat)

    def repr(self):
        # Calculate Length
        total_len = self._get_len()
        
        # Re-pack Header
        header = struct.pack(
            '>I B B 6B B H H B',
            total_len,
            self.idc,
            self.imp,
            self.fgp, 255, 255, 255, 255, 255, # FGP Array
            self.isr,
            self.hll,
            self.vll,
            self.cga
        )
        
        return header + self.dat
