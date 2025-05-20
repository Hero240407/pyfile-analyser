#!/usr/bin/env python3

import os
import platform
import datetime
import mimetypes
import hashlib
import re
import tkinter as tk
from tkinter import filedialog
import time
import sys

try:
    import PyPDF2
except ImportError:
    PyPDF2 = None
    print("WARNING: PyPDF2 not found. PDF text extraction will be disabled. Install with: pip install PyPDF2")

try:
    from docx import Document as DocxDocument
except ImportError:
    DocxDocument = None
    print("WARNING: python-docx not found. DOCX text extraction will be disabled. Install with: pip install python-docx")

try:
    from PIL import Image, ExifTags
    try:
        import pytesseract
        pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe' #<<<<----------------- CHANGE HERE AS YOU PATH
    except ImportError:
        pytesseract = None
        print("INFO: pytesseract not found. OCR for images will be disabled. Install Tesseract OCR engine and pytesseract python package.")
except ImportError:
    Image = ExifTags = None
    pytesseract = None
    print("WARNING: Pillow not found. Image metadata and text extraction will be disabled. Install with: pip install Pillow")

OPENCL_AVAILABLE = False
_np = None

try:
    import pyopencl as cl
    import numpy
    _np = numpy
    OPENCL_AVAILABLE = True
except ImportError:
    print("WARNING: PyOpenCL or NumPy not found. GPU acceleration will be disabled. Install with: pip install pyopencl numpy")
except Exception as e:
    print(f"WARNING: PyOpenCL/NumPy found but could not initialize: {e}. GPU acceleration will be disabled.")

try:
    from geopy.geocoders import Nominatim
    from geopy.exc import GeocoderTimedOut, GeocoderUnavailable
    GEOPY_AVAILABLE = True
except ImportError:
    GEOPY_AVAILABLE = False
    print("WARNING: geopy not found. GPS to Address conversion will be disabled. Install with: pip install geopy")


SUSPICIOUS_PATTERNS = [
    re.compile(r"<script.*?>.*?</script>", re.IGNORECASE | re.DOTALL),
    re.compile(r"eval\s*\(", re.IGNORECASE),
    re.compile(r"base64_decode\s*\(", re.IGNORECASE),
    re.compile(r"document\.write\s*\(", re.IGNORECASE),
    re.compile(r"powershell", re.IGNORECASE),
    re.compile(r"ActiveXObject", re.IGNORECASE),
    re.compile(r"vbscript", re.IGNORECASE),
    re.compile(r"function\s*\w+\s*\(.*?\)\s*\{.*?\}", re.IGNORECASE | re.DOTALL),
    re.compile(r"on[a-z]+\s*=", re.IGNORECASE),
    re.compile(r"<\?php", re.IGNORECASE),
]

SUSPICIOUS_KEYWORDS = [
    "malware", "virus", "trojan", "exploit", "shellcode", "payload",
    "obfuscate", "encrypt", "packed", "downloader", "dropper"
]

def _convert_to_degrees(value):
    """Helper function to convert GPS EXIF data to degrees."""
    d = float(value[0])
    m = float(value[1])
    s = float(value[2])
    return d + (m / 60.0) + (s / 3600.0)

def get_decimal_coords_from_exif_gps(gps_info):
    """
    Converts EXIF GPSInfo dictionary to decimal latitude and longitude.
    Returns (lat, lon) or (None, None) if not found or error.
    """
    try:
        lat_ref = gps_info.get(1)
        lat_dms = gps_info.get(2)
        lon_ref = gps_info.get(3)
        lon_dms = gps_info.get(4)

        if lat_ref and lat_dms and lon_ref and lon_dms:
            decimal_lat = _convert_to_degrees(lat_dms)
            if lat_ref == 'S': # South latitudes are negative
                decimal_lat = -decimal_lat

            decimal_lon = _convert_to_degrees(lon_dms)
            if lon_ref == 'W': # West longitudes are negative
                decimal_lon = -decimal_lon
            
            return decimal_lat, decimal_lon
        else:
            return None, None
    except Exception as e:
        print(f"Error parsing GPSInfo: {e}")
        return None, None

def get_address_from_coords(lat, lon, user_agent="my_file_analyzer_app/1.0"):
    """
    Performs reverse geocoding to get an address from latitude and longitude.
    Uses Nominatim (OpenStreetMap). Requires geopy.
    """
    if not GEOPY_AVAILABLE:
        return " (geopy library not available for address lookup)"
    if lat is None or lon is None:
        return " (Invalid coordinates for address lookup)"

    try:
        geolocator = Nominatim(user_agent=user_agent) # Be a good citizen, set a user agent
        location = geolocator.reverse(f"{lat}, {lon}", exactly_one=True, timeout=10) # 10s timeout
        return location.address if location else " (Address not found for coordinates)"
    except GeocoderTimedOut:
        return " (Address lookup timed out)"
    except GeocoderUnavailable:
        return " (Address lookup service unavailable)"
    except Exception as e:
        return f" (Error during address lookup: {e})"

#GPU (OpenCL) Helper
def get_opencl_sha256_gpu(data_bytes):
    if not OPENCL_AVAILABLE or not _np or not data_bytes:
        return None, "OpenCL or NumPy not available, or no data for GPU processing."
    try:
        platforms = cl.get_platforms()
        if not platforms: return None, "No OpenCL platforms found."
        devices = []
        for p in platforms: devices.extend(p.get_devices(cl.device_type.GPU))
        if not devices:
            for p in platforms: devices.extend(p.get_devices(cl.device_type.CPU))
        if not devices:
            for p in platforms: devices.extend(p.get_devices(cl.device_type.ALL))
        if not devices: return None, "No OpenCL devices found."

        ctx = cl.Context([devices[0]])
        queue = cl.CommandQueue(ctx)
        mf = cl.mem_flags
        input_buf = cl.Buffer(ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=data_bytes)
        result_host_buffer = bytearray(8)
        result_device_buf = cl.Buffer(ctx, mf.WRITE_ONLY, len(result_host_buffer))

        sum_kernel_src = """
        __kernel void simple_sum(__global const unsigned char *data,
                                 __global unsigned long *result,
                                 unsigned int N) {
            unsigned long sum = 0;
            for (unsigned int i = 0; i < N; ++i) { sum += data[i]; }
            *result = sum;
        }
        """
        prg = cl.Program(ctx, sum_kernel_src).build()
        prg.simple_sum(queue, (1,), None, input_buf, result_device_buf, _np.uint32(len(data_bytes)))
        cl.enqueue_copy(queue, result_host_buffer, result_device_buf).wait()
        gpu_sum = int.from_bytes(result_host_buffer, byteorder='little')
        return f"GPU_SimpleSum:{gpu_sum}", f"OpenCL device: {devices[0].name}"
    except Exception as e:
        return None, f"OpenCL Error: {e}"

def extract_text_from_pdf(filepath):
    if not PyPDF2: return " (PyPDF2 not available)"
    try:
        with open(filepath, 'rb') as f:
            reader = PyPDF2.PdfReader(f)
            text = "".join(page.extract_text() or "" for page in reader.pages)
            return text if text else " (No text extracted from PDF)"
    except Exception as e: return f" (Error reading PDF: {e})"

def extract_text_from_docx(filepath):
    if not DocxDocument: return " (python-docx not available)"
    try:
        doc = DocxDocument(filepath)
        return "\n".join([para.text for para in doc.paragraphs])
    except Exception as e: return f" (Error reading DOCX: {e})"

def extract_text_from_image(filepath): # For OCR part
    if not Image or not pytesseract: return " (Pillow or Pytesseract for OCR not available)"
    try:
        text = pytesseract.image_to_string(Image.open(filepath))
        return text.strip() if text.strip() else " (No text found by OCR)"
    except Exception as e: return f" (Error performing OCR: {e})"

def extract_strings_from_binary(filepath, min_len=6):
    try:
        with open(filepath, 'rb') as f: content = f.read()
        strings = []; current_string = ""
        for byte in content:
            if 32 <= byte <= 126: current_string += chr(byte)
            else:
                if len(current_string) >= min_len: strings.append(current_string)
                current_string = ""
        if len(current_string) >= min_len: strings.append(current_string)
        return "\n".join(strings) if strings else " (No significant printable strings found)"
    except Exception as e: return f" (Error reading binary strings: {e})"



def get_file_metadata(filepath):
    metadata = {}
    try:
        stat_info = os.stat(filepath)
        metadata["File Path"] = os.path.abspath(filepath)
        metadata["File Name"] = os.path.basename(filepath)
        metadata["Permissions (Octal)"] = oct(stat_info.st_mode)[-3:]
        mime_type, encoding = mimetypes.guess_type(filepath)
        metadata["MIME Type (guessed)"] = mime_type or "Unknown"
        metadata["Encoding (guessed)"] = encoding or "Unknown"
        try:
            import magic
            try:
                file_magic = magic.Magic(mime=True)
                metadata["MIME Type (libmagic)"] = file_magic.from_file(filepath)
            except magic.MagicException as me: metadata["MIME Type (libmagic)"] = f"Error: {me}"
            except NameError: pass
        except ImportError: metadata["MIME Type (libmagic)"] = "python-magic not installed"
        
        file_content = b""
        try:
            with open(filepath, 'rb') as f: file_content = f.read()
        except Exception as e: metadata["Content Reading Error"] = str(e)
        if file_content:
            metadata["MD5 (CPU)"] = hashlib.md5(file_content).hexdigest()
            metadata["SHA1 (CPU)"] = hashlib.sha1(file_content).hexdigest()
            metadata["SHA256 (CPU)"] = hashlib.sha256(file_content).hexdigest()
            gpu_hash_val, gpu_info = get_opencl_sha256_gpu(file_content)
            metadata["GPU Process Info"] = gpu_info
            if gpu_hash_val: metadata["GPU Demonstrative Value"] = gpu_hash_val
        else:
            metadata["Hashes"] = "File is empty or could not be read for hashing."
            metadata["GPU Process Info"] = "Skipped due to empty/unreadable file content."

    except FileNotFoundError: metadata["Error"] = "File not found."
    except Exception as e: metadata["Error"] = f"An error occurred getting metadata: {e}"
    return metadata


def analyze_content_for_suspicion(text_content):
    findings = []
    if not text_content or not isinstance(text_content, str): return findings
    for pattern in SUSPICIOUS_PATTERNS:
        try:
            matches = pattern.findall(text_content)
            if matches:
                for match in matches: findings.append(f"Suspicious pattern found (regex: {pattern.pattern}): {str(match)[:100]}...")
        except Exception as e: findings.append(f"Error matching pattern {pattern.pattern}: {e}")
    for keyword in SUSPICIOUS_KEYWORDS:
        if re.search(r'\b' + re.escape(keyword) + r'\b', text_content, re.IGNORECASE):
            findings.append(f"Suspicious keyword found: {keyword}")
    if len(text_content) > 100:
        from collections import Counter
        try:
            counts = Counter(text_content); text_len = len(text_content)
            entropy = -sum((count / text_len) * (_np.log2(count / text_len) if _np and callable(_np.log2) else ( (count / text_len) / (2) ) ) for count in counts.values()) # math.log2 can also be used
            if entropy > 4.8: findings.append(f"Potentially high entropy in text: {entropy:.2f} (may indicate obfuscation/encryption, or just compressed data)")
        except Exception as e: findings.append(f"Could not calculate entropy: {e}")
    return findings


def analyze_file(filepath):
    report_lines = []

    header = f"-Analyzing File: {filepath}"
    print(f"\n{header}")
    report_lines.append(header)

    metadata = get_file_metadata(filepath)
    for key, value in metadata.items():
        line = f"{key}: {value}"
        print(line)
        report_lines.append(line)

    if "Error" in metadata and "File not found" in metadata["Error"]:
        return report_lines
    if metadata.get("Content Reading Error"):
        err_msg = f"Could not read file content for further analysis: {metadata['Content Reading Error']}"
        print(err_msg); report_lines.append(f"\n{err_msg}")
        return report_lines

    extracted_text = ""
    mime_type_guess = metadata.get("MIME Type (libmagic)", metadata.get("MIME Type (guessed)", "")).lower()
    file_extension = os.path.splitext(filepath)[1].lower()

    content_header = "\n-Content Extraction & Analysis"
    print(content_header); report_lines.append(content_header)

    type_info = ""
    if 'application/pdf' in mime_type_guess or file_extension == '.pdf':
        type_info = "Type: PDF Document"
        extracted_text = extract_text_from_pdf(filepath)
    elif 'officedocument.wordprocessingml.document' in mime_type_guess or file_extension == '.docx':
        type_info = "Type: DOCX Document"
        extracted_text = extract_text_from_docx(filepath)
    elif 'image/' in mime_type_guess and Image and ExifTags:
        type_info = "Type: Image File"
        img_metadata_text_parts = []
        try:
            with Image.open(filepath) as img:
                img_metadata_text_parts.append(f"Format: {img.format}, Mode: {img.mode}, Size: {img.size}")
                raw_exif = img._getexif()
                if raw_exif:
                    img_metadata_text_parts.append("EXIF Data:")
                    gpsinfo_dict = {}
                    for tag_id, value in raw_exif.items():
                        tag_name = ExifTags.TAGS.get(tag_id, tag_id)
                        
                        if tag_name == "GPSInfo":
                            for gps_tag_id, gps_value in value.items():
                                gps_tag_name = ExifTags.GPSTAGS.get(gps_tag_id, gps_tag_id)
                                gpsinfo_dict[gps_tag_id] = gps_value
                                img_metadata_text_parts.append(f"  GPS Tag {gps_tag_name} ({gps_tag_id}): {gps_value}")
                            if gpsinfo_dict:
                                decimal_lat, decimal_lon = get_decimal_coords_from_exif_gps(gpsinfo_dict)
                                if decimal_lat is not None and decimal_lon is not None:
                                    gps_coords_str = f"  GPS Coordinates (Decimal): Lat {decimal_lat:.6f}, Lon {decimal_lon:.6f}"
                                    img_metadata_text_parts.append(gps_coords_str)
                                    print(gps_coords_str)
                                    
                                    address = get_address_from_coords(decimal_lat, decimal_lon)
                                    gps_address_str = f"  Estimated Address: {address}"
                                    img_metadata_text_parts.append(gps_address_str)
                                    print(gps_address_str)
                                else:
                                    img_metadata_text_parts.append("  GPS Coordinates: Could not parse from GPSInfo")
                        else:
                            if isinstance(value, bytes):
                                try: value_str = value.decode('utf-8', errors='replace')
                                except: value_str = repr(value)
                            else: value_str = str(value)
                            img_metadata_text_parts.append(f"  {tag_name}: {value_str[:200]}")
                else:
                    img_metadata_text_parts.append("No EXIF data found.")
            
            if pytesseract:
                ocr_attempt_msg = "Attempting OCR on image..."
                print(ocr_attempt_msg)
                ocr_text = extract_text_from_image(filepath)
                if ocr_text and ocr_text.strip() != "(No text found by OCR)":
                     img_metadata_text_parts.append(f"\nOCR Extracted Text:\n{ocr_text}")
                else: img_metadata_text_parts.append("No significant text found by OCR.")
            extracted_text = "\n".join(img_metadata_text_parts)
        except Exception as e:
            extracted_text = f" (Error processing image: {e})"
            
    elif 'text/' in mime_type_guess or \
         any(file_extension == ext for ext in ['.txt', '.log', '.csv', '.json', '.xml', '.html', '.js', '.py', '.sh', '.bat', '.css', '.md']):
        type_info = "Type: Text-based File"
        try:
            with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                extracted_text = f.read()
        except Exception as e: extracted_text = f" (Error reading text file: {e})"
    else:
        type_info = f"Type: Binary or Unknown (MIME: {mime_type_guess}, Ext: {file_extension})"
        str_extract_msg = "Attempting to extract printable strings..."
        print(str_extract_msg)
        extracted_text = extract_strings_from_binary(filepath)

    if type_info:
        print(type_info)
        report_lines.append(type_info)

    #Handle Extracted Text for Console and Report
    if isinstance(extracted_text, str) and extracted_text:
        print("\nExtracted Content Snippet (first 1000 characters):")
        print(extracted_text[:1000])
        if len(extracted_text) > 1000: print("...\n(Content truncated)")
        report_lines.append("\n-Full Extracted Content")
        report_lines.append(extracted_text)
    elif extracted_text:
        print(f"\nContent Extraction Note: {extracted_text}")
        report_lines.append(f"\n-Content Extraction Note"); report_lines.append(str(extracted_text))
    else:
        no_content_msg = "No textual content extracted or applicable."
        print(no_content_msg); report_lines.append(f"\n-Full Extracted Content"); report_lines.append(no_content_msg)

    #Suspicion Analysis
    suspicion_header = "\n-Suspicious Indicators (Rule-Based)"
    print(suspicion_header); report_lines.append(suspicion_header)
    if isinstance(extracted_text, str) and extracted_text:
        suspicious_findings = analyze_content_for_suspicion(extracted_text)
        if suspicious_findings:
            for finding in suspicious_findings: print(f"- {finding}"); report_lines.append(f"- {finding}")
        else:
            no_susp_msg = "No predefined suspicious indicators found in extracted text."
            print(no_susp_msg); report_lines.append(no_susp_msg)
    else:
        no_text_susp_msg = "No textual content available for rule-based analysis."
        print(no_text_susp_msg); report_lines.append(no_text_susp_msg)
        
    analysis_complete_msg = "\n-Analysis Complete"
    print(analysis_complete_msg); report_lines.append(analysis_complete_msg)
    return report_lines

#Main Function
def main():
    root = tk.Tk(); root.withdraw() 
    filepath = filedialog.askopenfilename(title="Select a file to analyze")
    if not filepath: print("No file selected. Exiting."); return
    if not os.path.exists(filepath): print(f"File not found: {filepath}. Exiting."); return

    start_analysis_time = time.perf_counter()
    report_lines_from_analysis = analyze_file(filepath)
    end_analysis_time = time.perf_counter()
    analysis_duration = end_analysis_time - start_analysis_time
    
    duration_str = f"Analysis Time: {analysis_duration:.4f}s"
    print(f"\n{duration_str}")

    report_filename = datetime.datetime.now().strftime("%m-%d-%Y-%H-%M-%S") + ".txt"
    full_report_content_for_file = [f"Analysis Report for: {os.path.basename(filepath)}",
                                    f"Report Generated: {datetime.datetime.now().strftime('%m-%d-%Y %H:%M:%S')}",
                                    duration_str] + ["="*30] + report_lines_from_analysis
    try:
        with open(report_filename, "w", encoding="utf-8") as f_report:
            f_report.write("\n".join(full_report_content_for_file))
        print(f"Full report saved to: {os.path.abspath(report_filename)}")
    except Exception as e:
        print(f"Error saving report to {report_filename}: {e}")

    print("\nNote: This script provides information extraction and basic pattern matching.")
    print("It is NOT a comprehensive antivirus solution. Interpret results with caution.")
    if not OPENCL_AVAILABLE: print("OpenCL/NumPy was not available or functional, so GPU acceleration for the demo task was skipped.")


if __name__ == "__main__":
    if OPENCL_AVAILABLE and _np:
        print("-OpenCL Initialization Info")
        try:
            platforms = cl.get_platforms()
            print(f"Found {len(platforms)} OpenCL platform(s).")
            for i, plat in enumerate(platforms):
                print(f"  Platform {i}: {plat.name} ({plat.vendor})")
                devices = plat.get_devices()
                for j, dev in enumerate(devices):
                    print(f"    Device {j}: {dev.name} (Type: {cl.device_type.to_string(dev.type)})")
                    print(f"      Max Compute Units: {dev.max_compute_units}")
                    print(f"      Global Memory: {dev.global_mem_size // (1024*1024)} MB")
        except Exception as e:
            print(f"Error during OpenCL enumeration: {e}"); OPENCL_AVAILABLE = False
        print("----------------------------------")
    else:
        print("Error: OpenCL Info: Not available or NumPy missing")
        if not _np and OPENCL_AVAILABLE: print("NumPy is required for OpenCL operations but was not imported successfully."); OPENCL_AVAILABLE = False
    main()