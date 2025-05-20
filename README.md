# Full File Analyser

## Description

`full-analyser.py` is a Python script designed to perform a comprehensive analysis of various file types. It extracts metadata, textual content (including OCR for images and text from PDFs/DOCX), performs basic suspicious pattern matching, and can optionally leverage GPU (OpenCL) for a demonstrative calculation. It also includes GPS coordinate extraction from image EXIF data and reverse geocoding to find an address.

## Features

*   **Basic File Metadata:** Extracts file name, path, size, permissions (octal), owner, group, creation/modification/access times.
*   **MIME Type Detection:** Uses both standard `mimetypes` and `python-magic` (if available) for more accurate MIME type identification.
*   **Hash Calculation:** Computes MD5, SHA1, and SHA256 hashes of the file content using the CPU.
*   **GPU Acceleration (Demonstrative):** If PyOpenCL and NumPy are available, performs a simple sum of file bytes on an OpenCL-compatible GPU (or CPU fallback via OpenCL) and reports the device used.
*   **Text Extraction From:**
    *   Plain text files (.txt, .log, .json, .py, .html, etc.).
    *   PDF files (using `PyPDF2`).
    *   DOCX files (using `python-docx`).
    *   Images using OCR (Optical Character Recognition) via `Pillow` and `pytesseract` (requires Tesseract OCR engine).
*   **Image Metadata (EXIF):**
    *   Extracts general EXIF tags from images.
    *   Parses GPSInfo from EXIF to get decimal latitude and longitude.
    *   Performs reverse geocoding (using `geopy` and Nominatim) to convert GPS coordinates to a human-readable address.
*   **Binary File Analysis:** Extracts printable strings (min length 6) from binary or unknown file types.
*   **Suspicious Content Detection:**
    *   Matches content against a list of predefined regular expression patterns (e.g., `<script>`, `eval\(`, `base64_decode\(`).
    *   Searches for a list of predefined suspicious keywords (e.g., "malware", "virus", "exploit").
    *   Calculates a basic Shannon entropy for extracted text; high entropy might suggest obfuscation or encryption.
*   **Reporting:**
    *   Prints detailed analysis to the console.
    *   Saves a comprehensive report to a timestamped `.txt` file.
*   **User Interface:** Uses Tkinter for a graphical file selection dialog.
*   **Dependency Management:** Provides warnings for missing optional libraries, allowing core functionality to proceed where possible.

## Prerequisites

*   Python 3.x
*   **Tesseract OCR Engine:** Required for OCR functionality on images.
    *   **Windows:** Download installer from [Tesseract at UB Mannheim](https://github.com/UB-Mannheim/tesseract/wiki) or [official Tesseract OCR GitHub](https://github.com/tesseract-ocr/tessdoc/blob/main/Installation.md).
    *   **Linux (Debian/Ubuntu):** `sudo apt-get update && sudo apt-get install tesseract-ocr tesseract-ocr-eng` (install `tesseract-ocr-eng` or other language packs as needed).
    *   **macOS (Homebrew):** `brew install tesseract`
    *   The script has a default path for Tesseract on Windows (`C:\Program Files\Tesseract-OCR\tesseract.exe`). If your installation is elsewhere, or on a different OS, you may need to configure this path in the script (see Configuration).

## Installation

1.  **Clone or download `full-analyser.py`**.

2.  **Install Python Libraries:**
    Open your terminal or command prompt and run:
    ```bash
    pip install PyPDF2 python-docx Pillow pytesseract pyopencl numpy geopy python-magic
    ```
    *   **Note for `python-magic` on Windows:** If you encounter issues installing `python-magic` (it might require libmagic DLLs), try `python-magic-bin` instead:
        ```bash
        pip install python-magic-bin
        ```
    *   **Note for `pyopencl`:** Installation can be complex. Ensure you have the necessary OpenCL drivers for your GPU/CPU and potentially an OpenCL SDK. See the [PyOpenCL installation guide](https://documen.tician.de/pyopencl/misc.html#installation). If installation fails or is not desired, the script will still run but without GPU acceleration.

3.  **Install Tesseract OCR Engine:** (See Prerequisites section above).

## Usage

1.  Navigate to the directory containing `full-analyser.py`.
2.  Run the script from your terminal:
    ```bash
    python full-analyser.py
    ```
    (On Linux/macOS, you might first `chmod +x full-analyser.py` and then run `./full-analyser.py`)
3.  A file dialog window will open. Select the file you wish to analyze.
4.  The script will output analysis details to the console.
5.  A text file report (e.g., `MM-DD-YYYY-HH-MM-SS.txt`) will be saved in the same directory as the script, containing the full analysis.

## Configuration

*   **Tesseract OCR Path:**
    The script includes a line to specify the Tesseract command path:
    ```python
    # Uncomment and set your Tesseract path if needed:
    pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe' # Example for Windows
    # pytesseract.pytesseract.tesseract_cmd = r'/usr/bin/tesseract' # Example for Linux
    ```
    The Windows path is active by default in the provided script. If `pytesseract` cannot find your Tesseract installation automatically (especially on Linux/macOS, or if installed in a non-standard Windows location), you'll need to uncomment the relevant line for your OS (or add a new one) and set the correct path to your `tesseract` executable.

*   **Suspicious Patterns and Keywords:**
    Near the beginning of the script, you can find and modify these lists:
    *   `SUSPICIOUS_PATTERNS`: A list of `re.compile()` objects for regex-based detection.
    *   `SUSPICIOUS_KEYWORDS`: A list of strings for keyword-based detection.

*   **Geocoding User Agent:**
    For reverse geocoding, the script uses `user_agent="my_file_analyzer_app/1.0"`. For extensive use, consider Nominatim's usage policy and potentially customize this.

## Output

*   **Console Output:** Displays OpenCL initialization info (if applicable), then real-time analysis steps, metadata, content snippets, and suspicious findings for the selected file. Concludes with analysis time.
*   **Report File:** A `.txt` file named with the current date and time (e.g., `10-26-2023-14-30-00.txt`). It contains:
    *   Report header with filename and generation time.
    *   Analysis duration.
    *   All extracted file metadata (path, size, permissions, MIME types, hashes, GPU info).
    *   Full extracted textual content (from PDFs, DOCX, images via OCR, text files, or strings from binaries).
    *   Image-specific metadata: format, mode, size, detailed EXIF data including GPS coordinates and estimated address.
    *   A list of any suspicious indicators found based on patterns, keywords, or high entropy.

## Dependencies

The script utilizes the following Python libraries:

*   **Standard Library:** `os`, `platform`, `datetime`, `mimetypes`, `hashlib`, `re`, `tkinter`, `time`, `sys`
*   **PyPDF2:** For reading and extracting text from PDF files.
*   **python-docx:** For reading and extracting text from DOCX files.
*   **Pillow (PIL Fork):** For image processing, EXIF data extraction (including GPS tags).
*   **pytesseract:** Python wrapper for Google's Tesseract OCR Engine.
*   **pyopencl:** For OpenCL-based GPU computation (optional, for a demonstrative task).
*   **numpy:** Required by `pyopencl` and used for entropy calculation.
*   **geopy:** For reverse geocoding GPS coordinates to addresses.
*   **python-magic:** For more accurate MIME type detection using libmagic (optional).

## Optional Features & Troubleshooting

*   **GPU Acceleration (PyOpenCL):**
    *   If `pyopencl` and `numpy` are correctly installed and an OpenCL-compatible device is found, a demonstrative sum of file bytes is computed on the GPU.
    *   If not available or not functional, the script prints warnings and skips this step. Ensure OpenCL drivers/SDK for your hardware are installed.
*   **OCR (Tesseract):**
    *   If Tesseract is not installed or `pytesseract` cannot find it, OCR for images will be disabled. Ensure Tesseract is installed and its path is correctly configured (see Installation and Configuration).
    *   OCR accuracy depends on image quality and installed Tesseract language data.
*   **Geocoding (geopy):**
    *   Requires an active internet connection to query the Nominatim (OpenStreetMap) service.
    *   Subject to service availability and rate limits.
    *   If `geopy` is not installed, GPS to address conversion is disabled.
*   **MIME Type Detection (`python-magic`):**
    *   Offers more reliable MIME type detection. If not installed, the script falls back to the standard `mimetypes` module.
    *   Windows users might need to ensure `libmagic` DLLs are accessible or use the `python-magic-bin` package.

## Disclaimer

This script is provided for educational and informational purposes. It is a tool for data extraction and basic pattern matching, **not a comprehensive antivirus or security analysis solution.** Interpret the results with caution. "Suspicious" indicators are based on simple heuristics and may generate false positives or miss sophisticated threats. Always use professional security tools for definitive malware detection or forensic analysis.
