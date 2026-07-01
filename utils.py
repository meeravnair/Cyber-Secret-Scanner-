"""
Utility functions for Cyber Secret Scanner Pro.

Provides Shannon entropy calculations, SHA-256 file hashing, binary file detection,
and Base64 validation logic.
"""
import math
import hashlib
import mimetypes
import re
from collections import Counter
from pathlib import Path

def calculate_entropy(text: str) -> float:
    """
    Calculates the Shannon Entropy of a given string.
    Higher values represent more randomness (typical of keys/tokens).

    Args:
        text (str): String input.

    Returns:
        float: Shannon Entropy in bits per character.
    """
    if not text:
        return 0.0
    
    # Count frequencies of each character
    counter = Counter(text)
    total_len = len(text)
    
    # Calculate Shannon Entropy
    entropy = 0.0
    for count in counter.values():
        p = count / total_len
        entropy -= p * math.log2(p)
        
    return entropy

def calculate_sha256(file_path: Path) -> str:
    """
    Computes the SHA-256 checksum of a file.

    Args:
        file_path (Path): Path to the file.

    Returns:
        str: Hex-encoded SHA-256 string, or empty string if file read failed.
    """
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception:
        return ""

def is_binary(file_path: Path) -> bool:
    """
    Determines if a file is binary by checking its mime type and searching
    the first 1024 bytes for null bytes or a high ratio of non-text characters.

    Args:
        file_path (Path): Path to the file.

    Returns:
        bool: True if the file is binary, False otherwise.
    """
    # Check mime type first
    mime, _ = mimetypes.guess_type(str(file_path))
    if mime and not mime.startswith("text/") and mime not in [
        "application/json", "application/javascript", "application/xml", 
        "application/x-yaml", "application/x-sh", "application/x-php"
    ]:
        return True

    # Read start of file to check for null byte
    try:
        with open(file_path, "rb") as f:
            chunk = f.read(1024)
            if b"\x00" in chunk:
                return True
            # Check text proportion (if > 30% of bytes are non-printable/control chars)
            if len(chunk) > 0:
                control_chars = sum(1 for byte in chunk if byte < 32 and byte not in (9, 10, 13))
                if (control_chars / len(chunk)) > 0.30:
                    return True
    except Exception:
        # If we can't open/read it, treat it safely as binary/unsupported
        return True

    return False

def is_valid_base64(text: str) -> bool:
    """
    Checks if a string is a valid Base64 representation.

    Args:
        text (str): String input.

    Returns:
        bool: True if the string matches Base64 character patterns and padding, False otherwise.
    """
    # Quick regex validation for base64 characters
    if not re.match(r"^[A-Za-z0-9+/]+={0,2}$", text):
        return False
    # Standard Base64 strings must have length divisible by 4 (with padding)
    # or be of reasonable size
    return len(text) % 4 == 0 or len(text) > 16
