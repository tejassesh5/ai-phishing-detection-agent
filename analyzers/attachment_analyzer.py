"""
Attachment risk analysis: suspicious extensions, macro-enabled Office docs,
password-protected archives, double extensions.
"""

import os
import re
import config


def analyze_attachments(parsed_email: dict) -> dict:
    """
    Returns:
        score   : 0–100
        flags   : list of finding strings
        details : per-attachment breakdown
    """
    attachments = parsed_email.get("attachments", [])
    if not attachments:
        return {"score": 0, "flags": [], "details": []}

    flags   = []
    details = []
    score   = 0

    for att in attachments:
        result = _analyze_attachment(att)
        details.append(result)
        flags.extend(result["flags"])
        score += result["risk_contribution"]

    score = max(0, min(100, score))
    return {"score": score, "flags": flags, "details": details}


def _analyze_attachment(att: dict) -> dict:
    fname    = att.get("filename", "")
    ct       = att.get("content_type", "").lower()
    size     = att.get("size", 0)
    flags    = []
    risk     = 0

    ext = os.path.splitext(fname)[-1].lower()

    # 1. Known dangerous extension
    if ext in config.SUSPICIOUS_EXTENSIONS:
        flags.append(f"Dangerous attachment extension: '{ext}' — {fname}")
        risk += 40

    # 2. Archive with potentially dangerous payload
    if ext in config.SUSPICIOUS_ARCHIVE_EXTENSIONS:
        flags.append(f"Archive attachment (may contain executable): {fname}")
        risk += 15

    # 3. Double extension trick  (e.g. invoice.pdf.exe)
    parts = fname.split(".")
    if len(parts) >= 3:
        inner_ext = f".{parts[-2].lower()}"
        if inner_ext in {".pdf", ".doc", ".jpg", ".png", ".txt"}:
            flags.append(f"Double extension trick detected: {fname}")
            risk += 30

    # 4. Macro-enabled Office documents
    if ext in {".docm", ".xlsm", ".pptm", ".dotm"}:
        flags.append(f"Macro-enabled Office document: {fname}")
        risk += 35

    # 5. Executable disguised as document via content type
    if ext in {".pdf", ".doc", ".docx"} and "application/x-" in ct:
        flags.append(f"Content-Type mismatch for {fname}: declared as {ct}")
        risk += 20

    # 6. Unusually large attachment
    if size > 10 * 1024 * 1024:   # 10 MB
        flags.append(f"Very large attachment ({size // (1024*1024)} MB): {fname}")
        risk += 5

    # 7. No extension (often used to bypass filters)
    if not ext and fname:
        flags.append(f"Attachment has no file extension: {fname}")
        risk += 15

    return {
        "filename":          fname,
        "extension":         ext,
        "content_type":      ct,
        "size_bytes":        size,
        "flags":             flags,
        "risk_contribution": min(risk, 100),
    }
