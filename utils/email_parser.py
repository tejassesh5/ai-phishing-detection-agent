"""
Parse raw .eml files or email strings into a structured dict consumed by analyzers.
"""

import email
import email.policy
from email import message_from_string, message_from_bytes
from email.utils import parseaddr
from typing import Optional
import os


def parse_eml_file(path: str) -> dict:
    """Parse a .eml file from disk."""
    with open(path, "rb") as f:
        raw = f.read()
    return _parse_message(message_from_bytes(raw, policy=email.policy.default))


def parse_eml_string(raw: str) -> dict:
    """Parse a raw email string."""
    return _parse_message(message_from_string(raw, policy=email.policy.default))


def _parse_message(msg) -> dict:
    from_raw   = msg.get("From", "")
    to_raw     = msg.get("To", "")
    reply_to   = msg.get("Reply-To", "")
    subject    = msg.get("Subject", "")
    date       = msg.get("Date", "")
    message_id = msg.get("Message-ID", "")

    from_name, from_addr = parseaddr(from_raw)
    _, reply_to_addr     = parseaddr(reply_to)

    body_plain = ""
    body_html  = ""
    attachments = []

    if msg.is_multipart():
        for part in msg.walk():
            ct   = part.get_content_type()
            disp = str(part.get("Content-Disposition", ""))

            if "attachment" in disp:
                fname = part.get_filename() or "unknown"
                attachments.append({
                    "filename": fname,
                    "content_type": ct,
                    "size": len(part.get_payload(decode=True) or b""),
                })
            elif ct == "text/plain" and not body_plain:
                body_plain = _decode_part(part)
            elif ct == "text/html" and not body_html:
                body_html = _decode_part(part)
    else:
        ct = msg.get_content_type()
        if ct == "text/html":
            body_html  = _decode_part(msg)
        else:
            body_plain = _decode_part(msg)

    # Collect all raw headers as a list of (name, value) tuples
    raw_headers = [(k, v) for k, v in msg.items()]

    return {
        "from_name":    from_name,
        "from_addr":    from_addr.lower(),
        "to":           to_raw,
        "reply_to":     reply_to_addr.lower() if reply_to_addr else "",
        "subject":      subject,
        "date":         date,
        "message_id":   message_id,
        "body_plain":   body_plain,
        "body_html":    body_html,
        "attachments":  attachments,
        "raw_headers":  raw_headers,
        "received":     msg.get_all("Received", []),
        "auth_results": msg.get("Authentication-Results", ""),
        "dkim_sig":     msg.get("DKIM-Signature", ""),
        "spf":          msg.get("Received-SPF", ""),
        "arc":          msg.get("ARC-Authentication-Results", ""),
    }


def _decode_part(part) -> str:
    try:
        payload = part.get_payload(decode=True)
        charset = part.get_content_charset() or "utf-8"
        return payload.decode(charset, errors="replace") if payload else ""
    except Exception:
        return ""
