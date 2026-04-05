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
    """Parse a raw email string. Falls back to Gmail/Outlook web paste format if headers missing."""
    result = _parse_message(message_from_string(raw, policy=email.policy.default))
    # If standard parsing missed key headers, try informal paste fallback
    if not result["from_addr"] and not result["subject"]:
        result = _parse_informal(raw, result)
    return result


def _parse_informal(raw: str, base: dict) -> dict:
    """
    Fallback parser for emails pasted from Gmail/Outlook web UI.
    Extracts From, To, Reply-To, Subject, Date using regex heuristics.
    """
    import re

    text = raw.strip()
    lines = text.splitlines()

    def find(pattern):
        for line in lines:
            m = re.search(pattern, line, re.IGNORECASE)
            if m:
                return m.group(1).strip()
        return ""

    # Subject — first non-empty line OR explicit "Subject:" label
    subject = find(r"^Subject\s*[:\-]\s*(.+)")
    if not subject and lines:
        subject = lines[0].strip()

    # From — "Name <email>" pattern anywhere in first 20 lines
    from_name, from_addr = "", ""
    for line in lines[:20]:
        m = re.search(r'([^<\n]+)<([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})>', line)
        if m:
            from_name = m.group(1).strip()
            from_addr = m.group(2).strip().lower()
            break
    if not from_addr:
        m = re.search(r'\b([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})\b', "\n".join(lines[:20]))
        if m:
            from_addr = m.group(1).lower()

    # Reply-To
    reply_to = find(r"^Reply-To\s*[:\-]\s*(.+)")
    _, reply_to_addr = parseaddr(reply_to)

    # To
    to = find(r"^To\s*[:\-]\s*(.+)")

    # Date — look for date-like strings
    date = find(r"((?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{1,2},?\s+\d{4}.{0,30}(?:AM|PM|[+-]\d{4})?)")
    if not date:
        date = find(r"\d{1,2}/\d{1,2}/\d{2,4}")

    # Body = everything after the first blank line following a header-like section
    body = "\n".join(lines)

    base.update({
        "from_name": from_name or base["from_name"],
        "from_addr": from_addr or base["from_addr"],
        "to":        to or base["to"],
        "reply_to":  reply_to_addr.lower() if reply_to_addr else base["reply_to"],
        "subject":   subject or base["subject"],
        "date":      date or base["date"],
        "body_plain": body,
    })
    return base


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
