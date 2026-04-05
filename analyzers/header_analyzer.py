"""
Email header analysis: SPF, DKIM, DMARC, sender spoofing, Reply-To mismatch.
"""

import re
import dns.resolver
from utils.domain_utils import extract_domain, normalize_domain, is_typosquat


def analyze_headers(parsed_email: dict) -> dict:
    """
    Returns:
        score      : 0–100 (higher = more suspicious)
        flags      : list of finding strings
        details    : dict with per-check results
    """
    flags   = []
    details = {}
    score   = 0

    from_addr   = parsed_email.get("from_addr", "")
    reply_to    = parsed_email.get("reply_to", "")
    auth_result = parsed_email.get("auth_results", "")
    spf_header  = parsed_email.get("spf", "")
    dkim_sig    = parsed_email.get("dkim_sig", "")
    from_name   = parsed_email.get("from_name", "")
    subject     = parsed_email.get("subject", "")

    from_domain = extract_domain(from_addr) if from_addr else ""

    # ------------------------------------------------------------------
    # 1. SPF check
    # ------------------------------------------------------------------
    spf_result = _check_spf(spf_header, auth_result, from_domain)
    details["spf"] = spf_result
    if spf_result == "fail":
        flags.append("SPF: FAIL — sender not authorised for this domain")
        score += 25
    elif spf_result == "softfail":
        flags.append("SPF: SOFTFAIL — sender may not be authorised")
        score += 10
    elif spf_result == "none":
        flags.append("SPF: no record found for sending domain")
        score += 8
    elif spf_result == "pass":
        score -= 5  # small trust bonus

    # ------------------------------------------------------------------
    # 2. DKIM check
    # ------------------------------------------------------------------
    dkim_result = _check_dkim(dkim_sig, auth_result)
    details["dkim"] = dkim_result
    if dkim_result == "fail":
        flags.append("DKIM: signature verification FAILED")
        score += 25
    elif dkim_result == "none":
        flags.append("DKIM: no signature present")
        score += 10
    elif dkim_result == "pass":
        score -= 5

    # ------------------------------------------------------------------
    # 3. DMARC check
    # ------------------------------------------------------------------
    dmarc_result = _check_dmarc(auth_result, from_domain)
    details["dmarc"] = dmarc_result
    if dmarc_result == "fail":
        flags.append("DMARC: policy check FAILED")
        score += 20
    elif dmarc_result == "none":
        flags.append("DMARC: no policy found for domain")
        score += 8
    elif dmarc_result == "pass":
        score -= 5

    # ------------------------------------------------------------------
    # 4. Reply-To mismatch
    # ------------------------------------------------------------------
    if reply_to and from_addr:
        reply_domain = extract_domain(reply_to)
        if reply_domain and reply_domain != from_domain:
            flags.append(
                f"Reply-To domain ({reply_domain}) differs from From domain ({from_domain})"
            )
            details["reply_to_mismatch"] = True
            score += 20
        else:
            details["reply_to_mismatch"] = False

    # ------------------------------------------------------------------
    # 5. Display name spoofing (e.g. "PayPal Security" <evil@random.com>)
    # ------------------------------------------------------------------
    if from_name:
        typosquat, matched = is_typosquat(from_domain)
        name_lower = from_name.lower()
        for brand in _brand_names_in_string(name_lower):
            if brand not in normalize_domain(from_domain):
                flags.append(
                    f"Display name impersonates '{brand}' but sending domain is '{from_domain}'"
                )
                details["display_name_spoof"] = brand
                score += 30
                break

    # ------------------------------------------------------------------
    # 6. Typosquatting on From domain
    # ------------------------------------------------------------------
    if from_domain:
        is_typo, brand = is_typosquat(from_domain)
        details["typosquat"] = {"detected": is_typo, "brand": brand}
        if is_typo:
            flags.append(f"From domain '{from_domain}' looks like a typosquat of '{brand}'")
            score += 25

    # ------------------------------------------------------------------
    # 7. Suspicious subject patterns
    # ------------------------------------------------------------------
    subj_flags = _check_subject(subject)
    if subj_flags:
        flags.extend(subj_flags)
        details["suspicious_subject"] = subj_flags
        score += min(15, len(subj_flags) * 5)

    score = max(0, min(100, score))
    return {"score": score, "flags": flags, "details": details}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _check_spf(spf_header: str, auth_results: str, domain: str) -> str:
    combined = (spf_header + " " + auth_results).lower()
    if "spf=pass" in combined:
        return "pass"
    if "spf=fail" in combined:
        return "fail"
    if "spf=softfail" in combined:
        return "softfail"
    if "spf=neutral" in combined:
        return "neutral"
    # Try live DNS lookup if no header info
    if domain:
        try:
            answers = dns.resolver.resolve(domain, "TXT")
            for r in answers:
                txt = r.to_text().lower()
                if "v=spf1" in txt:
                    return "dns_found"   # has SPF record, can't verify sender here
        except Exception:
            pass
    return "none"


def _check_dkim(dkim_sig: str, auth_results: str) -> str:
    ar = auth_results.lower()
    if "dkim=pass" in ar:
        return "pass"
    if "dkim=fail" in ar:
        return "fail"
    if dkim_sig:
        return "present"   # signature present but not verified in header
    return "none"


def _check_dmarc(auth_results: str, domain: str) -> str:
    ar = auth_results.lower()
    if "dmarc=pass" in ar:
        return "pass"
    if "dmarc=fail" in ar:
        return "fail"
    if domain:
        try:
            answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
            for r in answers:
                if "v=dmarc1" in r.to_text().lower():
                    return "dns_found"
        except Exception:
            pass
    return "none"


_SUSPICIOUS_SUBJECT_PATTERNS = [
    (r"urgent|immediately|action required|verify now|confirm now", "Urgency language in subject"),
    (r"account.{0,20}(suspend|clos|terminat|lock|disabl)", "Account suspension threat"),
    (r"password.{0,20}(expir|reset|chang)", "Password reset/expiry lure"),
    (r"winner|you.ve won|prize|reward|congratulation", "Prize/lottery lure"),
    (r"re:\s*re:|fw:\s*fw:", "Suspicious forwarded chain subject"),
    (r"invoice|payment|transaction|billing.{0,20}(due|fail|declin)", "Financial lure"),
    (r"unusual (sign.in|activity|login)", "Unusual activity alert"),
]


def _check_subject(subject: str) -> list[str]:
    found = []
    for pattern, label in _SUSPICIOUS_SUBJECT_PATTERNS:
        if re.search(pattern, subject, re.IGNORECASE):
            found.append(label)
    return found


_BRAND_LIST = [
    "paypal", "apple", "google", "microsoft", "amazon", "netflix", "facebook",
    "instagram", "twitter", "linkedin", "dropbox", "chase", "wellsfargo",
    "bankofamerica", "citibank", "usps", "fedex", "dhl", "irs", "outlook",
    "office365", "gmail", "yahoo", "ebay", "walmart",
]


def _brand_names_in_string(s: str) -> list[str]:
    return [b for b in _BRAND_LIST if b in s]
