"""
Domain similarity checks: typosquatting, lookalike, homograph detection.
"""

import unicodedata
import re
import tldextract


# Common homograph substitutions (unicode → ASCII lookalike)
HOMOGRAPH_MAP = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x",
    "ν": "v", "ω": "w", "і": "i", "ї": "i", "а": "a",
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t",
    "@": "a",
}

COMMON_BRANDS = [
    "paypal", "apple", "google", "microsoft", "amazon", "netflix", "facebook",
    "instagram", "twitter", "linkedin", "dropbox", "chase", "wellsfargo",
    "bankofamerica", "citibank", "usps", "fedex", "dhl", "irs", "outlook",
    "office365", "gmail", "yahoo", "ebay", "walmart", "target",
]


def extract_domain(addr: str) -> str:
    """Extract bare domain from an email address or URL."""
    if "@" in addr:
        return addr.split("@")[-1].lower().strip()
    ext = tldextract.extract(addr)
    return f"{ext.domain}.{ext.suffix}".lower() if ext.suffix else ext.domain.lower()


def normalize_domain(domain: str) -> str:
    """Normalize unicode/homograph chars to ASCII equivalents."""
    result = ""
    for ch in domain.lower():
        result += HOMOGRAPH_MAP.get(ch, ch)
    # NFKC normalization collapses many lookalike unicode chars
    return unicodedata.normalize("NFKC", result)


def levenshtein(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return levenshtein(s2, s1)
    if not s2:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (c1 != c2)))
        prev = curr
    return prev[-1]


def is_typosquat(domain: str, brand_list: list[str] | None = None) -> tuple[bool, str]:
    """
    Returns (True, matched_brand) if domain looks like a typosquat of a known brand.
    Uses normalized Levenshtein distance on the domain name (without TLD).
    """
    brands = brand_list or COMMON_BRANDS
    ext    = tldextract.extract(domain)
    d_name = normalize_domain(ext.domain)

    for brand in brands:
        b_norm = normalize_domain(brand)
        dist   = levenshtein(d_name, b_norm)
        # Exact substring or close edit distance
        if b_norm in d_name or d_name in b_norm:
            if d_name != b_norm:           # e.g. "paypal-secure" contains "paypal"
                return True, brand
        if 1 <= dist <= 2 and len(b_norm) >= 5:
            return True, brand
    return False, ""


def has_homograph(domain: str) -> bool:
    """True if domain contains non-ASCII / lookalike unicode characters."""
    try:
        domain.encode("ascii")
        return False
    except UnicodeEncodeError:
        return True


def is_subdomain_trick(display_domain: str, actual_domain: str) -> bool:
    """
    Detect tricks like  paypal.com.evil.net
    where paypal.com appears as a subdomain of the actual malicious domain.
    """
    norm_display = normalize_domain(extract_domain(display_domain))
    norm_actual  = normalize_domain(extract_domain(actual_domain))
    return norm_display != norm_actual and norm_display in actual_domain.lower()
