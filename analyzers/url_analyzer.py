"""
URL analysis: extraction, typosquatting, domain age, blacklist, shortener resolution.
"""

import datetime
import re
import whois
import tldextract
from utils.url_utils import (
    extract_urls_from_text,
    extract_urls_from_html,
    is_shortener,
    resolve_url,
    get_domain_from_url,
)
from utils.domain_utils import is_typosquat, has_homograph, normalize_domain
from core.threat_intel import is_blacklisted_domain, is_blacklisted_url
import config


def analyze_urls(parsed_email: dict) -> dict:
    """
    Returns:
        score   : 0–100
        flags   : list of finding strings
        details : per-URL breakdown
        urls    : all URLs found
    """
    body_plain = parsed_email.get("body_plain", "")
    body_html  = parsed_email.get("body_html", "")

    urls = list(set(
        extract_urls_from_text(body_plain) +
        extract_urls_from_html(body_html or body_plain)
    ))

    if not urls:
        return {"score": 0, "flags": [], "details": [], "urls": []}

    flags       = []
    url_details = []
    score       = 0

    for url in urls[:20]:   # cap at 20 to avoid rate limiting
        result = _analyze_single_url(url)
        url_details.append(result)
        flags.extend(result["flags"])
        score += result["risk_contribution"]

    score = max(0, min(100, score))
    return {"score": score, "flags": flags, "details": url_details, "urls": urls}


def analyze_single_url_standalone(url: str) -> dict:
    """Entry point for standalone URL-only analysis (no email context needed)."""
    result = _analyze_single_url(url)
    score  = max(0, min(100, result["risk_contribution"]))
    return {
        "score":   score,
        "flags":   result["flags"],
        "details": [result],
        "urls":    [url],
    }


# ---------------------------------------------------------------------------
# Internal
# ---------------------------------------------------------------------------

def _analyze_single_url(url: str) -> dict:
    flags       = []
    risk        = 0
    final_url   = url
    resolved    = None

    domain = get_domain_from_url(url)

    # 1. Blacklist check
    if is_blacklisted_url(url) or is_blacklisted_domain(domain):
        flags.append(f"URL/domain is on the threat intel blacklist: {domain}")
        risk += 40

    # 2. Shortener — resolve it
    if is_shortener(url):
        flags.append(f"URL shortener detected: {url}")
        resolved = resolve_url(url)
        final_url = resolved["final_url"]
        domain    = get_domain_from_url(final_url)
        risk += 10
        if resolved.get("error"):
            flags.append(f"Could not resolve shortened URL: {resolved['error']}")
            risk += 5

    # 3. Homograph (unicode lookalike) attack
    if has_homograph(domain):
        flags.append(f"Homograph/unicode lookalike attack detected in domain: {domain}")
        risk += 35

    # 4. Typosquatting
    is_typo, brand = is_typosquat(domain)
    if is_typo:
        flags.append(f"Domain '{domain}' is a likely typosquat of '{brand}'")
        risk += 30

    # 5. IP address used instead of domain
    if re.match(r"https?://\d{1,3}(\.\d{1,3}){3}", url):
        flags.append(f"URL uses raw IP address instead of domain: {url}")
        risk += 25

    # 6. Excessive subdomains (e.g. paypal.com.login.verify.evil.net)
    ext         = tldextract.extract(final_url)
    subdomain   = ext.subdomain
    if subdomain and subdomain.count(".") >= 2:
        flags.append(f"Suspicious number of subdomains in URL: {final_url}")
        risk += 15
    # Brand name appearing as subdomain of non-brand domain
    for brand_name in _BRANDS:
        if brand_name in subdomain.lower() and brand_name not in ext.domain.lower():
            flags.append(
                f"Brand name '{brand_name}' used as subdomain of unrelated domain '{ext.domain}.{ext.suffix}'"
            )
            risk += 25

    # 7. Domain age (newly registered = suspicious)
    age_days = _get_domain_age_days(domain)
    if age_days is not None and age_days < config.DOMAIN_AGE_THRESHOLD_DAYS:
        flags.append(
            f"Domain '{domain}' was registered only {age_days} days ago (threshold: {config.DOMAIN_AGE_THRESHOLD_DAYS})"
        )
        risk += 20

    # 8. Free hosting / dynamic DNS
    if _is_free_hosting(domain):
        flags.append(f"URL hosted on free/dynamic hosting: {domain}")
        risk += 10

    # 9. Misleading path (e.g. contains known brand names)
    path = url.split(domain, 1)[-1] if domain in url else ""
    for brand_name in _BRANDS:
        if brand_name in path.lower() and brand_name not in normalize_domain(domain):
            flags.append(
                f"Brand name '{brand_name}' appears in URL path but domain is '{domain}'"
            )
            risk += 15
            break

    return {
        "url":              url,
        "final_url":        final_url,
        "domain":           domain,
        "flags":            flags,
        "risk_contribution": min(risk, 100),
        "resolved":         resolved,
        "domain_age_days":  age_days,
    }


def _get_domain_age_days(domain: str) -> int | None:
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation and isinstance(creation, datetime.datetime):
            return (datetime.datetime.utcnow() - creation).days
    except Exception:
        pass
    return None


_FREE_HOSTING = {
    "000webhostapp.com", "weebly.com", "wix.com", "blogspot.com",
    "wordpress.com", "netlify.app", "github.io", "glitch.me",
    "no-ip.com", "dyndns.org", "ddns.net", "hopto.org", "zapto.org",
    "ngrok.io", "serveo.net",
}


def _is_free_hosting(domain: str) -> bool:
    return any(domain.endswith(fh) for fh in _FREE_HOSTING)


_BRANDS = [
    "paypal", "apple", "google", "microsoft", "amazon", "netflix", "facebook",
    "instagram", "twitter", "linkedin", "dropbox", "chase", "wellsfargo",
    "bankofamerica", "citibank", "usps", "fedex", "dhl", "irs", "outlook",
    "gmail", "yahoo", "ebay", "walmart",
]
