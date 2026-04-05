"""
URL extraction from HTML/plain-text bodies, shortener resolution, redirect chain following.
"""

import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import tldextract
import config


_URL_RE = re.compile(
    r'https?://[^\s<>"\')\]]+',
    re.IGNORECASE,
)


def extract_urls_from_text(text: str) -> list[str]:
    return list(set(_URL_RE.findall(text)))


def extract_urls_from_html(html: str) -> list[str]:
    urls = set(_URL_RE.findall(html))
    try:
        soup = BeautifulSoup(html, "lxml")
        for tag in soup.find_all(href=True):
            u = tag["href"].strip()
            if u.startswith("http"):
                urls.add(u)
        for tag in soup.find_all(src=True):
            u = tag["src"].strip()
            if u.startswith("http"):
                urls.add(u)
    except Exception:
        pass
    return list(urls)


def is_shortener(url: str) -> bool:
    host = urlparse(url).netloc.lower().lstrip("www.")
    return host in config.URL_SHORTENERS


def resolve_url(url: str, max_depth: int | None = None) -> dict:
    """
    Follow redirects and return final destination + chain.
    Returns: {final_url, chain, error}
    """
    depth = max_depth or config.MAX_REDIRECT_DEPTH
    chain = [url]
    current = url
    error = None

    try:
        resp = requests.head(
            current,
            allow_redirects=True,
            timeout=config.URL_REQUEST_TIMEOUT,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        # requests follows redirects automatically; capture full history
        for r in resp.history:
            if r.headers.get("Location"):
                chain.append(r.headers["Location"])
        chain.append(resp.url)
    except Exception as e:
        error = str(e)

    # deduplicate while preserving order
    seen = set()
    deduped = []
    for u in chain:
        if u not in seen:
            seen.add(u)
            deduped.append(u)

    return {
        "original": url,
        "final_url": deduped[-1],
        "chain": deduped,
        "error": error,
    }


def get_domain_from_url(url: str) -> str:
    ext = tldextract.extract(url)
    return f"{ext.domain}.{ext.suffix}".lower() if ext.suffix else ext.domain.lower()
