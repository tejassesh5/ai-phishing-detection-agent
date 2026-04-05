"""
Local threat intelligence: domain and URL blacklists.
Easily extended to pull from external feeds (Abuse.ch, PhishTank, etc.)
"""

import os
import config


_blacklist_domains: set[str] = set()
_blacklist_urls:    set[str] = set()
_loaded = False


def _load():
    global _loaded, _blacklist_domains, _blacklist_urls
    if _loaded:
        return

    if os.path.exists(config.BLACKLIST_DOMAINS_FILE):
        with open(config.BLACKLIST_DOMAINS_FILE) as f:
            _blacklist_domains = {
                line.strip().lower()
                for line in f
                if line.strip() and not line.startswith("#")
            }

    if os.path.exists(config.BLACKLIST_URLS_FILE):
        with open(config.BLACKLIST_URLS_FILE) as f:
            _blacklist_urls = {
                line.strip().lower()
                for line in f
                if line.strip() and not line.startswith("#")
            }

    _loaded = True


def is_blacklisted_domain(domain: str) -> bool:
    _load()
    d = domain.lower().strip()
    return d in _blacklist_domains or any(d.endswith(f".{b}") for b in _blacklist_domains)


def is_blacklisted_url(url: str) -> bool:
    _load()
    return url.lower().strip() in _blacklist_urls


def add_domain(domain: str):
    """Add a domain to the in-memory blacklist (persists for this session)."""
    _load()
    _blacklist_domains.add(domain.lower().strip())


def get_stats() -> dict:
    _load()
    return {
        "blacklisted_domains": len(_blacklist_domains),
        "blacklisted_urls":    len(_blacklist_urls),
    }
