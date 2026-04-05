import os
from dotenv import load_dotenv

load_dotenv()

# --- AI ---
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL = "gemini-1.5-flash"

# --- Optional threat intel APIs ---
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")

# --- Scoring weights (must sum to 100) ---
SCORE_WEIGHTS = {
    "headers":    25,   # SPF/DKIM/DMARC, sender spoofing
    "urls":       30,   # URL reputation, typosquatting
    "content":    30,   # AI content analysis
    "attachments": 15,  # Suspicious file types
}

# --- Threat score thresholds ---
THREAT_LEVELS = {
    "safe":      (0,  30),
    "suspicious":(31, 65),
    "phishing":  (66, 100),
}

# --- URL analysis ---
URL_REQUEST_TIMEOUT = 5        # seconds for redirect/shortener resolution
MAX_REDIRECT_DEPTH  = 5
DOMAIN_AGE_THRESHOLD_DAYS = 30 # domains newer than this are suspicious

# --- Known URL shorteners ---
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "short.link",
    "buff.ly", "rebrand.ly", "cutt.ly", "is.gd", "tiny.cc", "shorte.st",
}

# --- Suspicious attachment extensions ---
SUSPICIOUS_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".wsh",
    ".ps1", ".scr", ".pif", ".com", ".msi", ".dll", ".lnk", ".hta",
    ".docm", ".xlsm", ".pptm", ".dotm",   # macro-enabled Office
}

SUSPICIOUS_ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".gz", ".tar"}

# --- Paths ---
BLACKLIST_DOMAINS_FILE  = os.path.join(os.path.dirname(__file__), "threat_intel", "blacklist_domains.txt")
BLACKLIST_URLS_FILE     = os.path.join(os.path.dirname(__file__), "threat_intel", "blacklist_urls.txt")
