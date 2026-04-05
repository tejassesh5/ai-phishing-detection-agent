# AI Phishing Detection Agent

An AI-powered phishing detection tool that analyses emails, URLs, headers, and attachments to identify phishing attempts — all from an interactive CLI.

---

## Features

| Feature | Description |
|---------|-------------|
| Header Analysis | Validates SPF, DKIM, DMARC records and detects sender spoofing, display name tricks, and Reply-To mismatches |
| URL Analysis | Extracts and scans links for typosquatting, homograph attacks, lookalike domains, URL shorteners, domain age, and IP-based URLs |
| AI Content Analysis | Uses Gemini AI to detect urgency language, credential harvesting, brand impersonation, and phishing patterns |
| Attachment Scanning | Flags dangerous extensions, macro-enabled Office docs, double-extension tricks, and suspicious archives |
| Threat Intel | Local domain and URL blacklist — easily extended to external feeds (PhishTank, Abuse.ch) |
| Threat Scoring | Weighted 0–100 score across all categories with color-coded verdict: Safe / Suspicious / Phishing |
| JSON Export | Export full analysis reports as JSON for logging or enterprise integration |

---

## Threat Score

| Score | Verdict | Color |
|-------|---------|-------|
| 0 – 30 | Safe | Green |
| 31 – 65 | Suspicious | Yellow |
| 66 – 100 | Phishing | Red |

---

## Project Structure

```
ai-phishing-detection-agent/
├── main.py                        # CLI entry point and interactive menu
├── config.py                      # Configuration and defaults
├── requirements.txt               # Python dependencies
├── .env.example                   # Environment variable template
│
├── analyzers/
│   ├── header_analyzer.py         # SPF/DKIM/DMARC, spoofing, subject checks
│   ├── url_analyzer.py            # URL extraction, reputation, typosquatting
│   ├── content_analyzer.py        # Gemini AI email body analysis
│   └── attachment_analyzer.py     # Attachment risk assessment
│
├── core/
│   ├── threat_scorer.py           # Weighted score aggregation
│   ├── reporter.py                # Color-coded CLI output and JSON export
│   └── threat_intel.py            # Domain and URL blacklist management
│
├── utils/
│   ├── email_parser.py            # .eml file and raw email string parser
│   ├── domain_utils.py            # Typosquatting, homograph, Levenshtein checks
│   └── url_utils.py               # URL extraction, shortener resolution
│
├── threat_intel/
│   ├── blacklist_domains.txt      # Known malicious domains
│   └── blacklist_urls.txt         # Known malicious URLs
│
└── samples/
    └── sample_phishing.eml        # Sample phishing email for testing
```

---

## Setup

### 1. Clone the repo

```sh
git clone https://github.com/tejassesh5/ai-phishing-detection-agent.git
cd ai-phishing-detection-agent
```

### 2. Install dependencies

```sh
pip install -r requirements.txt
```

### 3. Gemini API key

1. Get a free API key at [Google AI Studio](https://aistudio.google.com/apikey) — click **Create API key in new project**
2. Copy `.env.example` to `.env` and add your key:

```sh
cp .env.example .env
```

```env
GEMINI_API_KEY=your_key_here
```

---

## Usage

### Interactive menu

```sh
python main.py
```

```
  What would you like to do?
    [1]  Analyse an email file (.eml)
    [2]  Analyse a URL
    [3]  Analyse raw email text (paste)
    [4]  Exit
```

### Analyse an email file directly

```sh
python main.py --email path/to/email.eml
```

### Analyse a URL

```sh
python main.py --url "http://paypa1-secure.com/login/verify"
```

### Skip AI analysis (faster, no API key needed)

```sh
python main.py --email path/to/email.eml --no-ai
```

### Export report as JSON

```sh
python main.py --email path/to/email.eml --json report.json
```

---

## Sample Output

```
  VERDICT : PHISHING
  SCORE   : 70/100  ████████████████████████████░░░░░░░░░░░░

  Category Breakdown:
    Headers        81/100  ████████████████░░░░
    Urls           70/100  ██████████████░░░░░░
    Content        95/100  ███████████████████░
    Attachments     0/100  ░░░░░░░░░░░░░░░░░░░░

  AI Summary:
    This email impersonates PayPal using a lookalike domain, urgent threats
    of account suspension, and malicious links designed to harvest credentials.

  Findings (21):
    • SPF: no record found for sending domain
    • DKIM: no signature present
    • Reply-To domain (evil-phisher.ru) differs from From domain (paypa1-secure.com)
    • From domain 'paypa1-secure.com' looks like a typosquat of 'paypal'
    • AI: credential harvesting language detected
    • AI: brand impersonation — 'PayPal'
    • ...
```

---

## Configuration

Edit `config.py` to change defaults:

| Setting | Default | Description |
|---------|---------|-------------|
| `GEMINI_MODEL` | `gemini-2.5-flash` | Gemini model used for AI analysis |
| `SCORE_WEIGHTS` | headers 25, urls 30, content 30, attachments 15 | Per-category scoring weights |
| `DOMAIN_AGE_THRESHOLD_DAYS` | `30` | Domains newer than this are flagged as suspicious |
| `URL_REQUEST_TIMEOUT` | `5` | Seconds to wait when resolving redirected/shortened URLs |
| `SUSPICIOUS_EXTENSIONS` | `.exe`, `.bat`, `.ps1`, `.docm`, etc. | File extensions flagged in attachments |

---

## Where to Get Test Emails

| Source | How |
|--------|-----|
| Your spam folder | Gmail → Spam → open email → ⋮ menu → **Download message** → `.eml` file |
| Kaggle dataset | [Fraudulent Email Corpus](https://www.kaggle.com/datasets/rtatman/fraudulent-email-corpus) |
| PhishTank | [phishtank.org](https://phishtank.org) — verified phishing URLs for `--url` mode |
| Built-in sample | `samples/sample_phishing.eml` — works out of the box |

---

## Security Notes

- `.env` is in `.gitignore` — never commit your API key
- No data is sent anywhere except the Gemini API for content analysis
- URL resolution uses HEAD requests only — no page content is downloaded
- WHOIS lookups are read-only

---

## Enterprise Upgrade Path

The modular architecture is designed to scale:

- **REST API** — drop a FastAPI layer on top of the analyzers
- **Bulk processing** — extend `main.py` to accept a directory of `.eml` files
- **External threat feeds** — plug PhishTank / Abuse.ch / VirusTotal into `threat_intel.py`
- **SIEM integration** — JSON export is compatible with Splunk, Elastic, and Microsoft Sentinel ingestion formats
- **Webhook alerts** — add a notifier module to push high-score results to Slack or Teams

---

## Tech Stack

- **Python 3.11+**
- [google-genai](https://pypi.org/project/google-genai/) — Gemini AI SDK
- [dnspython](https://pypi.org/project/dnspython/) — SPF/DMARC DNS lookups
- [tldextract](https://pypi.org/project/tldextract/) — Domain parsing
- [python-whois](https://pypi.org/project/python-whois/) — Domain age lookups
- [beautifulsoup4](https://pypi.org/project/beautifulsoup4/) — HTML body parsing
- [colorama](https://pypi.org/project/colorama/) — Color CLI output
- [python-dotenv](https://pypi.org/project/python-dotenv/) — Environment variable management
- [requests](https://pypi.org/project/requests/) — URL resolution and HTTP checks
