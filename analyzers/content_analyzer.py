"""
AI-powered content analysis using Google Gemini.
Detects phishing language patterns, credential harvesting, brand impersonation.
"""

import json
import re
from google import genai
from google.genai import types
import config


_client = None


def _get_client():
    global _client
    if _client is None:
        if not config.GEMINI_API_KEY:
            raise ValueError("GEMINI_API_KEY is not set in .env")
        _client = genai.Client(api_key=config.GEMINI_API_KEY)
    return _client


_SYSTEM_PROMPT = """You are an expert email security analyst specialising in phishing detection.
Analyse the provided email content and return a JSON object with this exact structure:

{
  "phishing_score": <integer 0-100>,
  "verdict": "<safe|suspicious|phishing>",
  "indicators": [<list of specific phishing indicators found>],
  "impersonated_brand": "<brand name or null>",
  "credential_harvesting": <true|false>,
  "urgency_tactics": <true|false>,
  "summary": "<one sentence plain-English summary>"
}

Scoring guide:
- 0-30:  safe, no meaningful indicators
- 31-65: suspicious, some indicators present but not conclusive
- 66-100: phishing, clear malicious intent

Be specific in indicators — quote exact phrases or patterns you found.
Respond with ONLY the JSON object, no markdown fences."""


def analyze_content(parsed_email: dict) -> dict:
    """
    Returns:
        score   : 0–100
        flags   : list of finding strings
        details : raw Gemini response dict
    """
    subject    = parsed_email.get("subject", "")
    from_addr  = parsed_email.get("from_addr", "")
    from_name  = parsed_email.get("from_name", "")
    body_plain = parsed_email.get("body_plain", "")
    body_html  = parsed_email.get("body_html", "")

    body = body_plain or _strip_html(body_html)

    # Truncate to stay within token limits (~4000 chars of body)
    body_excerpt = body[:4000] if body else "(no body)"

    prompt = f"""Subject: {subject}
From: {from_name} <{from_addr}>

Body:
{body_excerpt}"""

    try:
        client = _get_client()
        response = client.models.generate_content(
            model=config.GEMINI_MODEL,
            contents=prompt,
            config=types.GenerateContentConfig(
                system_instruction=_SYSTEM_PROMPT,
                temperature=0.1,
                max_output_tokens=2048,
                response_mime_type="application/json",
            ),
        )
        raw_text = response.text.strip()
        # Strip markdown code fences if model adds them anyway
        raw_text = re.sub(r"^```(?:json)?\n?", "", raw_text)
        raw_text = re.sub(r"\n?```$", "", raw_text)
        result   = json.loads(raw_text)
    except json.JSONDecodeError:
        result = {
            "phishing_score": 50,
            "verdict": "suspicious",
            "indicators": ["AI response could not be parsed"],
            "impersonated_brand": None,
            "credential_harvesting": False,
            "urgency_tactics": False,
            "summary": "Analysis inconclusive due to parsing error.",
        }
    except Exception as e:
        err_str = str(e)
        if "429" in err_str or "RESOURCE_EXHAUSTED" in err_str:
            # Extract retry delay if present
            import re as _re
            delay = _re.search(r"retry in (\d+)", err_str)
            hint = f"retry in {delay.group(1)}s" if delay else "try again shortly"
            msg = f"AI quota limit reached ({hint}) — run with --no-ai to skip"
        elif "GEMINI_API_KEY" in err_str or "API_KEY" in err_str:
            msg = "GEMINI_API_KEY not set — add it to .env or run with --no-ai"
        else:
            msg = f"AI unavailable: {err_str[:120]}"
        # Fall back to keyword analysis so content score isn't zero
        fallback = _keyword_analysis(parsed_email)
        fallback["indicators"].insert(0, msg)
        result = fallback

    score = int(result.get("phishing_score", 0))
    flags = []

    if result.get("credential_harvesting"):
        flags.append("AI: credential harvesting language detected")
    if result.get("urgency_tactics"):
        flags.append("AI: urgency/fear tactics detected")
    if result.get("impersonated_brand"):
        flags.append(f"AI: brand impersonation — '{result['impersonated_brand']}'")
    for ind in result.get("indicators", []):
        flags.append(f"AI: {ind}")

    return {"score": score, "flags": flags, "details": result}


def _keyword_analysis(parsed_email: dict) -> dict:
    """
    Rule-based keyword fallback when AI is unavailable.
    Scores email body against known phishing pattern categories.
    """
    body = parsed_email.get("body_plain", "") or _strip_html(parsed_email.get("body_html", ""))
    subject = parsed_email.get("subject", "")
    text = (subject + " " + body).lower()

    score = 0
    indicators = []
    credential_harvesting = False
    urgency_tactics = False
    impersonated_brand = None

    _PATTERNS = [
        # (regex, label, points, flags...)
        (r"verify.{0,30}(account|identity|details|information)", "Credential verification request", 20, "cred"),
        (r"confirm.{0,30}(account|banking|password|details|card)", "Account confirmation request", 20, "cred"),
        (r"(banking|account|card|password).{0,30}(details|number|information).{0,30}(below|here|link|click)", "Sensitive info submission request", 25, "cred"),
        (r"(click|follow).{0,20}(link|here|below).{0,30}(verify|confirm|update|restore|secure)", "Phishing call-to-action link", 20, "cred"),
        (r"(account|card).{0,20}(suspend|terminat|lock|disabl|restrict)", "Account suspension threat", 20, "urgency"),
        (r"(within|in).{0,10}(24|48|12|72).{0,10}(hours?|hrs?)", "Tight deadline pressure", 15, "urgency"),
        (r"(immediate|urgent|mandatory|must).{0,20}(action|verify|confirm|update)", "Urgency language", 15, "urgency"),
        (r"identity theft|unauthorized.{0,20}(access|transaction|activity)", "Identity theft / fraud claim", 15, "urgency"),
        (r"(unusual|suspicious|unauthorized).{0,20}(activity|sign.in|login|access)", "Suspicious activity claim", 15, "urgency"),
        (r"temporary suspension|permanent(ly)? (close|suspend|terminat)", "Account closure threat", 20, "urgency"),
        (r"(win|winner|won|prize|reward|congratulation).{0,30}(click|claim|collect|enter)", "Prize/lottery lure", 20),
        (r"(free|no cost).{0,20}(gift|iphone|cash|money|reward)", "Free gift lure", 15),
        (r"(nigerian?|prince|inheritance|million dollar|wire transfer)", "Advance-fee fraud (419 scam)", 25),
        (r"social security|ssn|date of birth|mother.{0,10}maiden", "PII harvesting request", 30, "cred"),
        (r"(dear (customer|user|member|valued|client)|hello user)", "Generic impersonal greeting", 10),
    ]

    _BRAND_PATTERNS = [
        ("paypal", r"paypal"), ("apple", r"apple\s*(id|account|support)"),
        ("microsoft", r"microsoft|outlook|office\s*365"),
        ("amazon", r"amazon|aws"), ("netflix", r"netflix"),
        ("chase", r"chase\s*(bank)?"), ("google", r"google"),
        ("irs", r"\birs\b|internal revenue"), ("fedex", r"fedex"),
        ("usps", r"\busps\b|postal service"),
    ]

    for pattern, label, points, *flags in _PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            indicators.append(label)
            score += points
            if "cred" in flags:
                credential_harvesting = True
            if "urgency" in flags:
                urgency_tactics = True

    for brand, pattern in _BRAND_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            impersonated_brand = brand
            break

    score = min(score, 100)
    verdict = "phishing" if score >= 66 else "suspicious" if score >= 31 else "safe"
    summary = f"Keyword analysis: {len(indicators)} phishing pattern(s) detected." if indicators else "No phishing keywords detected."

    return {
        "phishing_score": score,
        "verdict": verdict,
        "indicators": indicators,
        "impersonated_brand": impersonated_brand,
        "credential_harvesting": credential_harvesting,
        "urgency_tactics": urgency_tactics,
        "summary": summary,
    }


def _strip_html(html: str) -> str:
    if not html:
        return ""
    try:
        from bs4 import BeautifulSoup
        return BeautifulSoup(html, "lxml").get_text(separator=" ")
    except Exception:
        return re.sub(r"<[^>]+>", " ", html)
