"""
Formats and renders analysis results to the CLI.
Also supports JSON export for enterprise/API integration.
"""

import json
from colorama import Fore, Style, init

init(autoreset=True)

_LEVEL_COLORS = {
    "safe":       Fore.GREEN,
    "suspicious": Fore.YELLOW,
    "phishing":   Fore.RED,
}

_BAR_WIDTH = 40


def print_report(score_data: dict, content_details: dict, email_meta: dict | None = None):
    level = score_data["threat_level"]
    color = _LEVEL_COLORS.get(level, Fore.WHITE)
    final = score_data["final_score"]

    print()
    print(Style.BRIGHT + "=" * 60)
    print(Style.BRIGHT + "   AI PHISHING DETECTION AGENT — Analysis Report")
    print(Style.BRIGHT + "=" * 60)

    if email_meta:
        print(f"  Subject : {email_meta.get('subject', 'N/A')}")
        print(f"  From    : {email_meta.get('from_name', '')} <{email_meta.get('from_addr', '')}>")
        print(f"  Date    : {email_meta.get('date', 'N/A')}")
        print()

    # Threat level banner
    print(color + Style.BRIGHT + f"  VERDICT : {level.upper()}")
    print(color + Style.BRIGHT + f"  SCORE   : {final}/100  {_score_bar(final)}")
    print()

    # Sub-score breakdown
    print(Style.BRIGHT + "  Category Breakdown:")
    for cat, sub in score_data["sub_scores"].items():
        bar   = _score_bar(sub, width=20)
        clr   = _score_color(sub)
        print(f"    {cat.capitalize():<12} {clr}{sub:>3}/100  {bar}{Style.RESET_ALL}")
    print()

    # AI summary
    if content_details:
        summary = content_details.get("summary", "")
        if summary:
            print(Style.BRIGHT + "  AI Summary:")
            print(f"    {summary}")
            print()

    # Flags
    flags = score_data.get("all_flags", [])
    if flags:
        print(Style.BRIGHT + f"  Findings ({len(flags)}):")
        for f in flags:
            print(f"    {Fore.YELLOW}•{Style.RESET_ALL} {f}")
    else:
        print(f"  {Fore.GREEN}No suspicious indicators detected.{Style.RESET_ALL}")

    print()
    print(Style.BRIGHT + "=" * 60)
    print()


def print_url_report(score_data: dict, url_details: list):
    level = score_data["threat_level"]
    color = _LEVEL_COLORS.get(level, Fore.WHITE)
    final = score_data["final_score"]

    print()
    print(Style.BRIGHT + "=" * 60)
    print(Style.BRIGHT + "   AI PHISHING DETECTION AGENT — URL Analysis")
    print(Style.BRIGHT + "=" * 60)
    print(color + Style.BRIGHT + f"  VERDICT : {level.upper()}")
    print(color + Style.BRIGHT + f"  SCORE   : {final}/100  {_score_bar(final)}")
    print()

    for detail in url_details:
        url   = detail.get("url", "")
        risk  = detail.get("risk_contribution", 0)
        dflgs = detail.get("flags", [])
        clr   = _score_color(risk)
        print(f"  {clr}[{risk:>3}]{Style.RESET_ALL}  {url}")
        if detail.get("final_url") and detail["final_url"] != url:
            print(f"         → resolves to: {detail['final_url']}")
        for f in dflgs:
            print(f"         {Fore.YELLOW}• {f}{Style.RESET_ALL}")
        if dflgs:
            print()

    flags = score_data.get("all_flags", [])
    if not flags:
        print(f"  {Fore.GREEN}No suspicious URL indicators detected.{Style.RESET_ALL}")

    print(Style.BRIGHT + "=" * 60)
    print()


def export_json(score_data: dict, content_details: dict, url_data: dict, path: str):
    payload = {
        "threat_level": score_data["threat_level"],
        "final_score":  score_data["final_score"],
        "sub_scores":   score_data["sub_scores"],
        "flags":        score_data["all_flags"],
        "ai_analysis":  content_details,
        "url_analysis": url_data,
    }
    with open(path, "w") as f:
        json.dump(payload, f, indent=2)
    print(f"{Fore.CYAN}  Report saved to: {path}{Style.RESET_ALL}")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _score_bar(score: int, width: int = _BAR_WIDTH) -> str:
    filled = int((score / 100) * width)
    color  = _score_color(score)
    return color + "█" * filled + Style.DIM + "░" * (width - filled) + Style.RESET_ALL


def _score_color(score: int) -> str:
    if score <= 30:
        return Fore.GREEN
    if score <= 65:
        return Fore.YELLOW
    return Fore.RED
