"""
AI Phishing Detection Agent — Interactive CLI
"""

import sys
import os
import argparse
from colorama import Fore, Style, init

init(autoreset=True)

# ---------------------------------------------------------------------------
# Bootstrap path so sub-packages resolve correctly when run from any cwd
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.dirname(__file__))

from utils.email_parser import parse_eml_file, parse_eml_string
from analyzers.header_analyzer     import analyze_headers
from analyzers.url_analyzer        import analyze_urls, analyze_single_url_standalone
from analyzers.content_analyzer    import analyze_content
from analyzers.attachment_analyzer import analyze_attachments
from core.threat_scorer  import compute_final_score
from core.reporter       import print_report, print_url_report, export_json
from core.threat_intel   import get_stats


BANNER = f"""
{Fore.CYAN}{Style.BRIGHT}
  ╔══════════════════════════════════════════════╗
  ║      AI Phishing Detection Agent  v1.0       ║
  ║   Email · URL · Content · Attachments        ║
  ╚══════════════════════════════════════════════╝
{Style.RESET_ALL}"""


def main():
    parser = argparse.ArgumentParser(
        description="AI Phishing Detection Agent",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "--email", "-e",
        metavar="PATH",
        help="Path to a .eml file to analyse",
    )
    parser.add_argument(
        "--url", "-u",
        metavar="URL",
        help="Single URL to analyse (no email required)",
    )
    parser.add_argument(
        "--json", "-j",
        metavar="OUTPUT_PATH",
        help="Export full report as JSON to this path",
    )
    parser.add_argument(
        "--no-ai",
        action="store_true",
        help="Skip Gemini AI content analysis (faster, no API key needed)",
    )
    args = parser.parse_args()

    print(BANNER)

    # -----------------------------------------------------------------------
    # Mode 1: single URL analysis
    # -----------------------------------------------------------------------
    if args.url and not args.email:
        _run_url_analysis(args.url, args.json)
        return

    # -----------------------------------------------------------------------
    # Mode 2: interactive menu
    # -----------------------------------------------------------------------
    if not args.email:
        _interactive_menu(args)
        return

    # -----------------------------------------------------------------------
    # Mode 3: direct .eml file analysis
    # -----------------------------------------------------------------------
    _run_email_analysis(args.email, args.json, skip_ai=args.no_ai)


# ---------------------------------------------------------------------------
# Analysis runners
# ---------------------------------------------------------------------------

def _run_email_analysis(path: str, json_out: str | None, skip_ai: bool = False):
    if not os.path.exists(path):
        print(f"{Fore.RED}  Error: file not found — {path}{Style.RESET_ALL}")
        sys.exit(1)

    print(f"  Parsing email: {path}")
    parsed = parse_eml_file(path)

    print("  Analysing headers ...")
    header_res = analyze_headers(parsed)

    print("  Analysing URLs ...")
    url_res = analyze_urls(parsed)

    content_res = {"score": 0, "flags": [], "details": {}}
    if not skip_ai:
        print("  Analysing content with Gemini AI ...")
        try:
            content_res = analyze_content(parsed)
        except ValueError as e:
            print(f"  {Fore.YELLOW}AI skipped: {e}{Style.RESET_ALL}")

    print("  Analysing attachments ...")
    attach_res = analyze_attachments(parsed)

    score_data = compute_final_score(header_res, url_res, content_res, attach_res)

    print_report(score_data, content_res.get("details", {}), email_meta=parsed)

    if json_out:
        export_json(score_data, content_res.get("details", {}), url_res, json_out)


def _run_url_analysis(url: str, json_out: str | None):
    print(f"  Analysing URL: {url}\n")
    url_res = analyze_single_url_standalone(url)

    # Build a minimal score_data for the reporter
    score_data = {
        "final_score":  url_res["score"],
        "threat_level": _level_from_score(url_res["score"]),
        "sub_scores":   {"urls": url_res["score"], "headers": 0, "content": 0, "attachments": 0},
        "all_flags":    url_res["flags"],
    }

    print_url_report(score_data, url_res["details"])

    if json_out:
        export_json(score_data, {}, url_res, json_out)


def _level_from_score(score: int) -> str:
    if score <= 30:
        return "safe"
    if score <= 65:
        return "suspicious"
    return "phishing"


# ---------------------------------------------------------------------------
# Interactive menu
# ---------------------------------------------------------------------------

def _interactive_menu(args):
    stats = get_stats()
    print(f"  Threat Intel: {stats['blacklisted_domains']} domains  |  {stats['blacklisted_urls']} URLs\n")

    while True:
        print(Style.BRIGHT + "  What would you like to do?")
        print("    [1]  Analyse an email file (.eml)")
        print("    [2]  Analyse a URL")
        print("    [3]  Analyse raw email text (paste)")
        print("    [4]  Exit")
        print()

        choice = input("  Enter choice: ").strip()

        if choice == "1":
            path = input("  Path to .eml file: ").strip().strip('"')
            skip = _ask_skip_ai()
            json_path = _ask_json_export()
            _run_email_analysis(path, json_path, skip_ai=skip)

        elif choice == "2":
            url = input("  Enter URL: ").strip()
            json_path = _ask_json_export()
            _run_url_analysis(url, json_path)

        elif choice == "3":
            print("  Paste raw email text. Enter a line with just END when done:")
            lines = []
            while True:
                line = input()
                if line.strip() == "END":
                    break
                lines.append(line)
            raw = "\n".join(lines)
            skip = _ask_skip_ai()
            json_path = _ask_json_export()

            from utils.email_parser import parse_eml_string
            parsed = parse_eml_string(raw)
            header_res  = analyze_headers(parsed)
            url_res     = analyze_urls(parsed)
            content_res = {"score": 0, "flags": [], "details": {}}
            if not skip:
                try:
                    content_res = analyze_content(parsed)
                except ValueError as e:
                    print(f"  {Fore.YELLOW}AI skipped: {e}{Style.RESET_ALL}")
            attach_res  = analyze_attachments(parsed)
            score_data  = compute_final_score(header_res, url_res, content_res, attach_res)
            print_report(score_data, content_res.get("details", {}), email_meta=parsed)
            if json_path:
                export_json(score_data, content_res.get("details", {}), url_res, json_path)

        elif choice == "4":
            print(f"\n  {Fore.CYAN}Goodbye.{Style.RESET_ALL}\n")
            break
        else:
            print(f"  {Fore.RED}Invalid choice.{Style.RESET_ALL}\n")


def _ask_skip_ai() -> bool:
    ans = input("  Skip AI content analysis? (y/N): ").strip().lower()
    return ans == "y"


def _ask_json_export() -> str | None:
    ans = input("  Export report as JSON? Enter path or leave blank: ").strip()
    return ans if ans else None


if __name__ == "__main__":
    main()
