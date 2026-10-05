from __future__ import annotations
import argparse, getpass, json
from .analyzer import analyze
from .generator import generate_passphrase
from .hibp import check_pwned
from .matcher import find_matches


def main() -> None:
    p = argparse.ArgumentParser(description="Sentinel Pass — password security intelligence")
    sub = p.add_subparsers(dest="command")

    analyze_p = sub.add_parser("analyze", help="Analyze a password locally")
    analyze_p.add_argument("password", nargs="?", help="Avoid this for real secrets; shell history may expose arguments")
    analyze_p.add_argument("--json", action="store_true", dest="as_json")
    analyze_p.add_argument("--breach", action="store_true", help="Check HIBP using k-anonymity")

    gen_p = sub.add_parser("generate", help="Generate a CSPRNG passphrase")
    gen_p.add_argument("--words", type=int, default=5)
    gen_p.add_argument("--separator", default="-")

    match_p = sub.add_parser("match", help="Show predictable fragments")
    match_p.add_argument("password", nargs="?")

    args = p.parse_args()
    if args.command == "generate":
        print(generate_passphrase(args.words, args.separator))
        return
    if args.command == "match":
        password = args.password if args.password is not None else getpass.getpass("Password (hidden): ")
        print(json.dumps([m.__dict__ for m in find_matches(password)], indent=2))
        return

    password = getattr(args, "password", None)
    password = password if password is not None else getpass.getpass("Password (hidden): ")
    report = analyze(password)
    payload = report.to_dict()
    if getattr(args, "breach", False):
        payload["hibp"] = check_pwned(password).__dict__
    if getattr(args, "as_json", False):
        print(json.dumps(payload, indent=2))
        return
    print(f"\nSentinel Pass {report.score}/4 — {report.label}")
    print(f"Length: {report.length} | Effective entropy: {report.entropy:.1f} bits | Estimated guesses: {report.guesses:.3g}")
    print("\nThreat model:")
    print(f"  Online throttled: {report.crack.online}\n  Offline slow hash: {report.crack.offline_slow_hash}\n  Fast/GPU model:    {report.crack.fast_gpu}")
    print("\nFindings:")
    for x in report.findings:
        print(f"  [{x.severity.upper()}] {x.title}: {x.detail}")
    if not report.findings:
        print("  No obvious structural weaknesses detected.")
    if getattr(args, "breach", False):
        result = payload["hibp"]
        if result["error"]:
            print(f"\nHIBP: {result['error']}")
        elif result["compromised"]:
            print(f"\nHIBP: COMPROMISED — seen {result['count']:,} times in the corpus")
        else:
            print("\nHIBP: no match found in Pwned Passwords")
