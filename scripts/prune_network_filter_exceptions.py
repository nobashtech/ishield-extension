#!/usr/bin/env python3
"""Remove/verify imported filter exceptions that originate their own network requests.

This intentionally does NOT remove general scriptlet support. It only removes a very small
set of site-specific filter exceptions which create new HTTP requests themselves. Normal
request interception/blocking scriptlets remain enabled.
"""
from __future__ import annotations
from pathlib import Path
import argparse
import sys

ROOT = Path(__file__).resolve().parents[1]
BROWSERS = ("chrome", "edge", "firefox")

# Canonical filter-input rules that are outside iShield's local-only privacy boundary.
def forbidden_source_rule(line: str) -> bool:
    if "//scriptlet('google-ima3-dai')" in line or '//scriptlet("google-ima3-dai")' in line:
        return True
    if "fandango.com#%#" in line and "advertStreamingSessionStart" in line:
        return True
    if "tenasia.hankyung.com#%#" in line and "hkstatic.hankyung.com/css/rel/tenasia/w/common.css" in line:
        return True
    if "#%#" in line and ("fetch(" in line or "sendBeacon(" in line):
        return True
    return False

# These markers identify active generated actions that must never ship.
FORBIDDEN_ACTION_MARKERS = (
    "/ad-verify",  # stale wcostream anti-adblock exception
    "GoogleIma3Dai",
    "advertStreamingSessionStart",
    "hkstatic.hankyung.com/css/rel/tenasia/w/common.css",
)


def clean_inputs() -> int:
    removed = 0
    files = [ROOT / "extensions" / "shared" / "adguard" / "filters" / "ads.txt",
             ROOT / "extensions" / "shared" / "adguard" / "filters" / "privacy.txt"]
    files += [ROOT / "extensions" / b / "rules" / "adguard" / n
              for b in BROWSERS for n in ("ads.txt", "privacy.txt")]
    for p in files:
        if not p.exists():
            continue
        lines = p.read_text(encoding="utf-8").splitlines()
        kept = [line for line in lines if not forbidden_source_rule(line)]
        count = len(lines) - len(kept)
        if count:
            p.write_text("\n".join(kept) + "\n", encoding="utf-8")
            removed += count
    return removed


def verify_inputs() -> list[str]:
    failures: list[str] = []
    for b in BROWSERS:
        p = ROOT / "extensions" / b / "rules" / "adguard" / "ads.txt"
        if not p.exists():
            continue
        for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
            if forbidden_source_rule(line):
                failures.append(f"{b}: network-initiating imported filter at {p.name}:{n}")
    return failures


def verify_generated() -> list[str]:
    failures: list[str] = []
    for b in BROWSERS:
        for name in ("adguard-ads-main.js", "adguard-all-main.js", "adguard-privacy-main.js"):
            p = ROOT / "extensions" / b / "content" / name
            if not p.exists():
                continue
            text = p.read_text(encoding="utf-8")
            start = text.find("var actions =")
            end = text.find("]);\n  var request =", start) if start >= 0 else -1
            actions = text[start:end] if start >= 0 and end > start else ""
            for marker in FORBIDDEN_ACTION_MARKERS:
                if marker in actions:
                    failures.append(f"{b}: active generated filter action contains forbidden marker {marker!r} in {name}")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()
    removed = 0 if args.verify_only else clean_inputs()
    failures = verify_inputs() + verify_generated()
    if failures:
        print("network-filter privacy guard FAILED", file=sys.stderr)
        for item in failures:
            print(f"- {item}", file=sys.stderr)
        return 1
    print(f"network-filter privacy guard PASS (input lines removed this run: {removed})")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
