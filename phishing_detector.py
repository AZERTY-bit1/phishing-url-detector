#!/usr/bin/env python3
"""Phishing URL Detector.

Gives a risk score to a URL using simple, explainable heuristics
(IP address host, '@' trick, look-alike brands, suspicious TLDs,
too many subdomains, punycode...). Works fully offline: the URL is
never visited.
"""
import argparse
import ipaddress
import re
from urllib.parse import urlparse

SUSPICIOUS_TLDS = {"zip", "mov", "xyz", "top", "click", "gq", "tk", "ml", "cf", "ga", "work", "rest"}
SHORTENERS = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "cutt.ly", "rb.gy"}
BRANDS = {"paypal", "apple", "google", "microsoft", "amazon", "netflix", "facebook",
          "instagram", "ameli", "impots", "laposte", "chronopost", "orange", "free", "steam"}
KEYWORDS = {"login", "verify", "secure", "account", "update", "confirm", "password",
            "banking", "signin", "wallet", "gift", "free", "urgent", "suspend"}
LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a"})


def registered_domain(host: str) -> str:
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def analyze(url: str) -> dict:
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    u = urlparse(url)
    host = (u.hostname or "").lower()
    reasons = []
    score = 0

    def flag(points, why):
        nonlocal score
        score += points
        reasons.append(f"+{points} {why}")

    try:
        ipaddress.ip_address(host)
        flag(3, "host is a raw IP address")
    except ValueError:
        pass
    if "@" in u.netloc:
        flag(3, "'@' in URL hides the real destination")
    if u.scheme != "https":
        flag(1, "not using HTTPS")
    if host.startswith("xn--") or ".xn--" in host:
        flag(2, "punycode domain (possible look-alike letters)")
    if host.count(".") >= 4:
        flag(2, "many subdomains")
    if host.count("-") >= 3:
        flag(1, "many hyphens in domain")
    if len(url) > 100:
        flag(1, "very long URL")
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in SUSPICIOUS_TLDS:
        flag(2, f"suspicious TLD .{tld}")
    if host in SHORTENERS:
        flag(1, "URL shortener hides the destination")

    reg = registered_domain(host)
    normalized = host.translate(LEET)
    for brand in BRANDS:
        if brand in normalized and not reg.startswith(brand + "."):
            flag(3, f"mentions '{brand}' but real domain is '{reg}'")
            break

    path = (u.path + "?" + u.query).lower()
    found = sorted(k for k in KEYWORDS if k in path or k in host)
    if found:
        flag(min(len(found), 3), "sensitive keywords: " + ", ".join(found))

    if score >= 6:
        verdict = "DANGEROUS"
    elif score >= 3:
        verdict = "SUSPICIOUS"
    else:
        verdict = "PROBABLY SAFE"
    return {"url": url, "host": host, "score": score, "verdict": verdict, "reasons": reasons}


def main():
    p = argparse.ArgumentParser(description="Offline phishing URL risk checker")
    p.add_argument("urls", nargs="*", help="URLs to analyze")
    p.add_argument("-f", "--file", help="file with one URL per line")
    args = p.parse_args()
    urls = list(args.urls)
    if args.file:
        with open(args.file) as f:
            urls += [l.strip() for l in f if l.strip()]
    if not urls:
        p.error("give at least one URL")
    for url in urls:
        r = analyze(url)
        print(f"\n{r['verdict']:<14} score={r['score']:<3} {r['url']}")
        for why in r["reasons"]:
            print(f"   {why}")


if __name__ == "__main__":
    main()
