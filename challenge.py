#!/usr/bin/env python3
"""Calculate and submit a SafeLine challenge response."""

import json
import re
import sys
from urllib.parse import urlparse

import requests


if len(sys.argv) != 2:
    print("Usage: python challenge.py http://target.example/")
    sys.exit(1)

URL = sys.argv[1]
PARSED = urlparse(URL)
ORIGIN = f"{PARSED.scheme}://{PARSED.netloc}"


def calc(data):
    """Mix the challenge bytes and encode the result as 6-bit values."""
    t, n, total = 1, len(data), sum(data)
    r = (6 + n + total) % 6 + 6
    for _ in range(r):
        t *= 6
    if t < 6666:
        t *= n
    if t > 0x3F940AA:
        t //= n
    for idx, val in enumerate(data):
        t += pow(val, 3)
        t ^= idx
        t ^= val + idx
    result = []
    while t > 0:
        result.insert(0, t & 63)
        t >>= 6
    return result


session = requests.Session()
session.headers["User-Agent"] = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
)

print(f"Target: {URL}")
first = session.get(ORIGIN, timeout=15)
print(f"Initial response: HTTP {first.status_code}")

match = re.search(r'SafeLineChallenge\("([^"]+)"', first.text)
if not match:
    print("No SafeLine challenge was found on this page.")
    sys.exit(1)
client_id = match.group(1)
print(f"Client ID: {client_id}")

issued = session.post(
    f"{ORIGIN}/.safeline/challenge/v2/api/issue",
    json={"client_id": client_id, "level": 1},
    timeout=15,
)
challenge = issued.json()["data"]
print(f"Issue ID: {challenge['issue_id']}")

result = calc(challenge["data"])
print(f"Calculated result: {result}")

verified = session.post(
    f"{ORIGIN}/.safeline/challenge/v2/api/verify",
    json={
        "issue_id": challenge["issue_id"],
        "result": result,
        "serials": [],
        "client": {
            "userAgent": "",
            "platform": "",
            "language": "",
            "vendor": "",
            "screen": [0, 0],
            "visitorId": "",
            "score": 0,
            "target": [],
        },
    },
    timeout=15,
)
token = verified.json()["data"]["jwt"]
print("Verification returned a token.")

session.cookies.set("sl-challenge-jwt", token, path="/")
session.cookies.set("sl-challenge-server", "local", path="/")

final = session.get(ORIGIN, timeout=15)
passed = final.status_code != 468 and "SafeLineChallenge" not in final.text
print(f"Final response: HTTP {final.status_code}")
print("Challenge passed." if passed else "Challenge did not pass.")
if passed:
    print(final.text[:800])
