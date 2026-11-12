#!/usr/bin/env python3
"""计算并提交雷池 WAF 的行为验证结果。"""

import json
import re
import sys
from urllib.parse import urlparse

import requests


if len(sys.argv) != 2:
    print("用法：python challenge.py http://target.example/")
    sys.exit(1)

URL = sys.argv[1]
PARSED = urlparse(URL)
ORIGIN = f"{PARSED.scheme}://{PARSED.netloc}"


def calc(data):
    """混合验证数据的字节内容，并将结果编码为一组 6 比特值，即 0 到 63 的数值。"""
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

print(f"目标地址：{URL}")
first = session.get(ORIGIN, timeout=15)
print(f"首次响应：HTTP {first.status_code}")

match = re.search(r'SafeLineChallenge\("([^"]+)"', first.text)
if not match:
    print("此页面中未找到雷池行为验证。")
    sys.exit(1)
client_id = match.group(1)
print(f"客户端 ID：{client_id}")

issued = session.post(
    f"{ORIGIN}/.safeline/challenge/v2/api/issue",
    json={"client_id": client_id, "level": 1},
    timeout=15,
)
challenge = issued.json()["data"]
print(f"验证 ID：{challenge['issue_id']}")

result = calc(challenge["data"])
print(f"计算结果：{result}")

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
print("验证接口已返回令牌。")

session.cookies.set("sl-challenge-jwt", token, path="/")
session.cookies.set("sl-challenge-server", "local", path="/")

final = session.get(ORIGIN, timeout=15)
passed = final.status_code != 468 and "SafeLineChallenge" not in final.text
print(f"最终响应：HTTP {final.status_code}")
print("验证通过。" if passed else "验证未通过。")
if passed:
    print(final.text[:800])
