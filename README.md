# SafeLine Challenge

A small Python implementation of the SafeLine challenge flow. It extracts the client ID, requests challenge data, calculates the result, and submits it for verification.

## Usage

```bash
pip install requests urllib3
python challenge.py http://target.example/
```

## How it works

The calculation mixes the input length and byte sum with multiplication, XOR, and cubic values. It then encodes the result as a sequence of 6-bit values.

The HTTP flow is deliberately kept in one file so it is easy to follow:

1. Read `SafeLineChallenge` from the response.
2. Call `/.safeline/challenge/v2/api/issue`.
3. Calculate the result with `calc`.
4. Call `/.safeline/challenge/v2/api/verify`.
5. Retry the request with the returned cookie.

For security research and authorized testing only.
