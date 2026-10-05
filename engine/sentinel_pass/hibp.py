"""Privacy-preserving Have I Been Pwned password lookup.

Only a five-character SHA-1 prefix leaves the machine. The full hash is
compared locally against the returned suffix list.
"""
from __future__ import annotations

import hashlib
import urllib.error
import urllib.request
from dataclasses import dataclass


@dataclass(frozen=True)
class PwnedResult:
    compromised: bool
    count: int
    prefix: str
    error: str | None = None


def check_pwned(password: str, timeout: float = 5.0) -> PwnedResult:
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]
    request = urllib.request.Request(
        f"https://api.pwnedpasswords.com/range/{prefix}",
        headers={"User-Agent": "Sentinel-Pass/2.1 (password-security-tool)"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8")
    except (urllib.error.URLError, TimeoutError) as exc:
        return PwnedResult(False, 0, prefix, f"HIBP request failed: {exc}")

    for line in body.splitlines():
        parts = line.strip().split(":", 1)
        if len(parts) != 2:
            continue
        returned_suffix, raw_count = parts
        if returned_suffix.upper() == suffix:
            try:
                return PwnedResult(True, int(raw_count), prefix)
            except ValueError:
                return PwnedResult(True, 0, prefix, "HIBP returned an invalid prevalence count")
    return PwnedResult(False, 0, prefix)
