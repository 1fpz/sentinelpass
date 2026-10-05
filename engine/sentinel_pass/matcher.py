"""Small explainable matcher for high-value predictable fragments.

This is intentionally not presented as a replacement for a full password
strength estimator. It catches common building blocks that can be composed
into larger attack rules.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

WORDS = {
    "password", "admin", "welcome", "qwerty", "letmein", "dragon", "football",
    "monkey", "master", "login", "secret", "iloveyou", "sunshine", "princess",
    "baseball", "superman", "freedom", "whatever", "trustno1", "passw0rd",
}

@dataclass(frozen=True)
class Match:
    kind: str
    value: str
    start: int
    end: int


def find_matches(password: str) -> list[Match]:
    lower = password.lower()
    matches: list[Match] = []
    for word in WORDS:
        start = lower.find(word)
        if start >= 0:
            matches.append(Match("dictionary", password[start:start + len(word)], start, start + len(word)))
    for match in re.finditer(r"(?:19|20)\d{2}", password):
        matches.append(Match("year", match.group(), match.start(), match.end()))
    for match in re.finditer(r"(.)\1{2,}", password):
        matches.append(Match("repeat", match.group(), match.start(), match.end()))
    return sorted(matches, key=lambda x: (x.start, x.end))
