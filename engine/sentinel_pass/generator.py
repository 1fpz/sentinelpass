"""Cryptographically secure passphrase generation."""
from __future__ import annotations

import secrets

DEFAULT_WORDS = (
    "amber", "anchor", "atlas", "canyon", "cobalt", "comet", "crystal", "ember",
    "falcon", "forest", "harbor", "horizon", "lantern", "meadow", "mercury", "nebula",
    "orbit", "otter", "pixel", "quartz", "raven", "rocket", "signal", "silver",
    "summit", "thunder", "vector", "violet", "walnut", "zenith",
)


def generate_passphrase(words: int = 5, separator: str = "-") -> str:
    if not 3 <= words <= 12:
        raise ValueError("words must be between 3 and 12")
    if not separator:
        raise ValueError("separator cannot be empty")
    return separator.join(secrets.choice(DEFAULT_WORDS) for _ in range(words))
