# Threat Model

## Assets

The primary asset is the user's plaintext password during analysis.

## Trust boundary

The web application must not require a Sentinel Pass server to analyze a password. The current implementation keeps analysis in the browser. The Python CLI reads the password directly from the terminal and does not persist it.

## Attacker models

### Online throttled

A remote attacker is constrained by rate limiting and authentication controls. Sentinel Pass models this with a deliberately conservative illustrative rate rather than pretending to know the target service's actual controls.

### Offline slow hash

An attacker has obtained password hashes protected by a deliberately expensive password KDF. The estimate uses a generic low guess rate. Real values depend heavily on the selected KDF and parameters.

### Fast/GPU model

This is a comparison model for fast verification primitives, not a claim about a specific GPU. Password-storage systems should use adaptive, memory-hard KDFs instead of fast general-purpose hashes.

## Privacy

Never log plaintext passwords. Never include passwords in analytics, URLs, error messages, telemetry or crash reports. If breach checking is implemented, use Pwned Passwords k-anonymity rather than transmitting plaintext.

## Known limitations

Entropy is not equivalent to unpredictability. A password made from common words can have a much smaller effective search space than its character-set entropy suggests. Conversely, an unusual human-created password may still follow an attacker's mutation rules.
