# Engineering Notes

## Why not just a character counter?

Character-class policies routinely reward predictable constructions such as `P@ssword1`. Sentinel Pass separates theoretical character-space entropy from observed structural weaknesses.

## Why estimates are capped

Unbounded entropy formulas create absurdly precise crack times. Sentinel Pass caps estimates and reports them as threat-model outputs rather than measurements.

## Password storage guidance

If an application needs to store passwords, prefer Argon2id and tune memory/time cost for the target environment. bcrypt remains a legacy-compatible option. Never store plaintext passwords or use fast hashes such as SHA-256 as password storage primitives.
