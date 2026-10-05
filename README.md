# Sentinel Pass

**Password Security Intelligence & Attack Modeling Toolkit**

Sentinel Pass is a local-first security engineering project for analyzing password predictability, modeling attacker scenarios, checking real-world compromise exposure, and generating secure passphrases.

It is deliberately **not** a cosmetic password meter. The project separates theoretical character-space entropy from structural weaknesses such as dictionary fragments, keyboard patterns, repetition, dates and known compromised passwords.

## Features

- Pattern-aware local analysis
- Effective entropy estimation
- Explainable severity findings
- Online / offline / fast-hash threat models
- HIBP Pwned Passwords screening using **k-anonymity**
- CSPRNG passphrase generation with Python `secrets`
- Predictable-fragment matcher
- Optional Argon2id benchmark for storage-cost tuning
- Browser UI with no password persistence
- Python CLI
- JSON output for automation
- Automated tests

## Privacy model

The normal analyzer runs locally in the browser or CLI. Sentinel Pass does not send the plaintext password to its own server.

When the optional HIBP check is enabled, the application computes SHA-1 locally and sends only the **first five hexadecimal characters** of the hash to Have I Been Pwned. The returned suffixes are compared locally. The plaintext password and complete hash are never sent to HIBP. The web API route receives only that five-character prefix.

Do not run breach checks while a password is still being typed. The UI should submit only after the user explicitly asks for the check.

## Threat-model caveat

Crack-time figures are **estimates**, not measurements of a specific GPU or cracking cluster. Real resistance depends on password distribution, hash algorithm, parameters, attacker hardware, dictionaries, mutation rules and operational controls.

A password that has no obvious structural weakness is not guaranteed to be unique or uncompromised. The HIBP check is therefore a separate signal.

## Architecture

```text
sentinel-pass/
├── app/
│   ├── api/pwned/          # server-side HIBP range proxy; receives prefix only
│   ├── page.tsx            # security dashboard
│   └── globals.css
├── engine/
│   ├── sentinel_pass/
│   │   ├── analyzer.py     # explainable threat analysis
│   │   ├── hibp.py         # k-anonymity client
│   │   ├── matcher.py      # predictable fragment matching
│   │   ├── generator.py    # CSPRNG passphrases
│   │   ├── argon2_bench.py # local storage-cost benchmark
│   │   └── cli.py
│   └── tests/
├── docs/
└── README.md
```

## Web app

```bash
npm install
npm run dev
```

Open `http://localhost:3000`.

The web UI performs the analysis locally. The HIBP action is explicit and is not triggered on every keystroke.

## Python CLI

```bash
cd engine
python -m venv .venv
# Windows PowerShell
.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```

Analyze securely through the hidden prompt:

```bash
sentinel-pass analyze
```

JSON:

```bash
sentinel-pass analyze --json
```

HIBP k-anonymity check:

```bash
sentinel-pass analyze --breach
```

Generate a passphrase:

```bash
sentinel-pass generate --words 6 --separator -
```

Inspect predictable fragments:

```bash
sentinel-pass match
```

For real secrets, prefer the hidden prompt rather than passing the password as a command-line argument because shell history/process inspection can expose arguments.

## Argon2id benchmark

The optional benchmark is intended for **local tuning**, not password cracking:

```python
from sentinel_pass.argon2_bench import benchmark
print(benchmark())
```

The default configuration is aligned with one of OWASP's minimum Argon2id configurations. Production parameters should still be benchmarked on the actual authentication hardware.

## Tests

```bash
cd engine
pytest -q
```

## Security engineering principles

1. Never store plaintext passwords.
2. Do not treat character composition rules as proof of strength.
3. Keep compromise screening separate from theoretical entropy.
4. Send the minimum information necessary to external services.
5. Make threat-model assumptions visible.
6. Prefer reproducible tests over impressive-looking claims.
7. Benchmark password-storage parameters on the hardware that will actually verify passwords.

## Roadmap

- [x] HIBP k-anonymity breach checker
- [x] CSPRNG passphrase generator
- [x] Predictable-fragment matcher
- [x] Argon2id benchmark harness
- [ ] Expand matcher with weighted dictionaries and keyboard graphs
- [ ] Full zxcvbn-style scoring comparison
- [ ] SARIF report export
- [ ] CI security workflow
- [ ] Shared WebAssembly analysis core
- [ ] Offline HIBP corpus support

## References

- OWASP Password Storage Cheat Sheet
- Have I Been Pwned Pwned Passwords API
- Dropbox zxcvbn

## License

MIT
