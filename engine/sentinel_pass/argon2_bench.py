"""Optional local Argon2id benchmark for password-storage tuning."""
from __future__ import annotations

import time


def benchmark(password: str = "benchmark-only", memory_kib: int = 19456, time_cost: int = 2, parallelism: int = 1) -> dict:
    try:
        from argon2.low_level import Type, hash_secret_raw
    except ImportError as exc:
        raise RuntimeError("Install the optional 'argon2-cffi' dependency first") from exc

    salt = b"sentinel-pass-bench"[:16]
    started = time.perf_counter()
    hash_secret_raw(
        password.encode(), salt, time_cost, memory_kib, parallelism, 32, Type.ID
    )
    elapsed_ms = (time.perf_counter() - started) * 1000
    return {
        "algorithm": "Argon2id",
        "memory_kib": memory_kib,
        "time_cost": time_cost,
        "parallelism": parallelism,
        "elapsed_ms": round(elapsed_ms, 2),
        "note": "Benchmark only. Tune on the production authentication hardware.",
    }
