"""
⏱️  Side-Channel Timing Analyzer — Tests PQC implementations for timing leaks
=================================================================================
Timing side-channels are the most common implementation vulnerability in
cryptographic software. This module tests PQC reference implementations
for constant-time behavior.

Research context: Radboud's PQ-HINTS project studies how PQC algorithm
implementations leak secrets through physical side-channels. This tool
provides a basic timing analysis that can be run on any PQC library.

References:
• PQ-HINTS (Radboud University) — Modeling PQC implementation vulnerability
• NIST PQC standardization — CRYSTALS-Kyber, Dilithium, SPHINCS+, Falcon
• Kocher et al. — Timing attacks on implementations of Diffie-Hellman, RSA, DSS
"""

import time
import statistics
import struct
import hmac
import hashlib
import os
from typing import Dict, List, Optional, Tuple, Callable
from dataclasses import dataclass, field
from pathlib import Path


# ── Timing Test Framework ──────────────────────────────────────────

@dataclass
class TimingResult:
    """Results of a timing measurement on a cryptographic operation."""
    operation_name: str
    sample_size: int
    mean_time_ns: float
    median_time_ns: float
    std_dev_ns: float
    min_time_ns: float
    max_time_ns: float
    variance_coefficient: float  # std/mean — lower is more constant-time
    is_constant_time: Optional[bool] = None
    notes: str = ""

    @property
    def verdict(self) -> str:
        if self.is_constant_time is None:
            return "⚠️  INCONCLUSIVE"
        return "✅ CONSTANT-TIME" if self.is_constant_time else "❌ VARIABLE-TIME (leaks! 🤫)"


class TimingTest:
    """A single timing test for a cryptographic operation."""

    def __init__(
        self,
        name: str,
        function: Callable,
        input_generator: Callable,
        samples: int = 1000,
        warmup: int = 50,
    ):
        self.name = name
        self.function = function
        self.input_generator = input_generator
        self.samples = samples
        self.warmup = warmup

    def run(self) -> TimingResult:
        """Run the timing test and return results."""
        timings = []

        # Warmup
        for _ in range(self.warmup):
            inp = self.input_generator()
            self.function(inp)

        # Actual measurements
        for _ in range(self.samples):
            inp = self.input_generator()
            start = time.perf_counter_ns()
            self.function(inp)
            end = time.perf_counter_ns()
            timings.append(end - start)

        # Statistics
        mean = statistics.mean(timings)
        median = statistics.median(timings)
        std = statistics.stdev(timings) if len(timings) > 1 else 0
        cv = std / mean if mean > 0 else 0

        # Determine if constant-time: coefficient of variation < 0.05 = likely constant-time
        # Real constant-time implementations have CV < 0.01
        # Leaky implementations can have CV > 0.10 or even > 0.50
        is_ct = None
        notes = ""
        if cv < 0.01:
            is_ct = True
            notes = "Very low variance — consistent with constant-time implementation"
        elif cv < 0.05:
            is_ct = True
            notes = "Low variance — likely constant-time (minor noise expected)"
        elif cv < 0.10:
            is_ct = None
            notes = "Moderate variance — may have timing variations, investigate further"
        else:
            is_ct = False
            notes = f"HIGH VARIANCE (CV={cv:.3f}) — likely NOT constant-time! Potentially leaks secret-dependent timing information."

        return TimingResult(
            operation_name=self.name,
            sample_size=self.samples,
            mean_time_ns=mean,
            median_time_ns=median,
            std_dev_ns=std,
            min_time_ns=min(timings),
            max_time_ns=max(timings),
            variance_coefficient=cv,
            is_constant_time=is_ct,
            notes=notes,
        )


# ── Reference Implementations (Pure Python) ────────────────────────
# These simulate PQC operations for demonstration.
# In production, this would test actual liboqs/OpenSSL implementations.

def _sim_kyber_encaps(seed: bytes) -> bytes:
    """Simulate CRYSTALS-Kyber encapsulation (constant-time reference)."""
    # Constant-time: fixed number of operations regardless of input
    result = bytearray(32)
    for i in range(32):
        val = seed[i % len(seed)] ^ 0x5C
        for j in range(8):
            val = ((val << 1) | (val >> 7)) & 0xFF
        result[i] = val
    for _ in range(100):
        result = hashlib.sha256(bytes(result)).digest()
        result = bytearray(result)
    return bytes(result)


def _sim_kyber_encaps_leaky(seed: bytes) -> bytes:
    """Simulate CRYSTALS-Kyber with a timing leak (for comparison)."""
    result = bytearray(32)
    # Timing depends on seed value — this is the leak!
    for i in range(32):
        result[i] = seed[i % len(seed)] ^ 0x5C
    # Variable-time operation: loop depends on seed content
    extra = sum(seed) % 200  # BAD: input-dependent timing
    for _ in range(100 + extra):
        result = hashlib.sha256(bytes(result)).digest()
        result = bytearray(result)
    return bytes(result)


def _sim_dilithium_sign(seed: bytes) -> bytes:
    """Simulate CRYSTALS-Dilithium signing (constant-time reference)."""
    result = bytearray(64)
    for i in range(64):
        result[i] = seed[i % len(seed)] ^ 0xA3
    for _ in range(200):
        result = hashlib.sha256(bytes(result)).digest()
        result = bytearray(result)
    return bytes(result)


def _sim_dilithium_sign_leaky(seed: bytes) -> bytes:
    """Simulate CRYSTALS-Dilithium with timing leak (rejection sampling variant)."""
    result = bytearray(64)
    for i in range(64):
        result[i] = seed[i % len(seed)] ^ 0xA3
    # Timing depends on first byte of seed — rejection sampling leak
    for _ in range(200 + (seed[0] % 50)):
        result = hashlib.sha256(bytes(result)).digest()
        result = bytearray(result)
    return bytes(result)


def _sim_aes_constant(key: bytes) -> bytes:
    """Simulate AES-256 encryption (constant-time)."""
    result = bytearray(32)
    for i in range(32):
        result[i] = key[i % len(key)] ^ 0x1B
    for _ in range(50):
        result = hashlib.sha256(bytes(result)).digest()
        result = bytearray(result)
    return bytes(result)


def _variable_time_compare(a: bytes, b: bytes) -> bool:
    """Vulnerable comparison — exits early on mismatch (TIMING LEAK)."""
    if len(a) != len(b):
        return False
    for i in range(len(a)):
        if a[i] != b[i]:
            return False  # BAD: early exit leaks position of first difference!
    return True


def _constant_time_compare(a: bytes, b: bytes) -> bool:
    """Constant-time comparison — always checks all bytes."""
    if len(a) != len(b):
        return False
    result = 0
    for i in range(len(a)):
        result |= a[i] ^ b[i]
    return result == 0


# ── Input Generators ───────────────────────────────────────────────

def random_seed(size: int = 32) -> bytes:
    """Generate a random seed of given size."""
    return os.urandom(size)


def correlated_seed(size: int = 32) -> bytes:
    """Generate seed that triggers variable-time behavior."""
    data = os.urandom(size)
    # Make timing more variable by ensuring seed[0] varies
    return data


# ── Test Suite ─────────────────────────────────────────────────────

def get_test_suite() -> List[TimingTest]:
    """Get the full test suite of timing comparisons."""
    return [
        # PQC constant-time reference
        TimingTest(
            "CRYSTALS-Kyber Encapsulation (constant-time ref)",
            _sim_kyber_encaps,
            lambda: random_seed(32),
            samples=500,
        ),
        # PQC with timing leak
        TimingTest(
            "CRYSTALS-Kyber Encapsulation (LEAKY implementation)",
            _sim_kyber_encaps_leaky,
            lambda: correlated_seed(32),
            samples=500,
        ),
        # Dilithium constant-time
        TimingTest(
            "CRYSTALS-Dilithium Sign (constant-time ref)",
            _sim_dilithium_sign,
            lambda: random_seed(64),
            samples=500,
        ),
        # Dilithium with rejection sampling leak
        TimingTest(
            "CRYSTALS-Dilithium Sign (LEAKY — rejection sampling)",
            _sim_dilithium_sign_leaky,
            lambda: correlated_seed(64),
            samples=500,
        ),
        # AES constant-time
        TimingTest(
            "AES-256 Encryption (constant-time ref)",
            _sim_aes_constant,
            lambda: random_seed(32),
            samples=500,
        ),
        # Variable-time comparison (classic timing leak)
        TimingTest(
            "Memory Compare (VARIABLE-TIME — early exit)",
            lambda x: _variable_time_compare(x, b'\x00' * 32),
            lambda: os.urandom(32),
            samples=500,
        ),
        # Constant-time comparison
        TimingTest(
            "Memory Compare (constant-time)",
            lambda x: _constant_time_compare(x, b'\x00' * 32),
            lambda: os.urandom(32),
            samples=500,
        ),
    ]


# ── Run Tests ──────────────────────────────────────────────────────

def run_all_tests(tests: Optional[List[TimingTest]] = None) -> List[TimingResult]:
    """Run all timing tests and return results."""
    if tests is None:
        tests = get_test_suite()

    results = []
    print(f"  Running {len(tests)} timing tests ({tests[0].samples} samples each)...")
    for test in tests:
        result = test.run()
        results.append(result)

        verdict_emoji = "✅" if result.is_constant_time else ("❌" if result.is_constant_time is False else "⚠️")
        print(f"    {verdict_emoji} {result.operation_name}")
    return results


def format_results(results: List[TimingResult]) -> str:
    """Format timing test results for display and reporting."""
    lines = [
        "⏱️  SIDE-CHANNEL TIMING ANALYSIS REPORT",
        "=" * 60,
        "",
        "This analysis tests cryptographic operations for secret-dependent",
        "timing variations — the most common side-channel vulnerability.",
        "",
        f"Tests conducted: {len(results)}",
        f"Samples per test: {results[0].sample_size if results else 0}",
        f"Method: High-resolution timing (ns) with statistical analysis",
        "",
    ]

    # Summary
    ct_count = sum(1 for r in results if r.is_constant_time is True)
    leaky_count = sum(1 for r in results if r.is_constant_time is False)
    inc_count = sum(1 for r in results if r.is_constant_time is None)

    lines.append("SUMMARY:")
    lines.append(f"  ✅ Constant-time implementations: {ct_count}")
    lines.append(f"  ❌ Leaky implementations found:  {leaky_count}")
    lines.append(f"  ⚠️  Inconclusive:                {inc_count}")
    lines.append("")

    # Detail
    lines.append("DETAILED RESULTS:")
    lines.append("-" * 60)
    for r in results:
        verdict_emoji = "✅" if r.is_constant_time else ("❌" if r.is_constant_time is False else "⚠️")
        lines.append(f"")
        lines.append(f"  {verdict_emoji} {r.operation_name}")
        lines.append(f"     Mean:    {r.mean_time_ns:>10,.0f} ns")
        lines.append(f"     Median:  {r.median_time_ns:>10,.0f} ns")
        lines.append(f"     Std Dev: {r.std_dev_ns:>10,.0f} ns")
        lines.append(f"     CV:      {r.variance_coefficient:>10.4f}")
        lines.append(f"     Range:   {r.min_time_ns:>8,.0f} — {r.max_time_ns:>8,.0f} ns")
        lines.append(f"     Verdict: {r.verdict}")
        lines.append(f"     {r.notes}")

    lines.append("")
    lines.append("=" * 60)
    lines.append("INTERPRETATION:")
    lines.append("  • CV < 0.05:  Likely constant-time (safe)")
    lines.append("  • CV < 0.10:  Investigate further (possible minor leaks)")
    lines.append("  • CV > 0.10:  Likely NOT constant-time (timing leak)")
    lines.append("")
    lines.append("  Real-world impact:")
    lines.append("  • A timing leak in key comparison can reveal the secret key byte-by-byte")
    lines.append("  • Rejection sampling leaks can reveal secret coefficients")
    lines.append("  • Network-based timing can measure differences as small as 10-100μs")
    lines.append("")
    lines.append("  Research reference: Radboud DiS group PQ-HINTS project studies")
    lines.append("  how PQC implementations leak through physical side-channels.")
    lines.append("=" * 60)

    return "\n".join(lines)


if __name__ == "__main__":
    print("\n🔬 PQC Side-Channel Timing Analyzer")
    print("=" * 50)
    results = run_all_tests()
    print()
    print(format_results(results))
