"""
⚛️ Quantum Risk Assessor — Evaluates which classical crypto breaks under quantum
=================================================================================
Based on established quantum algorithm research (Shor 1994, Grover 1996):

• Shor's algorithm: factors integers & solves discrete log in polynomial time
    → Breaks RSA, ECC, DSA, Diffie-Hellman COMPLETELY
• Grover's algorithm: quadratically speeds up unstructured search
    → Halves effective security of symmetric ciphers (AES-128 → 64-bit)

Reference: NIST IR 8413 (Status Report on the Third Round of the PQC Standardization Process)
Reference: ETSI TR 103 619 (Migration Strategies for PQC)
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


# ── Algorithm Impact Database ────────────────────────────────────────

@dataclass
class QuantumImpact:
    """Security impact of quantum computing on a cryptographic algorithm."""
    algorithm: str
    category: str                  # asymmetric, symmetric, hash, signature, KEM
    security_level_bits: int       # Current classical security level
    post_quantum_security_bits: int  # Effective security against quantum
    broken: bool                   # Completely broken by quantum?
    breaking_algorithm: str        # Which quantum algorithm breaks it
    severity: str                  # CRITICAL, HIGH, MODERATE, LOW
    notes: str                     # Additional context
    recommendation: str            # What to migrate to

    def security_reduction(self) -> str:
        """Describe how security changes post-quantum."""
        if self.broken:
            return f"{self.security_level_bits}-bit → 0-bit (COMPLETELY BROKEN)"
        return f"{self.security_level_bits}-bit → {self.post_quantum_security_bits}-bit"


# Complete impact database
QUANTUM_IMPACTS: Dict[str, QuantumImpact] = {
    # ── Asymmetric (COMPLETELY BROKEN by Shor's algorithm) ──
    "RSA-1024": QuantumImpact(
        "RSA-1024", "asymmetric", 80, 0, True, "Shor's algorithm",
        "CRITICAL", "Factored in polynomial time on a large-scale quantum computer",
        "CRYSTALS-Kyber (KEM), CRYSTALS-Dilithium (signatures)"
    ),
    "RSA-2048": QuantumImpact(
        "RSA-2048", "asymmetric", 112, 0, True, "Shor's algorithm",
        "CRITICAL", "Factored in polynomial time — current standard, completely broken",
        "CRYSTALS-Kyber (KEM), CRYSTALS-Dilithium (signatures)"
    ),
    "RSA-3072": QuantumImpact(
        "RSA-3072", "asymmetric", 128, 0, True, "Shor's algorithm",
        "CRITICAL", "Larger key, same mathematical weakness — Shor doesn't care about key size",
        "CRYSTALS-Kyber (KEM), CRYSTALS-Dilithium (signatures)"
    ),
    "RSA-4096": QuantumImpact(
        "RSA-4096", "asymmetric", 140, 0, True, "Shor's algorithm",
        "CRITICAL", "Same vulnerability — Shor's runtime scales polynomially with key size",
        "CRYSTALS-Kyber (KEM), CRYSTALS-Dilithium (signatures)"
    ),
    "ECDSA-P256": QuantumImpact(
        "ECDSA-P256", "signature", 128, 0, True, "Shor's algorithm",
        "CRITICAL", "ECDLP solved in polynomial time — used everywhere (TLS, cryptocurrencies)",
        "CRYSTALS-Dilithium, Falcon"
    ),
    "ECDSA-P384": QuantumImpact(
        "ECDSA-P384", "signature", 192, 0, True, "Shor's algorithm",
        "CRITICAL", "Same vulnerability as P-256, just larger key",
        "CRYSTALS-Dilithium, Falcon"
    ),
    "ECDSA-P521": QuantumImpact(
        "ECDSA-P521", "signature", 256, 0, True, "Shor's algorithm",
        "CRITICAL", "Largest standard ECC curve — still broken by Shor",
        "CRYSTALS-Dilithium, Falcon"
    ),
    "Ed25519": QuantumImpact(
        "Ed25519", "signature", 128, 0, True, "Shor's algorithm",
        "CRITICAL", "Modern EdDSA — fast but quantum-vulnerable",
        "CRYSTALS-Dilithium, SPHINCS+"
    ),
    "Ed448": QuantumImpact(
        "Ed448", "signature", 224, 0, True, "Shor's algorithm",
        "CRITICAL", "Goldilocks curve — same mathematical vulnerability",
        "CRYSTALS-Dilithium, SPHINCS+"
    ),
    "X25519": QuantumImpact(
        "X25519", "KEM", 128, 0, True, "Shor's algorithm",
        "CRITICAL", "Curve25519 ECDH — most common key exchange on the internet",
        "CRYSTALS-Kyber, FrodokEM"
    ),
    "X448": QuantumImpact(
        "X448", "KEM", 224, 0, True, "Shor's algorithm",
        "CRITICAL", "Higher security ECDH — still broken",
        "CRYSTALS-Kyber, FrodokEM"
    ),
    "DSA-1024": QuantumImpact(
        "DSA-1024", "signature", 80, 0, True, "Shor's algorithm",
        "CRITICAL", "Discrete log signature — broken",
        "CRYSTALS-Dilithium, SPHINCS+"
    ),
    "DSA-2048": QuantumImpact(
        "DSA-2048", "signature", 112, 0, True, "Shor's algorithm",
        "CRITICAL", "Same DLP weakness as RSA",
        "CRYSTALS-Dilithium, SPHINCS+"
    ),
    "DH-2048": QuantumImpact(
        "DH-2048", "KEM", 112, 0, True, "Shor's algorithm",
        "CRITICAL", "Diffie-Hellman key exchange — broken by Shor",
        "CRYSTALS-Kyber, FrodokEM"
    ),
    "DH-4096": QuantumImpact(
        "DH-4096", "KEM", 140, 0, True, "Shor's algorithm",
        "CRITICAL", "Larger DH group — same vulnerability",
        "CRYSTALS-Kyber, FrodokEM"
    ),

    # ── Symmetric (security HALVED by Grover's algorithm) ──
    "AES-128": QuantumImpact(
        "AES-128", "symmetric", 128, 64, False, "Grover's algorithm",
        "HIGH", "Effective security halved to 64-bit — considered below threshold (~100 bits)",
        "AES-256 (the 256-bit key variant maintains 128-bit post-quantum security)"
    ),
    "AES-192": QuantumImpact(
        "AES-192", "symmetric", 192, 96, False, "Grover's algorithm",
        "MODERATE", "Effective security reduced to 96-bit — borderline acceptable",
        "AES-256"
    ),
    "AES-256": QuantumImpact(
        "AES-256", "symmetric", 256, 128, False, "Grover's algorithm",
        "LOW", "128-bit post-quantum security — considered quantum-safe by NIST",
        "Already quantum-resistant at current key size"
    ),
    "ChaCha20": QuantumImpact(
        "ChaCha20", "symmetric", 256, 128, False, "Grover's algorithm",
        "LOW", "256-bit key = 128-bit post-quantum security — safe",
        "Already quantum-resistant (256-bit key variant)"
    ),
    "3DES": QuantumImpact(
        "3DES", "symmetric", 112, 56, False, "Grover's algorithm",
        "HIGH", "56-bit post-quantum security — COMPLETELY inadequate",
        "AES-256"
    ),

    # ── Hash functions (security HALVED by Grover's) ──
    "SHA-1": QuantumImpact(
        "SHA-1", "hash", 80, 40, False, "Grover's algorithm",
        "CRITICAL", "Already classically broken (SHAttered), quantum accelerates collision finding",
        "SHA-256, SHA-3-256"
    ),
    "SHA-256": QuantumImpact(
        "SHA-256", "hash", 128, 64, False, "Grover's algorithm",
        "MODERATE", "64-bit collision resistance post-quantum — borderline",
        "SHA-512, SHA-3-256 (longer outputs restore margin)"
    ),
    "SHA-512": QuantumImpact(
        "SHA-512", "hash", 256, 128, False, "Grover's algorithm",
        "LOW", "128-bit post-quantum collision resistance — safe",
        "Already quantum-resistant"
    ),
    "SHA-3-256": QuantumImpact(
        "SHA-3-256", "hash", 128, 64, False, "Grover's algorithm",
        "MODERATE", "Same as SHA-256 — 64-bit post-quantum collision resistance",
        "SHA-3-512"
    ),
    "SHA-3-512": QuantumImpact(
        "SHA-3-512", "hash", 256, 128, False, "Grover's algorithm",
        "LOW", "128-bit post-quantum — safe",
        "Already quantum-resistant"
    ),
    "BLAKE2b": QuantumImpact(
        "BLAKE2b", "hash", 256, 128, False, "Grover's algorithm",
        "LOW", "256-bit output = 128-bit post-quantum — safe with full output",
        "Already quantum-resistant at full output length"
    ),

    # ── NIST PQC Standards (for reference / comparison) ──
    "CRYSTALS-Kyber-512": QuantumImpact(
        "CRYSTALS-Kyber-512", "KEM", 128, 128, False, "None (PQC)",
        "LOW", "NIST-selected KEM — quantum-safe, equivalent to AES-128",
        "Already PQC — NIST standard"
    ),
    "CRYSTALS-Kyber-768": QuantumImpact(
        "CRYSTALS-Kyber-768", "KEM", 192, 192, False, "None (PQC)",
        "LOW", "NIST-selected KEM — recommended for most use cases",
        "Already PQC — NIST standard"
    ),
    "CRYSTALS-Kyber-1024": QuantumImpact(
        "CRYSTALS-Kyber-1024", "KEM", 256, 256, False, "None (PQC)",
        "LOW", "NIST-selected KEM — highest security level",
        "Already PQC — NIST standard"
    ),
    "CRYSTALS-Dilithium-2": QuantumImpact(
        "CRYSTALS-Dilithium-2", "signature", 128, 128, False, "None (PQC)",
        "LOW", "NIST-selected signature — quantum-safe",
        "Already PQC — NIST standard"
    ),
    "CRYSTALS-Dilithium-3": QuantumImpact(
        "CRYSTALS-Dilithium-3", "signature", 192, 192, False, "None (PQC)",
        "LOW", "NIST-selected signature — recommended level",
        "Already PQC — NIST standard"
    ),
    "SPHINCS+-128": QuantumImpact(
        "SPHINCS+-128", "signature", 128, 128, False, "None (PQC)",
        "LOW", "NIST-selected stateless hash-based signature — conservative",
        "Already PQC — NIST standard"
    ),
    "Falcon-512": QuantumImpact(
        "Falcon-512", "signature", 128, 128, False, "None (PQC)",
        "LOW", "NIST-selected lattice signature — compact signatures",
        "Already PQC — NIST standard"
    ),
}


# ── Assessment Engine ───────────────────────────────────────────────

@dataclass
class AlgorithmAssessment:
    """Assessment of a specific algorithm instance in a codebase."""
    algorithm_key: str
    impact: QuantumImpact
    locations: List[Tuple[str, int]] = field(default_factory=list)  # (file, line)
    context: str = ""

    @property
    def severity_emoji(self) -> str:
        return {"CRITICAL": "🔴", "HIGH": "🟠", "MODERATE": "🟡", "LOW": "🟢"}.get(
            self.impact.severity, "⚪"
        )


class RiskAssessor:
    """Assesses quantum risk across a set of crypto findings."""

    def __init__(self):
        self.assessments: Dict[str, AlgorithmAssessment] = {}

    def assess(self, algorithm_name: str, file_path: str = "", line: int = 0):
        """Register and assess an algorithm usage."""
        # Normalize algorithm name
        key = self._normalize(algorithm_name)
        impact = QUANTUM_IMPACTS.get(key)

        if not impact:
            # Try fuzzy matching
            impact = self._fuzzy_match(algorithm_name)

        if impact:
            if key not in self.assessments:
                self.assessments[key] = AlgorithmAssessment(key, impact)
            if file_path:
                self.assessments[key].locations.append((file_path, line))

    def _normalize(self, name: str) -> str:
        """Normalize an algorithm name to match our database keys."""
        name = name.strip().upper()

        # RSA variants
        if name == "RSA":
            return "RSA-2048"  # Default to most common
        if name.startswith("RSA-"):
            return name if name in QUANTUM_IMPACTS else "RSA-2048"

        # ECC variants
        if name in ("ECC", "EC", "ECDSA", "ECDH"):
            return "ECDSA-P256"
        if name == "ED25519":
            return "Ed25519"
        if name == "ED448":
            return "Ed448"
        if name in ("X25519", "CURVE25519"):
            return "X25519"

        # Hash variants
        if name == "SHA1" or name == "SHA-1":
            return "SHA-1"
        if name in ("SHA256", "SHA-256"):
            return "SHA-256"
        if name in ("SHA512", "SHA-512"):
            return "SHA-512"

        # AES
        if name.startswith("AES"):
            if "256" in name:
                return "AES-256"
            if "192" in name:
                return "AES-192"
            return "AES-128"

        # DH
        if name in ("DH", "DIFFIE-HELLMAN", "DIFFIEHELLMAN"):
            return "DH-2048"

        # DSA
        if name == "DSA":
            return "DSA-2048"

        return name

    def _fuzzy_match(self, name: str) -> Optional[QuantumImpact]:
        """Try fuzzy matching for unknown algorithm names."""
        upper = name.upper()
        for key, impact in QUANTUM_IMPACTS.items():
            if upper in key or key in upper:
                return impact
        return None

    def get_summary(self) -> Dict:
        """Get a summary of the risk assessment."""
        by_severity = {"CRITICAL": 0, "HIGH": 0, "MODERATE": 0, "LOW": 0}
        by_category = {"asymmetric": 0, "symmetric": 0, "hash": 0, "signature": 0, "KEM": 0}

        for a in self.assessments.values():
            by_severity[a.impact.severity] += 1
            by_category[a.impact.category] += 1

        return {
            "total_algorithms": len(self.assessments),
            "by_severity": by_severity,
            "by_category": by_category,
            "critical_algorithms": [
                a.algorithm_key for a in self.assessments.values()
                if a.impact.severity == "CRITICAL"
            ],
            "stable_algorithms": [
                a.algorithm_key for a in self.assessments.values()
                if a.impact.severity == "LOW"
            ],
        }


def assess_from_findings(findings: list) -> RiskAssessor:
    """Run assessment from crypto scanner findings."""
    assessor = RiskAssessor()
    seen_locations = {}
    for f in findings:
        key = f.algorithm.upper()
        assessor.assess(f.algorithm, f.file_path, f.line_number)
        if key not in seen_locations:
            seen_locations[key] = []
        seen_locations[key].append(f"{f.file_path}:{f.line_number}")
        assessor.assessments[key].context = (
            f"Found in {len(seen_locations[key])} location(s): {', '.join(seen_locations[key][:3])}"
            f"{'...' if len(seen_locations[key]) > 3 else ''}. "
            f"{f.broken_by}. Recommended migration: {f.migration_target}"
        )
    return assessor


# ── Timeline Estimation ─────────────────────────────────────────────

def estimate_migration_urgency(algorithm_key: str) -> Tuple[str, str, str]:
    """
    Estimate migration urgency based on algorithm type and use case.

    Returns: (urgency_level, timeframe, explanation)
    """
    impact = QUANTUM_IMPACTS.get(algorithm_key)

    if not impact or impact.severity == "LOW":
        return ("LOW", "5-10 years", "Monitor developments, no immediate action needed")

    if impact.severity == "CRITICAL" and impact.category in ("asymmetric", "signature", "KEM"):
        return (
            "URGENT",
            "0-3 years",
            f"{algorithm_key} is completely broken by {impact.breaking_algorithm}. "
            "All data encrypted today with this algorithm could be decrypted retroactively "
            "once a large-scale quantum computer exists (harvest-now, decrypt-later attacks). "
            "Migration should begin immediately for long-lived secrets."
        )

    if impact.severity == "HIGH":
        return (
            "HIGH",
            "1-5 years",
            f"{algorithm_key} has significantly reduced security post-quantum. "
            "Plan migration within 1-5 years depending on data sensitivity."
        )

    return (
        "MEDIUM",
        "3-7 years",
        f"{algorithm_key} needs attention but is not the most critical priority. "
        "Include in medium-term migration planning."
    )


def format_assessment(assessor: RiskAssessor) -> str:
    """Format full risk assessment as text."""
    summary = assessor.get_summary()
    lines = [
        "⚛️  QUANTUM RISK ASSESSMENT",
        "=" * 50,
        "",
        f"Total algorithms analyzed: {summary['total_algorithms']}",
        "",
        "By Severity:",
        f"  🔴 CRITICAL: {summary['by_severity']['CRITICAL']}",
        f"  🟠 HIGH:     {summary['by_severity']['HIGH']}",
        f"  🟡 MODERATE: {summary['by_severity']['MODERATE']}",
        f"  🟢 LOW:      {summary['by_severity']['LOW']}",
        "",
        "By Category:",
        f"  Asymmetric crypto:  {summary['by_category']['asymmetric']}",
        f"  Symmetric crypto:   {summary['by_category']['symmetric']}",
        f"  Hash functions:     {summary['by_category']['hash']}",
        f"  Digital signatures: {summary['by_category']['signature']}",
        f"  Key Exchange (KEM): {summary['by_category']['KEM']}",
        "",
    ]

    if summary['critical_algorithms']:
        lines.append("🔴 CRITICAL — Must Migrate Immediately:")
        for algo in summary['critical_algorithms']:
            impact = QUANTUM_IMPACTS[algo]
            lines.append(f"  • {algo}")
            lines.append(f"    Broken by: {impact.breaking_algorithm}")
            lines.append(f"    Current security: {impact.security_level_bits}-bit → 0-bit")
            lines.append(f"    Migrate to: {impact.recommendation}")
            lines.append("")

    if summary['stable_algorithms']:
        lines.append("🟢 SAFE — Already Quantum-Resistant:")
        for algo in summary['stable_algorithms']:
            impact = QUANTUM_IMPACTS[algo]
            lines.append(f"  • {algo} — {impact.security_level_bits}-bit post-quantum security")
        lines.append("")

    lines.append("=" * 50)
    lines.append("Recommendation: Prioritize asymmetric crypto migration (RSA, ECC, DH)")
    lines.append("as these are completely broken by Shor's algorithm. Symmetric crypto")
    lines.append("needs key size doubling (AES-128 → AES-256) to maintain security.")
    lines.append("=" * 50)

    return "\n".join(lines)


if __name__ == "__main__":
    # Demo assessment
    assessor = RiskAssessor()
    test_algorithms = ["RSA", "ECDSA-P256", "AES-128", "AES-256", "SHA-256", "X25519"]
    for algo in test_algorithms:
        assessor.assess(algo)
        urgency, timeframe, explanation = estimate_migration_urgency(algo)
        print(f"{algo:15s} → {urgency:8s} ({timeframe}) — {explanation[:60]}...")

    print()
    print(format_assessment(assessor))
