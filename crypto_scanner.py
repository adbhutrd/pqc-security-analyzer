"""
📡 Crypto Scanner — Finds classical cryptographic algorithms in codebases
=========================================================================
Scans source code for usage of RSA, ECC, DSA, Diffie-Hellman, and other
classical crypto primitives that quantum computers (Shor's algorithm) will break.

Part of the PQC Security Analyzer — a research tool for demonstrating
quantum migration readiness.
"""

import re
import ast
import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Optional


# ── Detection Patterns ──────────────────────────────────────────────

# Algorithm name patterns (imports, strings, comments)
ALGORITHM_PATTERNS = {
    "RSA": {
        "patterns": [
            r'\bRSA\b', r'\brsa\b', r'RSA_[A-Z_]+',
            r'rsa\.(generate|encrypt|decrypt|sign|verify|import_key|export_key)',
            r'from\s+Crypto\.PublicKey\s+import\s+RSA',
            r'from\s+cryptography\.hazmat\.primitives\.asymmetric\s+import\s+rsa',
            r'OpenSSL::RSA', r'System\.Security\.Cryptography\.RSA',
            r'java\.security\.KeyPairGenerator.*RSA',
        ],
        "quantum_risk": "CRITICAL",
        "broken_by": "Shor's algorithm — factors RSA moduli in polynomial time",
        "migration_target": "CRYSTALS-Kyber (key encapsulation), CRYSTALS-Dilithium (signatures)",
        "key_size_warning": True,
    },
    "ECC": {
        "patterns": [
            r'\bECC\b', r'\bECDH\b', r'\bECDSA\b', r'\bEd25519\b', r'\bEd448\b',
            r'\bX25519\b', r'\bX448\b', r'\bsecp256k1\b', r'\bsecp256r1\b',
            r'\bprime256v1\b', r'\bP-256\b', r'\bP-384\b', r'\bP-521\b',
            r'ecdsa\.(sign|verify)', r'ecdh\.(generate|exchange)',
            r'from\s+Crypto\.PublicKey\s+import\s+ECC',
            r'from\s+cryptography\.hazmat\.primitives\.asymmetric\s+import\s+ec',
            r'OpenSSL::EC', r'java\.security\.KeyPairGenerator.*EC',
        ],
        "quantum_risk": "CRITICAL",
        "broken_by": "Shor's algorithm — solves ECDLP in polynomial time",
        "migration_target": "CRYSTALS-Kyber (KEM), CRYSTALS-Dilithium (signatures), Falcon",
        "key_size_warning": True,
    },
    "DSA": {
        "patterns": [
            r'\bDSA\b', r'\bdsa\b', r'DSA_[A-Z_]+',
            r'dsa\.(generate|sign|verify)',
            r'from\s+Crypto\.PublicKey\s+import\s+DSA',
            r'java\.security\.KeyPairGenerator.*DSA',
        ],
        "quantum_risk": "CRITICAL",
        "broken_by": "Shor's algorithm — solves DLP in polynomial time",
        "migration_target": "CRYSTALS-Dilithium, SPHINCS+ (stateless hash-based)",
        "key_size_warning": True,
    },
    "DH": {
        "patterns": [
            r'\bDiffie-Hellman\b', r'\bDiffieHellman\b', r'\bDH\b(?!-key)',
            r'\bffdhe', r'\bdh\.(generate|exchange|parameters)',
            r'from\s+Crypto\.Protocol\s+import\s+DiffieHellman',
            r'java\.security\.KeyPairGenerator.*DH',
            r'SSL_CTX_set_tmp_dh',
        ],
        "quantum_risk": "CRITICAL",
        "broken_by": "Shor's algorithm — solves DLP in polynomial time",
        "migration_target": "CRYSTALS-Kyber (key exchange), FrodokEM",
        "key_size_warning": False,
    },
    "AES": {
        "patterns": [
            r'\bAES\b', r'\baes\b', r'AES_[A-Z_]+',
            r'aes\.(new|encrypt|decrypt)',
            r'from\s+Crypto\.Cipher\s+import\s+AES',
            r'from\s+Cryptodome\.Cipher\s+import\s+AES',
        ],
        "quantum_risk": "MODERATE",
        "broken_by": "Grover's algorithm — halves security (AES-128 → 64-bit equivalent)",
        "migration_target": "AES-256 (double key size to maintain security)",
        "key_size_warning": True,
    },
    "SHA1": {
        "patterns": [
            r'\bSHA1\b', r'\bsha1\b', r'\bSHA-1\b',
            r'hashlib\.sha1', r'sha1\(',
            r'OpenSSL::Digest::SHA1',
        ],
        "quantum_risk": "LOW",
        "broken_by": "Already classically broken (SHAttered), Grover speeds collision search",
        "migration_target": "SHA-256, SHA-3 (any of the SHA-2/SHA-3 family)",
        "key_size_warning": False,
    },
    "SHA2": {
        "patterns": [
            r'\bSHA256\b', r'\bSHA-256\b', r'\bsha256\b',
            r'\bSHA384\b', r'\bSHA-384\b', r'\bsha384\b',
            r'\bSHA512\b', r'\bSHA-512\b', r'\bsha512\b',
            r'hashlib\.sha(256|384|512)',
        ],
        "quantum_risk": "MODERATE",
        "broken_by": "Grover's algorithm — halves effective security level",
        "migration_target": "SHA-512, SHA-3 (or double output length for equivalent security)",
        "key_size_warning": False,
    },
    "HMAC": {
        "patterns": [
            r'\bHMAC\b', r'\bhmac\b', r'hmac\.(new|digest)',
            r'from\s+Crypto\.Hash\s+import\s+HMAC',
        ],
        "quantum_risk": "MODERATE",
        "broken_by": "Grover's algorithm weakens — needs doubled key sizes",
        "migration_target": "KMAC (SHA-3 based), doubled key sizes for HMAC",
        "key_size_warning": True,
    },
}


@dataclass
class CryptoFinding:
    """A single finding of classical crypto usage in source code."""
    algorithm: str
    risk: str  # CRITICAL, MODERATE, LOW
    file_path: str
    line_number: int
    line_content: str
    broken_by: str
    migration_target: str


@dataclass
class ScanResult:
    """Complete scan results for a codebase."""
    findings: List[CryptoFinding] = field(default_factory=list)
    files_scanned: int = 0
    critical_count: int = 0
    moderate_count: int = 0
    low_count: int = 0

    def add(self, finding: CryptoFinding):
        self.findings.append(finding)
        if finding.risk == "CRITICAL":
            self.critical_count += 1
        elif finding.risk == "MODERATE":
            self.moderate_count += 1
        else:
            self.low_count += 1


class CryptoScanner:
    """Scans codebases for classical cryptographic algorithm usage."""

    # Directories to skip
    SKIP_DIRS = {
        '.git', '__pycache__', 'node_modules', '.venv', 'venv',
        'env', '.env', '.tox', '.eggs', 'eggs', 'dist', 'build',
        '.next', '.nuxt', '.cache', '.mypy_cache', '.pytest_cache',
        'target',  # Rust
        'vendor',  # Go
        '.bundle',  # Ruby
    }

    # File extensions to scan
    SCAN_EXTENSIONS = {
        '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.rs',
        '.rb', '.php', '.c', '.cpp', '.h', '.hpp', '.cs', '.swift',
        '.kt', '.scala', '.sh', '.pl', '.yaml', '.yml', '.json',
        '.xml', '.toml', '.cfg', '.conf', '.ini',
    }

    # File extensions to skip (binaries, images, etc.)
    SKIP_EXTENSIONS = {
        '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.pdf',
        '.zip', '.tar', '.gz', '.bz2', '.rar', '.7z',
        '.pyc', '.pyo', '.so', '.dll', '.dylib', '.exe',
        '.woff', '.woff2', '.ttf', '.eot',
        '.mp3', '.mp4', '.avi', '.mov',
        '.min.js', '.min.css',
    }

    def __init__(self, root_path: str, verbose: bool = False):
        self.root = Path(root_path).resolve()
        self.verbose = verbose
        self._compile_patterns()

    def _compile_patterns(self):
        """Pre-compile all regex patterns."""
        self.compiled = {}
        for algo, info in ALGORITHM_PATTERNS.items():
            self.compiled[algo] = [
                re.compile(p, re.IGNORECASE) for p in info["patterns"]
            ]

    def scan(self) -> ScanResult:
        """Scan the entire codebase for classical crypto usage."""
        result = ScanResult()
        python_files = []
        other_files = []

        # Walk directory tree
        for dirpath, dirnames, filenames in os.walk(self.root):
            # Skip unwanted directories
            dirnames[:] = [d for d in dirnames if d not in self.SKIP_DIRS]

            for filename in filenames:
                filepath = Path(dirpath) / filename
                ext = filepath.suffix.lower()

                # Skip binary/generated files
                if ext in self.SKIP_EXTENSIONS:
                    continue
                if filepath.name.endswith('.min.js') or filepath.name.endswith('.min.css'):
                    continue

                if ext in self.SCAN_EXTENSIONS:
                    if ext == '.py':
                        python_files.append(filepath)
                    else:
                        other_files.append(filepath)

        total_files = len(python_files) + len(other_files)
        if self.verbose:
            print(f"  Scanning {total_files} files ({len(python_files)} Python, {len(other_files)} other)...")

        # Scan Python files with AST analysis + regex
        for filepath in python_files:
            self._scan_file(filepath, result)
            result.files_scanned += 1

        # Scan other files with regex only
        for filepath in other_files:
            self._scan_file(filepath, result)
            result.files_scanned += 1

        return result

    def _scan_file(self, filepath: Path, result: ScanResult):
        """Scan a single file for crypto algorithm usage."""
        try:
            content = filepath.read_text(encoding='utf-8', errors='ignore')
        except Exception:
            return

        lines = content.split('\n')
        for algo, regexes in self.compiled.items():
            info = ALGORITHM_PATTERNS[algo]
            for i, line in enumerate(lines, 1):
                for regex in regexes:
                    match = regex.search(line)
                    if match:
                        # Avoid false positives from comments that say "not using X"
                        lower = line.lower()
                        if 'not use' in lower or "don't use" in lower or "avoid" in lower:
                            continue

                        result.add(CryptoFinding(
                            algorithm=algo,
                            risk=info["quantum_risk"],
                            file_path=str(filepath.relative_to(self.root)),
                            line_number=i,
                            line_content=line.strip()[:120],
                            broken_by=info["broken_by"],
                            migration_target=info["migration_target"],
                        ))
                        break  # One match per algorithm per line


def format_finding(finding: CryptoFinding) -> str:
    """Format a single finding for display."""
    risk_icon = {
        "CRITICAL": "🔴",
        "MODERATE": "🟡",
        "LOW": "🟢",
    }.get(finding.risk, "⚪")

    return (
        f"  {risk_icon} [{finding.risk:8s}] {finding.algorithm:6s} | "
        f"{finding.file_path}:{finding.line_number}\n"
        f"           {finding.line_content}"
    )


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    scanner = CryptoScanner(target, verbose=True)
    result = scanner.scan()
    print(f"\n📊 Scan Results for: {target}")
    print(f"   Files scanned: {result.files_scanned}")
    print(f"   🔴 Critical: {result.critical_count}")
    print(f"   🟡 Moderate: {result.moderate_count}")
    print(f"   🟢 Low: {result.low_count}")
    print(f"   Total: {len(result.findings)}\n")
    for f in result.findings:
        print(format_finding(f))
        print()
