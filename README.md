# ⚛️ PQC Security Analyzer

**Post-Quantum Cryptography Migration Readiness Assessment Tool**

A comprehensive analysis toolkit that scans codebases for classical cryptographic algorithm usage, assesses quantum computing impact, tests PQC implementations for timing side-channel vulnerabilities, and generates professional research-grade reports.

---

## 🎯 Research Motivation

This project was built as part of PhD research preparation targeting the **Netherlands cybersecurity ecosystem**. It directly addresses problems being actively researched at multiple Dutch universities:

| University | Research Group | Relevant Project |
|-----------|---------------|-----------------|
| **Radboud University** | Digital Security (DiS) | [PQ-HINTS](https://dis.cs.ru.nl/) — Modeling PQC implementation vulnerability to side-channel attacks |
| **TU Delft** | Cybersecurity (CYS) | Post-quantum cryptography migration strategies in real-world networks |
| **VU Amsterdam** | Computer Science | [Open PhD: Formal Methods for Concurrent Cryptographic Protocols](https://workingat.vu.nl/vacancies/phd-position-in-formal-methods-for-concurrent-cryptographic-protocols-amsterdam-1288339) |
| **UvA / QuSoft** | Quantum Software | Quantum network protocol verification and quantum-safe communication |
| **TU Eindhoven** | Security Group | €21.5M CiCS program — PQC formal verification and threat intelligence |

### The Problem

> "Companies don't know where their classical cryptography is buried — no tools exist to map 'cryptographic debt' before quantum computers break everything."

Large-scale quantum computers running **Shor's algorithm** will completely break:
- **RSA** (all key sizes)
- **Elliptic Curve Cryptography** (ECDSA, ECDH, Ed25519, X25519)
- **DSA** and **Diffie-Hellman**

**Grover's algorithm** halves the effective security of symmetric primitives:
- AES-128 → 64-bit effective security (below safe threshold)
- SHA-256 → 64-bit collision resistance

NIST has standardized replacement algorithms (CRYSTALS-Kyber for KEM, CRYSTALS-Dilithium for signatures), but **migration is complex** and **implementations can leak secrets through side-channels**.

---

## 🏗️ Project Architecture

```
pqc-analyzer/
├── README.md              ← This file
├── main.py                ← CLI entry point
├── crypto_scanner.py      ← Scans code for classical crypto usage (RSA, ECC, DH, DSA)
├── quantum_risk.py        ← Assesses quantum impact with NIST-referenced severity levels
├── sidechannel_test.py    ← Tests PQC implementations for timing side-channel leaks
├── report_generator.py    ← Generates HTML + Markdown research reports
└── __init__.py
```

### What Each Module Does

**1. Crypto Scanner** (`crypto_scanner.py`)
- Detects 8+ classical algorithm categories via regex + AST analysis
- Returns file:line locations with algorithm name and risk level
- Skips binaries, vendored deps, and false positives from comments

**2. Quantum Risk Assessment** (`quantum_risk.py`)
- Database of 35+ algorithms with quantum security levels
- Classifies into: CRITICAL (broken by Shor), HIGH (halved by Grover), MODERATE, LOW
- Provides migration recommendations to NIST PQC standards
- Estimates migration urgency timeline (0-3 years, 5-10 years, etc.)

**3. Side-Channel Timing Analyzer** (`sidechannel_test.py`)
- High-resolution timing analysis using `perf_counter_ns`
- Statistical analysis (mean, median, stddev, coefficient of variation)
- Compares constant-time vs leaky implementations
- CV < 0.05 = likely constant-time; CV > 0.10 = likely leaking

**4. Report Generator** (`report_generator.py`)
- Professional dark-themed HTML report with executive summary
- Markdown version for GitHub/gitlab
- All findings, risk assessments, and timing results in one document

---

## 🚀 Quick Start

```bash
# Run full analysis on any project directory
python3 main.py /path/to/your/project

# Scan only (no timing tests — faster)
python3 main.py --scan-only /path/to/project

# Timing analysis only (no scanning)
python3 main.py --timing-only

# Self-test: scan this project and run timing
python3 main.py --self-test

# Save reports to a specific directory
python3 main.py /path/to/project ./reports
```

### Example Output

```bash
$ python3 main.py --scan-only ~/my-project

📊 Scan Results
   Target: /home/user/my-project
   Files scanned: 142
   🔴 Critical: 3
   🟡 Moderate: 5
   🟢 Low: 2
   Total: 10

🔴 [CRITICAL ] RSA      | src/auth.py:47
           rsa.generate_private_key(key_size=2048)
🔴 [CRITICAL ] X25519   | src/kem.py:23
           private_key = x25519.X25519PrivateKey.generate()
🟡 [MODERATE] AES-128  | src/encrypt.py:15
           cipher = AES.new(key, AES.MODE_GCM)
⚛️  Quantum Risk Assessment:
  🔴 CRITICAL: 3 — Must migrate immediately
    • RSA-2048: Completely broken by Shor's algorithm
    • X25519: Completely broken by Shor's algorithm
    • ECDSA-P256: Completely broken by Shor's algorithm
```

---

## 📚 References

### Quantum Computing Impact
- **Shor, P.W.** (1994). "Algorithms for quantum computation: discrete logarithms and factoring." *FOCS 1994.*
- **Grover, L.K.** (1996). "A fast quantum mechanical algorithm for database search." *STOC 1996.*

### Standardization
- **NIST IR 8413** — Status Report on the Third Round of the PQC Standardization Process
- **NIST FIPS 203** — CRYSTALS-Kyber (Module-Lattice-Based Key Encapsulation Mechanism)
- **NIST FIPS 204** — CRYSTALS-Dilithium (Module-Lattice-Based Digital Signature Standard)
- **NIST FIPS 205** — SPHINCS+ (Stateless Hash-Based Digital Signature Standard)

### Side-Channel Analysis
- **Kocher, P.** (1996). "Timing Attacks on Implementations of Diffie-Hellman, RSA, DSS, and Other Systems." *CRYPTO 1996.*
- **PQ-HINTS (Radboud University)** — Modeling PQC algorithm vulnerability to physical attacks

### Netherlands Research Groups
- [Radboud DiS — PQ-HINTS](https://dis.cs.ru.nl/Research/Projects/PQ-HINTS)
- [TU Delft Cybersecurity](https://www.tudelft.nl/en/cybersecurity)
- [VU Amsterdam Computer Science](https://www.cs.vu.nl/)
- [UvA QuSoft](https://qusoft.org/)
- [TU Eindhoven Security Group](https://www.tue.nl/en/research/research-groups/security)

---

## 👤 About

**Researcher:** Enish Shah  
**Background:** MSc Cybersecurity, University of West London  
**Thesis:** Quantum Computing + Cybersecurity  
**Goal:** PhD position in Netherlands cybersecurity research  

This project demonstrates:
- Deep understanding of post-quantum cryptography and quantum algorithms
- Practical implementation skills (Python, regex, AST analysis, statistical methods)
- Research-oriented thinking — connecting problems to specific academic groups
- Side-channel security awareness (constant-time coding, timing attacks)

---

## 📄 License

This project is for academic demonstration purposes as part of PhD applications.
Research references and algorithm impact data are from publicly available NIST documents and academic publications.
