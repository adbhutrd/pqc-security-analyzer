# ⚛️ PQC Security Analyzer

**Post-Quantum Cryptography Migration Readiness Assessment Tool**

A comprehensive research toolkit that scans codebases for classical cryptographic algorithm usage, assesses quantum computing impact using established quantum algorithm theory, tests PQC implementations for timing side-channel vulnerabilities, and generates professional research-grade reports.

**Built for PhD research preparation in the Netherlands cybersecurity ecosystem.**

---

## 📋 Table of Contents

- [🎯 Research Motivation](#-research-motivation)
- [🔬 Research Questions](#-research-questions)
- [🏗️ Project Architecture](#️-project-architecture)
- [📊 Results & Findings](#-results--findings)
- [🚀 Quick Start](#-quick-start)
- [📚 References](#-references)
- [👤 About](#-about)
- [📄 License](#-license)

---

## 🎯 Research Motivation

### The Problem

> *"Companies don't know where their classical cryptography is buried — no tools exist to map 'cryptographic debt' before quantum computers break everything."*

Large-scale quantum computers running **Shor's algorithm** (1994) will completely break:
- **RSA** (all key sizes) — factoring in polynomial time
- **Elliptic Curve Cryptography** (ECDSA, ECDH, Ed25519, X25519) — ECDLP solved in polynomial time
- **DSA** and **Diffie-Hellman** — DLP solved in polynomial time

**Grover's algorithm** (1996) halves the effective security of symmetric primitives:
- AES-128 → 64-bit effective security (below safe threshold)
- SHA-256 → 64-bit collision resistance

NIST has standardized replacement algorithms (CRYSTALS-Kyber for KEM, CRYSTALS-Dilithium for signatures), but **migration is complex** and **implementations can leak secrets through side-channels**.

### Why This Matters for PhD Research

This project directly addresses problems being **actively researched at multiple Dutch universities**:

| University | Research Group | Project Alignment |
|-----------|---------------|-------------------|
| **Radboud University** | Digital Security (DiS) | [PQ-HINTS](https://dis.cs.ru.nl/) — Modeling PQC implementation vulnerability to side-channel attacks |
| **TU Delft** | Cybersecurity (CYS) | Post-quantum cryptography migration strategies in real-world networks |
| **VU Amsterdam** | Computer Science | [Open PhD: Formal Methods for Concurrent Cryptographic Protocols](https://workingat.vu.nl/) |
| **UvA / QuSoft** | Quantum Software | Quantum network protocol verification and quantum-safe communication |
| **TU Eindhoven** | Security Group | €21.5M CiCS program — PQC formal verification and threat intelligence |

---

## 🔬 Research Questions

This tool was built to investigate the following research questions:

1. **Scanner Question:** How prevalent is classical (quantum-vulnerable) cryptography in real-world open-source codebases? What is the distribution of RSA vs ECC vs symmetric crypto usage?

2. **Risk Question:** Given NIST PQC standardization (FIPS 203-205), what is the migration urgency for each algorithm class? Which algorithms face "harvest-now, decrypt-later" risk?

3. **Side-Channel Question:** Do current PQC reference implementations exhibit measurable timing variations that could enable side-channel attacks at the network level?

4. **Migration Question:** What automated tooling can help organizations map their "cryptographic debt" and prioritize migration paths?

---

## 🏗️ Project Architecture

```
pqc-analyzer/
├── main.py                 ← CLI entry point
├── crypto_scanner.py       ← Phase 1: Scans code for classical crypto usage (RSA, ECC, DH, DSA)
├── quantum_risk.py         ← Phase 2: Assesses quantum impact with NIST-referenced severity levels
├── sidechannel_test.py     ← Phase 3: Tests PQC implementations for timing side-channel leaks
├── report_generator.py     ← Phase 4: Generates HTML + Markdown research reports
├── requirements.txt        ← Zero external dependencies (stdlib only)
├── pyproject.toml          ← Package configuration
├── outreach/               ← Professor outreach templates (Radboud, UvA, VU, TU/e)
│   ├── 01_christian_schaffner_uva.md
│   ├── 02_tanja_lange_tue.md
│   ├── 03_vu_amsterdam_crypto.md
│   └── 04_radboud_dis_group.md
└── reports/                ← Generated analysis reports
```

### Research Methodology (4 Phases)

```
┌─────────────────────────────────────────────────────────────────┐
│  Phase 1: Crypto Scanner                                        │
│  Input:  Source code repository                                 │
│  Method: Regex + AST pattern matching across 8+ algorithm       │
│          categories with false-positive filtering                │
│  Output: File:line findings with algorithm class & risk level    │
└─────────────────────────────────────────────────────────────────┘
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│  Phase 2: Quantum Risk Assessment                               │
│  Input:  Algorithm findings from Phase 1                        │
│  Method: Database of 35+ algorithms with quantum security       │
│          levels based on Shor (1994) & Grover (1996)            │
│  Output: Severity-classified risk report + migration timeline   │
└─────────────────────────────────────────────────────────────────┘
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│  Phase 3: Side-Channel Timing Analysis                          │
│  Input:  Cryptographic implementations                          │
│  Method: High-resolution timing (perf_counter_ns) with          │
│          statistical analysis (mean, stddev, CV)                │
│  Output: Constant-time vs variable-time verdict per operation   │
└─────────────────────────────────────────────────────────────────┘
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│  Phase 4: Report Generation                                     │
│  Input:  All findings from Phases 1-3                          │
│  Method: HTML + Markdown template rendering                     │
│  Output: Professional research report with executive summary    │
└─────────────────────────────────────────────────────────────────┘
```

### Module Details

**1. Crypto Scanner** (`crypto_scanner.py`)
- Detects 8+ classical algorithm categories via regex + AST analysis
- Algorithms covered: RSA, ECC/ECDSA/ECDH, DSA, Diffie-Hellman, AES, SHA-1, SHA-2, HMAC
- Returns file:line locations with algorithm name and risk level
- Skips binaries, vendored deps, and false positives from negative comments
- Scans: `.py`, `.js`, `.ts`, `.java`, `.go`, `.rs`, `.c`, `.cpp`, `.php`, `.rb`, `.kt`, and more

**2. Quantum Risk Assessment** (`quantum_risk.py`)
- Database of 35+ algorithms with quantum security levels mapped from NIST IR 8413
- Classifies into: CRITICAL (broken by Shor), HIGH (halved by Grover), MODERATE, LOW
- Covers: asymmetric crypto, symmetric ciphers, hash functions, signatures, KEMs
- Provides migration recommendations to NIST PQC standards (FIPS 203-205)
- Estimates migration urgency timeline (0-3 years, 5-10 years, etc.)

**3. Side-Channel Timing Analyzer** (`sidechannel_test.py`)
- High-resolution timing analysis using `perf_counter_ns`
- Statistical analysis: mean, median, stddev, coefficient of variation (CV)
- Compares constant-time vs leaky reference implementations
- CV < 0.05 = likely constant-time; CV > 0.10 = likely leaking
- Tests: Kyber encaps, Dilithium sign, AES encrypt, memory comparison
- Research context: Radboud DiS PQ-HINTS project methodology

**4. Report Generator** (`report_generator.py`)
- Professional dark-themed HTML report with executive summary
- Markdown version for GitHub/gitlab/sharing
- All findings, risk assessments, and timing results in one document

---

## 📊 Results & Findings

### Demo: Scanning `pqc-analyzer` Codebase

When run against its own codebase (`python3 main.py --self-test`):

```
📊 Scan Results
   Target: .
   Files scanned: 6
   🔴 Critical: 98    (algorithm definitions referencing RSA, ECC, etc.)
   🟡 Moderate: 54    (AES, SHA-256 patterns in reference implementations)
   🟢 Low: 7          (quantum-safe references for comparison)
   Total: 159

⚛️  Quantum Risk Assessment:
  🔴 CRITICAL: RSA, ECC, DSA, DH — Completely broken by Shor's algorithm
     → Immediate migration to CRYSTALS-Kyber/Dilithium required
  🟡 MODERATE: AES-128, SHA-256 — Security halved by Grover's algorithm
     → Upgrade to AES-256, SHA-512 for post-quantum margin
  🟢 LOW: CRYSTALS-Kyber/Dilithium, AES-256 — Already quantum-resistant

⏱️  Side-Channel Timing Analysis:
  ✅ CRYSTALS-Kyber (constant-time ref) — CV=0.002, constant-time
  ❌ CRYSTALS-Kyber (LEAKY variant) — CV=0.281, NOT constant-time!
  ✅ CRYSTALS-Dilithium (constant-time ref) — CV=0.003, constant-time
  ❌ Memory Compare (variable-time) — CV=0.392, leaks position!
  ✅ Memory Compare (constant-time) — CV=0.001, constant-time
```

**Key insight:** The scanner correctly distinguishes between constant-time reference implementations (CV < 0.01) and leaky implementations (CV > 0.10). The variable-time memory comparison demonstrates how a single non-constant-time function can leak secret byte positions — the exact vulnerability exploited in real-world timing attacks (Kocher 1996, CloudFlare 2017).

### Real-World Usage

Run against any codebase:
```bash
python3 main.py /path/to/your/project ./reports
```

The tool generates a professional HTML report with:
- Executive summary with risk counts
- University research context
- Full crypto scanner findings table
- Side-channel timing analysis
- Migration recommendations

---

## 🚀 Quick Start

### Zero-Dependency Installation

```bash
# No pip install needed — uses only Python stdlib!
git clone https://github.com/adbhutrd/pqc-security-analyzer.git
cd pqc-security-analyzer

# Run full analysis on any project directory
python3 main.py /path/to/your/project

# Self-test (scan this project)
python3 main.py --self-test

# Scan only (no timing tests — faster)
python3 main.py --scan-only /path/to/project

# Timing analysis only
python3 main.py --timing-only
```

### Examples

```bash
# Full analysis with report generation
python3 main.py ~/my-project ./reports

# Quick scan of current directory
python3 main.py --scan-only .

# Timing side-channel tests only
python3 main.py --timing-only
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
  🔴 CRITICAL: RSA-2048, X25519, ECDSA-P256 — Broken by Shor
  🟡 MODERATE: AES-128 — Halved by Grover
  🟢 LOW: AES-256 — Quantum-safe

⏱️  Side-Channel Timing Analysis:
  ✅ Kyber constant-time ref — CV=0.002 (secure)
  ❌ Kyber LEAKY variant — CV=0.281 (vulnerable!)
```

### Generate HTML Report

```bash
# Full analysis saves to ./reports/
python3 main.py ~/my-project ./reports
open ./reports/pqc_analysis_report.html
```

---

## 📋 PhD Application Context

This project is part of my preparation for PhD applications in the Netherlands. Here's how it connects to my broader goals:

### What This Demonstrates

| Competency | Demonstrated By |
|-----------|----------------|
| **Quantum algorithm knowledge** | Risk assessment engine based on Shor (1994) and Grover (1996) |
| **NIST PQC standards literacy** | Migration recommendations referencing FIPS 203-205 |
| **Side-channel awareness** | Timing analysis methodology from Kocher (1996) through PQ-HINTS |
| **Practical engineering** | Working CLI tool with zero dependencies |
| **Research communication** | Professional reports + this README + outreach templates |
| **Academic networking** | Directly connected to 4 Dutch research groups with tailored emails |

### Outreach to Dutch Professors

I've prepared tailored outreach emails to professors at Dutch universities whose research aligns with this project:

| Professor | University | Research Area | Email |
|-----------|-----------|---------------|-------|
| **Christian Schaffner** | UvA / QuSoft | Quantum cryptography, quantum-safe protocols | [📧 Draft](outreach/01_christian_schaffner_uva.md) |
| **Tanja Lange** | TU Eindhoven | PQC, €21.5M CiCS programme | [📧 Draft](outreach/02_tanja_lange_tue.md) |
| **VU Amsterdam** | Vrije Universiteit | Formal methods for crypto protocols (Open PhD) | [📧 Draft](outreach/03_vu_amsterdam_crypto.md) |
| **DiS Group** | Radboud University | PQC side-channels (PQ-HINTS), applied security | [📧 Draft](outreach/04_radboud_dis_group.md) |

---

## 📚 References

### Foundational Papers
- **Shor, P.W.** (1994). "Algorithms for quantum computation: discrete logarithms and factoring." *FOCS 1994.*
- **Grover, L.K.** (1996). "A fast quantum mechanical algorithm for database search." *STOC 1996.*
- **Kocher, P.** (1996). "Timing Attacks on Implementations of Diffie-Hellman, RSA, DSS, and Other Systems." *CRYPTO 1996.*

### NIST Standards
- **NIST IR 8413** — Status Report on the Third Round of the PQC Standardization Process
- **NIST FIPS 203** — CRYSTALS-Kyber (Module-Lattice-Based Key Encapsulation Mechanism)
- **NIST FIPS 204** — CRYSTALS-Dilithium (Module-Lattice-Based Digital Signature Standard)
- **NIST FIPS 205** — SPHINCS+ (Stateless Hash-Based Digital Signature Standard)

### Industry Guidance
- **ETSI TR 103 619** — Migration Strategies and Recommendations for PQC
- **ENISA** — Post-Quantum Cryptography: Current state and quantum mitigation

### Netherlands Research Groups
- [Radboud DiS — PQ-HINTS](https://dis.cs.ru.nl/Research/Projects/PQ-HINTS)
- [TU Delft Cybersecurity](https://www.tudelft.nl/en/cybersecurity)
- [VU Amsterdam Computer Science](https://www.cs.vu.nl/)
- [UvA QuSoft](https://qusoft.org/)
- [TU Eindhoven Security Group](https://www.tue.nl/en/research/research-groups/security)

---

## 👤 About

**Researcher:** Enish Shah
**Background:** MSc Cybersecurity (Distinction), University of West London
**Thesis:** Mixed Quantum Computing and Cybersecurity: Post-Quantum Cryptography Readiness
**Goal:** PhD position in Netherlands cybersecurity research

This project demonstrates:
- **Deep understanding** of post-quantum cryptography, quantum algorithms, and NIST standards
- **Practical implementation** skills (Python, regex, AST analysis, statistical timing analysis)
- **Research-oriented thinking** — connecting specific problems to active academic groups
- **Side-channel security** awareness (constant-time coding, timing attack detection)
- **Academic communication** — professional reports and professor outreach templates

---

## 📄 License

MIT License — This project is for academic demonstration purposes as part of PhD applications.
Research references and algorithm impact data are from publicly available NIST documents and academic publications.
