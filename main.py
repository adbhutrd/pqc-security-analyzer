#!/usr/bin/env python3
"""
⚛️  PQC Security Analyzer — Post-Quantum Cryptography Migration Readiness Tool
=================================================================================
A comprehensive analysis tool that:
  1. Scans codebases for classical cryptographic algorithm usage (RSA, ECC, DH, DSA)
  2. Assesses quantum computing impact using established quantum algorithm research
  3. Tests PQC implementations for timing side-channel vulnerabilities
  4. Generates professional research-grade reports (HTML + Markdown)

Built as part of PhD research preparation in the Netherlands cybersecurity ecosystem.
Targets problems actively researched at Radboud (PQ-HINTS), TU Delft, VU Amsterdam, UvA.

Usage:
    python3 main.py <target_directory> [output_directory]
    
Examples:
    python3 main.py .                          # Scan current directory
    python3 main.py /path/to/project ./reports # Save reports to ./reports/
    python3 main.py --scan-only .              # Crypto scan only (no timing tests)
    python3 main.py --timing-only              # Timing analysis only
"""

import sys
import os
from pathlib import Path

# Handle both direct script execution and module import
try:
    from .crypto_scanner import CryptoScanner, format_finding
    from .quantum_risk import RiskAssessor, format_assessment
    from .sidechannel_test import run_all_tests, format_results
    from .report_generator import scan_and_report
except ImportError:
    # Running as script — add parent dir to path
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from crypto_scanner import CryptoScanner, format_finding
    from quantum_risk import RiskAssessor, format_assessment
    from sidechannel_test import run_all_tests, format_results
    from report_generator import scan_and_report


def run_scan(target_path: str):
    """Run crypto scanning only."""
    scanner = CryptoScanner(target_path, verbose=True)
    result = scanner.scan()

    print(f"\n📊 Scan Results")
    print(f"   Target: {target_path}")
    print(f"   Files scanned: {result.files_scanned}")
    print(f"   🔴 Critical: {result.critical_count}")
    print(f"   🟡 Moderate: {result.moderate_count}")
    print(f"   🟢 Low: {result.low_count}")
    print(f"   Total: {len(result.findings)}\n")

    if result.findings:
        for f in result.findings:
            print(format_finding(f))
            print()

    # Quantum risk assessment
    print("\n⚛️  Quantum Risk Assessment:\n")
    assessor = RiskAssessor()
    for f in result.findings:
        assessor.assess(f.algorithm)
    print(format_assessment(assessor))

    return result


def run_timing():
    """Run timing analysis only."""
    print("\n⏱️  Side-Channel Timing Analysis:\n")
    results = run_all_tests()
    print(f"\n{format_results(results)}")
    return results


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print(__doc__)
        return

    target = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else None

    if target == "--scan-only":
        target = sys.argv[2] if len(sys.argv) > 2 else "."
        run_scan(target)
    elif target == "--timing-only":
        run_timing()
    elif target == "--self-test":
        # Scan this project as a demo
        run_scan(".")
        print("\n" + "=" * 60)
        run_timing()
    else:
        # Full analysis
        out = Path(output_dir) if output_dir else Path(target) / "pqc_reports"
        out.mkdir(parents=True, exist_ok=True)
        scan_and_report(target, out)


if __name__ == "__main__":
    main()
