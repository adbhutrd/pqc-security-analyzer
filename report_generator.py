"""
📊 Report Generator — Produces professional research-grade analysis reports
===========================================================================
Generates HTML and Markdown reports that document the PQC migration analysis
for sharing with professors and including in PhD applications.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import List, Optional

# Handle both direct script execution and module import
try:
    from .crypto_scanner import CryptoFinding, ScanResult
    from .quantum_risk import RiskAssessor, format_assessment, estimate_migration_urgency
    from .sidechannel_test import TimingResult, format_results
except ImportError:
    import sys, os
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from crypto_scanner import CryptoFinding, ScanResult
    from quantum_risk import RiskAssessor, format_assessment, estimate_migration_urgency
    from sidechannel_test import TimingResult, format_results


REPORT_CSS = """
<style>
    :root {
        --bg: #0d1117;
        --card: #161b22;
        --border: #30363d;
        --text: #e6edf3;
        --text-muted: #8b949e;
        --accent: #7c3aed;
        --green: #2ea043;
        --red: #da3633;
        --yellow: #d29922;
        --orange: #d4760a;
    }
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        background: var(--bg);
        color: var(--text);
        line-height: 1.6;
        padding: 40px 20px;
        max-width: 960px;
        margin: 0 auto;
    }
    h1 { font-size: 2.2em; color: white; margin-bottom: 10px; }
    h2 { font-size: 1.5em; color: white; margin: 30px 0 15px; border-bottom: 2px solid var(--accent); padding-bottom: 8px; }
    h3 { font-size: 1.1em; color: var(--text); margin: 20px 0 10px; }
    .header {
        text-align: center;
        padding: 40px;
        background: linear-gradient(135deg, #1a1a2e, #16213e);
        border-radius: 16px;
        border: 1px solid var(--border);
        margin-bottom: 30px;
    }
    .header h1 { background: linear-gradient(135deg, #7c3aed, #a855f7); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
    .header .subtitle { color: var(--text-muted); font-size: 1.1em; margin-top: 10px; }
    .badge {
        display: inline-block;
        padding: 4px 12px;
        border-radius: 20px;
        font-size: 12px;
        font-weight: 600;
        margin: 0 4px;
    }
    .badge-critical { background: rgba(218, 54, 51, 0.15); color: var(--red); border: 1px solid rgba(218, 54, 51, 0.3); }
    .badge-high { background: rgba(212, 118, 10, 0.15); color: var(--orange); border: 1px solid rgba(212, 118, 10, 0.3); }
    .badge-moderate { background: rgba(210, 153, 34, 0.15); color: var(--yellow); border: 1px solid rgba(210, 153, 34, 0.3); }
    .badge-low { background: rgba(46, 160, 67, 0.15); color: var(--green); border: 1px solid rgba(46, 160, 67, 0.3); }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }
    .stat-card {
        background: var(--card);
        border: 1px solid var(--border);
        border-radius: 12px;
        padding: 20px;
        text-align: center;
    }
    .stat-card .number { font-size: 2em; font-weight: 700; color: white; }
    .stat-card .label { color: var(--text-muted); font-size: 0.85em; margin-top: 4px; }
    .finding {
        background: var(--card);
        border: 1px solid var(--border);
        border-radius: 8px;
        padding: 15px;
        margin: 10px 0;
    }
    .finding .algo { font-weight: 600; color: white; }
    .finding .location { color: var(--text-muted); font-size: 0.9em; }
    .finding .code { font-family: 'Courier New', monospace; font-size: 0.85em; background: rgba(0,0,0,0.3); padding: 8px; border-radius: 4px; margin-top: 8px; overflow-x: auto; }
    table { width: 100%; border-collapse: collapse; margin: 15px 0; }
    th { text-align: left; padding: 10px 12px; border-bottom: 2px solid var(--border); color: var(--text-muted); font-weight: 600; font-size: 0.85em; text-transform: uppercase; letter-spacing: 0.05em; }
    td { padding: 10px 12px; border-bottom: 1px solid var(--border); }
    .footer { text-align: center; color: var(--text-muted); font-size: 0.85em; margin-top: 40px; padding-top: 20px; border-top: 1px solid var(--border); }
    .section { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 25px; margin: 20px 0; }
    em { color: var(--accent); }
</style>
"""


def generate_html_report(
    scan_result: ScanResult,
    risk_assessment: str,
    timing_results: List[TimingResult],
    timing_report: str,
    target_path: str,
    output_path: Optional[Path] = None,
) -> str:
    """Generate a professional HTML report of all findings."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M")

    # Build findings table rows
    finding_rows = ""
    for f in scan_result.findings:
        risk_class = f"badge-{f.risk.lower()}" if f.risk in ("CRITICAL", "HIGH", "MODERATE", "LOW") else ""
        finding_rows += f"""
        <tr>
            <td><span class="badge {risk_class}">{f.risk}</span></td>
            <td><strong>{f.algorithm}</strong></td>
            <td>{f.file_path}:{f.line_number}</td>
            <td><code>{f.line_content[:80]}</code></td>
            <td style="font-size:0.9em">{f.migration_target[:50]}...</td>
        </tr>"""

    # Timing results
    timing_rows = ""
    for r in timing_results:
        verdict_emoji = "✅" if r.is_constant_time else ("❌" if r.is_constant_time is False else "⚠️")
        timing_rows += f"""
        <tr>
            <td>{verdict_emoji}</td>
            <td>{r.operation_name}</td>
            <td>{r.mean_time_ns:,.0f}</td>
            <td>{r.std_dev_ns:,.0f}</td>
            <td>{r.variance_coefficient:.4f}</td>
            <td>{'✅ Constant' if r.is_constant_time else ('❌ Leaks!' if r.is_constant_time is False else '⚠️ Inconclusive')}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PQC Security Analysis Report</title>
    {REPORT_CSS}
</head>
<body>

<div class="header">
    <h1>⚛️ PQC Security Analysis Report</h1>
    <p class="subtitle">Post-Quantum Cryptography Migration Readiness Assessment</p>
    <p style="color: var(--text-muted); margin-top: 15px;">
        Target: <code>{target_path}</code> &bull; Generated: {now}
    </p>
</div>

<!-- Executive Summary -->
<div class="section">
    <h2>📋 Executive Summary</h2>
    <div class="grid">
        <div class="stat-card">
            <div class="number" style="color: var(--red)">{scan_result.critical_count}</div>
            <div class="label">Critical Findings</div>
        </div>
        <div class="stat-card">
            <div class="number" style="color: var(--yellow)">{scan_result.moderate_count}</div>
            <div class="label">Moderate Findings</div>
        </div>
        <div class="stat-card">
            <div class="number" style="color: var(--green)">{scan_result.low_count}</div>
            <div class="label">Low Risk</div>
        </div>
        <div class="stat-card">
            <div class="number">{scan_result.files_scanned}</div>
            <div class="label">Files Scanned</div>
        </div>
    </div>
    <p style="margin-top: 15px;">
        This report analyzes the codebase for cryptographic algorithm usage and assesses
        the impact of large-scale quantum computing on security. Asymmetric cryptography
        (RSA, ECC, Diffie-Hellman) is <strong>completely broken</strong> by Shor's algorithm,
        while symmetric cryptography (AES) needs key size increases against Grover's algorithm.
    </p>
</div>

<!-- Research Context -->
<div class="section">
    <h2>🎯 Research Context</h2>
    <p>This tool was built as part of PhD research preparation in the Netherlands cybersecurity ecosystem. It addresses problems being actively researched at:</p>
    <ul style="margin: 15px 0; padding-left: 20px;">
        <li><strong>Radboud University (DiS):</strong> PQ-HINTS project — modeling PQC implementation vulnerabilities against side-channel attacks</li>
        <li><strong>TU Delft (Cybersecurity):</strong> Post-quantum cryptography migration strategies and network security</li>
        <li><strong>VU Amsterdam (VUSec):</strong> Formal verification of security protocols, including post-quantum protocols</li>
        <li><strong>UvA / QuSoft:</strong> Quantum network protocols and quantum-safe communication</li>
        <li><strong>TU Eindhoven:</strong> €21.5M CiCS program — PQC formal verification and threat intelligence</li>
    </ul>
    <p style="color: var(--text-muted); font-size: 0.9em;">
        Reference: NIST IR 8413, ETSI TR 103 619, PQ-HINTS (Radboud)
    </p>
</div>

<!-- Crypto Scanner Results -->
<div class="section">
    <h2>🔍 Cryptography Scanner Results</h2>
    <p>Found {len(scan_result.findings)} instances of cryptographic algorithm usage across {scan_result.files_scanned} files.</p>
    <table>
        <thead>
            <tr><th>Risk</th><th>Algorithm</th><th>Location</th><th>Context</th><th>Migration</th></tr>
        </thead>
        <tbody>
            {finding_rows}
        </tbody>
    </table>
</div>

<!-- Side-Channel Timing Analysis -->
<div class="section">
    <h2>⏱️  Side-Channel Timing Analysis</h2>
    <p>Tests cryptographic operations for secret-dependent timing variations — the most common side-channel vulnerability.</p>
    <table>
        <thead>
            <tr><th></th><th>Operation</th><th>Mean (ns)</th><th>StdDev (ns)</th><th>CV</th><th>Verdict</th></tr>
        </thead>
        <tbody>
            {timing_rows}
        </tbody>
    </table>
</div>

<!-- Footer -->
<div class="footer">
    <p>PQC Security Analyzer — Built for PhD research in Netherlands Cybersecurity</p>
    <p style="margin-top: 5px;">Researcher: Adbhut Ram Das &bull; MSc Cybersecurity, University of West London</p>
</div>

</body>
</html>"""

    if output_path:
        output_path.write_text(html)
        print(f"  📄 Report saved: {output_path}")

    return html


def generate_markdown_report(
    target_path: str,
    scan_result: ScanResult,
    risk_text: str,
    timing_text: str,
    output_path: Optional[Path] = None,
) -> str:
    """Generate a Markdown version of the analysis report."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M")

    lines = [
        "# ⚛️ PQC Security Analysis Report",
        f"**Target:** `{target_path}`  ",
        f"**Generated:** {now}  ",
        "",
        "## 📋 Executive Summary",
        "",
        f"| Metric | Count |",
        f"|--------|-------|",
        f"| 🔴 Critical | {scan_result.critical_count} |",
        f"| 🟡 Moderate | {scan_result.moderate_count} |",
        f"| 🟢 Low | {scan_result.low_count} |",
        f"| Files Scanned | {scan_result.files_scanned} |",
        f"| Total Findings | {len(scan_result.findings)} |",
        "",
        "## 🎯 Research Context",
        "",
        "This analysis was conducted as part of PhD research preparation targeting the",
        "Netherlands cybersecurity ecosystem. The problems addressed match active research at:",
        "",
        "- **Radboud University (DiS):** PQ-HINTS project — PQC side-channel vulnerability modeling",
        "- **TU Delft (Cybersecurity):** Post-quantum cryptographic migration strategies",
        "- **VU Amsterdam:** Formal methods for concurrent cryptographic protocols",
        "- **UvA / QuSoft:** Quantum network protocol security",
        "",
        "## 🔍 Cryptography Scanner Findings",
        "",
    ]

    if scan_result.findings:
        lines.append("| Risk | Algorithm | Location | Line |")
        lines.append("|------|-----------|----------|------|")
        for f in scan_result.findings:
            lines.append(f"| {f.risk} | {f.algorithm} | {f.file_path} | {f.line_number} |")

    lines.append("")
    lines.append("## ⚛️  Quantum Risk Assessment")
    lines.append("")
    lines.append("```")
    lines.append(risk_text)
    lines.append("```")
    lines.append("")
    lines.append("## ⏱️  Side-Channel Timing Analysis")
    lines.append("")
    lines.append("```")
    lines.append(timing_text)
    lines.append("```")
    lines.append("")
    lines.append("---")
    lines.append("*Generated by PQC Security Analyzer — PhD research project*")
    lines.append(f"*Researcher: Adbhut Ram Das, MSc Cybersecurity, University of West London*")

    md = "\n".join(lines)

    if output_path:
        output_path.write_text(md)
        print(f"  📄 Report saved: {output_path}")

    return md


def scan_and_report(target_path: str, output_dir: Optional[Path] = None) -> dict:
    """Run full analysis and generate reports."""
    try:
        from .crypto_scanner import CryptoScanner
        from .sidechannel_test import run_all_tests
    except ImportError:
        import sys, os
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from crypto_scanner import CryptoScanner
        from sidechannel_test import run_all_tests

    print(f"\n{'='*60}")
    print(f"  ⚛️  PQC Security Analyzer")
    print(f"  Target: {target_path}")
    print(f"{'='*60}")

    # 1. Crypto scanning
    print(f"\n🔍 Phase 1: Scanning for classical cryptography...")
    scanner = CryptoScanner(target_path, verbose=True)
    scan_result = scanner.scan()
    print(f"  Found {len(scan_result.findings)} findings "
          f"({scan_result.critical_count} critical, "
          f"{scan_result.moderate_count} moderate, "
          f"{scan_result.low_count} low)")

    # 2. Quantum risk assessment
    print(f"\n⚛️  Phase 2: Quantum risk assessment...")
    assessor = RiskAssessor()
    for f in scan_result.findings:
        assessor.assess(f.algorithm)
    risk_text = format_assessment(assessor)

    # 3. Side-channel timing tests
    print(f"\n⏱️  Phase 3: Timing side-channel analysis...")
    timing_results = run_all_tests()
    timing_text = format_results(timing_results)

    # 4. Generate reports
    print(f"\n📊 Phase 4: Generating reports...")
    if output_dir is None:
        output_dir = Path(".")

    html_path = output_dir / "pqc_analysis_report.html"
    md_path = output_dir / "pqc_analysis_report.md"

    generate_html_report(
        scan_result, risk_text, timing_results, timing_text,
        target_path, html_path
    )
    generate_markdown_report(
        target_path, scan_result, risk_text, timing_text, md_path
    )

    print(f"\n✅ Analysis complete!")
    print(f"   📄 HTML report: {html_path}")
    print(f"   📄 Markdown:    {md_path}")
    print()

    return {
        "scan_result": scan_result,
        "risk_text": risk_text,
        "timing_text": timing_text,
        "html_path": html_path,
        "md_path": md_path,
    }
