"""
Supply Chain Attack Mitigation — Dependency Vulnerability Audit
===============================================================
Demonstrates automated dependency scanning for known vulnerabilities,
version pinning best practices, and supply chain integrity checks.

In production, use: pip-audit, safety, Dependabot, Snyk, or OWASP Dependency-Check
"""

import re
import hashlib
import json


# ---------------------------------------------------------------------------
# Simulated vulnerability database (subset of real CVEs for illustration)
# ---------------------------------------------------------------------------

VULN_DATABASE = {
    "numpy": [
        {
            "id": "CVE-2021-34141",
            "affected_versions": ["<1.22.0"],
            "severity": "HIGH",
            "description": "Incomplete string comparison in numpy.core.multiarray"
        }
    ],
    "pillow": [
        {
            "id": "CVE-2023-44271",
            "affected_versions": ["<10.0.1"],
            "severity": "HIGH",
            "description": "Uncontrolled resource consumption in PIL.ImageFont"
        },
        {
            "id": "CVE-2021-25293",
            "affected_versions": ["<8.1.1"],
            "severity": "CRITICAL",
            "description": "Out-of-bounds read in SGI RLE image parser"
        }
    ],
    "transformers": [
        {
            "id": "CVE-2023-7018",
            "affected_versions": ["<4.36.0"],
            "severity": "HIGH",
            "description": "Arbitrary code execution via deserialization in from_pretrained()"
        }
    ],
    "pytorch": [
        {
            "id": "CVE-2022-45907",
            "affected_versions": ["<1.13.1"],
            "severity": "CRITICAL",
            "description": "Remote code execution via torch.load() (pickle deserialization)"
        }
    ],
    "requests": [
        {
            "id": "CVE-2023-32681",
            "affected_versions": ["<2.31.0"],
            "severity": "MEDIUM",
            "description": "Proxy-Authorization header leaked to third-party sites"
        }
    ],
    "cryptography": [
        {
            "id": "CVE-2023-49083",
            "affected_versions": ["<41.0.6"],
            "severity": "MEDIUM",
            "description": "NULL pointer dereference in PKCS12 parsing"
        }
    ],
}


# ---------------------------------------------------------------------------
# Version parsing and comparison
# ---------------------------------------------------------------------------

def parse_version(version_str: str) -> tuple:
    """Parse version string into comparable tuple."""
    version_str = re.sub(r'[^0-9.]', '', version_str)
    parts = version_str.split('.')
    result = []
    for p in parts[:4]:
        try:
            result.append(int(p))
        except ValueError:
            result.append(0)
    while len(result) < 4:
        result.append(0)
    return tuple(result)


def is_version_affected(installed_version: str, constraint: str) -> bool:
    """
    Check if installed_version satisfies the vulnerability constraint.
    Supports: <X.Y.Z, <=X.Y.Z, >X.Y.Z, >=X.Y.Z, ==X.Y.Z
    """
    installed = parse_version(installed_version)
    m = re.match(r'([<>]=?|==)([\d.]+)', constraint.strip())
    if not m:
        return False

    op, ver_str = m.group(1), m.group(2)
    constrained = parse_version(ver_str)

    ops = {
        '<':  installed < constrained,
        '<=': installed <= constrained,
        '>':  installed > constrained,
        '>=': installed >= constrained,
        '==': installed == constrained,
    }
    return ops.get(op, False)


def check_vulnerabilities(package: str, version: str) -> list:
    """Check if a specific package version has known vulnerabilities."""
    if package.lower() not in VULN_DATABASE:
        return []

    findings = []
    for vuln in VULN_DATABASE[package.lower()]:
        for constraint in vuln["affected_versions"]:
            if is_version_affected(version, constraint):
                findings.append({
                    "package": package,
                    "version": version,
                    "cve": vuln["id"],
                    "severity": vuln["severity"],
                    "description": vuln["description"],
                    "affected_constraint": constraint,
                })
                break

    return findings


# ---------------------------------------------------------------------------
# Requirements.txt parser and auditor
# ---------------------------------------------------------------------------

def parse_requirements(requirements_text: str) -> list:
    """Parse requirements.txt content into (package, version) tuples."""
    packages = []
    for line in requirements_text.strip().split('\n'):
        line = line.strip()
        if not line or line.startswith('#') or line.startswith('-'):
            continue

        # Handle common formats: package==1.0.0, package>=1.0.0, package
        m = re.match(r'^([A-Za-z0-9_.-]+)\s*([>=<!]=?\s*[\d.]+)?', line)
        if m:
            name = m.group(1).lower()
            version_spec = m.group(2)
            if version_spec:
                ver_m = re.search(r'[\d.]+', version_spec)
                version = ver_m.group(0) if ver_m else "0.0.0"
            else:
                version = None  # Unpinned
            packages.append({"name": name, "version": version, "original": line})

    return packages


def audit_requirements(requirements_text: str) -> dict:
    """
    Full vulnerability audit of a requirements.txt.

    Returns structured report with vulnerabilities and recommendations.
    """
    packages = parse_requirements(requirements_text)
    report = {
        "total_packages": len(packages),
        "unpinned": [],
        "vulnerabilities": [],
        "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
    }

    for pkg in packages:
        # Flag unpinned dependencies
        if pkg["version"] is None:
            report["unpinned"].append(pkg["name"])
            continue

        # Check vulnerabilities
        vulns = check_vulnerabilities(pkg["name"], pkg["version"])
        for v in vulns:
            report["vulnerabilities"].append(v)
            severity = v["severity"]
            if severity in report["severity_counts"]:
                report["severity_counts"][severity] += 1

    report["is_clean"] = len(report["vulnerabilities"]) == 0
    return report


# ---------------------------------------------------------------------------
# Hash pinning for requirements.txt
# ---------------------------------------------------------------------------

def generate_pinned_requirements(packages: list) -> str:
    """
    Generate a requirements.txt with hash pinning.
    In production: use `pip download` + `pip hash` to get real hashes.
    """
    lines = ["# Requirements with hash pinning for supply chain security"]
    lines.append("# Generated with: pip-compile --generate-hashes")
    lines.append("# Verify with:    pip install --require-hashes -r requirements.txt")
    lines.append("")

    for pkg in packages:
        name = pkg.get("name", "unknown")
        version = pkg.get("version", "0.0.0")
        # Simulate hash (in production: use real wheel hash from PyPI)
        fake_hash = hashlib.sha256(f"{name}=={version}".encode()).hexdigest()
        lines.append(f"{name}=={version} \\")
        lines.append(f"    --hash=sha256:{fake_hash}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    sample_requirements = """
# AI/ML project dependencies
numpy==1.21.0
pillow==9.0.0
transformers==4.30.0
torch==1.12.0
requests==2.28.0
cryptography==38.0.0
pandas
scikit-learn>=1.0.0
matplotlib
"""

    print("Dependency Vulnerability Audit Demo")
    print("=" * 60)

    report = audit_requirements(sample_requirements)

    print(f"\nTotal packages: {report['total_packages']}")
    print(f"Unpinned packages: {report['unpinned']}")
    print(f"Vulnerabilities found: {len(report['vulnerabilities'])}")
    print(f"Severity: {report['severity_counts']}")

    if report["vulnerabilities"]:
        print("\n--- Vulnerability Details ---")
        for v in report["vulnerabilities"]:
            print(f"\n  [{v['severity']}] {v['package']}=={v['version']}")
            print(f"    CVE: {v['cve']}")
            print(f"    Constraint: version {v['affected_constraint']}")
            print(f"    Description: {v['description']}")

    if report["unpinned"]:
        print(f"\n[WARNING] Unpinned packages (security risk): {report['unpinned']}")
        print("  Unpinned packages may be silently updated to malicious versions.")

    print("\n--- Hash-Pinned Requirements (first 2 packages) ---")
    packages = parse_requirements(sample_requirements)[:2]
    pinned = generate_pinned_requirements(packages)
    print(pinned)

    print("\n[Recommendations]")
    print("1. Run: pip-audit --requirement requirements.txt")
    print("2. Run: safety check -r requirements.txt")
    print("3. Pin ALL packages with exact versions")
    print("4. Add hash pinning: pip install --require-hashes")
    print("5. Enable Dependabot / Renovate for automated updates")
    print("6. Scan with Snyk or OWASP Dependency-Check in CI/CD")
