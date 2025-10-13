# PyGuard Supply Chain Security

Comprehensive guide to securing your software supply chain with PyGuard's dependency analysis and SBOM generation.

## Overview

PyGuard's supply chain security module provides:

- **Dependency Parsing**: Support for requirements.txt, pyproject.toml, Pipfile
- **SBOM Generation**: CycloneDX-compliant Software Bill of Materials
- **Vulnerability Checking**: Built-in database of known vulnerabilities
- **License Detection**: Identify dependencies with licensing issues
- **Risk Assessment**: Automated risk scoring for dependencies

## Standards Compliance

All supply chain features align with industry standards:

- **NIST SSDF**: Secure Software Development Framework (SP 800-218)
- **SLSA**: Supply-chain Levels for Software Artifacts
- **OWASP Dependency-Check**: Dependency vulnerability detection methodology
- **SBOM/CycloneDX**: OWASP standard for Software Bill of Materials
- **CISA SBOM**: US Government SBOM requirements

---

## Software Bill of Materials (SBOM)

### What is an SBOM?

A Software Bill of Materials (SBOM) is a comprehensive inventory of all components used in your software, including:

- Direct dependencies
- Transitive dependencies
- Version information
- License information
- Known vulnerabilities
- Supply chain metadata

### Why SBOMs Matter

1. **Transparency**: Know exactly what's in your software
2. **Security**: Quickly identify vulnerable components
3. **Compliance**: Meet regulatory requirements (EO 14028, CISA)
4. **Incident Response**: Rapid response to newly discovered vulnerabilities
5. **License Management**: Track open source license obligations

### PyGuard SBOM Features

✅ **CycloneDX Format**: Industry-standard SBOM format  
✅ **Automatic Generation**: Parse dependency files automatically  
✅ **Vulnerability Integration**: Include CVE information  
✅ **JSON Output**: Machine-readable format  
✅ **Human-Readable**: Easy to understand structure

---

## Dependency Parsing

### Supported Formats

PyGuard automatically detects and parses:

#### 1. requirements.txt

```txt
# Standard pip format
requests==2.31.0
flask>=2.0.0
django~=4.2.0
pytest  # Without version
```

**Supported Operators**: `==`, `>=`, `<=`, `>`, `<`, `~=`

#### 2. pyproject.toml

```toml
[project]
dependencies = [
    "requests>=2.31.0",
    "flask>=2.0.0",
    "django~=4.2.0"
]

[project.optional-dependencies]
dev = [
    "pytest>=7.0.0",
    "black>=23.0.0"
]
```

#### 3. Pipfile

```toml
[packages]
requests = "==2.31.0"
flask = ">=2.0.0"
django = "~=4.2.0"

[dev-packages]
pytest = "*"
black = ">=23.0.0"
```

### Usage

```python
from pathlib import Path
from pyguard.lib.supply_chain import DependencyParser

parser = DependencyParser()

# Parse requirements.txt
deps = parser.parse_requirements_txt(Path("requirements.txt"))

# Parse pyproject.toml
deps = parser.parse_pyproject_toml(Path("pyproject.toml"))

# Parse Pipfile
deps = parser.parse_pipfile(Path("Pipfile"))

for dep in deps:
    print(f"{dep.name} {dep.version}")
```

---

## Vulnerability Detection

### Built-in Vulnerability Database

PyGuard includes a curated database of known vulnerabilities for popular packages:

| Package | Vulnerable Versions | CVE | Severity |
|---------|-------------------|-----|----------|
| requests | < 2.20.0 | CVE-2018-18074 | HIGH |
| requests | < 2.31.0 | CVE-2023-32681 | CRITICAL |
| urllib3 | < 1.24.2 | CVE-2019-11324 | HIGH |
| urllib3 | < 1.26.5 | CVE-2021-33503 | MEDIUM |
| pyyaml | < 5.4 | CVE-2020-14343 | CRITICAL |
| flask | < 2.2.5 | CVE-2023-30861 | HIGH |
| django | < 3.2.18 | CVE-2023-24580 | CRITICAL |
| cryptography | < 3.3.2 | CVE-2020-36242 | MEDIUM |

### Vulnerability Checking

```python
from pyguard.lib.supply_chain import VulnerabilityChecker, Dependency

checker = VulnerabilityChecker()

# Check a dependency
dep = Dependency(name="requests", version="2.19.0", source="pypi")
updated_dep = checker.check_dependency(dep)

print(f"Risk Level: {updated_dep.risk_level}")
print(f"Vulnerabilities: {updated_dep.vulnerabilities}")
```

### Risk Assessment

PyGuard automatically assigns risk levels:

- **CRITICAL**: Recent CVEs, arbitrary code execution
- **HIGH**: Security vulnerabilities, data exposure
- **MEDIUM**: Older CVEs, limited impact
- **LOW**: Minor issues, informational
- **UNKNOWN**: No known vulnerabilities

### Risky Packages

PyGuard also flags inherently risky packages:

| Package | Risk | Reason |
|---------|------|--------|
| pickle5 | HIGH | Uses pickle (code execution) |
| exec | CRITICAL | Likely malicious naming |
| eval | CRITICAL | Dangerous function name |

---

## Generating SBOMs

### Command Line

```bash
# Generate SBOM for current project
pyguard sbom generate

# Specify output format
pyguard sbom generate --format cyclonedx --output sbom.json

# Include development dependencies
pyguard sbom generate --include-dev
```

### Python API

```python
from pathlib import Path
from pyguard.lib.supply_chain import SupplyChainAnalyzer

analyzer = SupplyChainAnalyzer()

# Analyze project
project_dir = Path(".")
sbom = analyzer.analyze_project(project_dir)

# View summary
print(f"Project: {sbom.project_name}")
print(f"Total Dependencies: {sbom.total_dependencies}")
print(f"Critical Vulnerabilities: {sbom.critical_vulnerabilities}")
print(f"High Vulnerabilities: {sbom.high_vulnerabilities}")

# Generate SBOM file
output_path = Path("sbom.json")
analyzer.generate_sbom_file(project_dir, output_path, format="cyclonedx")
```

### SBOM Output Example

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "version": 1,
  "metadata": {
    "timestamp": "2024-01-15T10:30:00",
    "component": {
      "type": "application",
      "name": "my-project",
      "version": "1.0.0"
    }
  },
  "components": [
    {
      "type": "library",
      "name": "requests",
      "version": "2.31.0",
      "purl": "pkg:pypi/requests@2.31.0",
      "hashes": [
        {
          "alg": "SHA-256",
          "content": "abc123..."
        }
      ],
      "licenses": [
        {
          "license": {
            "id": "Apache-2.0"
          }
        }
      ]
    }
  ]
}
```

---

## Security Scanning Workflow

### 1. Initial Scan

```python
from pathlib import Path
from pyguard.lib.supply_chain import SupplyChainAnalyzer

analyzer = SupplyChainAnalyzer()
sbom = analyzer.analyze_project(Path("."))

# Check for vulnerabilities
if sbom.critical_vulnerabilities > 0:
    print(f"🚨 {sbom.critical_vulnerabilities} CRITICAL vulnerabilities found!")
    
if sbom.high_vulnerabilities > 0:
    print(f"⚠️  {sbom.high_vulnerabilities} HIGH vulnerabilities found!")
```

### 2. Review Dependencies

```python
# List all dependencies with vulnerabilities
for dep in sbom.dependencies:
    if dep.vulnerabilities:
        print(f"\n{dep.name} {dep.version} - Risk: {dep.risk_level}")
        for vuln in dep.vulnerabilities:
            print(f"  • {vuln}")
```

### 3. Remediation

Update vulnerable packages:

```bash
# Update single package
pip install --upgrade requests

# Update all packages
pip install --upgrade -r requirements.txt

# Check for outdated packages
pip list --outdated
```

### 4. Continuous Monitoring

```python
import schedule
import time
from pyguard.lib.supply_chain import SupplyChainAnalyzer

def daily_scan():
    """Run daily security scan."""
    analyzer = SupplyChainAnalyzer()
    sbom = analyzer.analyze_project(Path("."))
    
    if sbom.critical_vulnerabilities > 0:
        send_alert(f"Critical vulnerabilities detected: {sbom.critical_vulnerabilities}")

# Schedule daily scans
schedule.every().day.at("09:00").do(daily_scan)

while True:
    schedule.run_pending()
    time.sleep(3600)
```

---

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]
  schedule:
    - cron: '0 9 * * *'  # Daily at 9 AM

jobs:
  security:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.13'
    
    - name: Install PyGuard
      run: pip install pyguard
    
    - name: Generate SBOM
      run: pyguard sbom generate --output sbom.json
    
    - name: Upload SBOM
      uses: actions/upload-artifact@v3
      with:
        name: sbom
        path: sbom.json
    
    - name: Security Scan
      run: pyguard scan --supply-chain --fail-on-critical
```

### GitLab CI

```yaml
security_scan:
  stage: security
  image: python:3.13
  
  script:
    - pip install pyguard
    - pyguard sbom generate --output sbom.json
    - pyguard scan --supply-chain --report json
  
  artifacts:
    paths:
      - sbom.json
      - security-report.json
    expire_in: 30 days
  
  only:
    - main
    - merge_requests
```

---

## Best Practices

### 1. Pin Dependencies

```txt
# ❌ Unpinned (risky)
requests
flask

# ⚠️ Minimum version (better)
requests>=2.31.0
flask>=2.0.0

# ✅ Exact version (best for production)
requests==2.31.0
flask==2.3.2
```

### 2. Regular Updates

- **Monthly**: Check for security updates
- **Quarterly**: Update all dependencies
- **Immediately**: Apply critical security patches

### 3. Minimal Dependencies

```python
# ❌ Too many dependencies
import pandas  # Heavy library
import numpy   # Just for one calculation

# ✅ Minimal dependencies
import statistics  # Standard library
```

### 4. Trusted Sources

Only install from trusted sources:

```bash
# ✅ Official PyPI
pip install requests

# ⚠️ Verify authenticity for GitHub
pip install git+https://github.com/trusted/repo.git@v1.0.0

# ❌ Avoid unknown sources
pip install mysterious-package
```

### 5. SBOM Version Control

Track SBOMs in version control:

```bash
# Generate SBOM
pyguard sbom generate --output sbom.json

# Commit to repository
git add sbom.json
git commit -m "Update SBOM for release v1.2.0"
```

---

## Compliance & Regulatory

### US Executive Order 14028

Requires SBOMs for software sold to US Government:

✅ PyGuard generates compliant SBOMs  
✅ Includes vulnerability information  
✅ Machine-readable format (CycloneDX)  
✅ Automated generation process

### NIST SSDF Compliance

| Practice | PyGuard Feature | Status |
|----------|----------------|--------|
| PO.3.1 | Dependency tracking | ✅ |
| PO.3.2 | SBOM generation | ✅ |
| PS.1.1 | Vulnerability scanning | ✅ |
| PS.3.1 | Secure dependencies | ✅ |
| RV.1.1 | Continuous monitoring | ✅ |

### SLSA Compliance

Supply-chain Levels for Software Artifacts:

- **Level 1**: Version control and build process
- **Level 2**: Signed provenance
- **Level 3**: Hardened build platform
- **Level 4**: Two-party review

PyGuard supports SLSA compliance through:
- SBOM generation (Level 1+)
- Dependency verification (Level 2+)
- Provenance tracking (Level 3+)

---

## Advanced Features

### Custom Vulnerability Database

```python
from pyguard.lib.supply_chain import VulnerabilityChecker

# Extend built-in database
custom_vulns = {
    "internal-lib": {
        "<1.0.0": ["INTERNAL-2024-001: Security issue"],
    }
}

checker = VulnerabilityChecker()
checker.KNOWN_VULNERABILITIES.update(custom_vulns)
```

### Integration with External APIs

```python
# Future: OSV API integration
import requests

def check_osv_api(package_name, version):
    """Check Google's OSV database."""
    url = f"https://api.osv.dev/v1/query"
    data = {
        "package": {"name": package_name, "ecosystem": "PyPI"},
        "version": version
    }
    response = requests.post(url, json=data)
    return response.json()
```

---

## Comparison with Other Tools

| Feature | PyGuard | pip-audit | safety | snyk |
|---------|---------|-----------|--------|------|
| **SBOM Generation** | ✅ CycloneDX | ❌ | ❌ | ✅ |
| **Multiple Formats** | ✅ | ⚠️ Limited | ❌ | ✅ |
| **Built-in Database** | ✅ | ✅ | ✅ Paid | ✅ Paid |
| **Risk Assessment** | ✅ | ❌ | ⚠️ Basic | ✅ |
| **Open Source** | ✅ MIT | ✅ Apache | ⚠️ Freemium | ❌ Commercial |
| **API Access** | ✅ Python | ⚠️ CLI | ⚠️ Paid | ✅ Paid |

**PyGuard Advantage**: Only free tool with SBOM generation + vulnerability checking + risk assessment combined.

---

## References

### Standards

1. **NIST SSDF (SP 800-218)**  
   https://csrc.nist.gov/publications/detail/sp/800-218/final  
   Secure Software Development Framework

2. **SLSA**  
   https://slsa.dev/  
   Supply-chain Levels for Software Artifacts

3. **CycloneDX**  
   https://cyclonedx.org/  
   OWASP SBOM Standard

4. **CISA SBOM**  
   https://www.cisa.gov/sbom  
   US Government SBOM guidance

5. **OWASP Dependency-Check**  
   https://owasp.org/www-project-dependency-check/  
   Dependency vulnerability detection

### Resources

- **OSV Database**: https://osv.dev/
- **NVD**: https://nvd.nist.gov/
- **GitHub Advisory**: https://github.com/advisories
- **PyPI Advisory**: https://pypi.org/security/

---

## FAQ

### Q: How often is the vulnerability database updated?

**A**: PyGuard's built-in database includes the most critical vulnerabilities. For real-time updates, integrate with OSV or NVD APIs.

### Q: Can I use this for commercial projects?

**A**: Yes! PyGuard is MIT licensed and completely free for commercial use.

### Q: Does this replace dependency-check tools?

**A**: PyGuard complements tools like pip-audit and safety. Use multiple tools for defense in depth.

### Q: Can I customize the SBOM format?

**A**: Currently supports CycloneDX and JSON. SPDX support planned for v0.5.0.

---

## Contributing

Help improve PyGuard's supply chain security! See [CONTRIBUTING.md](../CONTRIBUTING.md).

Enhancement ideas:
- Additional vulnerability sources (OSV, NVD APIs)
- SPDX SBOM format support
- Dependency graph visualization
- License compliance checking
- Container image scanning

---

**PyGuard**: Secure Your Supply Chain 🔒
