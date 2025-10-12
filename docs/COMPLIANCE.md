# Compliance Frameworks Guide

**PyGuard v0.5.0** provides comprehensive mapping to **6+ compliance frameworks**, helping organizations demonstrate security compliance and meet regulatory requirements.

---

## 🎯 Supported Frameworks

| Framework | Version | Coverage | Use Case |
|-----------|---------|----------|----------|
| **NIST CSF** | v1.1 | ✅ Full | Cybersecurity framework for all organizations |
| **ISO 27001** | 2022 | ✅ Full | Information security management |
| **SOC 2** | Type II | ✅ Full | Service organization controls |
| **PCI DSS** | v4.0 | ✅ Full | Payment card industry security |
| **GDPR** | Current | ✅ Technical | EU data protection regulation |
| **HIPAA** | Current | ✅ Security Rule | Healthcare data protection |

---

## 🚀 Quick Start

### Check NIST CSF Compliance

```python
from pyguard.lib.standards_integration import StandardsMapper

mapper = StandardsMapper()

# Detected security issues
issues = [
    {"type": "code_injection", "severity": "HIGH"},
    {"type": "hardcoded_credentials", "severity": "HIGH"},
]

# Check compliance
result = mapper.check_standard_compliance("NIST-CSF", issues)

print(f"Standard: {result['standard']}")
print(f"Compliant: {result['compliant']}")
print(f"Violations: {result['total_violations']}")

for violation in result['violations']:
    print(f"\n  Control: {violation['control_id']}")
    print(f"  Requirement: {violation['requirement']}")
```

### Generate Multi-Framework Report

```python
# Generate report for all frameworks
report = mapper.generate_compliance_report(issues)

for standard, controls in report.items():
    print(f"\n{standard}:")
    for control in controls:
        print(f"  - {control['control_id']}: {control['category']}")
```

### GDPR Technical Requirements

```python
from pyguard.lib.standards_integration import GDPRTechnicalControls

gdpr = GDPRTechnicalControls()
result = gdpr.check_gdpr_technical_requirements(issues)

print(f"Article 32 Violations: {result['article_32_violations']}")
print(f"Article 25 Violations: {result['article_25_violations']}")
print(f"Compliant: {result['compliant']}")

for rec in result['recommendations']:
    print(f"  - {rec}")
```

### HIPAA Security Rule

```python
from pyguard.lib.standards_integration import HIPAASecurityRule

hipaa = HIPAASecurityRule()
result = hipaa.check_hipaa_compliance(issues)

print("\nHIPAA Safeguards Status:")
for safeguard, status in result['safeguards_status'].items():
    print(f"  {safeguard}: {status}")
```

---

## 📋 Framework Details

### 1. NIST Cybersecurity Framework (CSF)

**Purpose**: Comprehensive cybersecurity risk management framework

**PyGuard Mappings:**

| Issue Type | Control ID | Category |
|-----------|-----------|----------|
| Code Injection | PR.AC-4 | Protect - Access Control |
| Hardcoded Credentials | PR.AC-1 | Protect - Access Control |
| Weak Cryptography | PR.DS-5 | Protect - Data Security |

**Example:**

```python
# Get all NIST CSF mappings
mappings = mapper.get_compliance_mappings("code_injection")

for mapping in mappings:
    if mapping.standard == "NIST-CSF":
        print(f"Control: {mapping.control_id}")
        print(f"Category: {mapping.category}")
        print(f"Description: {mapping.description}")
```

**Benefits:**
- ✅ Widely recognized across industries
- ✅ Risk-based approach
- ✅ Flexible implementation
- ✅ Continuous improvement focus

---

### 2. ISO/IEC 27001:2022

**Purpose**: International standard for information security management systems (ISMS)

**PyGuard Mappings:**

| Issue Type | Control ID | Category |
|-----------|-----------|----------|
| Code Injection | 8.8 | Management of technical vulnerabilities |
| Hardcoded Credentials | 8.5 | Secure authentication |
| SQL Injection | 8.14 | Secure coding |

**Example:**

```python
# Check ISO 27001 compliance
result = mapper.check_standard_compliance("ISO-27001", issues)

if not result['compliant']:
    print("ISO 27001 Violations:")
    for v in result['violations']:
        print(f"  Control {v['control_id']}: {v['requirement']}")
```

**Benefits:**
- ✅ Internationally recognized certification
- ✅ Comprehensive security coverage
- ✅ Regular audits and updates
- ✅ Business credibility

---

### 3. SOC 2 Type II

**Purpose**: Service organization controls for security, availability, processing integrity, confidentiality, and privacy

**PyGuard Mappings:**

| Issue Type | Control ID | Category |
|-----------|-----------|----------|
| Code Injection | CC6.1 | Logical and Physical Access Controls |
| Hardcoded Credentials | CC6.1 | Logical and Physical Access Controls |
| Logging Sensitive Data | CC7.2 | System Monitoring |

**Example:**

```python
result = mapper.check_standard_compliance("SOC-2", issues)

print(f"SOC 2 Compliance: {result['compliant']}")
print(f"Trust Service Criteria Affected: {len(result['violations'])}")
```

**Benefits:**
- ✅ Required for SaaS companies
- ✅ Customer trust and confidence
- ✅ Competitive advantage
- ✅ Third-party validated

---

### 4. PCI DSS 4.0

**Purpose**: Payment Card Industry Data Security Standard for protecting payment card data

**PyGuard Mappings:**

| Issue Type | Control ID | Category |
|-----------|-----------|----------|
| Hardcoded Credentials | 8.2.1 | User Authentication |
| Weak Cryptography | 4.2 | Encryption |
| SQL Injection | 6.5.1 | Secure Development |

**Example:**

```python
result = mapper.check_standard_compliance("PCI-DSS", issues)

if not result['compliant']:
    print("⚠️  PCI DSS violations found!")
    print("Required for payment processing compliance")
```

**Benefits:**
- ✅ Mandatory for payment processing
- ✅ Reduces breach liability
- ✅ Customer data protection
- ✅ Industry standard

---

### 5. GDPR (Technical Requirements)

**Purpose**: EU General Data Protection Regulation technical and organizational measures

**Key Articles:**
- **Article 32**: Security of processing
- **Article 25**: Data protection by design and by default

**Example:**

```python
gdpr = GDPRTechnicalControls()
result = gdpr.check_gdpr_technical_requirements(issues)

print(f"\nGDPR Article 32 (Security):")
print(f"  Violations: {result['article_32_violations']}")

print(f"\nGDPR Article 25 (Privacy by Design):")
print(f"  Violations: {result['article_25_violations']}")

print(f"\nRecommendations:")
for rec in result['recommendations']:
    print(f"  • {rec}")
```

**Technical Controls Mapped:**
- Encryption at rest and in transit
- Pseudonymization and anonymization
- Security testing and assessment
- Data minimization in logging
- Access controls and authentication

**Benefits:**
- ✅ EU market access
- ✅ Avoids massive fines (up to 4% revenue)
- ✅ Customer privacy protection
- ✅ Competitive advantage

---

### 6. HIPAA Security Rule

**Purpose**: Health Insurance Portability and Accountability Act technical safeguards

**Technical Safeguards:**
- **164.312(a)(1)**: Access Control
- **164.312(a)(2)(iv)**: Encryption and Decryption
- **164.312(b)**: Audit Controls

**Example:**

```python
hipaa = HIPAASecurityRule()
result = hipaa.check_hipaa_compliance(issues)

print("HIPAA Security Rule Status:")
for safeguard_id, status in result['safeguards_status'].items():
    icon = "✅" if status == "PASS" else "❌"
    print(f"  {icon} {safeguard_id}: {status}")
```

**Benefits:**
- ✅ Required for healthcare data
- ✅ Protects PHI (Protected Health Information)
- ✅ Avoids severe penalties
- ✅ Patient trust

---

## 🔧 Integration Examples

### CI/CD Pipeline

```yaml
# .github/workflows/compliance.yml
name: Compliance Check

on: [push, pull_request]

jobs:
  compliance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Run PyGuard Compliance Check
        run: |
          pip install pyguard
          python scripts/check_compliance.py
```

**check_compliance.py:**
```python
#!/usr/bin/env python3
import sys
from pathlib import Path
from pyguard.lib.ast_analyzer import ASTAnalyzer
from pyguard.lib.standards_integration import StandardsMapper

analyzer = ASTAnalyzer()
mapper = StandardsMapper()

# Analyze all Python files
all_issues = []
for py_file in Path("src").rglob("*.py"):
    security_issues, _ = analyzer.analyze_file(py_file)
    all_issues.extend([{"type": i.category, "severity": i.severity} 
                      for i in security_issues])

# Check required compliance frameworks
required_standards = ["NIST-CSF", "ISO-27001", "SOC-2"]

for standard in required_standards:
    result = mapper.check_standard_compliance(standard, all_issues)
    
    if not result['compliant']:
        print(f"❌ {standard}: {result['total_violations']} violations")
        sys.exit(1)
    else:
        print(f"✅ {standard}: Compliant")

print("\n✅ All compliance checks passed!")
```

### Automated Compliance Reporting

```python
from pyguard.lib.standards_integration import StandardsMapper
import json
from datetime import datetime

mapper = StandardsMapper()

# Collect all issues from analysis
issues = analyze_codebase()

# Generate comprehensive report
report = {
    "timestamp": datetime.now().isoformat(),
    "frameworks": {}
}

for standard in ["NIST-CSF", "ISO-27001", "SOC-2", "PCI-DSS"]:
    result = mapper.check_standard_compliance(standard, issues)
    report["frameworks"][standard] = {
        "compliant": result['compliant'],
        "violations": result['total_violations'],
        "details": result['violations']
    }

# Save report
with open("compliance_report.json", "w") as f:
    json.dump(report, f, indent=2)

# Generate HTML report
generate_html_report(report, "compliance_report.html")
```

### Pre-Deployment Check

```python
#!/usr/bin/env python3
"""
Pre-deployment compliance verification.
Ensures code meets all required compliance standards before deployment.
"""
import sys
from pyguard.lib.standards_integration import (
    StandardsMapper,
    GDPRTechnicalControls,
    HIPAASecurityRule
)

def check_deployment_readiness(issues):
    """Check if code is ready for deployment."""
    mapper = StandardsMapper()
    gdpr = GDPRTechnicalControls()
    hipaa = HIPAASecurityRule()
    
    # Critical frameworks for your organization
    critical_checks = [
        ("NIST-CSF", mapper.check_standard_compliance("NIST-CSF", issues)),
        ("PCI-DSS", mapper.check_standard_compliance("PCI-DSS", issues)),
        ("GDPR", gdpr.check_gdpr_technical_requirements(issues)),
        ("HIPAA", hipaa.check_hipaa_compliance(issues)),
    ]
    
    failed_checks = []
    for name, result in critical_checks:
        if not result['compliant']:
            failed_checks.append(name)
    
    if failed_checks:
        print("❌ Deployment blocked - compliance violations:")
        for framework in failed_checks:
            print(f"   - {framework}")
        sys.exit(1)
    
    print("✅ All compliance checks passed - deployment approved")

if __name__ == "__main__":
    issues = load_security_issues()
    check_deployment_readiness(issues)
```

---

## 📊 Compliance Dashboard

Create a visual compliance dashboard:

```python
from pyguard.lib.standards_integration import StandardsMapper
import matplotlib.pyplot as plt

mapper = StandardsMapper()
issues = analyze_codebase()

# Calculate compliance scores
frameworks = ["NIST-CSF", "ISO-27001", "SOC-2", "PCI-DSS"]
scores = []

for framework in frameworks:
    result = mapper.check_standard_compliance(framework, issues)
    # Score = 1.0 if compliant, or (1 - violations/total_possible)
    score = 1.0 if result['compliant'] else max(0, 1 - result['total_violations']/10)
    scores.append(score * 100)

# Create dashboard
fig, ax = plt.subplots(figsize=(10, 6))
bars = ax.bar(frameworks, scores, color=['green' if s == 100 else 'orange' for s in scores])
ax.set_ylabel('Compliance Score (%)')
ax.set_title('PyGuard Compliance Dashboard')
ax.set_ylim(0, 100)
ax.axhline(y=80, color='r', linestyle='--', label='Minimum Threshold')

# Add score labels
for bar, score in zip(bars, scores):
    height = bar.get_height()
    ax.text(bar.get_x() + bar.get_width()/2., height,
            f'{score:.1f}%', ha='center', va='bottom')

plt.legend()
plt.tight_layout()
plt.savefig('compliance_dashboard.png')
```

---

## 🎓 Best Practices

### 1. Choose Relevant Frameworks

Not all organizations need all frameworks:

- **E-commerce**: PCI DSS, GDPR
- **Healthcare**: HIPAA, GDPR, NIST CSF
- **SaaS**: SOC 2, ISO 27001, GDPR
- **Financial**: PCI DSS, SOC 2, ISO 27001
- **Government**: NIST CSF, ISO 27001

### 2. Automate Compliance Checks

- Run compliance checks on every commit
- Block deployments that violate critical requirements
- Generate compliance reports automatically
- Track compliance trends over time

### 3. Map Internal Policies

```python
# Extend StandardsMapper for internal policies
class CustomStandardsMapper(StandardsMapper):
    def __init__(self):
        super().__init__()
        
        # Add internal company policies
        self.company_policies = {
            "code_injection": ComplianceRequirement(
                standard="COMPANY-SEC",
                control_id="SEC-001",
                category="Code Security",
                description="No eval/exec allowed",
                technical_controls=["Static analysis", "Code review"],
                severity="CRITICAL"
            )
        }
```

### 4. Document Compliance Gaps

```python
# Generate gap analysis report
def generate_gap_analysis(issues, target_framework):
    mapper = StandardsMapper()
    result = mapper.check_standard_compliance(target_framework, issues)
    
    gaps = []
    for violation in result['violations']:
        gaps.append({
            "control": violation['control_id'],
            "current_state": "Non-compliant",
            "remediation": "Implement technical control",
            "priority": violation['issue'].get('severity', 'MEDIUM')
        })
    
    return gaps
```

---

## 📚 Additional Resources

- [NIST CSF](https://www.nist.gov/cyberframework)
- [ISO 27001](https://www.iso.org/standard/27001)
- [SOC 2](https://www.aicpa.org/interestareas/frc/assuranceadvisoryservices/sorhome.html)
- [PCI DSS](https://www.pcisecuritystandards.org/)
- [GDPR](https://gdpr.eu/)
- [HIPAA](https://www.hhs.gov/hipaa/)

---

<p align="center">
  <strong>PyGuard: Your Compliance Partner</strong>
  <br>
  Questions? Open an issue on GitHub!
</p>
