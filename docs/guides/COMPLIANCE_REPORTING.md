# Enhanced Compliance Reporting Guide

**PyGuard v0.8.0 Feature**

Generate audit-ready compliance reports mapping security findings to 10+ frameworks.

## Overview

Enhanced Compliance Reporting automatically maps PyGuard's security findings to multiple compliance frameworks, generating beautiful HTML reports and JSON data for audits and compliance documentation.

### Supported Frameworks

- **OWASP ASVS** - Application Security Verification Standard
- **PCI-DSS 4.0** - Payment Card Industry Data Security Standard
- **HIPAA** - Health Insurance Portability and Accountability Act
- **SOC 2** - Service Organization Control 2
- **ISO 27001** - Information Security Management
- **NIST CSF** - National Institute of Standards Cybersecurity Framework
- **GDPR** - General Data Protection Regulation
- **CCPA** - California Consumer Privacy Act
- **FedRAMP** - Federal Risk and Authorization Management Program
- **SOX** - Sarbanes-Oxley Act

## Quick Start

```bash
# Generate HTML compliance report
pyguard src/ --compliance-html compliance-report.html

# Generate JSON for programmatic access
pyguard src/ --compliance-json compliance-report.json

# Generate both formats
pyguard src/ \
  --compliance-html report.html \
  --compliance-json report.json
```

## HTML Reports

### Features

- **Beautiful styling** with modern CSS
- **Framework-organized** issues by compliance standard
- **Severity badges** (Critical, High, Medium, Low)
- **Audit-ready format** suitable for compliance documentation
- **Interactive layout** with clear sections
- **Issue summaries** with file locations and line numbers

### Example Output

HTML reports include:

1. **Header with metadata**
   - Generation timestamp
   - Total issues count
   - Framework coverage

2. **Summary dashboard**
   - Total issues card
   - Frameworks covered card
   - Visual statistics

3. **Framework sections**
   - Organized by compliance framework
   - Issue count per framework
   - First 10 issues shown per framework
   - File locations and severity badges

### Opening Reports

```bash
# Generate and open
pyguard src/ --compliance-html report.html
open report.html  # macOS
xdg-open report.html  # Linux
start report.html  # Windows
```

## JSON Reports

### Features

- **Machine-readable** format for automation
- **Complete metadata** about scan
- **Framework mapping** for all issues
- **Programmatic access** to compliance data

### JSON Structure

```json
{
  "metadata": {
    "generated_at": "2025-11-03T22:00:00",
    "tool": "PyGuard",
    "version": "0.7.0"
  },
  "summary": {
    "total_issues": 45,
    "by_severity": {
      "CRITICAL": 5,
      "HIGH": 12,
      "MEDIUM": 18,
      "LOW": 10,
      "INFO": 0
    },
    "critical_high_count": 17
  },
  "frameworks": {
    "OWASP": [...],
    "PCI-DSS": [...],
    "HIPAA": [...],
    ...
  },
  "issues": [...]
}
```

### Processing JSON Reports

```python
import json

# Load report
with open("compliance-report.json") as f:
    report = json.load(f)

# Access summary
print(f"Total issues: {report['summary']['total_issues']}")
print(f"Critical: {report['summary']['by_severity']['CRITICAL']}")

# Check specific framework
owasp_issues = report['frameworks']['OWASP']
print(f"OWASP issues: {len(owasp_issues)}")

# Filter high severity issues
high_severity = [
    issue for issue in report['issues']
    if issue['severity'] == 'HIGH'
]
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Compliance Scan
on:
  schedule:
    - cron: '0 0 * * 0'  # Weekly
  workflow_dispatch:

jobs:
  compliance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      
      - name: Install PyGuard
        run: pip install pyguard
      
      - name: Generate Compliance Reports
        run: |
          pyguard . \
            --compliance-html compliance-report.html \
            --compliance-json compliance-report.json
      
      - name: Upload Compliance Reports
        uses: actions/upload-artifact@v4
        with:
          name: compliance-reports
          path: |
            compliance-report.html
            compliance-report.json
      
      - name: Check Critical Issues
        run: |
          CRITICAL=$(python -c "import json; print(json.load(open('compliance-report.json'))['summary']['by_severity']['CRITICAL'])")
          if [ $CRITICAL -gt 0 ]; then
            echo "❌ Found $CRITICAL critical compliance issues"
            exit 1
          fi
```

### GitLab CI

```yaml
compliance-scan:
  stage: test
  script:
    - pip install pyguard
    - pyguard . --compliance-html compliance.html --compliance-json compliance.json
  artifacts:
    paths:
      - compliance.html
      - compliance.json
    reports:
      compliance: compliance.json
```

## Framework Mappings

### How Issues Are Mapped

PyGuard automatically maps security findings to relevant frameworks:

```python
# SQL Injection → Multiple Frameworks
issue_type: "sql-injection"
mapped_to:
  - OWASP ASVS (Input Validation)
  - PCI-DSS (Requirement 6.5.1)
  - ISO 27001 (A.14.2)

# Hardcoded Credentials → Security Frameworks
issue_type: "hardcoded-credentials"
mapped_to:
  - OWASP ASVS (Authentication)
  - PCI-DSS (Requirement 8.2)
  - SOC 2 (CC6.1)
  - ISO 27001 (A.9.4)

# PII Exposure → Privacy Frameworks
issue_type: "pii-exposure"
mapped_to:
  - HIPAA (Privacy Rule)
  - GDPR (Article 32)
  - CCPA (Section 1798.150)

# Weak Cryptography → Crypto Standards
issue_type: "weak-cryptography"
mapped_to:
  - NIST CSF (PR.DS-5)
  - FedRAMP (SC-13)
  - ISO 27001 (A.10.1)
```

## Use Cases

### 1. Audit Preparation

```bash
# Generate comprehensive compliance report
pyguard src/ \
  --compliance-html audit-$(date +%Y%m%d).html \
  --compliance-json audit-$(date +%Y%m%d).json

# Include in audit documentation package
```

### 2. Continuous Compliance Monitoring

```bash
# Daily compliance checks
0 0 * * * pyguard /app --compliance-json /reports/daily-compliance.json

# Alert on critical issues
if [ $(jq '.summary.by_severity.CRITICAL' report.json) -gt 0 ]; then
  send-alert "Critical compliance issues found"
fi
```

### 3. Executive Reporting

HTML reports provide executive-friendly summaries:
- Visual severity breakdown
- Framework coverage overview
- Trend analysis (with historical reports)
- Audit-ready documentation

### 4. Development Workflow

```bash
# Pre-release compliance check
pyguard src/ --compliance-html pre-release-compliance.html

# Review report before release
open pre-release-compliance.html

# Block release if critical issues found
```

## Combining with Other Features

### Git Diff Analysis

```bash
# Compliance report for PR changes only
pyguard --diff main..feature . \
  --compliance-html pr-compliance.html \
  --compliance-json pr-compliance.json
```

### Security-Only Mode

```bash
# Security-focused compliance report
pyguard src/ --security-only \
  --compliance-html security-compliance.html
```

### SARIF Output

```bash
# Generate both SARIF and compliance reports
pyguard src/ \
  --sarif \
  --compliance-html compliance.html \
  --compliance-json compliance.json
```

## Advanced Usage

### Framework-Specific Analysis

```python
from pyguard.lib.compliance_reporter import ComplianceReporter

reporter = ComplianceReporter()

# Generate report with framework focus
reporter.generate_html_report(
    issues=scan_results,
    output_path="hipaa-compliance.html",
    framework="HIPAA"  # Future: focus on specific framework
)
```

### Custom Framework Mapping

Future enhancement: Define custom framework mappings

```python
# Custom compliance requirement mapping
custom_mapping = {
    "internal-policy-001": {
        "check": "sql-injection",
        "severity": "CRITICAL",
        "requirements": ["Company Policy 3.2.1"]
    }
}
```

## Best Practices

### 1. Regular Scans

Schedule compliance scans regularly:
- **Daily** for active development
- **Weekly** for stable codebases
- **Before releases** always
- **After major changes** critical

### 2. Version Control Reports

Track compliance over time:

```bash
# Git-tracked compliance reports
mkdir -p compliance-reports/
pyguard src/ \
  --compliance-json compliance-reports/$(git rev-parse --short HEAD).json

git add compliance-reports/
git commit -m "Add compliance report for $(git rev-parse --short HEAD)"
```

### 3. Automated Alerts

Set up automated alerting:

```bash
#!/bin/bash
# compliance-alert.sh

REPORT="compliance.json"
pyguard src/ --compliance-json $REPORT

CRITICAL=$(jq '.summary.by_severity.CRITICAL' $REPORT)
HIGH=$(jq '.summary.by_severity.HIGH' $REPORT)

if [ $CRITICAL -gt 0 ]; then
  echo "🚨 CRITICAL: $CRITICAL critical compliance issues"
  # Send alert to Slack/Teams/Email
fi
```

### 4. Integration with Dashboards

Display compliance metrics:

```python
# Example: Send to monitoring dashboard
import requests
import json

with open("compliance-report.json") as f:
    report = json.load(f)

# Send to monitoring system
requests.post("https://dashboard/api/metrics", json={
    "service": "myapp",
    "compliance_score": 100 - report['summary']['critical_high_count'],
    "critical_issues": report['summary']['by_severity']['CRITICAL'],
    "frameworks_covered": len([f for f in report['frameworks'].values() if f]),
})
```

## Troubleshooting

### No Issues in Report

**Problem:** Compliance report shows zero issues.

**Causes:**
1. No security issues found (good!)
2. Code is already compliant
3. Need to run full scan (not using `--scan-only`)

**Solution:**
```bash
# Ensure you're running a complete scan
pyguard src/ --compliance-html report.html

# Verify issues are being detected
pyguard src/ | grep -i "issue"
```

### Framework Sections Empty

**Problem:** Specific framework section is empty.

**Explanation:** The issue types found don't map to that framework. For example:
- Code quality issues → Won't map to HIPAA
- Style violations → Won't map to PCI-DSS

### Large Report Size

**Problem:** HTML report is very large.

**Solution:**
1. Use JSON for programmatic access
2. Filter by severity: focus on CRITICAL/HIGH
3. Generate framework-specific reports (future feature)

## Performance Considerations

Report generation adds minimal overhead:

| Issues Found | HTML Generation | JSON Generation |
|-------------|----------------|----------------|
| 10 issues | < 50ms | < 10ms |
| 100 issues | < 200ms | < 50ms |
| 1000 issues | < 1s | < 200ms |

## Related Features

- **Git Diff Analysis** - Compliance reports for PR changes
- **SARIF Output** - GitHub Security integration
- **Standards Integration** - Framework mappings
- **HTML Reports** - Existing HTML reporter

## References

- [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/)
- [PCI DSS](https://www.pcisecuritystandards.org/)
- [HIPAA Security Rule](https://www.hhs.gov/hipaa/for-professionals/security/)
- [SOC 2](https://www.aicpa.org/soc)
- [ISO 27001](https://www.iso.org/isoiec-27001-information-security.html)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [GDPR](https://gdpr.eu/)

## Support

For issues or questions:
- [GitHub Issues](https://github.com/cboyd0319/PyGuard/issues)
- [GitHub Discussions](https://github.com/cboyd0319/PyGuard/discussions)
