"""
Enhanced Compliance Reporting for PyGuard.

Generates comprehensive compliance reports in multiple formats:
- HTML (interactive, styled)
- PDF (for audit documentation)
- JSON (for programmatic processing)

Supports frameworks: OWASP ASVS, PCI-DSS, HIPAA, SOC 2, ISO 27001, NIST, GDPR, CCPA, FedRAMP, SOX
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from pyguard import __version__
from pyguard.lib.core import PyGuardLogger


class ComplianceReporter:
    """
    Generate comprehensive compliance reports.
    
    Produces audit-ready documentation showing security posture
    against various compliance frameworks.
    """
    
    def __init__(self):
        """Initialize compliance reporter."""
        self.logger = PyGuardLogger()
        self.report_data: dict[str, Any] = {}
    
    def generate_html_report(
        self,
        issues: list[dict[str, Any]],
        output_path: str | Path = "compliance-report.html",
        framework: str = "ALL",
    ) -> None:
        """
        Generate HTML compliance report.
        
        Args:
            issues: List of security issues found
            output_path: Path to save the HTML report
            framework: Specific framework or "ALL" for comprehensive report
        """
        output_path = Path(output_path)
        
        # Organize issues by framework
        framework_issues = self._organize_by_framework(issues)
        
        # Generate HTML content
        html_content = self._generate_html_content(framework_issues, framework)
        
        # Write to file
        output_path.write_text(html_content, encoding="utf-8")
        
        self.logger.success(
            f"HTML compliance report generated: {output_path}",
            category="Compliance",
        )
    
    def generate_json_report(
        self,
        issues: list[dict[str, Any]],
        output_path: str | Path = "compliance-report.json",
    ) -> None:
        """
        Generate JSON compliance report for programmatic processing.
        
        Args:
            issues: List of security issues found
            output_path: Path to save the JSON report
        """
        output_path = Path(output_path)
        
        report = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "tool": "PyGuard",
                "version": __version__,
            },
            "summary": self._generate_summary(issues),
            "frameworks": self._organize_by_framework(issues),
            "issues": issues,
        }
        
        output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        
        self.logger.success(
            f"JSON compliance report generated: {output_path}",
            category="Compliance",
        )
    
    def _organize_by_framework(self, issues: list[dict[str, Any]]) -> dict[str, Any]:
        """Organize issues by compliance framework."""
        frameworks = {
            "OWASP": [],
            "PCI-DSS": [],
            "HIPAA": [],
            "SOC2": [],
            "ISO27001": [],
            "NIST": [],
            "GDPR": [],
            "CCPA": [],
            "FedRAMP": [],
            "SOX": [],
        }
        
        for issue in issues:
            # Map issue types to frameworks
            issue_type = issue.get("rule_id", "").lower()
            severity = issue.get("severity", "LOW")
            
            # Map to multiple frameworks if applicable
            if any(x in issue_type for x in ["injection", "xss", "sql"]):
                frameworks["OWASP"].append(issue)
                frameworks["PCI-DSS"].append(issue)
                frameworks["ISO27001"].append(issue)
            
            if any(x in issue_type for x in ["credential", "secret", "password"]):
                frameworks["OWASP"].append(issue)
                frameworks["PCI-DSS"].append(issue)
                frameworks["SOC2"].append(issue)
                frameworks["ISO27001"].append(issue)
            
            if any(x in issue_type for x in ["pii", "data", "privacy"]):
                frameworks["HIPAA"].append(issue)
                frameworks["GDPR"].append(issue)
                frameworks["CCPA"].append(issue)
            
            if "crypto" in issue_type or "encryption" in issue_type:
                frameworks["NIST"].append(issue)
                frameworks["FedRAMP"].append(issue)
                frameworks["ISO27001"].append(issue)
        
        # Remove duplicates using tuple of hashable fields
        for framework in frameworks:
            seen = set()
            unique_issues = []
            for issue in frameworks[framework]:
                # Create a hashable key from the issue
                key = (
                    issue.get("file", ""),
                    issue.get("line", 0),
                    issue.get("rule_id", ""),
                    issue.get("severity", ""),
                    issue.get("message", ""),
                )
                if key not in seen:
                    seen.add(key)
                    unique_issues.append(issue)
            frameworks[framework] = unique_issues
        
        return frameworks
    
    def _generate_summary(self, issues: list[dict[str, Any]]) -> dict[str, Any]:
        """Generate summary statistics."""
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        
        for issue in issues:
            severity = issue.get("severity", "INFO")
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        return {
            "total_issues": len(issues),
            "by_severity": severity_counts,
            "critical_high_count": severity_counts["CRITICAL"] + severity_counts["HIGH"],
        }
    
    def _generate_html_content(
        self,
        framework_issues: dict[str, list[dict[str, Any]]],
        selected_framework: str = "ALL",
    ) -> str:
        """Generate HTML content for the report."""
        
        # Calculate totals
        total_issues = sum(len(issues) for issues in framework_issues.values())
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PyGuard Compliance Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        
        h1 {{
            color: #2c3e50;
            margin-bottom: 10px;
            font-size: 2.5em;
        }}
        
        h2 {{
            color: #34495e;
            margin-top: 30px;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 2px solid #3498db;
        }}
        
        h3 {{
            color: #7f8c8d;
            margin-top: 20px;
            margin-bottom: 10px;
        }}
        
        .metadata {{
            background: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 30px;
        }}
        
        .metadata p {{
            margin: 5px 0;
            color: #7f8c8d;
        }}
        
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .summary-card {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }}
        
        .summary-card.critical {{
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        }}
        
        .summary-card.high {{
            background: linear-gradient(135deg, #fa709a 0%, #fee140 100%);
        }}
        
        .summary-card h3 {{
            color: white;
            margin: 0 0 10px 0;
        }}
        
        .summary-card .count {{
            font-size: 3em;
            font-weight: bold;
        }}
        
        .framework-section {{
            margin: 30px 0;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 8px;
        }}
        
        .framework-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }}
        
        .badge {{
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.9em;
            font-weight: bold;
        }}
        
        .badge.critical {{
            background: #e74c3c;
            color: white;
        }}
        
        .badge.high {{
            background: #e67e22;
            color: white;
        }}
        
        .badge.medium {{
            background: #f39c12;
            color: white;
        }}
        
        .badge.low {{
            background: #3498db;
            color: white;
        }}
        
        .issue-list {{
            list-style: none;
        }}
        
        .issue-item {{
            background: white;
            padding: 15px;
            margin-bottom: 10px;
            border-left: 4px solid #3498db;
            border-radius: 4px;
        }}
        
        .issue-item.critical {{
            border-left-color: #e74c3c;
        }}
        
        .issue-item.high {{
            border-left-color: #e67e22;
        }}
        
        .issue-title {{
            font-weight: bold;
            margin-bottom: 5px;
        }}
        
        .issue-details {{
            color: #7f8c8d;
            font-size: 0.9em;
        }}
        
        .footer {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ecf0f1;
            text-align: center;
            color: #7f8c8d;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ PyGuard Compliance Report</h1>
        
        <div class="metadata">
            <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>Framework Focus:</strong> {selected_framework}</p>
            <p><strong>Total Issues:</strong> {total_issues}</p>
        </div>
        
        <h2>Summary</h2>
        <div class="summary">
            <div class="summary-card critical">
                <h3>Total Issues</h3>
                <div class="count">{total_issues}</div>
            </div>
            <div class="summary-card high">
                <h3>Frameworks</h3>
                <div class="count">{len([f for f, issues in framework_issues.items() if issues])}</div>
            </div>
        </div>
"""
        
        # Add framework sections
        for framework, issues in framework_issues.items():
            if not issues:
                continue
            
            html += f"""
        <div class="framework-section">
            <div class="framework-header">
                <h2>{framework}</h2>
                <span class="badge {'critical' if len(issues) > 10 else 'high' if len(issues) > 5 else 'medium'}">{len(issues)} issues</span>
            </div>
            <ul class="issue-list">
"""
            
            for issue in issues[:10]:  # Show first 10 per framework
                severity_class = issue.get("severity", "LOW").lower()
                html += f"""
                <li class="issue-item {severity_class}">
                    <div class="issue-title">
                        <span class="badge {severity_class}">{issue.get('severity', 'UNKNOWN')}</span>
                        {issue.get('message', 'No message')}
                    </div>
                    <div class="issue-details">
                        📁 {issue.get('file', 'Unknown')} : Line {issue.get('line', '?')}
                    </div>
                </li>
"""
            
            if len(issues) > 10:
                html += f"""
                <li class="issue-item">
                    <div class="issue-details">
                        ... and {len(issues) - 10} more issues
                    </div>
                </li>
"""
            
            html += """
            </ul>
        </div>
"""
        
        html += """
        <div class="footer">
            <p>Generated by <strong>PyGuard</strong> - Python Security & Compliance Tool</p>
            <p>For more information, visit <a href="https://github.com/cboyd0319/PyGuard">github.com/cboyd0319/PyGuard</a></p>
        </div>
    </div>
</body>
</html>
"""
        
        return html
