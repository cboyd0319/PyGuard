"""
Track OWASP/CWE compliance annotations in code.

Extracts compliance references from code comments for audit trails.
"""

import subprocess
from typing import Any


class ComplianceTracker:
    """
    Track OWASP/CWE compliance annotations in code.
    """

    @staticmethod
    def find_compliance_annotations(path: str) -> dict[str, list[dict[str, Any]]]:
        """
        Find OWASP and CWE references in code comments.

        Args:
            path: Directory to analyze

        Returns:
            Dictionary of compliance annotations by type
        """
        annotations: dict[str, list[dict[str, Any]]] = {
            "OWASP": [],
            "CWE": [],
            "NIST": [],
            "PCI-DSS": [],
        }

        try:
            # Find OWASP references
            owasp_result = subprocess.run(
                [
                    "rg",
                    "--type",
                    "py",
                    "--line-number",
                    r"OWASP[\s-]*(ASVS|Top\s*10)?[\s-]*[A-Z]?\d+",
                    "--only-matching",
                    path,
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=60,
            )

            for line in owasp_result.stdout.strip().split("\n"):
                if line:
                    parts = line.split(":", 2)
                    if len(parts) >= 3:  # noqa: PLR2004 - threshold
                        file_path, line_num, ref = parts
                        annotations["OWASP"].append(
                            {"file": file_path, "line": int(line_num), "reference": ref.strip()}
                        )

            # Find CWE references
            cwe_result = subprocess.run(
                [
                    "rg",
                    "--type",
                    "py",
                    "--line-number",
                    r"CWE-\d+",
                    "--only-matching",
                    path,
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=60,
            )

            for line in cwe_result.stdout.strip().split("\n"):
                if line:
                    parts = line.split(":", 2)
                    if len(parts) >= 3:  # noqa: PLR2004 - threshold
                        file_path, line_num, ref = parts
                        annotations["CWE"].append(
                            {"file": file_path, "line": int(line_num), "reference": ref.strip()}
                        )

        except subprocess.TimeoutExpired:
            print("Warning: Compliance tracking timeout")
        except FileNotFoundError:
            # ripgrep not available
            pass

        return annotations

    @staticmethod
    def generate_compliance_report(path: str, output_path: str = "compliance-report.md"):
        """
        Generate compliance documentation from code annotations.

        Args:
            path: Directory to analyze
            output_path: Output file path for the report
        """
        annotations = ComplianceTracker.find_compliance_annotations(path)

        with open(output_path, "w") as f:
            f.write("# PyGuard Compliance Report\n\n")

            f.write(f"## OWASP References ({len(annotations['OWASP'])})\n\n")
            for ann in annotations["OWASP"]:
                f.write(f"- {ann['reference']} - `{ann['file']}:{ann['line']}`\n")

            f.write(f"\n## CWE References ({len(annotations['CWE'])})\n\n")
            for ann in annotations["CWE"]:
                f.write(f"- {ann['reference']} - `{ann['file']}:{ann['line']}`\n")

        print(f"Compliance report generated: {output_path}")
