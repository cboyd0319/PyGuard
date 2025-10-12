"""
Enhanced Security Detections for PyGuard.

Additional security checks beyond AST analysis:
- Backup file detection (.bak, .old, .backup, .tmp)
- Mass assignment vulnerabilities
- Memory disclosure patterns
- Clickjacking vulnerabilities
- Dependency confusion attacks

References:
- OWASP Top 10 2021 | https://owasp.org/Top10/ | High | Web application security risks
- CWE Top 25 2024 | https://cwe.mitre.org/top25/ | High | Most dangerous software weaknesses
- NIST 800-53 Rev 5 | https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final | High | Security controls
"""

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Set

from pyguard.lib.ast_analyzer import SecurityIssue
from pyguard.lib.core import FileOperations, PyGuardLogger


@dataclass
class FileSecurityIssue:
    """Security issue related to file system."""

    severity: str
    category: str
    message: str
    file_path: str
    fix_suggestion: str
    owasp_id: str
    cwe_id: str


class BackupFileDetector:
    """
    Detect backup files and sensitive files in repository.
    
    CWE-530: Exposure of Backup File to an Unauthorized Control Sphere
    """

    BACKUP_EXTENSIONS = {
        ".bak", ".backup", ".old", ".orig", ".tmp", ".temp", 
        ".swp", ".swo", ".save", "~", ".copy"
    }
    
    SENSITIVE_PATTERNS = {
        r"\.env$": "Environment file with secrets",
        r"\.env\.local$": "Local environment file",
        r"\.env\.production$": "Production environment file",
        r"id_rsa$": "SSH private key",
        r"\.pem$": "Private key file",
        r"\.key$": "Key file",
        r"\.pfx$": "Certificate file",
        r"\.p12$": "Certificate file",
        r"\.jks$": "Java keystore",
        r"\.keystore$": "Keystore file",
        r"\.credentials$": "Credentials file",
        r"\.npmrc$": "NPM credentials",
        r"\.pypirc$": "PyPI credentials",
        r"\.dockercfg$": "Docker credentials",
        r"config\.json$": "Configuration file",
        r"secrets\..*$": "Secrets file",
    }

    def __init__(self):
        """Initialize backup file detector."""
        self.logger = PyGuardLogger()
        self.file_ops = FileOperations()

    def scan_directory(self, directory: Path) -> List[FileSecurityIssue]:
        """
        Scan directory for backup files and sensitive files.
        
        Args:
            directory: Directory to scan
            
        Returns:
            List of file security issues found
        """
        issues = []
        
        for root, dirs, files in os.walk(directory):
            # Skip common ignore directories
            dirs[:] = [d for d in dirs if d not in {".git", ".venv", "node_modules", "__pycache__", ".tox"}]
            
            for filename in files:
                file_path = Path(root) / filename
                
                # Check for backup file extensions
                if any(str(filename).endswith(ext) for ext in self.BACKUP_EXTENSIONS):
                    issues.append(
                        FileSecurityIssue(
                            severity="MEDIUM",
                            category="Backup File Exposure",
                            message=f"Backup file detected: {filename}",
                            file_path=str(file_path),
                            fix_suggestion="Remove backup files from repository; add to .gitignore",
                            owasp_id="ASVS-14.3.4",
                            cwe_id="CWE-530",
                        )
                    )
                
                # Check for sensitive file patterns
                for pattern, description in self.SENSITIVE_PATTERNS.items():
                    if re.search(pattern, str(filename)):
                        issues.append(
                            FileSecurityIssue(
                                severity="HIGH",
                                category="Sensitive File Exposure",
                                message=f"{description} found in repository: {filename}",
                                file_path=str(file_path),
                                fix_suggestion="Remove sensitive files from repository; use environment variables or secure vaults",
                                owasp_id="ASVS-2.10.4",
                                cwe_id="CWE-798",
                            )
                        )
                        break
        
        return issues


class MassAssignmentDetector:
    """
    Detect potential mass assignment vulnerabilities.
    
    CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes
    """

    VULNERABLE_PATTERNS = [
        r"\.update\(\s*request\.",  # model.update(request.data)
        r"\.update\(\s*\*\*request\.",  # model.update(**request.json)
        r"for\s+key\s+in\s+request\.",  # for key in request.data
        r"\.from_dict\(\s*request\.",  # User.from_dict(request.json)
        r"__dict__\.update\(\s*request\.",  # obj.__dict__.update(request.form)
    ]

    def __init__(self):
        """Initialize mass assignment detector."""
        self.logger = PyGuardLogger()

    def scan_code(self, code: str, file_path: str) -> List[SecurityIssue]:
        """
        Scan code for mass assignment vulnerabilities.
        
        Args:
            code: Source code to scan
            file_path: Path to file being scanned
            
        Returns:
            List of security issues found
        """
        issues = []
        lines = code.split("\n")
        
        for line_num, line in enumerate(lines, 1):
            for pattern in self.VULNERABLE_PATTERNS:
                if re.search(pattern, line):
                    issues.append(
                        SecurityIssue(
                            severity="HIGH",
                            category="Mass Assignment",
                            message="Potential mass assignment vulnerability - user input directly updating object",
                            line_number=line_num,
                            column=0,
                            code_snippet=line.strip(),
                            fix_suggestion="Use explicit field whitelisting; validate allowed attributes before assignment",
                            owasp_id="ASVS-5.1.2",
                            cwe_id="CWE-915",
                        )
                    )
                    break
        
        return issues


class ClickjackingDetector:
    """
    Detect missing clickjacking protection.
    
    CWE-1021: Improper Restriction of Rendered UI Layers or Frames
    """

    FRAMEWORK_PATTERNS = {
        "flask": [
            (r"from flask import Flask", "Flask application"),
            (r"@app\.route", "Flask route"),
        ],
        "django": [
            (r"from django", "Django application"),
            (r"def\s+\w+\(request\)", "Django view"),
        ],
        "fastapi": [
            (r"from fastapi import FastAPI", "FastAPI application"),
            (r"@app\.(get|post|put|delete)", "FastAPI route"),
        ],
    }

    def __init__(self):
        """Initialize clickjacking detector."""
        self.logger = PyGuardLogger()

    def scan_code(self, code: str, file_path: str) -> List[SecurityIssue]:
        """
        Scan code for missing clickjacking protection.
        
        Args:
            code: Source code to scan
            file_path: Path to file being scanned
            
        Returns:
            List of security issues found
        """
        issues = []
        
        # Detect web framework usage
        framework = None
        for fw, patterns in self.FRAMEWORK_PATTERNS.items():
            for pattern, _ in patterns:
                if re.search(pattern, code):
                    framework = fw
                    break
            if framework:
                break
        
        if framework:
            # Check for X-Frame-Options or Content-Security-Policy
            has_protection = (
                re.search(r"X-Frame-Options", code, re.IGNORECASE) or
                re.search(r"frame-ancestors", code, re.IGNORECASE) or
                re.search(r"ClickjackingMiddleware", code) or
                re.search(r"clickjacking", code, re.IGNORECASE)
            )
            
            if not has_protection:
                issues.append(
                    SecurityIssue(
                        severity="MEDIUM",
                        category="Missing Clickjacking Protection",
                        message=f"{framework} application missing clickjacking protection headers",
                        line_number=1,
                        column=0,
                        code_snippet="",
                        fix_suggestion="Add X-Frame-Options: DENY or Content-Security-Policy: frame-ancestors 'none'",
                        owasp_id="ASVS-13.1.4",
                        cwe_id="CWE-1021",
                    )
                )
        
        return issues


class DependencyConfusionDetector:
    """
    Detect potential dependency confusion vulnerabilities.
    
    References:
    - https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610
    - CWE-494: Download of Code Without Integrity Check
    """

    PRIVATE_PACKAGE_INDICATORS = [
        r"^@[a-z0-9-]+/",  # Scoped packages
        r"^internal-",
        r"^private-",
        r"^company-",
        r"^corp-",
    ]

    def __init__(self):
        """Initialize dependency confusion detector."""
        self.logger = PyGuardLogger()

    def scan_requirements(self, requirements_file: Path) -> List[FileSecurityIssue]:
        """
        Scan requirements file for dependency confusion risks.
        
        Args:
            requirements_file: Path to requirements.txt or similar
            
        Returns:
            List of file security issues found
        """
        issues = []
        
        if not requirements_file.exists():
            return issues
        
        content = requirements_file.read_text()
        lines = content.split("\n")
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            
            # Extract package name
            package_name = line.split("==")[0].split(">=")[0].split("~=")[0].strip()
            
            # Check if it looks like a private package
            for pattern in self.PRIVATE_PACKAGE_INDICATORS:
                if re.match(pattern, package_name):
                    # Check if index-url is specified
                    has_index = "--index-url" in content or "--extra-index-url" in content
                    
                    if not has_index:
                        issues.append(
                            FileSecurityIssue(
                                severity="HIGH",
                                category="Dependency Confusion Risk",
                                message=f"Private package '{package_name}' without explicit index URL",
                                file_path=str(requirements_file),
                                fix_suggestion="Add --index-url to specify private package repository; use pip.conf for global settings",
                                owasp_id="ASVS-14.2.1",
                                cwe_id="CWE-494",
                            )
                        )
                    break
        
        return issues


class MemoryDisclosureDetector:
    """
    Detect potential memory disclosure issues.
    
    CWE-212: Improper Removal of Sensitive Information Before Storage or Transfer
    """

    MEMORY_PATTERNS = [
        (r"traceback\.print_exc\(\)", "Exception traceback in production"),
        (r"sys\.exc_info\(\)", "Exception info exposure"),
        (r"__dict__", "Object dictionary exposure"),
        (r"\bvars\(", "Variable exposure"),
        (r"\bdir\(", "Directory listing exposure"),
        (r"\blocals\(", "Local variables exposure"),
        (r"\bglobals\(", "Global variables exposure"),
    ]

    def __init__(self):
        """Initialize memory disclosure detector."""
        self.logger = PyGuardLogger()

    def scan_code(self, code: str, file_path: str) -> List[SecurityIssue]:
        """
        Scan code for memory disclosure vulnerabilities.
        
        Args:
            code: Source code to scan
            file_path: Path to file being scanned
            
        Returns:
            List of security issues found
        """
        issues = []
        lines = code.split("\n")
        
        for line_num, line in enumerate(lines, 1):
            for pattern, description in self.MEMORY_PATTERNS:
                if re.search(pattern, line):
                    issues.append(
                        SecurityIssue(
                            severity="MEDIUM",
                            category="Memory Disclosure",
                            message=f"Potential memory disclosure: {description}",
                            line_number=line_num,
                            column=0,
                            code_snippet=line.strip(),
                            fix_suggestion="Avoid exposing internal memory structures; sanitize error messages in production",
                            owasp_id="ASVS-7.4.1",
                            cwe_id="CWE-212",
                        )
                    )
                    break
        
        return issues
