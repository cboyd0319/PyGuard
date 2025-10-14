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
from typing import List

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
                            fix_suggestion="Use explicit field Allowlisting; validate allowed attributes before assignment",
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
        issues: List[FileSecurityIssue] = []

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


class AuthenticationBypassDetector:
    """
    Detect authentication bypass vulnerabilities.
    
    CWE-287: Improper Authentication
    CWE-306: Missing Authentication for Critical Function
    
    References:
    - OWASP ASVS v5.0 Section 2: Authentication
    - SANS CWE Top 25 #14: CWE-287
    """

    BYPASS_PATTERNS = [
        (r"if\s+True\s*:", "Hardcoded True condition bypasses authentication"),
        (r"if\s+1\s*:", "Hardcoded 1 condition bypasses authentication"),
        (r"if\s+False\s*:\s*#.*auth", "Disabled authentication check"),
        (r"#.*authenticate\(", "Commented out authentication"),
        (r"pass\s*#.*auth", "Authentication logic removed"),
        (r"return\s+True\s*#.*auth", "Always returns authenticated"),
    ]

    def __init__(self):
        """Initialize authentication bypass detector."""
        self.logger = PyGuardLogger()

    def scan_code(self, code: str) -> List[SecurityIssue]:
        """
        Scan code for authentication bypass patterns.
        
        Args:
            code: Source code to scan
            
        Returns:
            List of security issues found
        """
        issues = []
        lines = code.split("\n")

        for line_num, line in enumerate(lines, 1):
            for pattern, description in self.BYPASS_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append(
                        SecurityIssue(
                            severity="CRITICAL",
                            category="Authentication Bypass",
                            message=description,
                            line_number=line_num,
                            column=0,
                            code_snippet=line.strip(),
                            fix_suggestion="Implement proper authentication logic; never hardcode authentication decisions",
                            owasp_id="ASVS-2.1.1",
                            cwe_id="CWE-287",
                        )
                    )
                    break

        return issues


class AuthorizationBypassDetector:
    """
    Detect authorization bypass vulnerabilities.
    
    CWE-285: Improper Authorization
    CWE-639: Insecure Direct Object Reference (IDOR)
    
    References:
    - OWASP Top 10 2021 A01: Broken Access Control
    - SANS CWE Top 25 #25: CWE-863
    """

    IDOR_PATTERNS = [
        (r"\.get\(id\)", "Direct object access without authorization check"),
        (r"\.get\(request\..*id", "User-supplied ID without ownership verification"),
        (r"\.filter_by\(id=.*request", "Database query with user-supplied ID"),
        (r"WHERE\s+id\s*=\s*['\"]?\w+['\"]?", "SQL query with unverified ID"),
    ]

    def __init__(self):
        """Initialize authorization bypass detector."""
        self.logger = PyGuardLogger()

    def scan_code(self, code: str) -> List[SecurityIssue]:
        """
        Scan code for authorization bypass patterns.
        
        Args:
            code: Source code to scan
            
        Returns:
            List of security issues found
        """
        issues = []
        lines = code.split("\n")

        for line_num, line in enumerate(lines, 1):
            for pattern, description in self.IDOR_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    # Check if there's an ownership/permission check nearby
                    context_start = max(0, line_num - 3)
                    context_end = min(len(lines), line_num + 3)
                    context = "\n".join(lines[context_start:context_end])

                    # Look for authorization patterns
                    if not re.search(r"(check_permission|authorize|owner|current_user)", context, re.IGNORECASE):
                        issues.append(
                            SecurityIssue(
                                severity="HIGH",
                                category="Authorization Bypass (IDOR)",
                                message=description,
                                line_number=line_num,
                                column=0,
                                code_snippet=line.strip(),
                                fix_suggestion="Verify object ownership before access; check user permissions",
                                owasp_id="ASVS-4.1.1",
                                cwe_id="CWE-639",
                            )
                        )
                        break

        return issues


class InsecureSessionManagementDetector:
    """
    Detect insecure session management issues.
    
    CWE-384: Session Fixation
    CWE-613: Insufficient Session Expiration
    
    References:
    - OWASP ASVS v5.0 Section 3: Session Management
    - OWASP Top 10 2021 A07: Identification and Authentication Failures
    """

    SESSION_PATTERNS = [
        (r"session\[.+\]\s*=\s*request\.", "Session data from untrusted input"),
        (r"session\.permanent\s*=\s*True", "Permanent session without timeout"),
        (r"session_id\s*=\s*.*random\.", "Weak session ID generation"),
        (r"cookie.*httponly\s*=\s*False", "Session cookie without HttpOnly flag"),
        (r"cookie.*secure\s*=\s*False", "Session cookie without Secure flag"),
    ]

    def __init__(self):
        """Initialize session management detector."""
        self.logger = PyGuardLogger()

    def scan_code(self, code: str) -> List[SecurityIssue]:
        """
        Scan code for insecure session management.
        
        Args:
            code: Source code to scan
            
        Returns:
            List of security issues found
        """
        issues = []
        lines = code.split("\n")

        for line_num, line in enumerate(lines, 1):
            for pattern, description in self.SESSION_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append(
                        SecurityIssue(
                            severity="HIGH",
                            category="Insecure Session Management",
                            message=description,
                            line_number=line_num,
                            column=0,
                            code_snippet=line.strip(),
                            fix_suggestion="Use secure session management; set HttpOnly, Secure, and SameSite flags; implement session timeout",
                            owasp_id="ASVS-3.2.1",
                            cwe_id="CWE-384",
                        )
                    )
                    break

        return issues


class ResourceLeakDetector:
    """
    Detect resource leak vulnerabilities.
    
    CWE-404: Improper Resource Shutdown or Release
    CWE-772: Missing Release of Resource after Effective Lifetime
    
    References:
    - CERT Secure Coding FIO51-PY
    """

    RESOURCE_PATTERNS = [
        (r"open\([^)]+\)(?!.*with)", "File opened without context manager"),
        (r"socket\.socket\(", "Socket opened without proper closure"),
        (r"subprocess\.Popen\(", "Process without proper cleanup"),
        (r"threading\.Thread\(", "Thread without join()"),
    ]

    def __init__(self):
        """Initialize resource leak detector."""
        self.logger = PyGuardLogger()

    def scan_code(self, code: str) -> List[SecurityIssue]:
        """
        Scan code for resource leaks.
        
        Args:
            code: Source code to scan
            
        Returns:
            List of security issues found
        """
        issues = []
        lines = code.split("\n")

        for line_num, line in enumerate(lines, 1):
            for pattern, description in self.RESOURCE_PATTERNS:
                if re.search(pattern, line):
                    # Check if 'with' statement is used in context
                    context_start = max(0, line_num - 2)
                    context = "\n".join(lines[context_start:line_num])

                    if "with " not in context:
                        issues.append(
                            SecurityIssue(
                                severity="MEDIUM",
                                category="Resource Leak",
                                message=description,
                                line_number=line_num,
                                column=0,
                                code_snippet=line.strip(),
                                fix_suggestion="Use context managers (with statement) to ensure proper resource cleanup",
                                owasp_id="ASVS-1.4.2",
                                cwe_id="CWE-404",
                            )
                        )
                        break

        return issues


class UncontrolledResourceConsumptionDetector:
    """
    Detect uncontrolled resource consumption (DoS) vulnerabilities.
    
    CWE-400: Uncontrolled Resource Consumption
    CWE-770: Allocation of Resources Without Limits
    
    References:
    - OWASP ASVS v5.0 Section 5.1.5: Input Validation
    """

    DOS_PATTERNS = [
        (r"\.read\(\)(?!\s*\d+)", "Read without size limit"),
        (r"\.readlines\(\)", "Read all lines without limit"),
        (r"while\s+True:.*read", "Infinite loop with read"),
        (r"for\s+.*in\s+.*\.read", "Unbounded iteration over input"),
        (r"range\([^,)]+\)(?!.*if\s+.+<)", "Unbounded range without limit check"),
    ]

    def __init__(self):
        """Initialize resource consumption detector."""
        self.logger = PyGuardLogger()

    def scan_code(self, code: str) -> List[SecurityIssue]:
        """
        Scan code for uncontrolled resource consumption.
        
        Args:
            code: Source code to scan
            
        Returns:
            List of security issues found
        """
        issues = []
        lines = code.split("\n")

        for line_num, line in enumerate(lines, 1):
            for pattern, description in self.DOS_PATTERNS:
                if re.search(pattern, line):
                    issues.append(
                        SecurityIssue(
                            severity="MEDIUM",
                            category="Resource Exhaustion (DoS)",
                            message=f"Potential DoS: {description}",
                            line_number=line_num,
                            column=0,
                            code_snippet=line.strip(),
                            fix_suggestion="Set resource limits; validate input sizes; implement timeout mechanisms",
                            owasp_id="ASVS-5.1.5",
                            cwe_id="CWE-400",
                        )
                    )
                    break

        return issues


class ImproperCertificateValidationDetector:
    """
    Detect improper SSL/TLS certificate validation.
    
    CWE-295: Improper Certificate Validation
    
    References:
    - OWASP ASVS v5.0 Section 9: Communications
    - SANS CWE Top 25 (emerging)
    """

    CERT_PATTERNS = [
        (r"verify\s*=\s*False", "SSL certificate verification disabled"),
        (r"ssl\._create_unverified_context", "Unverified SSL context"),
        (r"CERT_NONE", "Certificate verification disabled"),
        (r"check_hostname\s*=\s*False", "Hostname verification disabled"),
    ]

    def __init__(self):
        """Initialize certificate validation detector."""
        self.logger = PyGuardLogger()

    def scan_code(self, code: str) -> List[SecurityIssue]:
        """
        Scan code for improper certificate validation.
        
        Args:
            code: Source code to scan
            
        Returns:
            List of security issues found
        """
        issues = []
        lines = code.split("\n")

        for line_num, line in enumerate(lines, 1):
            for pattern, description in self.CERT_PATTERNS:
                if re.search(pattern, line):
                    issues.append(
                        SecurityIssue(
                            severity="HIGH",
                            category="Improper Certificate Validation",
                            message=description,
                            line_number=line_num,
                            column=0,
                            code_snippet=line.strip(),
                            fix_suggestion="Enable SSL certificate verification; use default SSL context; validate hostnames",
                            owasp_id="ASVS-9.1.2",
                            cwe_id="CWE-295",
                        )
                    )
                    break

        return issues


class CryptographicNonceMisuseDetector:
    """
    Detect cryptographic nonce/IV misuse.
    
    CWE-323: Reusing a Nonce, Key Pair in Encryption
    CWE-329: Not Using a Random IV with CBC Mode
    
    References:
    - OWASP ASVS v5.0 Section 6.2: Cryptography
    """

    NONCE_PATTERNS = [
        (r"iv\s*=\s*b['\"]\\x00", "Hardcoded IV (all zeros)"),
        (r"nonce\s*=\s*b['\"]", "Hardcoded nonce"),
        (r"iv\s*=\s*['\"]", "Hardcoded IV string"),
        (r"\.encrypt\(.*,\s*iv\s*=\s*iv", "IV reuse detected"),
    ]

    def __init__(self):
        """Initialize nonce misuse detector."""
        self.logger = PyGuardLogger()

    def scan_code(self, code: str) -> List[SecurityIssue]:
        """
        Scan code for nonce/IV misuse.
        
        Args:
            code: Source code to scan
            
        Returns:
            List of security issues found
        """
        issues = []
        lines = code.split("\n")

        for line_num, line in enumerate(lines, 1):
            for pattern, description in self.NONCE_PATTERNS:
                if re.search(pattern, line):
                    issues.append(
                        SecurityIssue(
                            severity="HIGH",
                            category="Cryptographic Nonce Misuse",
                            message=description,
                            line_number=line_num,
                            column=0,
                            code_snippet=line.strip(),
                            fix_suggestion="Generate random IV/nonce for each encryption; use os.urandom() or secrets module",
                            owasp_id="ASVS-6.2.2",
                            cwe_id="CWE-323",
                        )
                    )
                    break

        return issues
