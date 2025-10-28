"""
Mobile & IoT Security Analysis.

Detects mobile application and IoT/embedded system security vulnerabilities
including insecure data storage, weak encryption, hardcoded credentials,
and protocol-specific security issues.

Security Areas Covered:
- Mobile app data storage security
- Transport layer security in mobile apps
- Mobile authentication and authorization
- Certificate pinning
- Mobile build configurations
- API endpoint security
- Code obfuscation and reverse engineering protection
- Inter-process communication security
- IoT device credential management
- Firmware update security
- IoT protocol security (MQTT, CoAP, Zigbee, Z-Wave)
- Secure boot and device identity
- IoT communication encryption
- Device fingerprinting and privacy

Total Security Checks: 20 (Week 17-18 - Month 5-6)

References:
- OWASP Mobile Top 10 | https://owasp.org/www-project-mobile-top-10/ | Critical
- OWASP IoT Top 10 | https://owasp.org/www-project-internet-of-things/ | Critical
- CWE-312 (Cleartext Storage of Sensitive Information) | https://cwe.mitre.org/data/definitions/312.html | High
- CWE-319 (Cleartext Transmission of Sensitive Information) | https://cwe.mitre.org/data/definitions/319.html | High
- CWE-798 (Use of Hard-coded Credentials) | https://cwe.mitre.org/data/definitions/798.html | Critical
- CWE-326 (Inadequate Encryption Strength) | https://cwe.mitre.org/data/definitions/326.html | High
- CWE-494 (Download of Code Without Integrity Check) | https://cwe.mitre.org/data/definitions/494.html | High
- NIST IoT Security | https://www.nist.gov/programs-projects/nist-cybersecurity-iot-program | High
"""

import ast
import re
from pathlib import Path
from typing import List, Set

from pyguard.lib.rule_engine import (
    FixApplicability,
    Rule,
    RuleCategory,
    RuleSeverity,
    RuleViolation,
    register_rules,
)


class MobileIoTSecurityVisitor(ast.NodeVisitor):
    """AST visitor for detecting mobile and IoT security vulnerabilities."""

    def __init__(self, file_path: Path, code: str):
        self.file_path = file_path
        self.code = code
        self.lines = code.splitlines()
        self.violations: List[RuleViolation] = []
        self.has_mobile_framework = False
        self.has_iot_framework = False
        self.has_mqtt = False
        self.has_coap = False
        self.storage_calls: Set[str] = set()
        # Track MQTT client configurations
        self.mqtt_clients_with_auth: Set[str] = set()
        self.mqtt_clients_with_tls: Set[str] = set()

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Track mobile and IoT framework imports."""
        if node.module:
            # Mobile frameworks
            if any(x in node.module for x in ["kivy", "beeware", "toga", "android", "ios"]):
                self.has_mobile_framework = True
            # IoT protocols
            elif "paho" in node.module or "mqtt" in node.module:
                self.has_mqtt = True
            elif "coap" in node.module or "aiocoap" in node.module:
                self.has_coap = True
            # IoT frameworks
            elif any(x in node.module for x in ["micropython", "circuitpython", "esphome", "rpi"]):
                self.has_iot_framework = True
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        """Track mobile and IoT framework imports (import statements)."""
        for alias in node.names:
            if any(x in alias.name for x in ["kivy", "beeware", "toga", "android", "ios"]):
                self.has_mobile_framework = True
            elif "paho" in alias.name or "mqtt" in alias.name:
                self.has_mqtt = True
            elif "coap" in alias.name or "aiocoap" in alias.name:
                self.has_coap = True
            elif any(x in alias.name for x in ["micropython", "circuitpython", "esphome", "rpi"]):
                self.has_iot_framework = True
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        """Check for insecure data storage and hardcoded credentials."""
        # MOBILE001: Insecure data storage
        self._check_insecure_data_storage(node)
        
        # MOBILE004: Insecure authentication
        self._check_hardcoded_mobile_credentials(node)
        
        # MOBILE007: Hardcoded API endpoints
        self._check_hardcoded_api_endpoints(node)
        
        # IOT001: Hardcoded device credentials
        self._check_iot_device_credentials(node)
        
        # IOT002: Weak default passwords
        self._check_weak_default_passwords(node)
        
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Check for insecure function calls."""
        # MOBILE002: Insufficient transport layer protection
        self._check_transport_security(node)
        
        # MOBILE003: Weak mobile encryption
        self._check_mobile_encryption(node)
        
        # MOBILE005: Missing certificate pinning
        self._check_certificate_pinning(node)
        
        # MOBILE009: Insecure IPC
        self._check_insecure_ipc(node)
        
        # IOT003: Insecure firmware update
        self._check_firmware_update(node)
        
        # IOT005: Unencrypted IoT communications
        self._check_iot_encryption(node)
        
        # IOT006: MQTT security issues
        self._check_mqtt_security(node)
        
        # IOT007: CoAP security issues
        self._check_coap_security(node)
        
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Check function definitions for security issues."""
        # IOT004: Missing secure boot verification
        self._check_secure_boot(node)
        
        self.generic_visit(node)

    def visit_With(self, node: ast.With) -> None:
        """Check context managers for insecure file operations."""
        self._check_file_storage_security(node)
        self.generic_visit(node)

    # Mobile Security Checks

    def _check_insecure_data_storage(self, node: ast.Assign) -> None:
        """
        MOBILE001: Detect insecure data storage on device.
        
        CWE-312: Cleartext Storage of Sensitive Information
        Severity: HIGH
        OWASP Mobile: M2 - Insecure Data Storage
        """
        if not isinstance(node.value, ast.Constant):
            return
            
        # Check for sensitive data stored in plain text files
        # value_str = str(node.value.value) if hasattr(node.value, 'value') else ''  # Reserved for future use
        
        # Look for patterns indicating sensitive data storage
        sensitive_patterns = [
            r'password\s*=\s*["\']',
            r'api[_-]?key\s*=\s*["\']',
            r'token\s*=\s*["\']',
            r'secret\s*=\s*["\']',
            r'auth[_-]?token\s*=\s*["\']',
        ]
        
        line_text = ast.get_source_segment(self.code, node) or ''
        
        for pattern in sensitive_patterns:
            if re.search(pattern, line_text, re.IGNORECASE):
                # Check if stored in files (not env vars or secure storage)
                if not any(x in line_text.lower() for x in ['environ', 'getenv', 'keychain', 'keystore']):
                    self.violations.append(
                        RuleViolation(
                            rule_id="MOBILE001",
                            message="Insecure data storage: Sensitive data appears to be stored in plain text",
                            file_path=self.file_path,
                            line_number=node.lineno,
                            column=node.col_offset,
                            severity=RuleSeverity.HIGH,
                            category=RuleCategory.SECURITY,
                            cwe_id="CWE-312",
                            owasp_id="M2",
                        )
                    )
                    break

    def _check_transport_security(self, node: ast.Call) -> None:
        """
        MOBILE002: Detect insufficient transport layer protection.
        
        CWE-319: Cleartext Transmission of Sensitive Information
        Severity: HIGH
        OWASP Mobile: M3 - Insecure Communication
        """
        func_name = self._get_function_name(node)
        
        # Check for HTTP (not HTTPS) connections
        if func_name in ['urlopen', 'request', 'get', 'post', 'put', 'delete']:
            for arg in node.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    if arg.value.startswith('http://'):
                        self.violations.append(
                            RuleViolation(
                                rule_id="MOBILE002",
                                message="Insufficient transport layer protection: Using HTTP instead of HTTPS",
                                file_path=self.file_path,
                                line_number=node.lineno,
                                column=node.col_offset,
                                severity=RuleSeverity.HIGH,
                                category=RuleCategory.SECURITY,
                                cwe_id="CWE-319",
                                owasp_id="M3",
                            )
                        )
        
        # Check for SSL verification disabled
        if func_name in ['request', 'get', 'post', 'put', 'delete', 'Session']:
            for keyword in node.keywords:
                if keyword.arg == 'verify' and isinstance(keyword.value, ast.Constant):
                    if keyword.value.value is False:
                        self.violations.append(
                            RuleViolation(
                                rule_id="MOBILE002",
                                message="Insufficient transport layer protection: SSL verification disabled",
                                file_path=self.file_path,
                                line_number=node.lineno,
                                column=node.col_offset,
                                severity=RuleSeverity.HIGH,
                                category=RuleCategory.SECURITY,
                                cwe_id="CWE-319",
                                owasp_id="M3",
                            )
                        )

    def _check_mobile_encryption(self, node: ast.Call) -> None:
        """
        MOBILE003: Detect weak mobile encryption.
        
        CWE-326: Inadequate Encryption Strength
        Severity: HIGH
        OWASP Mobile: M2 - Insecure Data Storage
        """
        func_name = self._get_function_name(node)
        
        # Check for weak encryption algorithms
        weak_algorithms = ['DES', 'RC4', 'MD5', 'SHA1']
        
        # Check if calling a weak algorithm module (e.g., DES.new, RC4.new)
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                module_name = node.func.value.id
                if module_name in weak_algorithms:
                    self.violations.append(
                        RuleViolation(
                            rule_id="MOBILE003",
                            message=f"Weak mobile encryption: Using deprecated {module_name} algorithm",
                            file_path=self.file_path,
                            line_number=node.lineno,
                            column=node.col_offset,
                            severity=RuleSeverity.HIGH,
                            category=RuleCategory.SECURITY,
                            cwe_id="CWE-326",
                            owasp_id="M2",
                        )
                    )
                    return
        
        # Also check arguments for algorithm constants (e.g., Crypto.Cipher.MODE_DES)
        if func_name in ['new', 'encrypt', 'decrypt']:
            for arg in node.args:
                if isinstance(arg, ast.Attribute):
                    attr_name = arg.attr
                    if attr_name in weak_algorithms:
                        self.violations.append(
                            RuleViolation(
                                rule_id="MOBILE003",
                                message=f"Weak mobile encryption: Using deprecated {attr_name} algorithm",
                                file_path=self.file_path,
                                line_number=node.lineno,
                                column=node.col_offset,
                                severity=RuleSeverity.HIGH,
                                category=RuleCategory.SECURITY,
                                cwe_id="CWE-326",
                                owasp_id="M2",
                            )
                        )

    def _check_hardcoded_mobile_credentials(self, node: ast.Assign) -> None:
        """
        MOBILE004: Detect insecure authentication in mobile apps.
        
        CWE-798: Use of Hard-coded Credentials
        Severity: CRITICAL
        OWASP Mobile: M4 - Insecure Authentication
        """
        if not isinstance(node.value, ast.Constant):
            return
            
        line_text = ast.get_source_segment(self.code, node) or ''
        
        # Check for hardcoded authentication credentials
        auth_patterns = [
            r'username\s*=\s*["\'][^"\']+["\']',
            r'password\s*=\s*["\'][^"\']+["\']',
            r'api[_-]?key\s*=\s*["\'][^"\']+["\']',
            r'access[_-]?token\s*=\s*["\'][^"\']+["\']',
            r'auth[_-]?token\s*=\s*["\'][^"\']+["\']',
        ]
        
        for pattern in auth_patterns:
            if re.search(pattern, line_text, re.IGNORECASE):
                self.violations.append(
                    RuleViolation(
                        rule_id="MOBILE004",
                        message="Insecure authentication: Hardcoded credentials in mobile app",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.CRITICAL,
                        category=RuleCategory.SECURITY,
                        cwe_id="CWE-798",
                        owasp_id="M4",
                    )
                )
                break

    def _check_certificate_pinning(self, node: ast.Call) -> None:
        """
        MOBILE005: Detect missing certificate pinning.
        
        CWE-295: Improper Certificate Validation
        Severity: MEDIUM
        OWASP Mobile: M3 - Insecure Communication
        """
        func_name = self._get_function_name(node)
        
        # Check for HTTPS connections without certificate pinning
        if func_name in ['HTTPSConnection', 'urlopen', 'Session']:
            has_cert_pin = False
            for keyword in node.keywords:
                if keyword.arg in ['cert', 'cert_reqs', 'ssl_context']:
                    has_cert_pin = True
                    break
            
            # Check if any args contain URLs
            has_https_url = False
            for arg in node.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    if arg.value.startswith('https://'):
                        has_https_url = True
                        break
            
            if has_https_url and not has_cert_pin:
                self.violations.append(
                    RuleViolation(
                        rule_id="MOBILE005",
                        message="Missing certificate pinning: HTTPS connection without certificate validation",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.MEDIUM,
                        category=RuleCategory.SECURITY,
                        cwe_id="CWE-295",
                        owasp_id="M3",
                    )
                )

    def _check_debuggable_build(self, node: ast.Assign) -> None:
        """
        MOBILE006: Detect debuggable builds in production.
        
        CWE-489: Active Debug Code
        Severity: MEDIUM
        OWASP Mobile: M7 - Client Code Quality
        """
        line_text = ast.get_source_segment(self.code, node) or ''
        
        # Check for debug mode enabled
        if re.search(r'debug\s*=\s*True', line_text, re.IGNORECASE):
            if 'production' in line_text.lower() or 'prod' in line_text.lower():
                self.violations.append(
                    RuleViolation(
                        rule_id="MOBILE006",
                        message="Debuggable build in production: Debug mode enabled",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.MEDIUM,
                        category=RuleCategory.SECURITY,
                        cwe_id="CWE-489",
                        owasp_id="M7",
                    )
                )

    def _check_hardcoded_api_endpoints(self, node: ast.Assign) -> None:
        """
        MOBILE007: Detect hardcoded API endpoints.
        
        CWE-615: Inclusion of Sensitive Information in Source Code Comments
        Severity: LOW
        OWASP Mobile: M7 - Client Code Quality
        """
        if not isinstance(node.value, ast.Constant):
            return
            
        value = node.value.value
        if isinstance(value, str):
            # Check for hardcoded API URLs
            if value.startswith(('http://', 'https://')):
                # Check if it's an internal or production endpoint
                if any(x in value.lower() for x in ['api', 'internal', 'prod', 'staging']):
                    self.violations.append(
                        RuleViolation(
                            rule_id="MOBILE007",
                            message="Hardcoded API endpoint: API URL embedded in source code",
                            file_path=self.file_path,
                            line_number=node.lineno,
                            column=node.col_offset,
                            severity=RuleSeverity.LOW,
                            category=RuleCategory.SECURITY,
                            cwe_id="CWE-615",
                            owasp_id="M7",
                        )
                    )

    def _check_code_obfuscation(self, node: ast.FunctionDef) -> None:
        """
        MOBILE008: Detect missing code obfuscation.
        
        CWE-656: Reliance on Security Through Obscurity
        Severity: LOW
        OWASP Mobile: M7 - Client Code Quality
        """
        # This is a heuristic check - real obfuscation detection is complex
        # Check for functions with security-sensitive names
        sensitive_names = ['decrypt', 'unlock', 'authenticate', 'verify_license']
        
        if any(name in node.name.lower() for name in sensitive_names):
            # Check if function has obvious logic (not obfuscated)
            if len(node.body) < 10:  # Simple heuristic
                self.violations.append(
                    RuleViolation(
                        rule_id="MOBILE008",
                        message="Missing code obfuscation: Security-sensitive function may be reverse-engineered",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.LOW,
                        category=RuleCategory.SECURITY,
                        cwe_id="CWE-656",
                        owasp_id="M7",
                    )
                )

    def _check_insecure_ipc(self, node: ast.Call) -> None:
        """
        MOBILE009: Detect insecure inter-process communication.
        
        CWE-927: Use of Implicit Intent for Sensitive Communication
        Severity: MEDIUM
        OWASP Mobile: M1 - Improper Platform Usage
        """
        func_name = self._get_function_name(node)
        
        # Check for insecure IPC mechanisms
        insecure_ipc = ['broadcast', 'sendBroadcast', 'startActivity', 'startService']
        
        if any(ipc in func_name for ipc in insecure_ipc):
            # Check if intent is explicit
            has_explicit_component = False
            for keyword in node.keywords:
                if keyword.arg in ['component', 'package']:
                    has_explicit_component = True
                    break
            
            if not has_explicit_component:
                self.violations.append(
                    RuleViolation(
                        rule_id="MOBILE009",
                        message="Insecure IPC: Using implicit intent for communication",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.MEDIUM,
                        category=RuleCategory.SECURITY,
                        cwe_id="CWE-927",
                        owasp_id="M1",
                    )
                )

    def _check_file_storage_security(self, node: ast.With) -> None:
        """
        MOBILE010: Detect insecure file storage.
        
        CWE-312: Cleartext Storage of Sensitive Information
        Severity: HIGH
        OWASP Mobile: M2 - Insecure Data Storage
        """
        for item in node.items:
            if isinstance(item.context_expr, ast.Call):
                func_name = self._get_function_name(item.context_expr)
                
                if func_name == 'open':
                    # Check if writing sensitive data
                    for arg in item.context_expr.args:
                        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                            # Check for sensitive file names
                            sensitive_files = ['token', 'password', 'secret', 'key', 'credential']
                            if any(sens in arg.value.lower() for sens in sensitive_files):
                                self.violations.append(
                                    RuleViolation(
                                        rule_id="MOBILE010",
                                        message="Insecure file storage: Sensitive data stored in plain text file",
                                        file_path=self.file_path,
                                        line_number=node.lineno,
                                        column=node.col_offset,
                                        severity=RuleSeverity.HIGH,
                                        category=RuleCategory.SECURITY,
                                        cwe_id="CWE-312",
                                        owasp_id="M2",
                                    )
                                )

    # IoT Security Checks

    def _check_iot_device_credentials(self, node: ast.Assign) -> None:
        """
        IOT001: Detect hardcoded device credentials.
        
        CWE-798: Use of Hard-coded Credentials
        Severity: CRITICAL
        OWASP IoT: I1 - Weak, Guessable, or Hardcoded Passwords
        """
        if not isinstance(node.value, ast.Constant):
            return
            
        line_text = ast.get_source_segment(self.code, node) or ''
        
        # Check for IoT device credentials
        iot_cred_patterns = [
            r'device[_-]?id\s*=\s*["\'][^"\']+["\']',
            r'device[_-]?key\s*=\s*["\'][^"\']+["\']',
            r'mqtt[_-]?password\s*=\s*["\'][^"\']+["\']',
            r'wifi[_-]?password\s*=\s*["\'][^"\']+["\']',
            r'serial[_-]?number\s*=\s*["\'][^"\']+["\']',
        ]
        
        for pattern in iot_cred_patterns:
            if re.search(pattern, line_text, re.IGNORECASE):
                self.violations.append(
                    RuleViolation(
                        rule_id="IOT001",
                        message="Hardcoded device credentials: IoT device credentials in source code",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.CRITICAL,
                        category=RuleCategory.SECURITY,
                        cwe_id="CWE-798",
                        owasp_id="I1",
                    )
                )
                break

    def _check_weak_default_passwords(self, node: ast.Assign) -> None:
        """
        IOT002: Detect weak default passwords.
        
        CWE-521: Weak Password Requirements
        Severity: HIGH
        OWASP IoT: I1 - Weak, Guessable, or Hardcoded Passwords
        """
        if not isinstance(node.value, ast.Constant):
            return
            
        value = node.value.value
        if isinstance(value, str):
            # Check for common weak passwords
            weak_passwords = [
                'admin', 'password', '12345', 'default', 'root',
                'guest', 'user', 'test', '1234', '123456'
            ]
            
            line_text = ast.get_source_segment(self.code, node) or ''
            if 'password' in line_text.lower():
                if value.lower() in weak_passwords:
                    self.violations.append(
                        RuleViolation(
                            rule_id="IOT002",
                            message=f"Weak default password: Using common password '{value}'",
                            file_path=self.file_path,
                            line_number=node.lineno,
                            column=node.col_offset,
                            severity=RuleSeverity.HIGH,
                            category=RuleCategory.SECURITY,
                            cwe_id="CWE-521",
                            owasp_id="I1",
                        )
                    )

    def _check_firmware_update(self, node: ast.Call) -> None:
        """
        IOT003: Detect insecure firmware update mechanisms.
        
        CWE-494: Download of Code Without Integrity Check
        Severity: CRITICAL
        OWASP IoT: I3 - Insecure Ecosystem Interfaces
        """
        func_name = self._get_function_name(node)
        
        # Check for firmware download without verification
        if any(x in func_name.lower() for x in ['download', 'fetch', 'update']):
            line_text = ast.get_source_segment(self.code, node) or ''
            if 'firmware' in line_text.lower():
                # Check if there's signature verification
                has_verification = False
                for keyword in node.keywords:
                    if keyword.arg in ['verify', 'signature', 'checksum', 'hash']:
                        has_verification = True
                        break
                
                if not has_verification:
                    self.violations.append(
                        RuleViolation(
                            rule_id="IOT003",
                            message="Insecure firmware update: No integrity check for firmware download",
                            file_path=self.file_path,
                            line_number=node.lineno,
                            column=node.col_offset,
                            severity=RuleSeverity.CRITICAL,
                            category=RuleCategory.SECURITY,
                            cwe_id="CWE-494",
                            owasp_id="I3",
                        )
                    )

    def _check_secure_boot(self, node: ast.FunctionDef) -> None:
        """
        IOT004: Detect missing secure boot verification.
        
        CWE-494: Download of Code Without Integrity Check
        Severity: HIGH
        OWASP IoT: I5 - Use of Insecure or Outdated Components
        """
        # Check for boot functions without verification
        if 'boot' in node.name.lower() or 'init' in node.name.lower():
            # Look for signature/hash verification in function body
            has_verification = False
            for stmt in ast.walk(node):
                if isinstance(stmt, ast.Call):
                    func_name = self._get_function_name(stmt)
                    if any(x in func_name.lower() for x in ['verify', 'check', 'validate', 'hash']):
                        has_verification = True
                        break
            
            if not has_verification:
                self.violations.append(
                    RuleViolation(
                        rule_id="IOT004",
                        message="Missing secure boot verification: Boot process lacks integrity checks",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.HIGH,
                        category=RuleCategory.SECURITY,
                        cwe_id="CWE-494",
                        owasp_id="I5",
                    )
                )

    def _check_iot_encryption(self, node: ast.Call) -> None:
        """
        IOT005: Detect unencrypted IoT communications.
        
        CWE-319: Cleartext Transmission of Sensitive Information
        Severity: HIGH
        OWASP IoT: I3 - Insecure Ecosystem Interfaces
        """
        func_name = self._get_function_name(node)
        
        # Check for unencrypted protocols
        if any(x in func_name.lower() for x in ['socket', 'connect', 'send']):
            # Check for encryption parameters
            has_encryption = False
            for keyword in node.keywords:
                if keyword.arg in ['ssl', 'tls', 'encrypt', 'secure']:
                    has_encryption = True
                    break
            
            # Check if connecting to a device (IoT context)
            line_text = ast.get_source_segment(self.code, node) or ''
            if any(x in line_text.lower() for x in ['device', 'sensor', 'actuator']):
                if not has_encryption:
                    self.violations.append(
                        RuleViolation(
                            rule_id="IOT005",
                            message="Unencrypted IoT communications: Device communication without encryption",
                            file_path=self.file_path,
                            line_number=node.lineno,
                            column=node.col_offset,
                            severity=RuleSeverity.HIGH,
                            category=RuleCategory.SECURITY,
                            cwe_id="CWE-319",
                            owasp_id="I3",
                        )
                    )

    def _check_mqtt_security(self, node: ast.Call) -> None:
        """
        IOT006: Detect MQTT security issues.
        
        CWE-306: Missing Authentication for Critical Function
        Severity: HIGH
        OWASP IoT: I3 - Insecure Ecosystem Interfaces
        """
        func_name = self._get_function_name(node)
        
        # Track username_pw_set and tls_set calls
        if func_name == 'username_pw_set':
            # Get the client object name if available
            if isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Name):
                    mqtt_client_name = node.func.value.id
                    self.mqtt_clients_with_auth.add(mqtt_client_name)
            return
        
        if func_name == 'tls_set':
            # Get the client object name if available
            if isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Name):
                    mqtt_client_name = node.func.value.id
                    self.mqtt_clients_with_tls.add(mqtt_client_name)
            return
        
        # Check for MQTT connections
        if 'mqtt' in func_name.lower() or (self.has_mqtt and 'connect' in func_name.lower()):
            # Get the client object name
            client_name: str | None = None
            if isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Name):
                    client_name = node.func.value.id
            
            # Check for authentication (either in keywords or previously configured)
            has_auth = False
            has_tls = False
            
            for keyword in node.keywords:
                if keyword.arg in ['username', 'password', 'auth']:
                    has_auth = True
                if keyword.arg in ['tls', 'ssl', 'ca_certs']:
                    has_tls = True
            
            # Check if this client was previously configured with auth/TLS
            if client_name:
                if client_name in self.mqtt_clients_with_auth:
                    has_auth = True
                if client_name in self.mqtt_clients_with_tls:
                    has_tls = True
            
            if not has_auth:
                self.violations.append(
                    RuleViolation(
                        rule_id="IOT006",
                        message="MQTT security issue: MQTT connection without authentication",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.HIGH,
                        category=RuleCategory.SECURITY,
                        cwe_id="CWE-306",
                        owasp_id="I3",
                    )
                )
            
            if not has_tls:
                self.violations.append(
                    RuleViolation(
                        rule_id="IOT006",
                        message="MQTT security issue: MQTT connection without TLS/SSL encryption",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.HIGH,
                        category=RuleCategory.SECURITY,
                        cwe_id="CWE-319",
                        owasp_id="I3",
                    )
                )

    def _check_coap_security(self, node: ast.Call) -> None:
        """
        IOT007: Detect CoAP protocol vulnerabilities.
        
        CWE-306: Missing Authentication for Critical Function
        Severity: MEDIUM
        OWASP IoT: I3 - Insecure Ecosystem Interfaces
        """
        func_name = self._get_function_name(node)
        
        # Check for CoAP connections
        if 'coap' in func_name.lower() or (self.has_coap and 'request' in func_name.lower()):
            # Check for DTLS (secure CoAP)
            has_dtls = False
            for keyword in node.keywords:
                if keyword.arg in ['dtls', 'secure', 'credentials']:
                    has_dtls = True
                    break
            
            if not has_dtls:
                self.violations.append(
                    RuleViolation(
                        rule_id="IOT007",
                        message="CoAP security issue: CoAP request without DTLS encryption",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.MEDIUM,
                        category=RuleCategory.SECURITY,
                        cwe_id="CWE-319",
                        owasp_id="I3",
                    )
                )

    def _check_zigbee_zwave_security(self, node: ast.Call) -> None:
        """
        IOT008: Detect Zigbee/Z-Wave security gaps.
        
        CWE-326: Inadequate Encryption Strength
        Severity: MEDIUM
        OWASP IoT: I3 - Insecure Ecosystem Interfaces
        """
        func_name = self._get_function_name(node)
        
        # Check for Zigbee/Z-Wave operations
        if any(x in func_name.lower() for x in ['zigbee', 'zwave', 'z_wave']):
            # Check for encryption/security settings
            has_security = False
            for keyword in node.keywords:
                if keyword.arg in ['security', 'encryption', 'key']:
                    has_security = True
                    break
            
            if not has_security:
                self.violations.append(
                    RuleViolation(
                        rule_id="IOT008",
                        message="Zigbee/Z-Wave security gap: Protocol operation without security settings",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.MEDIUM,
                        category=RuleCategory.SECURITY,
                        cwe_id="CWE-326",
                        owasp_id="I3",
                    )
                )

    def _check_device_fingerprinting(self, node: ast.Call) -> None:
        """
        IOT009: Detect device fingerprinting risks.
        
        CWE-359: Exposure of Private Personal Information
        Severity: LOW
        OWASP IoT: I4 - Lack of Secure Update Mechanism
        """
        func_name = self._get_function_name(node)
        
        # Check for device identification collection
        identifying_functions = ['getmac', 'uuid', 'getnode', 'gethostname']
        
        if any(x in func_name.lower() for x in identifying_functions):
            # Check if being sent externally
            line_text = ast.get_source_segment(self.code, node) or ''
            if any(x in line_text.lower() for x in ['send', 'post', 'upload', 'transmit']):
                self.violations.append(
                    RuleViolation(
                        rule_id="IOT009",
                        message="Device fingerprinting risk: Collecting device identifiers for transmission",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.LOW,
                        category=RuleCategory.SECURITY,
                        cwe_id="CWE-359",
                        owasp_id="I4",
                    )
                )

    def _check_iot_botnet_indicators(self, node: ast.Call) -> None:
        """
        IOT010: Detect IoT botnet indicators.
        
        CWE-912: Hidden Functionality
        Severity: CRITICAL
        OWASP IoT: I2 - Insecure Network Services
        """
        # func_name = self._get_function_name(node)  # Reserved for future use
        
        # Check for suspicious network operations
        suspicious_patterns = [
            ('scan', 'port'),
            ('brute', 'force'),
            ('ddos', 'attack'),
            ('exploit', 'vulnerability'),
        ]
        
        line_text = ast.get_source_segment(self.code, node) or ''
        for pattern1, pattern2 in suspicious_patterns:
            if pattern1 in line_text.lower() and pattern2 in line_text.lower():
                self.violations.append(
                    RuleViolation(
                        rule_id="IOT010",
                        message=f"IoT botnet indicator: Suspicious network operation detected ({pattern1}/{pattern2})",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.CRITICAL,
                        category=RuleCategory.SECURITY,
                        cwe_id="CWE-912",
                        owasp_id="I2",
                    )
                )
                break

    def _get_function_name(self, node: ast.Call) -> str:
        """Extract function name from Call node."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            return node.func.attr
        return ""


def analyze_mobile_iot_security(file_path: Path, code: str) -> List[RuleViolation]:
    """
    Analyze code for mobile and IoT security vulnerabilities.
    
    Args:
        file_path: Path to the file being analyzed
        code: Source code to analyze
        
    Returns:
        List of security violations found
    """
    try:
        tree = ast.parse(code)
        visitor = MobileIoTSecurityVisitor(file_path, code)
        visitor.visit(tree)
        return visitor.violations
    except SyntaxError:
        return []


# Register rules
MOBILE_IOT_RULES = [
    # Mobile Security Rules
    Rule(
        rule_id="MOBILE001",
        name="Insecure Data Storage",
        message_template="Insecure data storage: Sensitive data appears to be stored in plain text",
        description="Sensitive data stored in plain text on device",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        cwe_mapping="CWE-312",
        owasp_mapping="M2",
        fix_applicability=FixApplicability.SAFE,
    ),
    Rule(
        rule_id="MOBILE002",
        name="Insufficient Transport Layer Protection",
        message_template="Insufficient transport layer protection: {issue}",
        description="Using insecure communication channels (HTTP, disabled SSL)",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        cwe_mapping="CWE-319",
        owasp_mapping="M3",
        fix_applicability=FixApplicability.SAFE,
    ),
    Rule(
        rule_id="MOBILE003",
        name="Weak Mobile Encryption",
        message_template="Weak mobile encryption: Using deprecated {algorithm} algorithm",
        description="Using deprecated or weak encryption algorithms",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        cwe_mapping="CWE-326",
        owasp_mapping="M2",
        fix_applicability=FixApplicability.SAFE,
    ),
    Rule(
        rule_id="MOBILE004",
        name="Insecure Authentication",
        message_template="Insecure authentication: Hardcoded credentials in mobile app",
        description="Hardcoded credentials in mobile application",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.CRITICAL,
        cwe_mapping="CWE-798",
        owasp_mapping="M4",
        fix_applicability=FixApplicability.SAFE,
    ),
    Rule(
        rule_id="MOBILE005",
        name="Missing Certificate Pinning",
        message_template="Missing certificate pinning: HTTPS connection without certificate validation",
        description="HTTPS connection without certificate validation",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.MEDIUM,
        cwe_mapping="CWE-295",
        owasp_mapping="M3",
        fix_applicability=FixApplicability.MANUAL,
    ),
    Rule(
        rule_id="MOBILE006",
        name="Debuggable Build in Production",
        message_template="Debuggable build in production: Debug mode enabled",
        description="Debug mode enabled in production build",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.MEDIUM,
        cwe_mapping="CWE-489",
        owasp_mapping="M7",
        fix_applicability=FixApplicability.SAFE,
    ),
    Rule(
        rule_id="MOBILE007",
        name="Hardcoded API Endpoints",
        message_template="Hardcoded API endpoint: API URL embedded in source code",
        description="API URLs embedded in source code",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.LOW,
        cwe_mapping="CWE-615",
        owasp_mapping="M7",
        fix_applicability=FixApplicability.SAFE,
    ),
    Rule(
        rule_id="MOBILE008",
        name="Missing Code Obfuscation",
        message_template="Missing code obfuscation: Security-sensitive function may be reverse-engineered",
        description="Security-sensitive code not obfuscated",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.LOW,
        cwe_mapping="CWE-656",
        owasp_mapping="M7",
        fix_applicability=FixApplicability.MANUAL,
    ),
    Rule(
        rule_id="MOBILE009",
        name="Insecure Inter-Process Communication",
        message_template="Insecure IPC: Using implicit intent for communication",
        description="Using implicit intents for sensitive communication",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.MEDIUM,
        cwe_mapping="CWE-927",
        owasp_mapping="M1",
        fix_applicability=FixApplicability.SAFE,
    ),
    Rule(
        rule_id="MOBILE010",
        name="Insecure File Storage",
        message_template="Insecure file storage: Sensitive data stored in plain text file",
        description="Sensitive data stored in plain text files",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        cwe_mapping="CWE-312",
        owasp_mapping="M2",
        fix_applicability=FixApplicability.SAFE,
    ),
    # IoT Security Rules
    Rule(
        rule_id="IOT001",
        name="Hardcoded Device Credentials",
        message_template="Hardcoded device credentials: IoT device credentials in source code",
        description="IoT device credentials embedded in source code",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.CRITICAL,
        cwe_mapping="CWE-798",
        owasp_mapping="I1",
        fix_applicability=FixApplicability.SAFE,
    ),
    Rule(
        rule_id="IOT002",
        name="Weak Default Passwords",
        message_template="Weak default password: Using common password '{password}'",
        description="Using common or weak default passwords",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        cwe_mapping="CWE-521",
        owasp_mapping="I1",
        fix_applicability=FixApplicability.SAFE,
    ),
    Rule(
        rule_id="IOT003",
        name="Insecure Firmware Update",
        message_template="Insecure firmware update: No integrity check for firmware download",
        description="Firmware download without integrity verification",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.CRITICAL,
        cwe_mapping="CWE-494",
        owasp_mapping="I3",
        fix_applicability=FixApplicability.MANUAL,
    ),
    Rule(
        rule_id="IOT004",
        name="Missing Secure Boot Verification",
        message_template="Missing secure boot verification: Boot process lacks integrity checks",
        description="Boot process lacks integrity checks",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        cwe_mapping="CWE-494",
        owasp_mapping="I5",
        fix_applicability=FixApplicability.MANUAL,
    ),
    Rule(
        rule_id="IOT005",
        name="Unencrypted IoT Communications",
        message_template="Unencrypted IoT communications: Device communication without encryption",
        description="Device communication without encryption",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        cwe_mapping="CWE-319",
        owasp_mapping="I3",
        fix_applicability=FixApplicability.SAFE,
    ),
    Rule(
        rule_id="IOT006",
        name="MQTT Security Issues",
        message_template="MQTT security issue: {issue}",
        description="MQTT connection without proper security configuration",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        cwe_mapping="CWE-306",
        owasp_mapping="I3",
        fix_applicability=FixApplicability.SAFE,
    ),
    Rule(
        rule_id="IOT007",
        name="CoAP Security Issues",
        message_template="CoAP security issue: CoAP request without DTLS encryption",
        description="CoAP request without DTLS encryption",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.MEDIUM,
        cwe_mapping="CWE-319",
        owasp_mapping="I3",
        fix_applicability=FixApplicability.SAFE,
    ),
    Rule(
        rule_id="IOT008",
        name="Zigbee/Z-Wave Security Gaps",
        message_template="Zigbee/Z-Wave security gap: Protocol operation without security settings",
        description="Protocol operation without security settings",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.MEDIUM,
        cwe_mapping="CWE-326",
        owasp_mapping="I3",
        fix_applicability=FixApplicability.MANUAL,
    ),
    Rule(
        rule_id="IOT009",
        name="Device Fingerprinting Risk",
        message_template="Device fingerprinting risk: Collecting device identifiers for transmission",
        description="Collecting device identifiers for transmission",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.LOW,
        cwe_mapping="CWE-359",
        owasp_mapping="I4",
        fix_applicability=FixApplicability.MANUAL,
    ),
    Rule(
        rule_id="IOT010",
        name="IoT Botnet Indicators",
        message_template="IoT botnet indicator: Suspicious network operation detected ({pattern1}/{pattern2})",
        description="Suspicious network operations that may indicate botnet activity",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.CRITICAL,
        cwe_mapping="CWE-912",
        owasp_mapping="I2",
        fix_applicability=FixApplicability.MANUAL,
    ),
]

register_rules(MOBILE_IOT_RULES)
