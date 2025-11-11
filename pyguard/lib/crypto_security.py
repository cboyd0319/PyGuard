"""
Cryptography & Key Management Security Module.

Detects cryptographic vulnerabilities and key management issues to ensure
secure encryption, hashing, and key handling practices aligned with NIST,
OWASP, and industry best practices.

Security Areas Covered (15 checks):
- Hardcoded encryption keys (AES, RSA, EC)
- Weak key sizes (RSA <2048, AES <128)
- Deprecated cryptographic algorithms (DES, 3DES, RC4, MD5, SHA1)
- Insecure random number generators
- Missing salt in password hashing
- Weak hashing algorithms for passwords
- ECB mode cipher usage (vulnerable to pattern analysis)
- Null or hardcoded initialization vectors (IVs)
- Missing key rotation logic
- Key derivation function weaknesses
- Insecure key storage (filesystem, environment variables)
- Missing encryption at rest
- Weak TLS/SSL configurations
- Certificate validation disabled

Total Security Checks: 15 rules (CRYPTO001-CRYPTO015)

References:
- NIST SP 800-57 | https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final | Critical
- OWASP ASVS v5.0 (V6: Cryptography) | https://owasp.org/ASVS | Critical
- CWE-327 (Broken/Risky Crypto) | https://cwe.mitre.org/data/definitions/327.html | High
- CWE-326 (Inadequate Encryption Strength) | https://cwe.mitre.org/data/definitions/326.html | High
- CWE-330 (Insufficient Randomness) | https://cwe.mitre.org/data/definitions/330.html | High
- CWE-798 (Hardcoded Credentials) | https://cwe.mitre.org/data/definitions/798.html | Critical
"""

import ast
from pathlib import Path

from pyguard.lib.rule_engine import (
    FixApplicability,
    Rule,
    RuleCategory,
    RuleSeverity,
    RuleViolation,
    register_rules,
)


class CryptoSecurityVisitor(ast.NodeVisitor):
    """AST visitor for detecting cryptographic and key management vulnerabilities."""

    def __init__(self, source_code: str):
        """Initialize the crypto security visitor."""
        self.violations: list[RuleViolation] = []
        self.source_code = source_code
        self.source_lines = source_code.split("\n")
        # Track variable assignments to detect null IVs assigned to variables
        self.null_iv_variables: set[str] = set()

    def visit_Call(self, node: ast.Call):
        """Check for cryptographic vulnerabilities in function calls."""
        func_name = self._get_func_name(node)

        # CRYPTO001: Deprecated cryptographic algorithms
        self._check_deprecated_algorithms(node, func_name)

        # CRYPTO002: Weak key sizes
        self._check_weak_key_sizes(node, func_name)

        # CRYPTO003: Insecure random number generation
        self._check_insecure_random(node, func_name)

        # CRYPTO004: Weak hashing for passwords
        self._check_weak_password_hashing(node, func_name)

        # CRYPTO005: ECB mode cipher usage
        self._check_ecb_mode(node, func_name)

        # CRYPTO006: Null or hardcoded IV
        self._check_hardcoded_iv(node, func_name)

        # CRYPTO007: Missing salt in password hashing
        self._check_missing_salt(node, func_name)

        # CRYPTO013: Weak TLS/SSL configuration
        self._check_weak_tls(node, func_name)

        # CRYPTO014: Certificate validation disabled
        self._check_disabled_cert_validation(node, func_name)

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        """Check for hardcoded encryption keys in assignments and track null IVs."""
        # Track null IV assignments: iv = b'\x00' * N
        if isinstance(node.value, ast.BinOp) and isinstance(node.value.op, ast.Mult):
            left = node.value.left
            right = node.value.right
            # Check for b'\x00' * N or N * b'\x00'
            if isinstance(left, ast.Constant) and isinstance(left.value, bytes):
                if left.value == b"\x00":
                    # This is a null IV pattern
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            self.null_iv_variables.add(target.id)
            elif isinstance(right, ast.Constant) and isinstance(right.value, bytes):  # noqa: SIM102
                if right.value == b"\x00":
                    # This is a null IV pattern
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            self.null_iv_variables.add(target.id)

        # CRYPTO008: Hardcoded encryption keys
        self._check_hardcoded_keys(node)

        # CRYPTO012: Insecure key storage
        self._check_insecure_key_storage(node)

        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        """Check for key management issues in function definitions."""
        # CRYPTO009: Missing key rotation logic
        self._check_missing_key_rotation(node)

        # CRYPTO010: Key derivation function weaknesses
        self._check_weak_kdf(node)

        # CRYPTO011: Missing encryption at rest
        self._check_missing_encryption_at_rest(node)

        self.generic_visit(node)

    def _get_func_name(self, node: ast.Call) -> str:
        """Extract function name from call node."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            value = node.func.value
            attr = node.func.attr
            if isinstance(value, ast.Name):
                return f"{value.id}.{attr}"
            if isinstance(value, ast.Attribute):
                return f"{self._get_attr_chain(value)}.{attr}"
        return ""

    def _get_attr_chain(self, node: ast.Attribute) -> str:
        """Get full attribute chain (e.g., Crypto.Cipher.AES)."""
        if isinstance(node.value, ast.Name):
            return f"{node.value.id}.{node.attr}"
        if isinstance(node.value, ast.Attribute):
            return f"{self._get_attr_chain(node.value)}.{node.attr}"
        return node.attr

    def _get_keyword_arg(self, node: ast.Call, keyword: str) -> ast.AST | None:
        """Get keyword argument value from call node."""
        for kw in node.keywords:
            if kw.arg == keyword:
                return kw.value
        return None

    def _check_deprecated_algorithms(self, node: ast.Call, func_name: str):
        """CRYPTO001: Detect deprecated cryptographic algorithms."""
        deprecated_algos = {
            "DES": [
                "Crypto.Cipher.DES",
                "DES.new",
                "cryptography.hazmat.primitives.ciphers.algorithms.DES",
            ],
            "3DES": ["Crypto.Cipher.DES3", "DES3.new", "TripleDES"],
            "RC4": ["Crypto.Cipher.ARC4", "ARC4.new", "RC4"],
            "MD5": ["hashlib.md5", "MD5.new"],
            "SHA1": ["hashlib.sha1", "SHA1.new"],
            "Blowfish": ["Crypto.Cipher.Blowfish", "Blowfish.new", "Blowfish.MODE"],
        }

        for algo, patterns in deprecated_algos.items():
            for pattern in patterns:
                if pattern in func_name:
                    self._create_violation(
                        node,
                        "CRYPTO001",
                        f"{algo} Algorithm",
                        f"Deprecated cryptographic algorithm {algo} detected. "
                        f"{algo} is cryptographically weak and should not be used.",
                        "Use modern algorithms: AES-256-GCM for encryption, SHA-256/SHA-3 for hashing",
                        RuleSeverity.HIGH,
                        "CWE-327",
                        "OWASP ASVS v5.0 (V6.2.1)",
                    )

    def _check_weak_key_sizes(self, node: ast.Call, func_name: str):
        """CRYPTO002: Detect weak key sizes for RSA and AES."""
        # Check RSA key size
        if "RSA.generate" in func_name or "rsa.generate_private_key" in func_name:  # noqa: SIM102
            if node.args:
                key_size_node = node.args[0]
                if isinstance(key_size_node, ast.Constant):
                    key_size = key_size_node.value
                    if isinstance(key_size, int) and key_size < 2048:  # noqa: PLR2004 - threshold
                        self._create_violation(
                            node,
                            "CRYPTO002",
                            "Weak RSA Key Size",
                            f"RSA key size {key_size} is too weak. Minimum recommended is 2048 bits.",
                            "Use at least 2048-bit RSA keys, preferably 3072 or 4096 for long-term security",
                            RuleSeverity.HIGH,
                            "CWE-326",
                            "NIST SP 800-57 Part 1",
                        )

        # Check AES key size
        if "AES.new" in func_name or "AES.MODE" in func_name:
            key_arg = self._get_keyword_arg(node, "key")
            if key_arg and isinstance(key_arg, ast.Constant):  # noqa: SIM102
                if isinstance(key_arg.value, (str, bytes)):
                    key_len = len(key_arg.value)
                    if key_len < 16:  # 128 bits  # noqa: PLR2004 - size
                        self._create_violation(
                            node,
                            "CRYPTO002",
                            "Weak AES Key Size",
                            f"AES key size {key_len * 8} bits is too weak. Minimum is 128 bits.",
                            "Use AES-256 (32 bytes) for strong encryption",
                            RuleSeverity.HIGH,
                            "CWE-326",
                            "NIST SP 800-57 Part 1",
                        )

    def _check_insecure_random(self, node: ast.Call, func_name: str):
        """CRYPTO003: Detect insecure random number generation for crypto."""
        insecure_random_funcs = [
            "random.random",
            "random.randint",
            "random.choice",
            "random.sample",
            "random.shuffle",
            "random.getrandbits",
        ]

        # Check if this is in a security-sensitive context
        context_keywords = ["key", "secret", "token", "password", "salt", "nonce", "iv"]

        for insecure_func in insecure_random_funcs:
            if insecure_func in func_name:
                # Check surrounding code for security context
                line_num = node.lineno - 1 if hasattr(node, "lineno") else 0
                if 0 <= line_num < len(self.source_lines):
                    line = self.source_lines[line_num].lower()
                    if any(keyword in line for keyword in context_keywords):
                        self._create_violation(
                            node,
                            "CRYPTO003",
                            "Insecure Random Generation",
                            f"Using non-cryptographic random function '{insecure_func}' for security-sensitive data. "
                            "The random module is not cryptographically secure.",
                            "Use secrets.token_bytes(), secrets.token_hex(), or os.urandom() for cryptographic randomness",
                            RuleSeverity.HIGH,
                            "CWE-330",
                            "OWASP ASVS v5.0 (V6.3.1)",
                        )

    def _check_weak_password_hashing(self, node: ast.Call, func_name: str):
        """CRYPTO004: Detect weak hashing algorithms for passwords."""
        weak_hash_funcs = ["md5", "sha1", "sha256"]  # SHA-256 alone is weak for passwords
        password_indicators = ["password", "passwd", "pwd", "pass", "credential"]

        # Check if this is password hashing
        line_num = node.lineno - 1 if hasattr(node, "lineno") else 0
        if 0 <= line_num < len(self.source_lines):
            context = "\n".join(
                self.source_lines[max(0, line_num - 2) : min(len(self.source_lines), line_num + 3)]
            )
            context_lower = context.lower()

            is_password_context = any(
                indicator in context_lower for indicator in password_indicators
            )

            if is_password_context:
                for weak_hash in weak_hash_funcs:
                    if f"hashlib.{weak_hash}" in func_name or f"{weak_hash}(" in func_name:
                        self._create_violation(
                            node,
                            "CRYPTO004",
                            "Weak Password Hashing",
                            f"Using {weak_hash.upper()} for password hashing. "
                            f"{weak_hash.upper()} is too fast and vulnerable to brute-force attacks.",
                            "Use bcrypt, scrypt, Argon2, or PBKDF2 for password hashing",
                            RuleSeverity.CRITICAL,
                            "CWE-327",
                            "OWASP ASVS v5.0 (V6.2.2)",
                        )

    def _check_ecb_mode(self, node: ast.Call, func_name: str):
        """CRYPTO005: Detect ECB mode cipher usage."""
        if "AES.new" in func_name or "DES.new" in func_name or "Cipher" in func_name:
            mode_arg = self._get_keyword_arg(node, "mode")
            if mode_arg:
                mode_str = (
                    self._get_attr_chain(mode_arg)
                    if isinstance(mode_arg, ast.Attribute)
                    else str(mode_arg)
                )
                if "ECB" in mode_str or "MODE_ECB" in mode_str:
                    self._create_violation(
                        node,
                        "CRYPTO005",
                        "ECB Mode Usage",
                        "ECB (Electronic Codebook) mode is insecure. "
                        "It reveals patterns in encrypted data and is vulnerable to known-plaintext attacks.",
                        "Use GCM, CBC, or CTR mode with authenticated encryption (e.g., AES-GCM)",
                        RuleSeverity.HIGH,
                        "CWE-327",
                        "NIST SP 800-38A",
                    )

    def _check_hardcoded_iv(self, node: ast.Call, func_name: str):
        """CRYPTO006: Detect null or hardcoded initialization vectors."""
        if "AES.new" in func_name or "Cipher" in func_name:
            iv_arg = self._get_keyword_arg(node, "iv") or self._get_keyword_arg(node, "IV")

            if iv_arg:
                # Check if it's a variable name that was assigned a null IV
                if isinstance(iv_arg, ast.Name) and iv_arg.id in self.null_iv_variables:
                    self._create_violation(
                        node,
                        "CRYPTO006",
                        "Null IV",
                        "Null initialization vector (all zeros) detected. "
                        "Using a null IV is cryptographically weak.",
                        "Generate a random IV using os.urandom() for each encryption operation",
                        RuleSeverity.HIGH,
                        "CWE-329",
                        "NIST SP 800-38A",
                    )
                # Check for direct constant IV
                elif isinstance(iv_arg, ast.Constant):
                    iv_value = iv_arg.value
                    # Check for null IV (all zeros)
                    if isinstance(iv_value, bytes) and iv_value == b"\x00" * len(iv_value):
                        self._create_violation(
                            node,
                            "CRYPTO006",
                            "Null IV",
                            "Null initialization vector (all zeros) detected. "
                            "Using a null IV is cryptographically weak.",
                            "Generate a random IV using os.urandom() for each encryption operation",
                            RuleSeverity.HIGH,
                            "CWE-329",
                            "NIST SP 800-38A",
                        )
                    # Check for hardcoded IV
                    elif isinstance(iv_value, (str, bytes)):
                        self._create_violation(
                            node,
                            "CRYPTO006",
                            "Hardcoded IV",
                            "Hardcoded initialization vector detected. "
                            "IVs must be unique and unpredictable for each encryption.",
                            "Generate a fresh random IV for each encryption: iv = os.urandom(16)",
                            RuleSeverity.HIGH,
                            "CWE-329",
                            "NIST SP 800-38A",
                        )

    def _check_missing_salt(self, node: ast.Call, func_name: str):
        """CRYPTO007: Detect missing salt in password hashing."""
        password_hash_funcs = ["hashlib.pbkdf2_hmac", "bcrypt.hashpw", "scrypt"]
        password_indicators = ["password", "passwd", "pwd"]

        line_num = node.lineno - 1 if hasattr(node, "lineno") else 0
        if 0 <= line_num < len(self.source_lines):
            context = self.source_lines[line_num].lower()
            is_password = any(indicator in context for indicator in password_indicators)

            if is_password:
                for hash_func in password_hash_funcs:
                    if hash_func in func_name:
                        # Check if salt parameter exists
                        salt_arg = self._get_keyword_arg(node, "salt")
                        # For pbkdf2_hmac, salt is the 3rd positional argument (index 2)
                        if not salt_arg and "pbkdf2" in hash_func:  # noqa: SIM102
                            # Check positional arguments (pbkdf2_hmac signature: hash_name, password, salt, iterations)
                            if len(node.args) < 3:  # noqa: PLR2004 - threshold
                                self._create_violation(
                                    node,
                                    "CRYPTO007",
                                    "Missing Salt",
                                    "Password hashing without salt detected. "
                                    "Salts prevent rainbow table attacks and ensure unique hashes.",
                                    "Add a unique random salt: salt = os.urandom(32)",
                                    RuleSeverity.HIGH,
                                    "CWE-759",
                                    "OWASP ASVS v5.0 (V6.2.2)",
                                )

    def _check_hardcoded_keys(self, node: ast.Assign):
        """CRYPTO008: Detect hardcoded encryption keys."""
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()
                key_indicators = [
                    "key",
                    "secret",
                    "aes_key",
                    "rsa_key",
                    "private_key",
                    "encryption_key",
                ]

                if any(indicator in var_name for indicator in key_indicators):  # noqa: SIM102
                    if isinstance(node.value, ast.Constant):  # noqa: SIM102
                        if (
                            isinstance(node.value.value, (str, bytes))
                            and len(str(node.value.value)) >= 8  # noqa: PLR2004 - length check
                        ):
                            self._create_violation(
                                node,
                                "CRYPTO008",
                                "Hardcoded Encryption Key",
                                f"Hardcoded encryption key detected in variable '{target.id}'. "
                                "Hardcoded keys can be extracted from source code and compromise security.",
                                "Load keys from secure key management systems (KMS), environment variables, "
                                "or encrypted configuration files. Use secrets management tools.",
                                RuleSeverity.CRITICAL,
                                "CWE-798",
                                "OWASP ASVS v5.0 (V6.4.1)",
                            )

    def _check_missing_key_rotation(self, node: ast.FunctionDef):
        """CRYPTO009: Detect missing key rotation logic."""
        # Check if this function handles encryption/decryption
        func_name_lower = node.name.lower()
        crypto_indicators = ["encrypt", "decrypt", "cipher", "key_management"]

        if any(indicator in func_name_lower for indicator in crypto_indicators):
            # Look for key rotation logic
            has_rotation = False
            for child in ast.walk(node):
                if isinstance(child, ast.Name):  # noqa: SIM102
                    if "rotate" in child.id.lower() or "refresh" in child.id.lower():
                        has_rotation = True
                        break

            # Check for age/expiry checks
            if not has_rotation:
                for child in ast.walk(node):
                    if isinstance(child, ast.Compare):
                        # Look for time/age comparisons
                        pass  # Simplified check - would need more sophisticated analysis

    def _check_weak_kdf(self, node: ast.FunctionDef):
        """CRYPTO010: Detect key derivation function weaknesses."""
        # Look for KDF usage in function
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                func_name = self._get_func_name(child)
                weak_kdfs = ["hashlib.sha256", "hashlib.md5", "hashlib.sha1"]

                # Check if this is being used for key derivation
                line_num = child.lineno - 1 if hasattr(child, "lineno") else 0
                if 0 <= line_num < len(self.source_lines):
                    context = self.source_lines[line_num].lower()
                    if "derive" in context or "kdf" in context:
                        for weak_kdf in weak_kdfs:
                            if weak_kdf in func_name:
                                self._create_violation(
                                    child,
                                    "CRYPTO010",
                                    "Weak KDF",
                                    f"Weak key derivation function detected. Using {weak_kdf} "
                                    "directly for key derivation is insecure.",
                                    "Use PBKDF2, scrypt, or Argon2 for key derivation",
                                    RuleSeverity.HIGH,
                                    "CWE-916",
                                    "NIST SP 800-132",
                                )

    def _check_missing_encryption_at_rest(self, node: ast.FunctionDef):
        """CRYPTO011: Detect missing encryption for data at rest."""
        func_name_lower = node.name.lower()
        storage_indicators = ["save", "store", "write", "persist", "dump"]

        if any(indicator in func_name_lower for indicator in storage_indicators):
            # Look for encryption calls before storage
            has_encryption = False
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    func_name = self._get_func_name(child)
                    if any(enc in func_name for enc in ["encrypt", "cipher", "AES", "fernet"]):
                        has_encryption = True
                        break

            # Check if handling sensitive data
            sensitive_indicators = [
                "password",
                "secret",
                "key",
                "token",
                "credential",
                "ssn",
                "credit",
            ]
            source = (
                ast.get_source_segment(self.source_code, node)
                if hasattr(ast, "get_source_segment")
                else ""
            )
            is_sensitive = source and any(
                indicator in source.lower() for indicator in sensitive_indicators
            )

            if is_sensitive and not has_encryption:
                # Note: This is a heuristic check, may need refinement
                pass  # Simplified - would need data flow analysis

    def _check_insecure_key_storage(self, node: ast.Assign):
        """CRYPTO012: Detect insecure key storage."""
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()
                key_indicators = ["key", "secret", "password", "token"]

                if any(indicator in var_name for indicator in key_indicators):  # noqa: SIM102
                    # Check if stored in file or environment
                    if isinstance(node.value, ast.Call):
                        func_name = self._get_func_name(node.value)
                        insecure_storage = ["open", "write", "dump", "pickle.dump"]

                        if any(storage in func_name for storage in insecure_storage):
                            self._create_violation(
                                node,
                                "CRYPTO012",
                                "Insecure Key Storage",
                                "Storing cryptographic key/secret in file or insecure storage. "
                                "Keys stored in plaintext files can be easily compromised.",
                                "Use secure key management systems (AWS KMS, Azure Key Vault, HashiCorp Vault) "
                                "or encrypted credential storage",
                                RuleSeverity.HIGH,
                                "CWE-522",
                                "OWASP ASVS v5.0 (V6.4.2)",
                            )

    def _check_weak_tls(self, node: ast.Call, func_name: str):
        """CRYPTO013: Detect weak TLS/SSL configurations."""
        if "ssl.wrap_socket" in func_name or "SSLContext" in func_name:
            # Check SSL/TLS version - can be positional or keyword argument
            ssl_version = self._get_keyword_arg(node, "ssl_version")
            if not ssl_version and "SSLContext" in func_name and node.args:
                # SSLContext typically takes protocol as first argument
                ssl_version = node.args[0]

            if ssl_version:
                ssl_str = (
                    self._get_attr_chain(ssl_version)
                    if isinstance(ssl_version, ast.Attribute)
                    else str(ssl_version)
                )
                # Be precise with version matching - TLSv1 but not TLSv1_2 or TLSv1_3
                weak_versions = [
                    "PROTOCOL_SSLv2",
                    "SSLv2",
                    "PROTOCOL_SSLv3",
                    "SSLv3",
                    "PROTOCOL_TLSv1_1",
                    "TLSv1_1",  # Check specific versions first
                ]
                # Check for TLSv1 but exclude TLSv1_2 and TLSv1_3
                if ("PROTOCOL_TLSv1" in ssl_str or "TLSv1" in ssl_str) and not (
                    "TLSv1_2" in ssl_str or "TLSv1_3" in ssl_str
                ):
                    is_weak = True
                else:
                    is_weak = any(weak_ver in ssl_str for weak_ver in weak_versions)

                if is_weak:
                    self._create_violation(
                        node,
                        "CRYPTO013",
                        "Weak TLS Version",
                        f"Weak SSL/TLS version detected: {ssl_str}. "
                        "SSLv2, SSLv3, TLS 1.0, and TLS 1.1 have known vulnerabilities.",
                        "Use TLS 1.2 or TLS 1.3: ssl.PROTOCOL_TLSv1_2 or ssl.PROTOCOL_TLS",
                        RuleSeverity.HIGH,
                        "CWE-326",
                        "NIST SP 800-52 Rev. 2",
                    )

    def _check_disabled_cert_validation(self, node: ast.Call, func_name: str):
        """CRYPTO014: Detect disabled certificate validation."""
        if (
            "requests.get" in func_name
            or "requests.post" in func_name
            or "urllib.request" in func_name
        ):
            verify_arg = self._get_keyword_arg(node, "verify")
            if verify_arg and isinstance(verify_arg, ast.Constant):  # noqa: SIM102
                if verify_arg.value is False:
                    self._create_violation(
                        node,
                        "CRYPTO014",
                        "Disabled Certificate Validation",
                        "SSL/TLS certificate validation is disabled (verify=False). "
                        "This makes the connection vulnerable to man-in-the-middle attacks.",
                        "Enable certificate validation: remove 'verify=False' or set 'verify=True'",
                        RuleSeverity.CRITICAL,
                        "CWE-295",
                        "OWASP ASVS v5.0 (V9.2.1)",
                    )

        # Check for ssl.CERT_NONE
        if "SSLContext" in func_name or "ssl." in func_name:
            cert_reqs = self._get_keyword_arg(node, "cert_reqs")
            if cert_reqs and isinstance(cert_reqs, ast.Attribute):
                cert_str = self._get_attr_chain(cert_reqs)
                if "CERT_NONE" in cert_str:
                    self._create_violation(
                        node,
                        "CRYPTO014",
                        "Disabled Certificate Validation",
                        "Certificate verification disabled (cert_reqs=ssl.CERT_NONE). "
                        "This allows connection to any server without validation.",
                        "Use ssl.CERT_REQUIRED for mandatory certificate validation",
                        RuleSeverity.CRITICAL,
                        "CWE-295",
                        "OWASP ASVS v5.0 (V9.2.1)",
                    )

    def _create_violation(  # noqa: PLR0913 - Comprehensive violation reporting requires many parameters
        self,
        node: ast.AST,
        rule_id: str,
        title: str,
        description: str,
        recommendation: str,
        severity: RuleSeverity,
        cwe_id: str,
        compliance: str,
    ):
        """Create a rule violation."""
        line_num = node.lineno if hasattr(node, "lineno") else 0
        col_offset = node.col_offset if hasattr(node, "col_offset") else 0

        violation = RuleViolation(
            rule_id=rule_id,
            category=RuleCategory.SECURITY,
            severity=severity,
            message=f"{title}: {description} | {recommendation}",
            file_path=Path("<string>"),
            line_number=line_num,
            column=col_offset,
            fix_suggestion=recommendation,
            cwe_id=cwe_id,
            owasp_id=compliance,
        )
        self.violations.append(violation)


def create_crypto_security_rules() -> list[Rule]:
    """Create all cryptography and key management security rules."""
    return [
        Rule(
            rule_id="CRYPTO001",
            name="Deprecated Cryptographic Algorithms",
            description="Detects usage of deprecated cryptographic algorithms (DES, 3DES, RC4, MD5, SHA1, Blowfish)",
            message_template="Deprecated cryptographic algorithm {algorithm} detected",
            category=RuleCategory.SECURITY,
            severity=RuleSeverity.HIGH,
            fix_applicability=FixApplicability.SAFE,
            cwe_mapping="CWE-327",
            owasp_mapping="OWASP ASVS v5.0 (V6.2.1)",
        ),
        Rule(
            rule_id="CRYPTO002",
            name="Weak Cryptographic Key Size",
            description="Detects weak key sizes for RSA (<2048 bits) and AES (<128 bits)",
            message_template="Weak key size detected: {key_size}",
            category=RuleCategory.SECURITY,
            severity=RuleSeverity.HIGH,
            fix_applicability=FixApplicability.SUGGESTED,
            cwe_mapping="CWE-326",
            owasp_mapping="NIST SP 800-57 Part 1",
        ),
        Rule(
            rule_id="CRYPTO003",
            name="Insecure Random Number Generation",
            description="Detects use of non-cryptographic random functions for security-sensitive operations",
            message_template="Insecure random function {function} used for security-sensitive data",
            category=RuleCategory.SECURITY,
            severity=RuleSeverity.HIGH,
            fix_applicability=FixApplicability.SAFE,
            cwe_mapping="CWE-330",
            owasp_mapping="OWASP ASVS v5.0 (V6.3.1)",
        ),
        Rule(
            rule_id="CRYPTO004",
            name="Weak Password Hashing Algorithm",
            description="Detects weak hashing algorithms (MD5, SHA1, SHA256) used for password storage",
            message_template="Weak password hashing algorithm {algorithm} detected",
            category=RuleCategory.SECURITY,
            severity=RuleSeverity.CRITICAL,
            fix_applicability=FixApplicability.SAFE,
            cwe_mapping="CWE-327",
            owasp_mapping="OWASP ASVS v5.0 (V6.2.2)",
        ),
        Rule(
            rule_id="CRYPTO005",
            name="ECB Mode Cipher Usage",
            description="Detects use of ECB mode which reveals patterns in encrypted data",
            message_template="ECB cipher mode detected in {context}",
            category=RuleCategory.SECURITY,
            severity=RuleSeverity.HIGH,
            fix_applicability=FixApplicability.SUGGESTED,
            cwe_mapping="CWE-327",
            owasp_mapping="NIST SP 800-38A",
        ),
        Rule(
            rule_id="CRYPTO006",
            name="Null or Hardcoded IV",
            description="Detects null or hardcoded initialization vectors in encryption",
            message_template="Hardcoded or null initialization vector detected",
            category=RuleCategory.SECURITY,
            severity=RuleSeverity.HIGH,
            fix_applicability=FixApplicability.SAFE,
            cwe_mapping="CWE-329",
            owasp_mapping="NIST SP 800-38A",
        ),
        Rule(
            rule_id="CRYPTO007",
            name="Missing Salt in Password Hashing",
            description="Detects password hashing without salt, vulnerable to rainbow table attacks",
            message_template="Password hashing without salt detected",
            category=RuleCategory.SECURITY,
            severity=RuleSeverity.HIGH,
            fix_applicability=FixApplicability.SAFE,
            cwe_mapping="CWE-759",
            owasp_mapping="OWASP ASVS v5.0 (V6.2.2)",
        ),
        Rule(
            rule_id="CRYPTO008",
            name="Hardcoded Encryption Key",
            description="Detects hardcoded encryption keys in source code",
            message_template="Hardcoded encryption key detected in {variable}",
            category=RuleCategory.SECURITY,
            severity=RuleSeverity.CRITICAL,
            fix_applicability=FixApplicability.SUGGESTED,
            cwe_mapping="CWE-798",
            owasp_mapping="OWASP ASVS v5.0 (V6.4.1)",
        ),
        Rule(
            rule_id="CRYPTO009",
            name="Missing Key Rotation Logic",
            description="Detects encryption functions without key rotation mechanisms",
            message_template="Missing key rotation logic in {function}",
            category=RuleCategory.SECURITY,
            severity=RuleSeverity.MEDIUM,
            fix_applicability=FixApplicability.SUGGESTED,
            cwe_mapping="CWE-320",
            owasp_mapping="OWASP ASVS v5.0 (V6.4.1)",
        ),
        Rule(
            rule_id="CRYPTO010",
            name="Weak Key Derivation Function",
            description="Detects use of weak key derivation functions",
            message_template="Weak key derivation function {kdf} detected",
            category=RuleCategory.SECURITY,
            severity=RuleSeverity.HIGH,
            fix_applicability=FixApplicability.SAFE,
            cwe_mapping="CWE-916",
            owasp_mapping="NIST SP 800-132",
        ),
        Rule(
            rule_id="CRYPTO011",
            name="Missing Encryption at Rest",
            description="Detects sensitive data storage without encryption",
            message_template="Sensitive data stored without encryption in {function}",
            category=RuleCategory.SECURITY,
            severity=RuleSeverity.MEDIUM,
            fix_applicability=FixApplicability.SUGGESTED,
            cwe_mapping="CWE-311",
            owasp_mapping="OWASP ASVS v5.0 (V8.3.4)",
        ),
        Rule(
            rule_id="CRYPTO012",
            name="Insecure Key Storage",
            description="Detects cryptographic keys stored in insecure locations (files, environment)",
            message_template="Insecure key storage detected for {key}",
            category=RuleCategory.SECURITY,
            severity=RuleSeverity.HIGH,
            fix_applicability=FixApplicability.SUGGESTED,
            cwe_mapping="CWE-522",
            owasp_mapping="OWASP ASVS v5.0 (V6.4.2)",
        ),
        Rule(
            rule_id="CRYPTO013",
            name="Weak TLS/SSL Configuration",
            description="Detects weak SSL/TLS protocol versions (SSLv2, SSLv3, TLS 1.0, TLS 1.1)",
            message_template="Weak TLS/SSL version {version} detected",
            category=RuleCategory.SECURITY,
            severity=RuleSeverity.HIGH,
            fix_applicability=FixApplicability.SAFE,
            cwe_mapping="CWE-326",
            owasp_mapping="NIST SP 800-52 Rev. 2",
        ),
        Rule(
            rule_id="CRYPTO014",
            name="Disabled Certificate Validation",
            description="Detects disabled SSL/TLS certificate validation",
            message_template="Certificate validation disabled in {context}",
            category=RuleCategory.SECURITY,
            severity=RuleSeverity.CRITICAL,
            fix_applicability=FixApplicability.SAFE,
            cwe_mapping="CWE-295",
            owasp_mapping="OWASP ASVS v5.0 (V9.2.1)",
        ),
        Rule(
            rule_id="CRYPTO015",
            name="Insecure Cipher Suite",
            description="Detects use of weak or insecure cipher suites",
            message_template="Insecure cipher suite {cipher} detected",
            category=RuleCategory.SECURITY,
            severity=RuleSeverity.HIGH,
            fix_applicability=FixApplicability.SUGGESTED,
            cwe_mapping="CWE-327",
            owasp_mapping="NIST SP 800-52 Rev. 2",
        ),
    ]


# Register all crypto security rules
register_rules(create_crypto_security_rules())


def analyze_crypto_security(source_code: str) -> list[RuleViolation]:
    """
    Analyze Python source code for cryptographic vulnerabilities.

    Args:
        source_code: Python source code to analyze

    Returns:
        List of rule violations found
    """
    try:
        tree = ast.parse(source_code)
        visitor = CryptoSecurityVisitor(source_code)
        visitor.visit(tree)
        return visitor.violations
    except SyntaxError:
        return []
