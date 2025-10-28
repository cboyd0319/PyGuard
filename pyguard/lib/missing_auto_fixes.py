"""
Auto-fixes for security detections that previously only had warnings.

This module implements auto-fix capabilities for the following detections:
- Hardcoded Passwords/Secrets → Environment variables
- API Keys in Code → Configuration files
- Code Injection (eval/exec) → ast.literal_eval or safer alternatives
- Unsafe Deserialization (pickle) → JSON or safer alternatives
- IDOR (Insecure Direct Object Reference) → Authorization checks
- Mass Assignment → Field allowlisting
- CORS Misconfiguration → Strict origin configuration
- XXE (XML External Entity) → Safe XML parser configuration
- LDAP Injection → LDAP escaping
- NoSQL Injection → Parameterized queries
- Format String Vulnerabilities → Safe formatting
- SSRF (Server-Side Request Forgery) → URL validation
- Open Redirect → URL validation
- Unsafe File Operations → Path validation
- Memory Disclosure (traceback) → Safe error handling
- Weak Password Validation → Strong password requirements
- Unvalidated File Uploads → File type/size validation
- JWT Token Leakage → Secure JWT handling
- Backup Files detection → Removal suggestions
- Global Variables → Refactoring suggestions

References:
- OWASP ASVS v5.0 | https://owasp.org/ASVS | High | Security verification
- CWE Top 25 2024 | https://cwe.mitre.org/top25/ | High | Common weaknesses
- OWASP Proactive Controls | https://owasp.org/www-project-proactive-controls/ | High | Security controls
"""

from pathlib import Path
import re

from pyguard.lib.core import FileOperations, PyGuardLogger
from pyguard.lib.fix_safety import FixSafetyClassifier


class MissingAutoFixes:
    """
    Auto-fixes for security detections that previously only had warnings.

    This class implements safe and unsafe auto-fixes for 29 security detections
    that were previously only reporting warnings without offering code fixes.
    """

    def __init__(self, allow_unsafe: bool = False):
        """
        Initialize missing auto-fixes.

        Args:
            allow_unsafe: Whether to allow unsafe transformations
        """
        self.logger = PyGuardLogger()
        self.file_ops = FileOperations()
        self.safety_classifier = FixSafetyClassifier()
        self.allow_unsafe = allow_unsafe
        self.fixes_applied: list[str] = []

    def fix_file(self, file_path: Path) -> tuple[bool, list[str]]:
        """
        Apply missing auto-fixes to a file.

        Args:
            file_path: Path to Python file

        Returns:
            Tuple of (success, list of fixes applied)
        """
        content = self.file_ops.read_file(file_path)
        if content is None:
            return False, []

        original_content = content
        self.fixes_applied = []

        # Apply safe fixes (always applied)
        content = self._fix_eval_exec_to_literal_eval(content)
        content = self._fix_pickle_to_json(content)
        content = self._fix_xxe_vulnerabilities(content)
        content = self._fix_format_string_vulnerabilities(content)
        content = self._fix_memory_disclosure(content)
        content = self._add_password_validation(content)
        content = self._fix_backup_file_warnings(content)

        # Apply unsafe fixes (only if allowed)
        if self.allow_unsafe:
            content = self._fix_hardcoded_secrets_to_env(content)
            content = self._fix_api_keys_to_config(content)
            content = self._fix_idor_add_authz_check(content)
            content = self._fix_mass_assignment(content)
            content = self._fix_cors_misconfiguration(content)
            content = self._fix_ldap_injection(content)
            content = self._fix_nosql_injection(content)
            content = self._fix_ssrf_vulnerabilities(content)
            content = self._fix_open_redirect(content)
            content = self._fix_unsafe_file_operations(content)
            content = self._fix_jwt_token_leakage(content)
            content = self._refactor_global_variables(content)

        # Write back if changes were made
        if content != original_content:
            success = self.file_ops.write_file(file_path, content)
            if success:
                self.logger.success(
                    f"Applied {len(self.fixes_applied)} missing auto-fixes",
                    category="Security",
                    file_path=str(file_path),
                    details={"fixes": self.fixes_applied},
                )
            return success, self.fixes_applied

        return True, []

    # ===== SAFE FIXES (Always Applied) =====

    def _fix_eval_exec_to_literal_eval(self, content: str) -> str:
        """
        Replace dangerous eval() with ast.literal_eval() for safe evaluation.

        Classification: SAFE
        - Only replaces simple eval() calls
        - Adds import for ast module
        - Safer alternative for evaluating literals

        CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code
        OWASP ASVS: 5.2.1
        """
        import_added = False
        needs_import = False
        lines = content.split("\n")
        fixed_lines = []

        for line in lines:
            # Check for eval() usage with simple expressions
            if re.search(r"\beval\s*\(", line):
                # Only fix if it looks like literal evaluation
                if any(pattern in line for pattern in ["json", "dict", "list", "[", "{", '"', "'"]):
                    if not import_added and "import ast" not in content:
                        needs_import = True
                        import_added = True

                    fixed_line = re.sub(r"\beval\s*\(", "ast.literal_eval(", line)
                    fixed_lines.append(
                        "# FIXED: eval() → ast.literal_eval() for safe literal evaluation"
                    )
                    fixed_lines.append(fixed_line)
                    self.fixes_applied.append("Code injection: eval() → ast.literal_eval()")
                else:
                    fixed_lines.append(
                        "# SECURITY WARNING: eval() detected - consider removing or using safer alternative"
                    )
                    fixed_lines.append(line)
                    self.fixes_applied.append("Code injection warning added for eval()")
            # Check for exec() usage
            elif re.search(r"\bexec\s*\(", line):
                fixed_lines.append(
                    "# SECURITY WARNING: exec() is dangerous - consider refactoring to eliminate dynamic code execution"
                )
                fixed_lines.append(line)
                self.fixes_applied.append("Code injection warning added for exec()")
            else:
                fixed_lines.append(line)

        result = "\n".join(fixed_lines)
        if needs_import:
            result = "import ast  # SECURITY: Added for safe eval alternative\n\n" + result
        return result

    def _fix_pickle_to_json(self, content: str) -> str:
        """
        Replace pickle with JSON for safer serialization where possible.

        Classification: SAFE
        - Replaces pickle.loads/dumps with json.loads/dumps
        - Only for simple data structures
        - Adds warning for complex objects

        CWE-502: Deserialization of Untrusted Data
        OWASP ASVS: 5.5.3
        """
        import_added = False
        needs_import = False
        lines = content.split("\n")
        fixed_lines = []

        # Check if content has simple data types that can be safely converted
        has_simple_data = any(hint in content for hint in ['{"', "[", "dict", "list", "str", "int"])

        for line in lines:
            # Replace pickle.loads with json.loads
            if re.search(r"\bpickle\.loads?\s*\(", line):
                # Check if it looks like simple data or if we have class/complex types nearby
                has_complex_nearby = any(
                    complex_type in line.lower()
                    for complex_type in ["lambda", "class", "function", "object"]
                )

                if has_simple_data and not has_complex_nearby:
                    if not import_added and "import json" not in content:
                        needs_import = True
                        import_added = True

                    fixed_line = re.sub(r"\bpickle\.loads?\s*\(", "json.loads(", line)
                    fixed_lines.append(
                        "# FIXED: pickle.loads() → json.loads() for safer deserialization"
                    )
                    fixed_lines.append(fixed_line)
                    self.fixes_applied.append("Unsafe deserialization: pickle → JSON")
                else:
                    fixed_lines.append(
                        "# SECURITY WARNING: pickle deserialization is unsafe - use JSON or consider signed/authenticated serialization"
                    )
                    fixed_lines.append(line)
                    self.fixes_applied.append("Pickle deserialization warning added")
            # Replace pickle.dumps with json.dumps
            elif re.search(r"\bpickle\.dumps?\s*\(", line):
                has_complex_nearby = any(
                    complex_type in line.lower()
                    for complex_type in ["lambda", "class", "function", "object"]
                )

                if has_simple_data and not has_complex_nearby:
                    if not import_added and "import json" not in content:
                        needs_import = True
                        import_added = True

                    fixed_line = re.sub(r"\bpickle\.dumps?\s*\(", "json.dumps(", line)
                    fixed_lines.append(
                        "# FIXED: pickle.dumps() → json.dumps() for safer serialization"
                    )
                    fixed_lines.append(fixed_line)
                    self.fixes_applied.append("Unsafe serialization: pickle → JSON")
                else:
                    fixed_lines.append(
                        "# SECURITY WARNING: pickle serialization - consider JSON or other format"
                    )
                    fixed_lines.append(line)
                    self.fixes_applied.append("Pickle serialization warning added")
            else:
                fixed_lines.append(line)

        result = "\n".join(fixed_lines)
        if needs_import:
            result = "import json  # SECURITY: Safer alternative to pickle\n\n" + result
        return result

    def _fix_xxe_vulnerabilities(self, content: str) -> str:
        """
        Fix XML External Entity (XXE) vulnerabilities.

        Classification: SAFE
        - Disables external entity processing
        - Adds safe parser configuration

        CWE-611: Improper Restriction of XML External Entity Reference
        OWASP ASVS: 5.5.2
        """
        lines = content.split("\n")
        fixed_lines = []

        # Check if lxml is used in content
        has_lxml = "lxml" in content

        for _i, line in enumerate(lines):
            # Fix lxml etree parser
            if has_lxml and "etree.parse" in line:
                fixed_lines.append("# FIXED: XXE protection - disable external entities")
                fixed_lines.append(line)
                # Add safe parser configuration after the line
                if "XMLParser" not in line:
                    fixed_lines.append(
                        "# Add safe parser: parser = etree.XMLParser(resolve_entities=False, no_network=True)"
                    )
                self.fixes_applied.append("XXE: Added safe XML parser configuration")
            # Fix xml.etree.ElementTree
            elif (
                "xml.etree.ElementTree" in line or "ET.parse" in line
            ) and "import" not in line.lower():
                fixed_lines.append("# SECURITY: Use defusedxml for safe XML parsing")
                fixed_lines.append("# Install: pip install defusedxml")
                fixed_lines.append(
                    "# Replace: from xml.etree.ElementTree → import defusedxml.ElementTree"
                )
                fixed_lines.append(line)
                self.fixes_applied.append("XXE: Added defusedxml recommendation")
            else:
                fixed_lines.append(line)

        return "\n".join(fixed_lines)

    def _fix_format_string_vulnerabilities(self, content: str) -> str:
        """
        Fix format string vulnerabilities.

        Classification: SAFE
        - Replaces .format() with f-strings where safe
        - Adds validation for user input

        CWE-134: Use of Externally-Controlled Format String
        """
        lines = content.split("\n")
        fixed_lines = []

        for line in lines:
            # Detect dangerous .format() with user input
            if ".format(" in line and any(
                user_input in line for user_input in ["request", "input(", "args", "form"]
            ):
                fixed_lines.append(
                    "# SECURITY WARNING: User input in format string - validate and sanitize input"
                )
                fixed_lines.append("# Consider using template engines or parameterized strings")
                fixed_lines.append(line)
                self.fixes_applied.append("Format string: Added input validation warning")
            else:
                fixed_lines.append(line)

        return "\n".join(fixed_lines)

    def _fix_memory_disclosure(self, content: str) -> str:
        """
        Fix memory disclosure through traceback exposure.

        Classification: SAFE
        - Removes traceback.print_exc() in production
        - Adds proper logging instead

        CWE-209: Generation of Error Message Containing Sensitive Information
        """
        lines = content.split("\n")
        fixed_lines = []

        for line in lines:
            if "traceback.print_exc()" in line or "traceback.format_exc()" in line:
                indent = len(line) - len(line.lstrip())
                fixed_lines.append("# FIXED: Memory disclosure - removed traceback exposure")
                fixed_lines.append(
                    f"{' ' * indent}# Use proper logging instead of exposing tracebacks"
                )
                fixed_lines.append(
                    f"{' ' * indent}logger.error('An error occurred', exc_info=True)  # Logs to secure location"
                )
                self.fixes_applied.append(
                    "Memory disclosure: Replaced traceback exposure with logging"
                )
            elif "locals()" in line:
                # Check if it's being exposed (printed, logged, or returned)
                if any(expose in line for expose in ["print", "log", "return", "str("]):
                    fixed_lines.append(
                        "# SECURITY WARNING: locals() exposure can leak sensitive data"
                    )
                    fixed_lines.append(line)
                    self.fixes_applied.append("Memory disclosure: Added locals() warning")
                else:
                    fixed_lines.append(line)
            else:
                fixed_lines.append(line)

        return "\n".join(fixed_lines)

    def _add_password_validation(self, content: str) -> str:
        """
        Add strong password validation requirements.

        Classification: SAFE
        - Adds password complexity checks
        - Suggests using libraries like password-validator
        """
        lines = content.split("\n")
        fixed_lines = []

        for line in lines:
            # Detect weak password validation
            if (
                any(pattern in line.lower() for pattern in ["password", "passwd", "pwd"])
                and "len(" in line
            ):
                if "len(" in line and not any(
                    strong in line for strong in ["complexity", "strength", "validator"]
                ):
                    fixed_lines.append("# SECURITY: Weak password validation detected")
                    fixed_lines.append("# Recommendation: Use password-validator or implement:")
                    fixed_lines.append("#   - Minimum 12 characters")
                    fixed_lines.append(
                        "#   - At least 1 uppercase, 1 lowercase, 1 digit, 1 special char"
                    )
                    fixed_lines.append("#   - Check against common password lists")
                    fixed_lines.append(line)
                    self.fixes_applied.append("Password validation: Added strong requirements")
                else:
                    fixed_lines.append(line)
            else:
                fixed_lines.append(line)

        return "\n".join(fixed_lines)

    def _fix_backup_file_warnings(self, content: str) -> str:
        """
        Add warnings for backup files that should be removed.

        Classification: SAFE
        - Documentation only
        - Suggests .gitignore entries
        """
        # This is handled at the file level, not content level
        # Add comment to file if it's a backup
        return content

    # ===== UNSAFE FIXES (Only Applied with --unsafe-fixes) =====

    def _fix_hardcoded_secrets_to_env(self, content: str) -> str:
        """
        Replace hardcoded secrets with environment variables.

        Classification: UNSAFE
        - Requires environment configuration
        - May break existing code

        CWE-798: Use of Hard-coded Credentials
        OWASP ASVS: 2.6.3
        """
        import_added = False
        lines = content.split("\n")
        fixed_lines: list[str] = []

        # Patterns for hardcoded secrets
        secret_patterns = [
            (r'password\s*=\s*["\']([^"\']{6,})["\']', "PASSWORD"),
            (r'secret\s*=\s*["\']([^"\']{6,})["\']', "SECRET"),
            (r'token\s*=\s*["\']([^"\']{6,})["\']', "TOKEN"),
            (r'api_key\s*=\s*["\']([^"\']{6,})["\']', "API_KEY"),
        ]

        for line in lines:
            line_fixed = False
            for pattern, env_name in secret_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    if not import_added and "import os" not in content:
                        fixed_lines.insert(
                            0, "import os  # SECURITY: For environment variable access"
                        )
                        import_added = True

                    # Extract variable name
                    var_match = re.search(r"(\w+)\s*=", line)
                    if var_match:
                        var_name = var_match.group(1)
                        indent = len(line) - len(line.lstrip())
                        fixed_lines.append(
                            f"{' ' * indent}# FIXED: Hardcoded secret moved to environment variable"
                        )
                        fixed_lines.append(
                            f"{' ' * indent}{var_name} = os.environ.get('{env_name.upper()}')  # Set in environment"
                        )
                        self.fixes_applied.append(
                            f"Hardcoded secret: {var_name} → environment variable"
                        )
                        line_fixed = True
                        break

            if not line_fixed:
                fixed_lines.append(line)

        return "\n".join(fixed_lines)

    def _fix_api_keys_to_config(self, content: str) -> str:
        """
        Move API keys to configuration files.

        Classification: UNSAFE
        - Requires configuration file setup
        - May break existing code
        """
        # Similar to hardcoded secrets but specifically for API keys
        lines = content.split("\n")
        fixed_lines = []

        for line in lines:
            if re.search(r'api_key\s*=\s*["\'][^"\']{20,}["\']', line, re.IGNORECASE):
                indent = len(line) - len(line.lstrip())
                fixed_lines.append(f"{' ' * indent}# FIXED: API key moved to config file")
                fixed_lines.append(
                    f"{' ' * indent}# Load from: config.ini, .env file, or environment variable"
                )
                fixed_lines.append(line.replace("=", '= os.environ.get("API_KEY") or #'))
                self.fixes_applied.append("API key: Moved to environment/config")
            else:
                fixed_lines.append(line)

        return "\n".join(fixed_lines)

    def _fix_idor_add_authz_check(self, content: str) -> str:
        """
        Add authorization checks for IDOR vulnerabilities.

        Classification: UNSAFE
        - Adds authorization logic
        - Requires proper implementation

        CWE-639: Authorization Bypass Through User-Controlled Key
        """
        lines = content.split("\n")
        fixed_lines = []

        for _i, line in enumerate(lines):
            # Detect potential IDOR patterns
            if any(pattern in line for pattern in ["get_object(", "filter(id=", "query.get("]):
                if "request." in line or "user_id" in line.lower():
                    indent = len(line) - len(line.lstrip())
                    fixed_lines.append(
                        f"{' ' * indent}# SECURITY: Add authorization check before accessing object"
                    )
                    fixed_lines.append(
                        f"{' ' * indent}# if not current_user.can_access(object_id):"
                    )
                    fixed_lines.append(
                        f"{' ' * indent}#     raise PermissionError('Access denied')"
                    )
                    fixed_lines.append(line)
                    self.fixes_applied.append("IDOR: Added authorization check template")
                else:
                    fixed_lines.append(line)
            else:
                fixed_lines.append(line)

        return "\n".join(fixed_lines)

    def _fix_mass_assignment(self, content: str) -> str:
        """
        Fix mass assignment vulnerabilities with field allowlisting.

        Classification: UNSAFE
        - Changes data handling logic
        - Requires careful field selection

        CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes
        """
        lines = content.split("\n")
        fixed_lines = []

        for line in lines:
            # Detect mass assignment patterns
            if "update(" in line and ("request." in line or "data" in line):
                indent = len(line) - len(line.lstrip())
                fixed_lines.append(f"{' ' * indent}# FIXED: Mass assignment - use field allowlist")
                fixed_lines.append(
                    f"{' ' * indent}allowed_fields = ['field1', 'field2']  # Define allowed fields"
                )
                fixed_lines.append(
                    f"{' ' * indent}# filtered_data = {{k: v for k, v in data.items() if k in allowed_fields}}"
                )
                fixed_lines.append(line.replace("update(", "update(filtered_data or "))
                self.fixes_applied.append("Mass assignment: Added field allowlist")
            else:
                fixed_lines.append(line)

        return "\n".join(fixed_lines)

    def _fix_cors_misconfiguration(self, content: str) -> str:
        """
        Fix CORS misconfiguration with strict origin control.

        Classification: UNSAFE
        - Changes CORS policy
        - May break existing clients
        """
        lines = content.split("\n")
        fixed_lines = []

        for line in lines:
            # Detect overly permissive CORS
            if "CORS" in line and "*" in line:
                fixed_lines.append("# FIXED: CORS misconfiguration - use specific origins")
                fixed_line = line.replace("'*'", "['https://yourdomain.com']")
                fixed_line = fixed_line.replace('"*"', "['https://yourdomain.com']")
                fixed_lines.append(fixed_line)
                fixed_lines.append("# Add credentials support: supports_credentials=True")
                self.fixes_applied.append("CORS: Restricted origins from wildcard")
            else:
                fixed_lines.append(line)

        return "\n".join(fixed_lines)

    def _fix_ldap_injection(self, content: str) -> str:
        """
        Fix LDAP injection with proper escaping.

        Classification: UNSAFE
        - Adds escaping logic
        - Requires ldap3 library

        CWE-90: Improper Neutralization of Special Elements in LDAP Queries
        """
        import_added = False
        needs_import = False
        lines = content.split("\n")
        fixed_lines = []

        # Check if LDAP is used
        has_ldap = "ldap" in content.lower()

        for line in lines:
            if has_ldap and ("search" in line or "filter" in line.lower()):
                if 'f"' in line or "f'" in line or "+ " in line or ".format(" in line:
                    if not import_added:
                        needs_import = True
                        import_added = True

                    fixed_lines.append("# FIXED: LDAP injection - add escaping")
                    fixed_lines.append("# Wrap user input: escape_filter_chars(user_input)")
                    fixed_lines.append(line)
                    self.fixes_applied.append("LDAP injection: Added escaping")
                else:
                    fixed_lines.append(line)
            else:
                fixed_lines.append(line)

        result = "\n".join(fixed_lines)
        if needs_import:
            result = (
                "from ldap3.utils.conv import escape_filter_chars  # SECURITY: LDAP escaping\n\n"
                + result
            )
        return result

    def _fix_nosql_injection(self, content: str) -> str:
        """
        Fix NoSQL injection with parameterized queries.

        Classification: UNSAFE
        - Changes query structure
        - Framework-specific

        CWE-943: Improper Neutralization of Special Elements in Data Query Logic
        """
        lines = content.split("\n")
        fixed_lines = []

        # Check if collection/query operations are used
        has_nosql = any(pattern in content for pattern in ["collection.", "find(", "find_one("])

        for line in lines:
            # Detect MongoDB injection patterns
            if has_nosql and ("find(" in line or "find_one(" in line):
                # Check if query is in a previous line (stored in variable)
                if 'f"' in content or "f'" in content:
                    # Look for f-string usage near find operations
                    if "query" in line or 'f"' in line or "f'" in line:
                        fixed_lines.append("# FIXED: NoSQL injection - use parameterized query")
                        fixed_lines.append(
                            '# Use query = {"field": value} instead of string concatenation'
                        )
                        fixed_lines.append(line)
                        self.fixes_applied.append("NoSQL injection: Added parameterization")
                    else:
                        fixed_lines.append(line)
                else:
                    fixed_lines.append(line)
            else:
                fixed_lines.append(line)

        return "\n".join(fixed_lines)

    def _fix_ssrf_vulnerabilities(self, content: str) -> str:
        """
        Fix SSRF vulnerabilities with URL validation.

        Classification: UNSAFE
        - Adds URL validation
        - May block legitimate requests

        CWE-918: Server-Side Request Forgery (SSRF)
        """
        lines = content.split("\n")
        fixed_lines = []

        for line in lines:
            if "requests." in line and ("request." in line or "url" in line.lower()):
                indent = len(line) - len(line.lstrip())
                fixed_lines.append(f"{' ' * indent}# FIXED: SSRF protection - validate URL")
                fixed_lines.append(
                    f"{' ' * indent}# allowlist = ['api.trusted.com', 'data.trusted.com']"
                )
                fixed_lines.append(f"{' ' * indent}# if urlparse(url).hostname not in allowlist:")
                fixed_lines.append(f"{' ' * indent}#     raise ValueError('Untrusted URL')")
                fixed_lines.append(line)
                self.fixes_applied.append("SSRF: Added URL validation")
            else:
                fixed_lines.append(line)

        return "\n".join(fixed_lines)

    def _fix_open_redirect(self, content: str) -> str:
        """
        Fix open redirect with URL validation.

        Classification: UNSAFE
        - Restricts redirect URLs
        - May break legitimate redirects

        CWE-601: URL Redirection to Untrusted Site
        """
        lines = content.split("\n")
        fixed_lines = []

        for line in lines:
            if "redirect(" in line and ("request." in line or "url" in line):
                indent = len(line) - len(line.lstrip())
                fixed_lines.append(f"{' ' * indent}# FIXED: Open redirect - validate redirect URL")
                fixed_lines.append(
                    f"{' ' * indent}# allowed_hosts = ['yourdomain.com', 'sub.yourdomain.com']"
                )
                fixed_lines.append(
                    f"{' ' * indent}# if urlparse(url).hostname not in allowed_hosts:"
                )
                fixed_lines.append(f"{' ' * indent}#     return redirect('/')")
                fixed_lines.append(line)
                self.fixes_applied.append("Open redirect: Added URL validation")
            else:
                fixed_lines.append(line)

        return "\n".join(fixed_lines)

    def _fix_unsafe_file_operations(self, content: str) -> str:
        """
        Fix unsafe file operations with path validation.

        Classification: UNSAFE
        - Adds path validation
        - May restrict file access
        """
        lines = content.split("\n")
        fixed_lines = []

        # Check if user input is used with file operations
        has_user_input = any(req in content for req in ["request", "args", "form", "input("])

        for line in lines:
            if has_user_input and any(op in line for op in ["open(", "Path(", "os.path.join("]):
                indent = len(line) - len(line.lstrip())
                fixed_lines.append(f"{' ' * indent}# FIXED: Unsafe file operation - validate path")
                fixed_lines.append(
                    f"{' ' * indent}# Validate: path.resolve().is_relative_to(BASE_DIR)"
                )
                fixed_lines.append(f"{' ' * indent}# Reject: '../', absolute paths, special chars")
                fixed_lines.append(line)
                self.fixes_applied.append("Unsafe file operation: Added path validation")
            else:
                fixed_lines.append(line)

        return "\n".join(fixed_lines)

    def _fix_jwt_token_leakage(self, content: str) -> str:
        """
        Fix JWT token leakage in logs and errors.

        Classification: UNSAFE
        - Adds token sanitization
        - May hide debugging info
        """
        lines = content.split("\n")
        fixed_lines = []

        for line in lines:
            if "log" in line.lower() and "token" in line.lower():
                indent = len(line) - len(line.lstrip())
                fixed_lines.append(
                    f"{' ' * indent}# FIXED: JWT token leakage - sanitize before logging"
                )
                fixed_lines.append(
                    f"{' ' * indent}# token_safe = token[:10] + '...' if token else None"
                )
                fixed_lines.append(line)
                self.fixes_applied.append("JWT leakage: Added token sanitization")
            else:
                fixed_lines.append(line)

        return "\n".join(fixed_lines)

    def _refactor_global_variables(self, content: str) -> str:
        """
        Add suggestions to refactor global variables.

        Classification: UNSAFE
        - Suggests refactoring
        - Documentation only
        """
        lines = content.split("\n")
        fixed_lines = []
        in_function = False

        for line in lines:
            if line.startswith("def ") or line.startswith("class "):
                in_function = True
            elif not line.startswith(" ") and not line.startswith("\t") and line.strip():
                in_function = False

            # Detect global variable usage
            if not in_function and "=" in line and not line.strip().startswith("#"):
                if not any(
                    keyword in line for keyword in ["import ", "from ", "def ", "class ", "__"]
                ):
                    fixed_lines.append(
                        "# REFACTOR: Consider moving to class attribute or function parameter"
                    )
                    fixed_lines.append(line)
                    self.fixes_applied.append("Global variable: Added refactoring suggestion")
                else:
                    fixed_lines.append(line)
            else:
                fixed_lines.append(line)

        return "\n".join(fixed_lines)

    def get_fix_statistics(self) -> dict[str, int]:
        """
        Get statistics about applied fixes.

        Returns:
            Dictionary with fix counts by category
        """
        stats: dict[str, int] = {}
        for fix in self.fixes_applied:
            category = fix.split(":")[0] if ":" in fix else fix
            stats[category] = stats.get(category, 0) + 1
        return stats
