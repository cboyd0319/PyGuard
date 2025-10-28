"""
Celery Security Analysis.

Detects and auto-fixes common security vulnerabilities in Celery applications.
This module provides Celery-specific security checks focusing on distributed task queues,
message broker security, worker security, and async task patterns.

Security Areas Covered (20 checks):
- Task signature spoofing
- Message broker security (Redis/RabbitMQ)
- Result backend injection
- Task serialization (pickle risks)
- Worker privilege escalation
- Beat scheduler injection
- Canvas workflow tampering
- Task routing manipulation
- Rate limit bypass
- Retry logic vulnerabilities
- Task revocation bypasses
- Chord/chain/group security
- Task result exposure
- Worker pool exhaustion
- Monitoring interface security
- Flower dashboard access
- Task argument injection
- Missing task authentication
- Insecure RPC calls
- Broker connection security

Total Security Checks: 20 rules (CELERY001-CELERY020)

References:
- Celery Security | https://docs.celeryq.dev/en/stable/userguide/security.html | High
- OWASP ASVS v5.0 | https://owasp.org/ASVS | High | Application Security Verification Standard
- CWE-502 (Deserialization) | https://cwe.mitre.org/data/definitions/502.html | Critical
- CWE-287 (Authentication) | https://cwe.mitre.org/data/definitions/287.html | High
- CWE-311 (Missing Encryption) | https://cwe.mitre.org/data/definitions/311.html | High
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


class CelerySecurityVisitor(ast.NodeVisitor):
    """AST visitor for detecting Celery security vulnerabilities."""

    def __init__(self, file_path: Path, code: str):
        self.file_path = file_path
        self.code = code
        self.lines = code.splitlines()
        self.violations: list[RuleViolation] = []
        self.has_celery_import = False
        self.has_task_decorator = False
        self.task_functions: set[str] = set()
        self.broker_urls: list[str] = []

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Track Celery imports."""
        if node.module and node.module.startswith("celery"):
            self.has_celery_import = True
            for alias in node.names:
                if alias.name in ("task", "Task", "Celery"):
                    self.has_task_decorator = True
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        """Track Celery imports."""
        for alias in node.names:
            if alias.name.startswith("celery"):
                self.has_celery_import = True
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Analyze Celery task functions for security issues."""
        if not self.has_celery_import:
            self.generic_visit(node)
            return

        # Check if it's a Celery task
        is_task = any(
            (isinstance(dec, ast.Name) and dec.id == "task")
            or (isinstance(dec, ast.Attribute) and dec.attr == "task")
            or (
                isinstance(dec, ast.Call)
                and isinstance(dec.func, ast.Name)
                and dec.func.id == "task"
            )
            or (
                isinstance(dec, ast.Call)
                and isinstance(dec.func, ast.Attribute)
                and dec.func.attr == "task"
            )
            for dec in node.decorator_list
        )

        if is_task:
            self.task_functions.add(node.name)

            # CELERY001: Check for pickle serialization
            self._check_pickle_serialization(node)

            # CELERY002: Check for task signature spoofing
            self._check_task_signature_spoofing(node)

            # CELERY003: Check for missing task authentication
            self._check_missing_task_auth(node)

            # CELERY004: Check for task argument injection
            self._check_task_argument_injection(node)

            # CELERY005: Check for result exposure
            self._check_result_exposure(node)

            # CELERY006: Check for insecure retry logic
            self._check_retry_logic(node)

            # CELERY007: Check for rate limit bypass
            self._check_rate_limit_bypass(node)

            # CELERY008: Check for worker pool exhaustion
            self._check_worker_pool_exhaustion(node)

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Check for Celery configuration and call-based vulnerabilities."""
        if not self.has_celery_import:
            self.generic_visit(node)
            return

        # CELERY009: Check broker URL security
        self._check_broker_url_security(node)

        # CELERY010: Check result backend injection
        self._check_result_backend_injection(node)

        # CELERY011: Check for insecure canvas operations
        self._check_canvas_security(node)

        # CELERY012: Check for task revocation bypass
        self._check_task_revocation(node)

        # CELERY013: Check monitoring interface security
        self._check_monitoring_security(node)

        # CELERY014: Check Flower dashboard access
        self._check_flower_security(node)

        # CELERY019: Check insecure RPC calls
        self._check_insecure_rpc_calls(node)

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        """Check for insecure Celery configuration assignments."""
        if not self.has_celery_import:
            self.generic_visit(node)
            return

        # CELERY015: Check broker connection security
        self._check_broker_connection_config(node)

        # CELERY016: Check task routing security
        self._check_task_routing_config(node)

        # CELERY017: Check Beat scheduler security
        self._check_beat_scheduler_config(node)

        # CELERY018: Check worker privilege config
        self._check_worker_privilege_config(node)

        # CELERY020: Check task protocol security
        self._check_task_protocol_security(node)

        self.generic_visit(node)

    def _check_pickle_serialization(self, node: ast.FunctionDef) -> None:
        """CELERY001: Detect unsafe pickle serialization in tasks."""
        # Check task decorator for serializer parameter
        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Call):
                for kw in decorator.keywords:
                    if kw.arg == "serializer" and isinstance(kw.value, ast.Constant):
                        if kw.value.value == "pickle":
                            self.violations.append(
                                RuleViolation(
                                    rule_id="CELERY001",
                                    file_path=self.file_path,
                                    line_number=node.lineno,
                                    column=node.col_offset,
                                    severity=RuleSeverity.CRITICAL,
                                    category=RuleCategory.SECURITY,
                                    message="Task uses pickle serializer - vulnerable to arbitrary code execution",
                                    fix_suggestion="Use JSON serializer instead: @task(serializer='json'). "
                                    "Pickle can deserialize malicious payloads leading to RCE.",
                                    cwe_id="CWE-502",
                                    owasp_id="A08:2021 - Software and Data Integrity Failures",
                                    fix_applicability=FixApplicability.SAFE,
                                )
                            )

    def _check_task_signature_spoofing(self, node: ast.FunctionDef) -> None:
        """CELERY002: Detect task signature spoofing vulnerabilities."""
        # Check if task accepts untrusted input without validation
        for stmt in ast.walk(node):
            if isinstance(stmt, ast.Call):
                if isinstance(stmt.func, ast.Attribute):
                    # Check for apply_async with user-controlled args
                    if stmt.func.attr == "apply_async":
                        for kw in stmt.keywords:
                            if kw.arg in {"args", "kwargs"}:
                                # Simplified check - in production would track data flow
                                self.violations.append(
                                    RuleViolation(
                                        rule_id="CELERY002",
                                        file_path=self.file_path,
                                        line_number=stmt.lineno,
                                        column=stmt.col_offset,
                                        severity=RuleSeverity.HIGH,
                                        category=RuleCategory.SECURITY,
                                        message="Task signature may accept untrusted arguments - spoofing risk",
                                        fix_suggestion="Validate all task arguments. Use task.signature() with bind=True and validate self.request. "
                                        "Consider using task_protocol=2 for enhanced security.",
                                        cwe_id="CWE-345",
                                        owasp_id="A08:2021 - Software and Data Integrity Failures",
                                        fix_applicability=FixApplicability.MANUAL,
                                    )
                                )

    def _check_missing_task_auth(self, node: ast.FunctionDef) -> None:
        """CELERY003: Detect tasks without authentication checks."""
        # Check if task has any authentication/authorization
        has_auth_check = False
        for stmt in ast.walk(node):
            if isinstance(stmt, ast.Call) and isinstance(stmt.func, ast.Attribute):
                # Look for common auth patterns
                if stmt.func.attr in (
                    "authenticate",
                    "authorize",
                    "check_permission",
                    "verify",
                ):
                    has_auth_check = True
                    break

        # Check for sensitive operations without auth
        has_sensitive_ops = False
        for stmt in ast.walk(node):
            if isinstance(stmt, ast.Call) and isinstance(stmt.func, ast.Attribute):
                if stmt.func.attr in ("delete", "remove", "drop", "execute", "system"):
                    has_sensitive_ops = True
                    break

        if has_sensitive_ops and not has_auth_check:
            self.violations.append(
                RuleViolation(
                    rule_id="CELERY003",
                    file_path=self.file_path,
                    line_number=node.lineno,
                    column=node.col_offset,
                    severity=RuleSeverity.HIGH,
                    category=RuleCategory.SECURITY,
                    message="Task performs sensitive operations without authentication",
                    fix_suggestion="Add authentication checks at task start. Use @task(bind=True) and validate self.request.id. "
                    "Consider task-level permissions or OAuth2 integration.",
                    cwe_id="CWE-287",
                    owasp_id="A07:2021 - Identification and Authentication Failures",
                    fix_applicability=FixApplicability.MANUAL,
                )
            )

    def _check_task_argument_injection(self, node: ast.FunctionDef) -> None:
        """CELERY004: Detect task argument injection vulnerabilities."""
        for stmt in ast.walk(node):
            if isinstance(stmt, ast.Call):
                # Check for SQL/command execution with task args
                if isinstance(stmt.func, ast.Attribute):
                    if stmt.func.attr in ("execute", "system", "call", "Popen"):
                        # Check if function parameters are used directly
                        for arg in node.args.args:
                            arg_name = arg.arg
                            # Check if task arg is used in dangerous call
                            for call_arg in stmt.args:
                                if isinstance(call_arg, ast.Name) and call_arg.id == arg_name:
                                    self.violations.append(
                                        RuleViolation(
                                            rule_id="CELERY004",
                                            file_path=self.file_path,
                                            line_number=stmt.lineno,
                                            column=stmt.col_offset,
                                            severity=RuleSeverity.CRITICAL,
                                            category=RuleCategory.SECURITY,
                                            message="Task argument used directly in dangerous operation - injection risk",
                                            fix_suggestion="Validate and sanitize all task arguments. Use parameterized queries for SQL, "
                                            "whitelist validation for commands, and escape special characters.",
                                            cwe_id="CWE-94",
                                            owasp_id="A03:2021 - Injection",
                                            fix_applicability=FixApplicability.MANUAL,
                                        )
                                    )

    def _check_result_exposure(self, node: ast.FunctionDef) -> None:
        """CELERY005: Detect sensitive data exposure in task results."""
        # Check for return statements with potentially sensitive data
        for stmt in ast.walk(node):
            if isinstance(stmt, ast.Return) and stmt.value:
                # Check for dict with sensitive keys
                if isinstance(stmt.value, ast.Dict):
                    for key in stmt.value.keys:
                        if isinstance(key, ast.Constant):
                            key_str = str(key.value).lower()
                            if any(
                                sensitive in key_str
                                for sensitive in [
                                    "password",
                                    "secret",
                                    "token",
                                    "key",
                                    "credential",
                                    "private",
                                ]
                            ):
                                self.violations.append(
                                    RuleViolation(
                                        rule_id="CELERY005",
                                        file_path=self.file_path,
                                        line_number=stmt.lineno,
                                        column=stmt.col_offset,
                                        severity=RuleSeverity.HIGH,
                                        category=RuleCategory.SECURITY,
                                        message="Task returns sensitive data - exposure via result backend",
                                        fix_suggestion="Never return passwords, secrets, or credentials in task results. "
                                        "Use secure storage and return only references/IDs. "
                                        "Ensure result backend is encrypted (Redis TLS, encrypted DB).",
                                        cwe_id="CWE-200",
                                        owasp_id="A01:2021 - Broken Access Control",
                                        fix_applicability=FixApplicability.MANUAL,
                                    )
                                )

    def _check_retry_logic(self, node: ast.FunctionDef) -> None:
        """CELERY006: Detect insecure retry logic."""
        # Check for unlimited retries
        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Call):
                has_max_retries = False
                has_retry_backoff = False
                for kw in decorator.keywords:
                    if kw.arg == "max_retries":
                        has_max_retries = True
                        if isinstance(kw.value, ast.Constant) and kw.value.value is None:
                            self.violations.append(
                                RuleViolation(
                                    rule_id="CELERY006",
                                    file_path=self.file_path,
                                    line_number=node.lineno,
                                    column=node.col_offset,
                                    severity=RuleSeverity.MEDIUM,
                                    category=RuleCategory.SECURITY,
                                    message="Task configured with unlimited retries - resource exhaustion risk",
                                    fix_suggestion="Set max_retries to a reasonable limit (e.g., 3-5). "
                                    "Use autoretry_for with specific exceptions only.",
                                    cwe_id="CWE-400",
                                    owasp_id="A04:2021 - Insecure Design",
                                    fix_applicability=FixApplicability.SAFE,
                                )
                            )
                    if kw.arg in ("retry_backoff", "retry_backoff_max"):
                        has_retry_backoff = True

                if not has_retry_backoff and has_max_retries:
                    self.violations.append(
                        RuleViolation(
                            rule_id="CELERY006",
                            file_path=self.file_path,
                            line_number=node.lineno,
                            column=node.col_offset,
                            severity=RuleSeverity.LOW,
                            category=RuleCategory.SECURITY,
                            message="Task retry without exponential backoff - DoS amplification risk",
                            fix_suggestion="Add retry_backoff=True or retry_backoff_max to prevent retry storms. "
                            "Use exponential backoff to avoid overwhelming services.",
                            cwe_id="CWE-400",
                            owasp_id="A04:2021 - Insecure Design",
                            fix_applicability=FixApplicability.SUGGESTED,
                        )
                    )

    def _check_rate_limit_bypass(self, node: ast.FunctionDef) -> None:
        """CELERY007: Detect missing rate limiting on tasks."""
        # Check for rate_limit parameter
        has_rate_limit = False
        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Call):
                for kw in decorator.keywords:
                    if kw.arg == "rate_limit":
                        has_rate_limit = True
                        break

        # Check if task seems to do expensive operations
        has_expensive_ops = False
        for stmt in ast.walk(node):
            if isinstance(stmt, ast.Call) and isinstance(stmt.func, ast.Attribute):
                if stmt.func.attr in ("request", "get", "post", "execute", "query"):
                    has_expensive_ops = True
                    break

        if has_expensive_ops and not has_rate_limit:
            self.violations.append(
                RuleViolation(
                    rule_id="CELERY007",
                    file_path=self.file_path,
                    line_number=node.lineno,
                    column=node.col_offset,
                    severity=RuleSeverity.MEDIUM,
                    category=RuleCategory.SECURITY,
                    message="Task performs expensive operations without rate limiting",
                    fix_suggestion="Add rate_limit parameter: @task(rate_limit='10/m') to prevent abuse. "
                    "Adjust limit based on resource constraints.",
                    cwe_id="CWE-770",
                    owasp_id="A04:2021 - Insecure Design",
                    fix_applicability=FixApplicability.SUGGESTED,
                )
            )

    def _check_worker_pool_exhaustion(self, node: ast.FunctionDef) -> None:
        """CELERY008: Detect potential worker pool exhaustion."""
        # Check for blocking operations in tasks
        for stmt in ast.walk(node):
            if isinstance(stmt, ast.Call):
                if isinstance(stmt.func, ast.Name):
                    # Check for blocking calls without timeout
                    if stmt.func.id in ("sleep", "input", "wait"):
                        has_timeout = any(kw.arg == "timeout" for kw in stmt.keywords)
                        if not has_timeout:
                            self.violations.append(
                                RuleViolation(
                                    rule_id="CELERY008",
                                    file_path=self.file_path,
                                    line_number=stmt.lineno,
                                    column=stmt.col_offset,
                                    severity=RuleSeverity.MEDIUM,
                                    category=RuleCategory.PERFORMANCE,
                                    message="Task uses blocking operation without timeout - worker pool exhaustion risk",
                                    fix_suggestion="Add timeout parameter to prevent indefinite blocking. "
                                    "Use task time_limit and soft_time_limit decorators.",
                                    cwe_id="CWE-400",
                                    owasp_id="A04:2021 - Insecure Design",
                                    fix_applicability=FixApplicability.MANUAL,
                                )
                            )

    def _check_broker_url_security(self, node: ast.Call) -> None:
        """CELERY009: Detect insecure broker URL configuration."""
        # Check for Celery app initialization
        if isinstance(node.func, ast.Name) and node.func.id == "Celery":
            for kw in node.keywords:
                if kw.arg == "broker" and isinstance(kw.value, ast.Constant):
                    broker_url = str(kw.value.value)
                    self.broker_urls.append(broker_url)

                    # Check for insecure protocols
                    if broker_url.startswith(("redis://", "amqp://", "mongodb://")):
                        if "localhost" not in broker_url and "127.0.0.1" not in broker_url:
                            self.violations.append(
                                RuleViolation(
                                    rule_id="CELERY009",
                                    file_path=self.file_path,
                                    line_number=node.lineno,
                                    column=node.col_offset,
                                    severity=RuleSeverity.HIGH,
                                    category=RuleCategory.SECURITY,
                                    message="Broker URL uses unencrypted protocol - credentials exposed in transit",
                                    fix_suggestion="Use encrypted protocols: rediss:// for Redis, amqps:// for RabbitMQ, "
                                    "mongodb+srv:// for MongoDB. Enable TLS/SSL on broker.",
                                    cwe_id="CWE-311",
                                    owasp_id="A02:2021 - Cryptographic Failures",
                                    fix_applicability=FixApplicability.MANUAL,
                                )
                            )

                    # Check for credentials in URL
                    if "@" in broker_url and (
                        "password" in broker_url.lower() or ":" in broker_url.split("@")[0]
                    ):
                        self.violations.append(
                            RuleViolation(
                                rule_id="CELERY009",
                                file_path=self.file_path,
                                line_number=node.lineno,
                                column=node.col_offset,
                                severity=RuleSeverity.CRITICAL,
                                category=RuleCategory.SECURITY,
                                message="Broker URL contains hardcoded credentials - secret exposure",
                                fix_suggestion="Move credentials to environment variables. Use CELERY_BROKER_URL env var. "
                                "Never commit credentials to source code.",
                                cwe_id="CWE-798",
                                owasp_id="A07:2021 - Identification and Authentication Failures",
                                fix_applicability=FixApplicability.MANUAL,
                            )
                        )

    def _check_result_backend_injection(self, node: ast.Call) -> None:
        """CELERY010: Detect result backend injection vulnerabilities."""
        # Check for backend configuration with user input
        if isinstance(node.func, ast.Name) and node.func.id == "Celery":
            for kw in node.keywords:
                if kw.arg == "backend":
                    # Check if backend URL comes from user input (simplified)
                    if isinstance(kw.value, ast.Call):
                        if isinstance(kw.value.func, ast.Attribute):
                            if kw.value.func.attr in ("get", "getenv", "input"):
                                self.violations.append(
                                    RuleViolation(
                                        rule_id="CELERY010",
                                        file_path=self.file_path,
                                        line_number=node.lineno,
                                        column=node.col_offset,
                                        severity=RuleSeverity.HIGH,
                                        category=RuleCategory.SECURITY,
                                        message="Result backend URL from user input - injection and SSRF risk",
                                        fix_suggestion="Use hardcoded backend URLs or validate against whitelist. "
                                        "Never accept backend URLs from user input.",
                                        cwe_id="CWE-943",
                                        owasp_id="A03:2021 - Injection",
                                        fix_applicability=FixApplicability.MANUAL,
                                    )
                                )

    def _check_canvas_security(self, node: ast.Call) -> None:
        """CELERY011: Detect insecure canvas operations (chain/chord/group)."""
        if isinstance(node.func, ast.Name):
            # Check for canvas primitives
            if node.func.id in ("chain", "chord", "group"):
                # Check for task signatures from user input
                for arg in node.args:
                    if isinstance(arg, ast.Call):
                        # Simplified check for apply_async or signature
                        self.violations.append(
                            RuleViolation(
                                rule_id="CELERY011",
                                file_path=self.file_path,
                                line_number=node.lineno,
                                column=node.col_offset,
                                severity=RuleSeverity.MEDIUM,
                                category=RuleCategory.SECURITY,
                                message=f"Canvas operation ({node.func.id}) may use untrusted task signatures",
                                fix_suggestion="Validate all task signatures in canvas workflows. "
                                "Use immutable signatures to prevent tampering. "
                                "Apply task-level authentication.",
                                cwe_id="CWE-345",
                                owasp_id="A08:2021 - Software and Data Integrity Failures",
                                fix_applicability=FixApplicability.MANUAL,
                            )
                        )

    def _check_task_revocation(self, node: ast.Call) -> None:
        """CELERY012: Detect task revocation bypass vulnerabilities."""
        if isinstance(node.func, ast.Attribute):
            if node.func.attr == "revoke":
                # Check if revoke is called without terminate
                has_terminate = any(kw.arg == "terminate" for kw in node.keywords)
                if not has_terminate:
                    self.violations.append(
                        RuleViolation(
                            rule_id="CELERY012",
                            file_path=self.file_path,
                            line_number=node.lineno,
                            column=node.col_offset,
                            severity=RuleSeverity.LOW,
                            category=RuleCategory.SECURITY,
                            message="Task revocation without terminate flag - task may continue execution",
                            fix_suggestion="Use revoke(terminate=True) to forcefully stop running tasks. "
                            "Also check task_reject_on_worker_lost setting.",
                            cwe_id="CWE-400",
                            owasp_id="A04:2021 - Insecure Design",
                            fix_applicability=FixApplicability.SUGGESTED,
                        )
                    )

    def _check_monitoring_security(self, node: ast.Call) -> None:
        """CELERY013: Detect insecure monitoring interface configuration."""
        # Check for celery events or control commands without auth
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in ("control", "events"):
                line_num = node.lineno
                if line_num < len(self.lines):
                    line = self.lines[line_num - 1]
                    # Check if authentication is configured
                    if "broker_use_ssl" not in line and "security" not in line.lower():
                        self.violations.append(
                            RuleViolation(
                                rule_id="CELERY013",
                                file_path=self.file_path,
                                line_number=node.lineno,
                                column=node.col_offset,
                                severity=RuleSeverity.MEDIUM,
                                category=RuleCategory.SECURITY,
                                message="Monitoring interface accessed without security configuration",
                                fix_suggestion="Configure broker_use_ssl and enable authentication for monitoring. "
                                "Restrict network access to monitoring ports. Use Celery security features.",
                                cwe_id="CWE-306",
                                owasp_id="A07:2021 - Identification and Authentication Failures",
                                fix_applicability=FixApplicability.MANUAL,
                            )
                        )

    def _check_flower_security(self, node: ast.Call) -> None:
        """CELERY014: Detect insecure Flower dashboard configuration."""
        # Check for Flower app initialization
        if isinstance(node.func, ast.Attribute):
            if "flower" in str(node.func).lower():
                # Check for basic_auth or auth configuration
                has_auth = any(
                    kw.arg in ("basic_auth", "auth", "oauth2_key", "oauth2_secret")
                    for kw in node.keywords
                )
                if not has_auth:
                    self.violations.append(
                        RuleViolation(
                            rule_id="CELERY014",
                            file_path=self.file_path,
                            line_number=node.lineno,
                            column=node.col_offset,
                            severity=RuleSeverity.HIGH,
                            category=RuleCategory.SECURITY,
                            message="Flower dashboard configured without authentication",
                            fix_suggestion="Configure Flower authentication: --basic_auth=user:password or OAuth2. "
                            "Never expose Flower dashboard publicly without auth.",
                            cwe_id="CWE-306",
                            owasp_id="A07:2021 - Identification and Authentication Failures",
                            fix_applicability=FixApplicability.MANUAL,
                        )
                    )

    def _check_broker_connection_config(self, node: ast.Assign) -> None:
        """CELERY015: Detect insecure broker connection configuration."""
        for target in node.targets:
            if isinstance(target, ast.Name):
                # Check for broker connection settings
                if target.id in ("broker_use_ssl", "BROKER_USE_SSL"):
                    if isinstance(node.value, ast.Constant) and node.value.value is False:
                        self.violations.append(
                            RuleViolation(
                                rule_id="CELERY015",
                                file_path=self.file_path,
                                line_number=node.lineno,
                                column=node.col_offset,
                                severity=RuleSeverity.HIGH,
                                category=RuleCategory.SECURITY,
                                message="Broker SSL/TLS explicitly disabled - unencrypted communication",
                                fix_suggestion="Enable SSL/TLS for broker: broker_use_ssl=True. "
                                "Configure broker_ssl_options with cert validation.",
                                cwe_id="CWE-319",
                                owasp_id="A02:2021 - Cryptographic Failures",
                                fix_applicability=FixApplicability.SAFE,
                            )
                        )

                # Check for result backend SSL
                if target.id in ("result_backend_use_ssl", "RESULT_BACKEND_USE_SSL"):
                    if isinstance(node.value, ast.Constant) and node.value.value is False:
                        self.violations.append(
                            RuleViolation(
                                rule_id="CELERY015",
                                file_path=self.file_path,
                                line_number=node.lineno,
                                column=node.col_offset,
                                severity=RuleSeverity.MEDIUM,
                                category=RuleCategory.SECURITY,
                                message="Result backend SSL/TLS explicitly disabled",
                                fix_suggestion="Enable SSL/TLS for result backend to protect task results in transit.",
                                cwe_id="CWE-319",
                                owasp_id="A02:2021 - Cryptographic Failures",
                                fix_applicability=FixApplicability.SAFE,
                            )
                        )

    def _check_task_routing_config(self, node: ast.Assign) -> None:
        """CELERY016: Detect task routing manipulation risks."""
        for target in node.targets:
            if isinstance(target, ast.Name):
                # Check for task_routes configuration
                if target.id in ("task_routes", "CELERY_ROUTES"):
                    # Check if routes come from user input (simplified)
                    if isinstance(node.value, ast.Call):
                        self.violations.append(
                            RuleViolation(
                                rule_id="CELERY016",
                                file_path=self.file_path,
                                line_number=node.lineno,
                                column=node.col_offset,
                                severity=RuleSeverity.MEDIUM,
                                category=RuleCategory.SECURITY,
                                message="Task routing configuration from dynamic source - manipulation risk",
                                fix_suggestion="Use static routing configuration. Never accept routing rules from user input. "
                                "Validate queue names against whitelist.",
                                cwe_id="CWE-15",
                                owasp_id="A04:2021 - Insecure Design",
                                fix_applicability=FixApplicability.MANUAL,
                            )
                        )

    def _check_beat_scheduler_config(self, node: ast.Assign) -> None:
        """CELERY017: Detect Beat scheduler injection vulnerabilities."""
        for target in node.targets:
            if isinstance(target, ast.Name):
                # Check for beat_schedule configuration
                if target.id in ("beat_schedule", "CELERYBEAT_SCHEDULE"):
                    # Check if schedule is modified at runtime
                    if isinstance(node.value, ast.Dict):
                        for _key, value in zip(node.value.keys, node.value.values, strict=False):
                            # Check for task names from variables (potential injection)
                            if isinstance(value, ast.Dict):
                                for k, v in zip(value.keys, value.values, strict=False):
                                    if isinstance(k, ast.Constant) and k.value == "task":
                                        if not isinstance(v, ast.Constant):
                                            self.violations.append(
                                                RuleViolation(
                                                    rule_id="CELERY017",
                                                    file_path=self.file_path,
                                                    line_number=node.lineno,
                                                    column=node.col_offset,
                                                    severity=RuleSeverity.HIGH,
                                                    category=RuleCategory.SECURITY,
                                                    message="Beat schedule task name from variable - injection risk",
                                                    fix_suggestion="Use hardcoded task names in beat_schedule. "
                                                    "Never accept task names from user input or configuration files.",
                                                    cwe_id="CWE-94",
                                                    owasp_id="A03:2021 - Injection",
                                                    fix_applicability=FixApplicability.MANUAL,
                                                )
                                            )

    def _check_worker_privilege_config(self, node: ast.Assign) -> None:
        """CELERY018: Detect worker privilege escalation risks."""
        for target in node.targets:
            if isinstance(target, ast.Name):
                # Check for worker user/group settings
                if target.id in ("worker_user", "worker_group", "C_FORCE_ROOT"):
                    if target.id == "C_FORCE_ROOT":
                        if isinstance(node.value, ast.Constant) and node.value.value is True:
                            self.violations.append(
                                RuleViolation(
                                    rule_id="CELERY018",
                                    file_path=self.file_path,
                                    line_number=node.lineno,
                                    column=node.col_offset,
                                    severity=RuleSeverity.CRITICAL,
                                    category=RuleCategory.SECURITY,
                                    message="Worker configured to run as root - privilege escalation risk",
                                    fix_suggestion="Never run Celery workers as root. Create dedicated unprivileged user. "
                                    "Remove C_FORCE_ROOT setting and run as non-root user.",
                                    cwe_id="CWE-250",
                                    owasp_id="A04:2021 - Insecure Design",
                                    fix_applicability=FixApplicability.SAFE,
                                )
                            )

    def _check_insecure_rpc_calls(self, node: ast.Call) -> None:
        """CELERY019: Detect insecure RPC calls to workers."""
        if isinstance(node.func, ast.Attribute):
            # Check for direct RPC calls without authentication
            if node.func.attr in ("control.inspect", "control.broadcast", "control.pool_restart"):
                self.violations.append(
                    RuleViolation(
                        rule_id="CELERY019",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.MEDIUM,
                        category=RuleCategory.SECURITY,
                        message="Worker RPC call without authentication check",
                        fix_suggestion="Implement authentication for worker control RPC calls. "
                        "Use broker_use_ssl and validate caller identity. "
                        "Restrict network access to management interfaces.",
                        cwe_id="CWE-306",
                        owasp_id="A07:2021 - Identification and Authentication Failures",
                        fix_applicability=FixApplicability.MANUAL,
                    )
                )

    def _check_task_protocol_security(self, node: ast.Assign) -> None:
        """CELERY020: Detect insecure task protocol version."""
        for target in node.targets:
            if isinstance(target, ast.Name):
                # Check for task_protocol setting
                if target.id in ("task_protocol", "CELERY_TASK_PROTOCOL"):
                    if isinstance(node.value, ast.Constant):
                        # Protocol 1 is less secure than protocol 2
                        if node.value.value == 1:
                            self.violations.append(
                                RuleViolation(
                                    rule_id="CELERY020",
                                    file_path=self.file_path,
                                    line_number=node.lineno,
                                    column=node.col_offset,
                                    severity=RuleSeverity.MEDIUM,
                                    category=RuleCategory.SECURITY,
                                    message="Task protocol version 1 is less secure than version 2",
                                    fix_suggestion="Upgrade to task_protocol=2 for enhanced security. "
                                    "Protocol 2 includes better error handling and security features.",
                                    cwe_id="CWE-757",
                                    owasp_id="A05:2021 - Security Misconfiguration",
                                    fix_applicability=FixApplicability.SAFE,
                                )
                            )


def analyze_celery_security(file_path: Path, code: str) -> list[RuleViolation]:
    """
    Analyze Python code for Celery security vulnerabilities.

    Args:
        file_path: Path to the file being analyzed
        code: Source code content

    Returns:
        List of rule violations found
    """
    violations: list[RuleViolation] = []

    try:
        tree = ast.parse(code)
        visitor = CelerySecurityVisitor(file_path, code)
        visitor.visit(tree)
        violations.extend(visitor.violations)
    except SyntaxError:
        pass

    return violations


# Define rules for registration
CELERY_RULES = [
    Rule(
        rule_id="CELERY001",
        name="celery-pickle-serialization",
        message_template="Task uses pickle serializer",
        severity=RuleSeverity.CRITICAL,
        category=RuleCategory.SECURITY,
        description="Detects tasks using unsafe pickle serialization",
        explanation="Pickle serialization can execute arbitrary code during deserialization",
        fix_applicability=FixApplicability.SAFE,
        owasp_mapping="A08:2021 - Software and Data Integrity Failures",
        cwe_mapping="CWE-502",
    ),
    Rule(
        rule_id="CELERY002",
        name="celery-task-signature-spoofing",
        message_template="Task signature spoofing vulnerability",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.SECURITY,
        description="Detects potential task signature spoofing vulnerabilities",
        explanation="Unvalidated task signatures can be spoofed to execute arbitrary tasks",
        fix_applicability=FixApplicability.MANUAL,
        owasp_mapping="A08:2021 - Software and Data Integrity Failures",
        cwe_mapping="CWE-345",
    ),
    Rule(
        rule_id="CELERY003",
        name="celery-missing-task-auth",
        message_template="Task performs sensitive operations without authentication",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.SECURITY,
        description="Detects tasks performing sensitive operations without authentication",
        explanation="Tasks without authentication can be executed by anyone with broker access",
        fix_applicability=FixApplicability.MANUAL,
        owasp_mapping="A07:2021 - Identification and Authentication Failures",
        cwe_mapping="CWE-287",
    ),
    Rule(
        rule_id="CELERY004",
        name="celery-argument-injection",
        message_template="Task argument injection vulnerability",
        severity=RuleSeverity.CRITICAL,
        category=RuleCategory.SECURITY,
        description="Detects task arguments used in dangerous operations without validation",
        explanation="Unvalidated task arguments can lead to code injection or command injection",
        fix_applicability=FixApplicability.MANUAL,
        owasp_mapping="A03:2021 - Injection",
        cwe_mapping="CWE-94",
    ),
    Rule(
        rule_id="CELERY005",
        name="celery-result-exposure",
        message_template="Task returns sensitive data",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.SECURITY,
        description="Detects tasks returning sensitive data via result backend",
        explanation="Sensitive data in task results can be exposed through result backend",
        fix_applicability=FixApplicability.MANUAL,
        owasp_mapping="A01:2021 - Broken Access Control",
        cwe_mapping="CWE-200",
    ),
    Rule(
        rule_id="CELERY006",
        name="celery-insecure-retry",
        message_template="Insecure retry configuration",
        severity=RuleSeverity.MEDIUM,
        category=RuleCategory.SECURITY,
        description="Detects tasks with insecure retry logic",
        explanation="Unlimited retries or missing backoff can lead to resource exhaustion",
        fix_applicability=FixApplicability.SAFE,
        owasp_mapping="A04:2021 - Insecure Design",
        cwe_mapping="CWE-400",
    ),
    Rule(
        rule_id="CELERY007",
        name="celery-missing-rate-limit",
        message_template="Task missing rate limiting",
        severity=RuleSeverity.MEDIUM,
        category=RuleCategory.SECURITY,
        description="Detects expensive tasks without rate limiting",
        explanation="Tasks without rate limits can be abused for DoS attacks",
        fix_applicability=FixApplicability.SUGGESTED,
        owasp_mapping="A04:2021 - Insecure Design",
        cwe_mapping="CWE-770",
    ),
    Rule(
        rule_id="CELERY008",
        name="celery-worker-pool-exhaustion",
        message_template="Potential worker pool exhaustion",
        severity=RuleSeverity.MEDIUM,
        category=RuleCategory.PERFORMANCE,
        description="Detects blocking operations that can exhaust worker pool",
        explanation="Blocking operations without timeouts can tie up worker processes",
        fix_applicability=FixApplicability.MANUAL,
        owasp_mapping="A04:2021 - Insecure Design",
        cwe_mapping="CWE-400",
    ),
    Rule(
        rule_id="CELERY009",
        name="celery-insecure-broker",
        message_template="Insecure broker URL configuration",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.SECURITY,
        description="Detects insecure broker URL configuration",
        explanation="Unencrypted broker connections or hardcoded credentials expose sensitive data",
        fix_applicability=FixApplicability.MANUAL,
        owasp_mapping="A02:2021 - Cryptographic Failures",
        cwe_mapping="CWE-311",
    ),
    Rule(
        rule_id="CELERY010",
        name="celery-result-backend-injection",
        message_template="Result backend injection vulnerability",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.SECURITY,
        description="Detects result backend URLs from untrusted sources",
        explanation="User-controlled backend URLs can lead to injection or SSRF",
        fix_applicability=FixApplicability.MANUAL,
        owasp_mapping="A03:2021 - Injection",
        cwe_mapping="CWE-943",
    ),
    Rule(
        rule_id="CELERY011",
        name="celery-canvas-tampering",
        message_template="Canvas workflow tampering risk",
        severity=RuleSeverity.MEDIUM,
        category=RuleCategory.SECURITY,
        description="Detects potentially unsafe canvas operations",
        explanation="Canvas workflows with untrusted signatures can be tampered with",
        fix_applicability=FixApplicability.MANUAL,
        owasp_mapping="A08:2021 - Software and Data Integrity Failures",
        cwe_mapping="CWE-345",
    ),
    Rule(
        rule_id="CELERY012",
        name="celery-revocation-bypass",
        message_template="Task revocation bypass",
        severity=RuleSeverity.LOW,
        category=RuleCategory.SECURITY,
        description="Detects task revocation without terminate flag",
        explanation="Revoked tasks without terminate may continue execution",
        fix_applicability=FixApplicability.SUGGESTED,
        owasp_mapping="A04:2021 - Insecure Design",
        cwe_mapping="CWE-400",
    ),
    Rule(
        rule_id="CELERY013",
        name="celery-monitoring-security",
        message_template="Insecure monitoring interface",
        severity=RuleSeverity.MEDIUM,
        category=RuleCategory.SECURITY,
        description="Detects monitoring interface without security configuration",
        explanation="Unprotected monitoring interfaces expose worker control and task data",
        fix_applicability=FixApplicability.MANUAL,
        owasp_mapping="A07:2021 - Identification and Authentication Failures",
        cwe_mapping="CWE-306",
    ),
    Rule(
        rule_id="CELERY014",
        name="celery-flower-no-auth",
        message_template="Flower dashboard without authentication",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.SECURITY,
        description="Detects Flower dashboard configured without authentication",
        explanation="Unprotected Flower dashboard exposes task data and worker control",
        fix_applicability=FixApplicability.MANUAL,
        owasp_mapping="A07:2021 - Identification and Authentication Failures",
        cwe_mapping="CWE-306",
    ),
    Rule(
        rule_id="CELERY015",
        name="celery-broker-no-ssl",
        message_template="Broker SSL/TLS disabled",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.SECURITY,
        description="Detects broker connections without SSL/TLS encryption",
        explanation="Unencrypted broker connections expose tasks and credentials in transit",
        fix_applicability=FixApplicability.SAFE,
        owasp_mapping="A02:2021 - Cryptographic Failures",
        cwe_mapping="CWE-319",
    ),
    Rule(
        rule_id="CELERY016",
        name="celery-task-routing-manipulation",
        message_template="Task routing manipulation risk",
        severity=RuleSeverity.MEDIUM,
        category=RuleCategory.SECURITY,
        description="Detects dynamic task routing configuration",
        explanation="Dynamic routing can be manipulated to route tasks to unauthorized queues",
        fix_applicability=FixApplicability.MANUAL,
        owasp_mapping="A04:2021 - Insecure Design",
        cwe_mapping="CWE-15",
    ),
    Rule(
        rule_id="CELERY017",
        name="celery-beat-scheduler-injection",
        message_template="Beat scheduler injection risk",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.SECURITY,
        description="Detects Beat scheduler with dynamic task names",
        explanation="Dynamic task names in beat schedule can lead to code injection",
        fix_applicability=FixApplicability.MANUAL,
        owasp_mapping="A03:2021 - Injection",
        cwe_mapping="CWE-94",
    ),
    Rule(
        rule_id="CELERY018",
        name="celery-worker-runs-as-root",
        message_template="Worker configured to run as root",
        severity=RuleSeverity.CRITICAL,
        category=RuleCategory.SECURITY,
        description="Detects workers configured to run with root privileges",
        explanation="Workers running as root can lead to privilege escalation if compromised",
        fix_applicability=FixApplicability.SAFE,
        owasp_mapping="A04:2021 - Insecure Design",
        cwe_mapping="CWE-250",
    ),
    Rule(
        rule_id="CELERY019",
        name="celery-insecure-rpc",
        message_template="Worker RPC call without authentication",
        severity=RuleSeverity.MEDIUM,
        category=RuleCategory.SECURITY,
        description="Detects worker RPC calls without authentication checks",
        explanation="Unauthenticated RPC calls allow unauthorized worker control",
        fix_applicability=FixApplicability.MANUAL,
        owasp_mapping="A07:2021 - Identification and Authentication Failures",
        cwe_mapping="CWE-306",
    ),
    Rule(
        rule_id="CELERY020",
        name="celery-insecure-protocol",
        message_template="Task protocol version 1 is less secure",
        severity=RuleSeverity.MEDIUM,
        category=RuleCategory.SECURITY,
        description="Detects use of less secure task protocol version 1",
        explanation="Protocol version 1 lacks security improvements in version 2",
        fix_applicability=FixApplicability.SAFE,
        owasp_mapping="A05:2021 - Security Misconfiguration",
        cwe_mapping="CWE-757",
    ),
]

# Register rules
register_rules(CELERY_RULES)
