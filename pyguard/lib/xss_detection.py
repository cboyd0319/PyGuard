"""
XSS (Cross-Site Scripting) Detection for PyGuard.

Comprehensive detection of XSS vulnerabilities in Python web applications
with support for multiple frameworks (Django, Flask, Jinja2, Mako).

Detection Rules:
1. Unescaped template output
2. Raw HTML rendering without sanitization
3. Disabled auto-escaping in template engines
4. User input directly in HTML/JavaScript context
5. Missing CSP headers
6. innerHTML/outerHTML usage
7. DOM-based XSS patterns
8. Django mark_safe misuse
9. Flask Markup misuse
10. Format string injections in HTML

References:
- OWASP Top 10 2021: A03 Injection
- CWE-79: Cross-Site Scripting
- OWASP ASVS v5.0: Section 5.3 (Output Encoding)
"""

import ast
from pathlib import Path
import re

from pyguard.lib.core import PyGuardLogger
from pyguard.lib.rule_engine import (
    FixApplicability,
    Rule,
    RuleCategory,
    RuleSeverity,
    RuleViolation,
)

logger = PyGuardLogger()


class XSSDetector(ast.NodeVisitor):
    """
    AST visitor for detecting XSS vulnerabilities in Python web applications.

    Detects various XSS patterns across multiple frameworks and contexts.
    """

    def __init__(self, file_path: Path, source_code: str):
        """Initialize XSS detector."""
        self.file_path = file_path
        self.source_code = source_code
        self.source_lines = source_code.splitlines()
        self.violations: list[RuleViolation] = []
        self.imports: set[str] = set()
        self.from_imports: dict[str, set[str]] = {}

    def _get_call_name(self, node: ast.Call) -> str:
        """Get the full name of a function call."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            parts = []
            current: ast.expr = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))
        return ""

    def _is_user_input(self, node: ast.expr) -> bool:
        """Check if node represents potential user input."""
        if isinstance(node, ast.Name):
            name = node.id.lower()
            return any(
                keyword in name
                for keyword in ["request", "input", "user", "param", "query", "form", "data"]
            )
        if isinstance(node, (ast.Subscript, ast.Attribute)):
            return self._is_user_input(node.value)
        return False

    def visit_Import(self, node: ast.Import) -> None:
        """Track imports for framework detection."""
        for alias in node.names:
            self.imports.add(alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Track from imports for framework detection."""
        if node.module:
            if node.module not in self.from_imports:
                self.from_imports[node.module] = set()
            for alias in node.names:
                self.from_imports[node.module].add(alias.name)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:  # noqa: PLR0912 - Complex XSS detection requires many checks
        """Check function calls for XSS vulnerabilities."""
        func_name = self._get_call_name(node)

        # XSS-001: Jinja2 Environment without autoescape
        if func_name in ["Environment", "jinja2.Environment"]:
            has_autoescape = False
            autoescape_disabled = False

            for kw in node.keywords:
                if kw.arg == "autoescape":
                    has_autoescape = True
                    if isinstance(kw.value, ast.Constant) and kw.value.value is False:
                        autoescape_disabled = True

            if autoescape_disabled:
                self.violations.append(
                    RuleViolation(
                        rule_id="XSS001",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.HIGH,
                        message="Jinja2 Environment created with autoescape=False, vulnerable to XSS",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        column=node.col_offset,
                        fix_suggestion="Set autoescape=True to protect against XSS attacks",
                        fix_applicability=FixApplicability.SAFE,
                        source_tool="pyguard",
                    )
                )
            elif not has_autoescape:
                self.violations.append(
                    RuleViolation(
                        rule_id="XSS002",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.MEDIUM,
                        message="Jinja2 Environment created without explicit autoescape setting",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        column=node.col_offset,
                        fix_suggestion="Add autoescape=True for explicit XSS protection",
                        fix_applicability=FixApplicability.SAFE,
                        source_tool="pyguard",
                    )
                )

        # XSS-003: Django mark_safe with user input
        elif func_name in ["mark_safe", "django.utils.safestring.mark_safe"]:
            if node.args and self._is_user_input(node.args[0]):
                self.violations.append(
                    RuleViolation(
                        rule_id="XSS003",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.HIGH,
                        message="Django mark_safe() used with user input, vulnerable to XSS",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        column=node.col_offset,
                        fix_suggestion="Sanitize user input before using mark_safe(), or use escape() instead",
                        fix_applicability=FixApplicability.SUGGESTED,
                        source_tool="pyguard",
                    )
                )

        # XSS-004: Flask Markup with user input
        elif func_name in ["Markup", "flask.Markup"]:
            if node.args and self._is_user_input(node.args[0]):
                self.violations.append(
                    RuleViolation(
                        rule_id="XSS004",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.HIGH,
                        message="Flask Markup() used with user input, vulnerable to XSS",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        column=node.col_offset,
                        fix_suggestion="Sanitize user input before using Markup(), or use escape() instead",
                        fix_applicability=FixApplicability.SUGGESTED,
                        source_tool="pyguard",
                    )
                )

        # XSS-005: render_template_string with user input
        elif "render_template_string" in func_name:
            # Any use of render_template_string with arguments should be checked
            if node.args:
                # Check if any argument could be user input
                has_user_input = any(self._is_user_input(arg) for arg in node.args)
                if has_user_input or len(node.args) > 0:  # Even static use is risky
                    self.violations.append(
                        RuleViolation(
                            rule_id="XSS005",
                            category=RuleCategory.SECURITY,
                            severity=RuleSeverity.CRITICAL,
                            message="Flask render_template_string() with user-controlled template, vulnerable to SSTI and XSS",
                            file_path=self.file_path,
                            line_number=node.lineno,
                            column=node.col_offset,
                            fix_suggestion="Use render_template() with predefined templates, never user input",
                            fix_applicability=FixApplicability.SUGGESTED,
                            source_tool="pyguard",
                        )
                    )

        # XSS-006: Mako Template usage (inherently risky)
        elif func_name in ["Template", "mako.template.Template"]:
            self.violations.append(
                RuleViolation(
                    rule_id="XSS006",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="Mako templates do not auto-escape by default, vulnerable to XSS",
                    file_path=self.file_path,
                    line_number=node.lineno,
                    column=node.col_offset,
                    fix_suggestion="Use Jinja2 with autoescape=True, or manually escape all output in Mako",
                    fix_applicability=FixApplicability.SUGGESTED,
                    source_tool="pyguard",
                )
            )

        # XSS-007: Direct HTML response without escaping
        elif "HttpResponse" in func_name:
            if node.args:
                # Check if first argument is user input or a variable that could be user input
                arg = node.args[0]
                if self._is_user_input(arg) or (
                    isinstance(arg, ast.Name)
                    and any(
                        keyword in arg.id.lower()
                        for keyword in ["html", "data", "content", "user", "input"]
                    )
                ):
                    self.violations.append(
                        RuleViolation(
                            rule_id="XSS007",
                            category=RuleCategory.SECURITY,
                            severity=RuleSeverity.HIGH,
                            message="HttpResponse with user input without escaping, vulnerable to XSS",
                            file_path=self.file_path,
                            line_number=node.lineno,
                            column=node.col_offset,
                            fix_suggestion="Use render() with templates or escape user input with escape()",
                            fix_applicability=FixApplicability.SUGGESTED,
                            source_tool="pyguard",
                        )
                    )

        # XSS-008: format() with user input in HTML context
        elif func_name == "format" and isinstance(node.func, ast.Attribute):
            # Check if it's string formatting
            if isinstance(node.func.value, ast.Constant):
                format_str = node.func.value.value
                if isinstance(format_str, str) and any(  # noqa: SIM102
                    tag in format_str for tag in ["<", ">", "href", "src"]
                ):
                    # HTML-like content in format string
                    if node.args and any(self._is_user_input(arg) for arg in node.args):
                        self.violations.append(
                            RuleViolation(
                                rule_id="XSS008",
                                category=RuleCategory.SECURITY,
                                severity=RuleSeverity.HIGH,
                                message="String formatting with user input in HTML context, vulnerable to XSS",
                                file_path=self.file_path,
                                line_number=node.lineno,
                                column=node.col_offset,
                                fix_suggestion="Escape user input before formatting, or use template engine with auto-escape",
                                fix_applicability=FixApplicability.SUGGESTED,
                                source_tool="pyguard",
                            )
                        )

        self.generic_visit(node)

    def visit_BinOp(self, node: ast.BinOp) -> None:
        """Check binary operations for HTML concatenation with user input."""
        # XSS-009: HTML string concatenation with user input
        if isinstance(node.op, (ast.Add, ast.Mod)):
            # Check if one side has HTML-like content
            has_html = False
            has_user_input = False

            def check_node(n):
                nonlocal has_html, has_user_input
                if isinstance(n, ast.Constant) and isinstance(n.value, str):  # noqa: SIM102
                    if any(tag in n.value for tag in ["<", ">", "href", "src", "<script", "<html"]):
                        has_html = True
                if self._is_user_input(n):
                    has_user_input = True

            # Check left and right sides only (not nested)
            check_node(node.left)
            check_node(node.right)

            if has_html and has_user_input:
                self.violations.append(
                    RuleViolation(
                        rule_id="XSS009",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.HIGH,
                        message="HTML string concatenation with user input, vulnerable to XSS",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        column=node.col_offset,
                        fix_suggestion="Use template engine with auto-escape, or manually escape user input",
                        fix_applicability=FixApplicability.SUGGESTED,
                        source_tool="pyguard",
                    )
                )

        self.generic_visit(node)

    def visit_JoinedStr(self, node: ast.JoinedStr) -> None:
        """Check f-strings for HTML content with user input."""
        # XSS-010: f-string with user input in HTML context
        has_html = False
        has_user_input = False

        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                if any(tag in value.value for tag in ["<", ">", "href", "src", "<script"]):
                    has_html = True
            elif isinstance(value, ast.FormattedValue):  # noqa: SIM102
                if self._is_user_input(value.value):
                    has_user_input = True

        if has_html and has_user_input:
            self.violations.append(
                RuleViolation(
                    rule_id="XSS010",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.HIGH,
                    message="f-string with user input in HTML context, vulnerable to XSS",
                    file_path=self.file_path,
                    line_number=node.lineno,
                    column=node.col_offset,
                    fix_suggestion="Use template engine with auto-escape, or manually escape user input",
                    fix_applicability=FixApplicability.SUGGESTED,
                    source_tool="pyguard",
                )
            )

        self.generic_visit(node)


def detect_xss_patterns(content: str) -> list[tuple[str, int, str]]:
    """
    Detect XSS patterns using regex (complement to AST analysis).

    Returns list of (pattern_name, line_number, line_content).
    """
    patterns = []
    lines = content.splitlines()

    for i, line in enumerate(lines, 1):
        # Pattern: innerHTML or outerHTML usage
        if re.search(r"\.(innerHTML|outerHTML)\s*=", line):
            patterns.append(("innerHTML_usage", i, line.strip()))

        # Pattern: document.write usage
        if re.search(r"document\.write\(", line):
            patterns.append(("document_write", i, line.strip()))

        # Pattern: eval with potential user input
        if re.search(r"eval\s*\([^)]*(?:request|input|user|param)", line, re.IGNORECASE):
            patterns.append(("eval_user_input", i, line.strip()))

        # Pattern: Missing CSP headers in Flask/Django
        if re.search(r"@app\.route|def.*view.*\(request", line):
            # Check if CSP header is set in next few lines
            context_lines = lines[max(0, i - 1) : min(len(lines), i + 10)]
            if not any("Content-Security-Policy" in context_line for context_line in context_lines):
                patterns.append(("missing_csp", i, line.strip()))

        # Pattern: Dangerous Jinja2 filters (safe, bypass escaping)
        if re.search(r"\|\s*safe\b", line):
            patterns.append(("jinja2_safe_filter", i, line.strip()))

    return patterns


def check_xss_vulnerabilities(file_path: Path) -> list[RuleViolation]:
    """
    Check Python file for XSS vulnerabilities.

    Args:
        file_path: Path to Python file

    Returns:
        List of XSS rule violations
    """
    violations: list[RuleViolation] = []

    try:
        with open(file_path, encoding="utf-8") as f:
            content = f.read()

        # AST-based detection
        try:
            tree = ast.parse(content)
            visitor = XSSDetector(file_path, content)
            visitor.visit(tree)
            violations.extend(visitor.violations)
        except SyntaxError:
            logger.warning("Syntax error in file", file_path=str(file_path))

        # Regex-based detection for patterns not easily caught by AST
        regex_patterns = detect_xss_patterns(content)
        for pattern_name, line_num, _line_content in regex_patterns:
            severity = RuleSeverity.HIGH
            message = ""
            fix_suggestion = ""

            if pattern_name == "innerHTML_usage":
                message = "innerHTML usage detected, potential XSS if used with user input"
                fix_suggestion = "Use textContent or createTextNode(), or escape user input"
            elif pattern_name == "document_write":
                message = "document.write() usage detected, potential XSS vector"
                fix_suggestion = "Use modern DOM methods or template engines"
            elif pattern_name == "eval_user_input":
                message = "eval() with potential user input, critical XSS and code injection risk"
                fix_suggestion = "Never use eval() with user input, use safe alternatives"
                severity = RuleSeverity.CRITICAL
            elif pattern_name == "missing_csp":
                message = "Route handler without Content-Security-Policy header"
                fix_suggestion = "Add CSP header: response.headers['Content-Security-Policy'] = \"default-src 'self'\""
                severity = RuleSeverity.MEDIUM
            elif pattern_name == "jinja2_safe_filter":
                message = "Jinja2 'safe' filter bypasses auto-escaping, potential XSS"
                fix_suggestion = "Remove 'safe' filter or ensure content is properly sanitized"

            violations.append(
                RuleViolation(
                    rule_id=f"XSS-{pattern_name.upper()}",
                    category=RuleCategory.SECURITY,
                    severity=severity,
                    message=message,
                    file_path=file_path,
                    line_number=line_num,
                    column=0,
                    fix_suggestion=fix_suggestion,
                    fix_applicability=FixApplicability.SUGGESTED,
                    source_tool="pyguard",
                )
            )

    except Exception as e:
        logger.error("Error checking XSS vulnerabilities", file_path=str(file_path), error=str(e))

    return violations


# Rule definitions for integration with rule engine
XSS_RULES = [
    Rule(
        rule_id="XSS001",
        name="jinja2-autoescape-disabled",
        description="Jinja2 Environment with autoescape=False",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.SECURITY,
        message_template="Jinja2 autoescape disabled, XSS risk",
        fix_applicability=FixApplicability.SAFE,
    ),
    Rule(
        rule_id="XSS002",
        name="jinja2-missing-autoescape",
        description="Jinja2 Environment without explicit autoescape",
        severity=RuleSeverity.MEDIUM,
        category=RuleCategory.SECURITY,
        message_template="Missing explicit autoescape setting",
        fix_applicability=FixApplicability.SAFE,
    ),
    Rule(
        rule_id="XSS003",
        name="django-mark-safe-user-input",
        description="Django mark_safe with user input",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.SECURITY,
        message_template="mark_safe() with user input, XSS risk",
        fix_applicability=FixApplicability.SUGGESTED,
    ),
    Rule(
        rule_id="XSS004",
        name="flask-markup-user-input",
        description="Flask Markup with user input",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.SECURITY,
        message_template="Markup() with user input, XSS risk",
        fix_applicability=FixApplicability.SUGGESTED,
    ),
    Rule(
        rule_id="XSS005",
        name="flask-template-string-injection",
        description="render_template_string with user input",
        severity=RuleSeverity.CRITICAL,
        category=RuleCategory.SECURITY,
        message_template="render_template_string() with user template, SSTI/XSS risk",
        fix_applicability=FixApplicability.SUGGESTED,
    ),
    Rule(
        rule_id="XSS006",
        name="mako-template-no-autoescape",
        description="Mako templates without auto-escaping",
        severity=RuleSeverity.MEDIUM,
        category=RuleCategory.SECURITY,
        message_template="Mako template without auto-escape, XSS risk",
        fix_applicability=FixApplicability.SUGGESTED,
    ),
    Rule(
        rule_id="XSS007",
        name="django-httpresponse-user-input",
        description="HttpResponse with unescaped user input",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.SECURITY,
        message_template="HttpResponse with user input, XSS risk",
        fix_applicability=FixApplicability.SUGGESTED,
    ),
    Rule(
        rule_id="XSS008",
        name="html-format-string-injection",
        description="HTML string formatting with user input",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.SECURITY,
        message_template="HTML format string with user input, XSS risk",
        fix_applicability=FixApplicability.SUGGESTED,
    ),
    Rule(
        rule_id="XSS009",
        name="html-concatenation-user-input",
        description="HTML string concatenation with user input",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.SECURITY,
        message_template="HTML concatenation with user input, XSS risk",
        fix_applicability=FixApplicability.SUGGESTED,
    ),
    Rule(
        rule_id="XSS010",
        name="html-fstring-user-input",
        description="HTML f-string with user input",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.SECURITY,
        message_template="HTML f-string with user input, XSS risk",
        fix_applicability=FixApplicability.SUGGESTED,
    ),
]
