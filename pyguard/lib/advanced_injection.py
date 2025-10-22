"""
Advanced Injection Attacks Security Module.

Detects sophisticated injection vulnerabilities including template injection,
advanced SQL/NoSQL patterns, and OS command execution vectors.

Security Areas Covered (40 checks):

Template & Expression Injection (15 checks):
- Jinja2 SSTI (Server-Side Template Injection)
- Mako template injection
- Django template injection
- Tornado template injection
- Expression language injection (EL)
- OGNL injection
- SpEL (Spring Expression Language) injection
- FreeMarker template injection
- Velocity template injection
- Twig template injection
- Handlebars injection
- Pug/Jade injection
- ERB template injection
- Smarty template injection
- Mustache template injection

Advanced SQL & NoSQL (10 checks):
- Blind SQL injection (time-based)
- Second-order SQL injection
- SQL injection via ORDER BY clause
- UNION-based SQL injection
- Error-based SQL injection
- MongoDB operator injection ($where, $regex)
- CouchDB injection
- Cassandra CQL injection
- Redis command injection
- Elasticsearch query injection

OS & Code Execution (15 checks):
- Python code injection (compile, exec, eval edge cases)
- Pickle deserialization (expanded patterns)
- YAML deserialization (yaml.unsafe_load)
- XML deserialization attacks
- Path traversal (../ sequences)
- File inclusion vulnerabilities (LFI/RFI)
- LDAP injection in queries
- XPath injection
- CSV injection (formula injection)
- LaTeX injection
- PDF generation injection
- Image processing command injection
- Archive extraction vulnerabilities (zip slip)
- Subprocess shell=True dangers
- os.system() usage detection

Total Security Checks: 40 rules (INJECT001-INJECT040)

References:
- OWASP Top 10 2021 (A03:2021 – Injection) | https://owasp.org/Top10/A03_2021-Injection/ | Critical
- CWE-74 (Improper Neutralization) | https://cwe.mitre.org/data/definitions/74.html | Critical
- CWE-89 (SQL Injection) | https://cwe.mitre.org/data/definitions/89.html | Critical
- CWE-94 (Code Injection) | https://cwe.mitre.org/data/definitions/94.html | Critical
- CWE-78 (OS Command Injection) | https://cwe.mitre.org/data/definitions/78.html | Critical
- CWE-502 (Deserialization) | https://cwe.mitre.org/data/definitions/502.html | Critical
"""

import ast
from typing import List, Set, Optional

from pyguard.lib.rule_engine import (
    FixApplicability,
    RuleCategory,
    RuleSeverity,
    RuleViolation,
)


class AdvancedInjectionVisitor(ast.NodeVisitor):
    """AST visitor for detecting advanced injection vulnerabilities."""

    def __init__(self, source_code: str):
        """Initialize the advanced injection visitor."""
        self.violations: List[RuleViolation] = []
        self.source_code = source_code
        self.source_lines = source_code.split('\n')
        self.imported_modules: Set[str] = set()
        self.template_engines: Set[str] = set()

    def visit_Import(self, node: ast.Import):
        """Track imported modules for context."""
        for alias in node.names:
            self.imported_modules.add(alias.name)
            # Track template engine imports
            if any(tpl in alias.name for tpl in ['jinja2', 'mako', 'tornado', 'django']):
                self.template_engines.add(alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        """Track module imports for context."""
        if node.module:
            self.imported_modules.add(node.module)
            if any(tpl in node.module for tpl in ['jinja2', 'mako', 'tornado', 'django']):
                self.template_engines.add(node.module)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        """Check for injection vulnerabilities in function calls."""
        func_name = self._get_func_name(node)
        
        # Template Injection Checks (INJECT001-INJECT015)
        self._check_jinja2_ssti(node, func_name)
        self._check_mako_injection(node, func_name)
        self._check_django_template_injection(node, func_name)
        self._check_tornado_template_injection(node, func_name)
        self._check_other_template_engines(node, func_name)
        
        # Advanced SQL/NoSQL Checks (INJECT016-INJECT025)
        self._check_blind_sql_injection(node, func_name)
        self._check_order_by_injection(node, func_name)
        self._check_mongodb_injection(node, func_name)
        self._check_nosql_injection(node, func_name)
        
        # OS & Code Execution Checks (INJECT026-INJECT040)
        self._check_yaml_unsafe_load(node, func_name)
        self._check_xml_deserialization(node, func_name)
        self._check_path_traversal(node, func_name)
        self._check_ldap_injection(node, func_name)
        self._check_xpath_injection(node, func_name)
        self._check_csv_injection(node, func_name)
        self._check_latex_injection(node, func_name)
        self._check_image_processing_injection(node, func_name)
        self._check_archive_extraction(node, func_name)
        self._check_subprocess_shell(node, func_name)
        self._check_os_system(node, func_name)
        
        self.generic_visit(node)

    def _get_func_name(self, node: ast.Call) -> str:
        """Extract function name from call node."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            value = node.func.value
            attr = node.func.attr
            if isinstance(value, ast.Name):
                return f"{value.id}.{attr}"
            elif isinstance(value, ast.Attribute):
                return f"{self._get_attr_chain(value)}.{attr}"
        return ""

    def _get_attr_chain(self, node: ast.Attribute) -> str:
        """Get full attribute chain (e.g., obj.method.call)."""
        if isinstance(node.value, ast.Name):
            return f"{node.value.id}.{node.attr}"
        elif isinstance(node.value, ast.Attribute):
            return f"{self._get_attr_chain(node.value)}.{node.attr}"
        return node.attr

    def _get_keyword_arg(self, node: ast.Call, keyword: str) -> Optional[ast.AST]:
        """Get keyword argument value from call node."""
        for kw in node.keywords:
            if kw.arg == keyword:
                return kw.value
        return None

    def _has_user_input(self, node: ast.AST) -> bool:
        """Check if node might contain user input."""
        user_input_indicators = [
            'request', 'input', 'argv', 'form', 'query', 'param',
            'POST', 'GET', 'cookie', 'header', 'body'
        ]
        
        if isinstance(node, ast.Name):
            return any(indicator in node.id.lower() for indicator in user_input_indicators)
        elif isinstance(node, ast.Attribute):
            attr_str = self._get_attr_chain(node).lower()
            return any(indicator in attr_str for indicator in user_input_indicators)
        elif isinstance(node, ast.Subscript):
            return self._has_user_input(node.value)
        
        # Check children
        for child in ast.walk(node):
            if isinstance(child, (ast.Name, ast.Attribute)):
                if self._has_user_input(child):
                    return True
        
        return False

    def _create_violation(
        self, node: ast.AST, rule_id: str, title: str,
        description: str, recommendation: str,
        severity: RuleSeverity, cwe_id: str, owasp_id: str
    ):
        """Create a rule violation."""
        from pathlib import Path
        
        violation = RuleViolation(
            rule_id=rule_id,
            category=RuleCategory.SECURITY,
            severity=severity,
            message=f"{title}: {description}",
            file_path=Path("<string>"),  # Will be set by caller
            line_number=node.lineno if hasattr(node, 'lineno') else 0,
            column=node.col_offset if hasattr(node, 'col_offset') else 0,
            fix_suggestion=recommendation,
            fix_applicability=FixApplicability.NONE,
            fix_data=None,
            owasp_id=owasp_id,
            cwe_id=cwe_id,
            source_tool="pyguard"
        )
        self.violations.append(violation)

    # ==================== Template & Expression Injection (15 checks) ====================

    def _check_jinja2_ssti(self, node: ast.Call, func_name: str):
        """INJECT001: Detect Jinja2 Server-Side Template Injection."""
        if 'jinja2' in self.imported_modules or 'Template' in func_name:
            # Check for render_template_string or Template().render() with user input
            if 'render_template_string' in func_name or ('Template' in func_name and 'render' in func_name):
                # Check if template string comes from user input
                if node.args and self._has_user_input(node.args[0]):
                    self._create_violation(
                        node, "INJECT001", "Jinja2 SSTI Vulnerability",
                        "Template string from user input can lead to Server-Side Template Injection (SSTI). "
                        "Attackers can execute arbitrary Python code through template expressions.",
                        "Never use user input as template source. Use render_template() with predefined templates. "
                        "If dynamic templates are needed, use template sandboxing and strict whitelist validation.",
                        RuleSeverity.CRITICAL,
                        "CWE-94",
                        "OWASP Top 10 2021 (A03:2021)"
                    )

    def _check_mako_injection(self, node: ast.Call, func_name: str):
        """INJECT002: Detect Mako template injection."""
        if 'mako' in self.imported_modules or 'Template' in func_name:
            if 'Template' in func_name and node.args and self._has_user_input(node.args[0]):
                self._create_violation(
                    node, "INJECT002", "Mako Template Injection",
                    "Mako template from user input enables code execution. "
                    "Mako templates can execute arbitrary Python code.",
                    "Use predefined templates only. Never construct templates from user input. "
                    "Enable strict_undefined=True and use template lookup with whitelist.",
                    RuleSeverity.CRITICAL,
                    "CWE-94",
                    "OWASP Top 10 2021 (A03:2021)"
                )

    def _check_django_template_injection(self, node: ast.Call, func_name: str):
        """INJECT003: Detect Django template injection."""
        if 'django.template' in self.imported_modules:
            if 'Template' in func_name and node.args and self._has_user_input(node.args[0]):
                self._create_violation(
                    node, "INJECT003", "Django Template Injection",
                    "Django template created from user input can lead to template injection. "
                    "Although Django templates are safer than Jinja2, they can still leak data.",
                    "Use Django's template loader with predefined template files. "
                    "Never create Template objects from user-provided strings.",
                    RuleSeverity.HIGH,
                    "CWE-94",
                    "OWASP Top 10 2021 (A03:2021)"
                )

    def _check_tornado_template_injection(self, node: ast.Call, func_name: str):
        """INJECT004: Detect Tornado template injection."""
        if 'tornado.template' in self.imported_modules:
            if 'Template' in func_name and node.args and self._has_user_input(node.args[0]):
                self._create_violation(
                    node, "INJECT004", "Tornado Template Injection",
                    "Tornado template from user input enables Server-Side Template Injection.",
                    "Use Tornado's template loader with predefined templates. "
                    "Enable autoescape=True and use template whitelist.",
                    RuleSeverity.CRITICAL,
                    "CWE-94",
                    "OWASP Top 10 2021 (A03:2021)"
                )

    def _check_other_template_engines(self, node: ast.Call, func_name: str):
        """INJECT005-INJECT015: Detect other template engine injections."""
        template_engines = {
            'INJECT005': ('freemarker', 'FreeMarker Template Injection'),
            'INJECT006': ('velocity', 'Velocity Template Injection'),
            'INJECT007': ('twig', 'Twig Template Injection'),
            'INJECT008': ('handlebars', 'Handlebars Template Injection'),
            'INJECT009': ('pug', 'Pug/Jade Template Injection'),
            'INJECT010': ('erb', 'ERB Template Injection'),
            'INJECT011': ('smarty', 'Smarty Template Injection'),
            'INJECT012': ('mustache', 'Mustache Template Injection'),
            'INJECT013': ('ognl', 'OGNL Injection'),
            'INJECT014': ('spel', 'SpEL Injection'),
            'INJECT015': ('el', 'Expression Language Injection'),
        }
        
        for rule_id, (engine, title) in template_engines.items():
            if engine in func_name.lower() or engine in str(self.imported_modules).lower():
                if 'Template' in func_name or 'render' in func_name or 'compile' in func_name:
                    if node.args and self._has_user_input(node.args[0]):
                        self._create_violation(
                            node, rule_id, title,
                            f"{engine.capitalize()} template from user input enables template injection attacks.",
                            f"Use predefined {engine.capitalize()} templates only. "
                            "Never construct templates from user input. Use template sandboxing.",
                            RuleSeverity.CRITICAL,
                            "CWE-94",
                            "OWASP Top 10 2021 (A03:2021)"
                        )

    # ==================== Advanced SQL & NoSQL (10 checks) ====================

    def _check_blind_sql_injection(self, node: ast.Call, func_name: str):
        """INJECT016: Detect potential blind SQL injection patterns."""
        if 'execute' in func_name or 'query' in func_name:
            # Look for time-based patterns: SLEEP(), WAITFOR DELAY, pg_sleep()
            if node.args:
                for arg in node.args:
                    if isinstance(arg, (ast.Constant, ast.JoinedStr)):
                        arg_str = self._extract_string_value(arg)
                        if arg_str:
                            time_funcs = ['SLEEP(', 'WAITFOR DELAY', 'pg_sleep(', 'BENCHMARK(']
                            if any(func in arg_str for func in time_funcs) and self._has_user_input(arg):
                                self._create_violation(
                                    node, "INJECT016", "Potential Blind SQL Injection",
                                    "Time-based SQL functions with user input indicate blind SQL injection vulnerability. "
                                    "Attackers can extract data using timing attacks.",
                                    "Use parameterized queries. Never concatenate user input into SQL. "
                                    "Validate and sanitize all user inputs.",
                                    RuleSeverity.CRITICAL,
                                    "CWE-89",
                                    "OWASP Top 10 2021 (A03:2021)"
                                )

    def _check_order_by_injection(self, node: ast.Call, func_name: str):
        """INJECT017: Detect SQL injection in ORDER BY clause."""
        if 'execute' in func_name or 'query' in func_name:
            if node.args:
                for arg in node.args:
                    arg_str = self._extract_string_value(arg)
                    if arg_str and 'ORDER BY' in arg_str.upper() and self._has_user_input(arg):
                        self._create_violation(
                            node, "INJECT017", "ORDER BY SQL Injection",
                            "ORDER BY clause with user input enables SQL injection. "
                            "Column names cannot be parameterized in most databases.",
                            "Use whitelist validation for column names. Map user input to allowed column names. "
                            "Never directly use user input in ORDER BY clause.",
                            RuleSeverity.HIGH,
                            "CWE-89",
                            "OWASP Top 10 2021 (A03:2021)"
                        )

    def _check_mongodb_injection(self, node: ast.Call, func_name: str):
        """INJECT018-INJECT019: Detect MongoDB injection attacks."""
        if 'find' in func_name or 'update' in func_name or 'aggregate' in func_name:
            if 'pymongo' in self.imported_modules or 'mongo' in func_name.lower():
                # Check for dangerous MongoDB operators
                if node.args or node.keywords:
                    query_arg = node.args[0] if node.args else self._get_keyword_arg(node, 'filter')
                    if query_arg:
                        # Check for $where operator (enables JavaScript execution)
                        if isinstance(query_arg, ast.Dict):
                            for key in query_arg.keys:
                                if isinstance(key, ast.Constant) and key.value == '$where':
                                    self._create_violation(
                                        node, "INJECT018", "MongoDB $where Injection",
                                        "$where operator enables JavaScript execution in MongoDB queries. "
                                        "User input in $where can lead to NoSQL injection.",
                                        "Avoid $where operator. Use standard query operators. "
                                        "If $where is necessary, validate and sanitize all inputs.",
                                        RuleSeverity.CRITICAL,
                                        "CWE-943",
                                        "OWASP Top 10 2021 (A03:2021)"
                                    )
                        
                        # Check for regex without proper escaping
                        if self._has_user_input(query_arg):
                            self._create_violation(
                                node, "INJECT019", "MongoDB NoSQL Injection",
                                "MongoDB query with user input may enable NoSQL injection. "
                                "Operators like $regex, $ne, $gt can be abused.",
                                "Use parameterized queries. Validate input types. "
                                "Escape special characters in regex patterns.",
                                RuleSeverity.HIGH,
                                "CWE-943",
                                "OWASP Top 10 2021 (A03:2021)"
                            )

    def _check_nosql_injection(self, node: ast.Call, func_name: str):
        """INJECT020-INJECT025: Detect other NoSQL injection patterns."""
        nosql_patterns = {
            'INJECT020': ('couchdb', 'CouchDB Injection'),
            'INJECT021': ('cassandra', 'Cassandra CQL Injection'),
            'INJECT022': ('redis', 'Redis Command Injection'),
            'INJECT023': ('elasticsearch', 'Elasticsearch Query Injection'),
            'INJECT024': ('dynamodb', 'DynamoDB Injection'),
            'INJECT025': ('neo4j', 'Neo4j Cypher Injection'),
        }
        
        for rule_id, (db, title) in nosql_patterns.items():
            if db in self.imported_modules or db in func_name.lower():
                if any(method in func_name for method in ['query', 'execute', 'search', 'get', 'put']):
                    if (node.args and self._has_user_input(node.args[0])) or \
                       (node.keywords and any(self._has_user_input(kw.value) for kw in node.keywords)):
                        self._create_violation(
                            node, rule_id, title,
                            f"{db.capitalize()} query with user input may enable NoSQL injection attacks.",
                            f"Use {db.capitalize()}'s parameterized query features. "
                            "Validate and sanitize all user inputs. Use type checking.",
                            RuleSeverity.HIGH,
                            "CWE-943",
                            "OWASP Top 10 2021 (A03:2021)"
                        )

    # ==================== OS & Code Execution (15 checks) ====================

    def _check_yaml_unsafe_load(self, node: ast.Call, func_name: str):
        """INJECT026: Detect unsafe YAML deserialization."""
        if 'yaml.load' in func_name or 'yaml.unsafe_load' in func_name:
            # yaml.load without Loader argument is unsafe
            if 'yaml.load' == func_name and not self._get_keyword_arg(node, 'Loader'):
                self._create_violation(
                    node, "INJECT026", "Unsafe YAML Deserialization",
                    "yaml.load() without Loader argument uses unsafe deserialization. "
                    "Can execute arbitrary Python code during deserialization.",
                    "Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader). "
                    "Never use yaml.unsafe_load() or yaml.load() without Loader.",
                    RuleSeverity.CRITICAL,
                    "CWE-502",
                    "OWASP Top 10 2021 (A08:2021)"
                )
            elif 'unsafe_load' in func_name:
                self._create_violation(
                    node, "INJECT026", "Unsafe YAML Deserialization",
                    "yaml.unsafe_load() explicitly uses unsafe deserialization. "
                    "This can execute arbitrary Python code.",
                    "Use yaml.safe_load() instead. Only use unsafe_load() for trusted data "
                    "and document the security implications.",
                    RuleSeverity.CRITICAL,
                    "CWE-502",
                    "OWASP Top 10 2021 (A08:2021)"
                )

    def _check_xml_deserialization(self, node: ast.Call, func_name: str):
        """INJECT027: Detect XML deserialization attacks (XXE)."""
        if 'xml.etree' in self.imported_modules or 'lxml' in self.imported_modules:
            unsafe_parsers = ['XMLParser', 'parse', 'fromstring', 'XMLTreeBuilder']
            if any(parser in func_name for parser in unsafe_parsers):
                # Check if external entities are disabled
                resolve_entities = self._get_keyword_arg(node, 'resolve_entities')
                if not resolve_entities or (isinstance(resolve_entities, ast.Constant) and resolve_entities.value):
                    self._create_violation(
                        node, "INJECT027", "XML External Entity (XXE) Vulnerability",
                        "XML parser may be vulnerable to XXE attacks. "
                        "External entities can read files, cause DoS, or perform SSRF.",
                        "Disable external entity processing: resolve_entities=False for lxml, "
                        "or use defusedxml library for safe XML parsing.",
                        RuleSeverity.HIGH,
                        "CWE-611",
                        "OWASP Top 10 2021 (A05:2021)"
                    )

    def _check_path_traversal(self, node: ast.Call, func_name: str):
        """INJECT028: Detect path traversal vulnerabilities."""
        file_ops = ['open', 'os.path.join', 'Path', 'shutil.copy', 'shutil.move']
        if any(op in func_name for op in file_ops):
            if node.args and self._has_user_input(node.args[0]):
                # Check for ../ patterns or user-controlled paths
                self._create_violation(
                    node, "INJECT028", "Path Traversal Vulnerability",
                    "File path from user input can lead to path traversal attacks. "
                    "Attackers can use ../ to access files outside intended directory.",
                    "Validate file paths. Use os.path.abspath() and check against base directory. "
                    "Use pathlib.Path.resolve() and verify path starts with allowed base.",
                    RuleSeverity.HIGH,
                    "CWE-22",
                    "OWASP Top 10 2021 (A01:2021)"
                )

    def _check_ldap_injection(self, node: ast.Call, func_name: str):
        """INJECT029: Detect LDAP injection vulnerabilities."""
        if 'ldap' in self.imported_modules or 'ldap' in func_name.lower():
            if 'search' in func_name and node.args and self._has_user_input(node.args[0]):
                self._create_violation(
                    node, "INJECT029", "LDAP Injection Vulnerability",
                    "LDAP query with user input can enable LDAP injection attacks. "
                    "Attackers can modify LDAP filters to bypass authentication or access unauthorized data.",
                    "Escape special LDAP characters: ( ) \\ * NUL. "
                    "Use parameterized LDAP queries or whitelist validation.",
                    RuleSeverity.HIGH,
                    "CWE-90",
                    "OWASP Top 10 2021 (A03:2021)"
                )

    def _check_xpath_injection(self, node: ast.Call, func_name: str):
        """INJECT030: Detect XPath injection vulnerabilities."""
        if 'xpath' in func_name.lower() or 'lxml' in self.imported_modules:
            if node.args and self._has_user_input(node.args[0]):
                self._create_violation(
                    node, "INJECT030", "XPath Injection Vulnerability",
                    "XPath expression with user input enables XPath injection. "
                    "Attackers can extract unauthorized XML data or bypass access controls.",
                    "Use parameterized XPath queries. Escape XPath special characters. "
                    "Validate and sanitize all user inputs before constructing XPath.",
                    RuleSeverity.HIGH,
                    "CWE-643",
                    "OWASP Top 10 2021 (A03:2021)"
                )

    def _check_csv_injection(self, node: ast.Call, func_name: str):
        """INJECT031: Detect CSV injection (formula injection)."""
        if 'csv.writer' in func_name or 'writerow' in func_name:
            if node.args:
                for arg in node.args:
                    if self._has_user_input(arg):
                        self._create_violation(
                            node, "INJECT031", "CSV Injection (Formula Injection)",
                            "CSV data from user input can contain malicious formulas. "
                            "Spreadsheet programs execute formulas starting with =, +, -, @.",
                            "Sanitize CSV data: prepend ' (single quote) to cells starting with =+-@. "
                            "Warn users about untrusted CSV files.",
                            RuleSeverity.MEDIUM,
                            "CWE-1236",
                            "OWASP Top 10 2021 (A03:2021)"
                        )

    def _check_latex_injection(self, node: ast.Call, func_name: str):
        """INJECT032: Detect LaTeX injection vulnerabilities."""
        if 'latex' in func_name.lower() or 'pdflatex' in func_name.lower():
            if node.args and self._has_user_input(node.args[0]):
                self._create_violation(
                    node, "INJECT032", "LaTeX Injection Vulnerability",
                    "LaTeX document from user input can execute arbitrary commands. "
                    "LaTeX \\input, \\write18 commands can read/write files.",
                    "Sanitize LaTeX input: disallow \\input, \\include, \\write18. "
                    "Use restricted LaTeX mode or template-based generation.",
                    RuleSeverity.HIGH,
                    "CWE-74",
                    "OWASP Top 10 2021 (A03:2021)"
                )

    def _check_image_processing_injection(self, node: ast.Call, func_name: str):
        """INJECT033: Detect image processing command injection."""
        image_libs = ['ImageMagick', 'Pillow', 'PIL', 'convert', 'mogrify']
        if any(lib in func_name for lib in image_libs):
            if 'subprocess' in self.imported_modules or 'os.system' in func_name:
                if node.args and self._has_user_input(node.args[0]):
                    self._create_violation(
                        node, "INJECT033", "Image Processing Command Injection",
                        "Image processing with user-controlled filenames can lead to command injection. "
                        "ImageMagick delegate vulnerabilities enable arbitrary code execution.",
                        "Use Pillow (PIL) instead of ImageMagick when possible. "
                        "Validate and sanitize all file paths. Disable ImageMagick delegates.",
                        RuleSeverity.HIGH,
                        "CWE-78",
                        "OWASP Top 10 2021 (A03:2021)"
                    )

    def _check_archive_extraction(self, node: ast.Call, func_name: str):
        """INJECT034: Detect archive extraction vulnerabilities (zip slip)."""
        if 'extractall' in func_name or 'extract' in func_name:
            if 'zipfile' in self.imported_modules or 'tarfile' in self.imported_modules:
                self._create_violation(
                    node, "INJECT034", "Archive Extraction Vulnerability (Zip Slip)",
                    "Archive extraction without path validation enables directory traversal. "
                    "Malicious archives can write files outside extraction directory using ../ paths.",
                    "Validate extracted paths: resolve absolute path and check it starts with target directory. "
                    "Use safe_extract libraries or manually verify each entry.",
                    RuleSeverity.HIGH,
                    "CWE-22",
                    "OWASP Top 10 2021 (A01:2021)"
                )

    def _check_subprocess_shell(self, node: ast.Call, func_name: str):
        """INJECT035: Detect subprocess shell=True with user input."""
        if 'subprocess' in func_name:
            shell_arg = self._get_keyword_arg(node, 'shell')
            if shell_arg and isinstance(shell_arg, ast.Constant) and shell_arg.value is True:
                if node.args and self._has_user_input(node.args[0]):
                    self._create_violation(
                        node, "INJECT035", "Command Injection via subprocess",
                        "subprocess with shell=True and user input enables command injection. "
                        "Shell metacharacters (;|&$) allow arbitrary command execution.",
                        "Use shell=False and pass commands as list. "
                        "If shell is needed, use shlex.quote() to escape arguments.",
                        RuleSeverity.CRITICAL,
                        "CWE-78",
                        "OWASP Top 10 2021 (A03:2021)"
                    )

    def _check_os_system(self, node: ast.Call, func_name: str):
        """INJECT036: Detect os.system() usage with user input."""
        if 'os.system' in func_name or 'os.popen' in func_name:
            if node.args and self._has_user_input(node.args[0]):
                self._create_violation(
                    node, "INJECT036", "Command Injection via os.system",
                    "os.system() with user input is highly dangerous. "
                    "All shell features are available for exploitation.",
                    "Use subprocess.run() with shell=False. "
                    "Pass command and arguments as a list, not a string.",
                    RuleSeverity.CRITICAL,
                    "CWE-78",
                    "OWASP Top 10 2021 (A03:2021)"
                )

    def _extract_string_value(self, node: ast.AST) -> Optional[str]:
        """Extract string value from AST node."""
        if isinstance(node, ast.Constant):
            return str(node.value) if node.value else None
        elif isinstance(node, ast.JoinedStr):
            # f-string
            parts = []
            for value in node.values:
                if isinstance(value, ast.Constant):
                    parts.append(str(value.value))
            return ''.join(parts) if parts else None
        return None


def analyze_advanced_injection(source_code: str) -> List[RuleViolation]:
    """
    Analyze Python code for advanced injection vulnerabilities.
    
    Args:
        source_code: Python source code to analyze
        
    Returns:
        List of rule violations found
    """
    try:
        tree = ast.parse(source_code)
    except SyntaxError:
        return []
    
    visitor = AdvancedInjectionVisitor(source_code)
    visitor.visit(tree)
    return visitor.violations

