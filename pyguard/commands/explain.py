"""PyGuard explain command - Explain security issues and best practices."""

from __future__ import annotations

import argparse

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel


class ExplainCommand:
    """Explain security issues and best practices."""

    # Knowledge base of explanations
    EXPLANATIONS = {
        "hardcoded-password": {
            "title": "Hardcoded Password",
            "severity": "CRITICAL",
            "description": """
# Hardcoded Password

Hardcoded passwords in source code are a critical security vulnerability.

## Why It's Dangerous

- **Source Control Exposure**: Passwords in code are stored in version control history forever
- **Insider Threats**: Anyone with code access can see credentials
- **Accidental Leaks**: Code might be shared publicly or leaked
- **Rotation Difficulty**: Changing passwords requires code changes and redeployment

## How to Fix

1. **Use Environment Variables**:
   ```python
   import os
   password = os.getenv('DB_PASSWORD')
   ```

2. **Use Secret Management Systems**:
   - AWS Secrets Manager
   - Azure Key Vault
   - HashiCorp Vault
   - GCP Secret Manager

3. **Use Configuration Files** (with proper permissions):
   ```python
   import json
   with open('/etc/myapp/secrets.json') as f:
       secrets = json.load(f)
   password = secrets['db_password']
   ```

## References

- **OWASP**: A07:2021 – Identification and Authentication Failures
- **CWE**: CWE-798 (Use of Hard-coded Credentials)
""",
        },
        "sql-injection": {
            "title": "SQL Injection",
            "severity": "CRITICAL",
            "description": """
# SQL Injection

SQL injection allows attackers to execute arbitrary SQL commands.

## Why It's Dangerous

- **Data Breach**: Attackers can read sensitive data
- **Data Modification**: Can update or delete records
- **Authentication Bypass**: Can bypass login mechanisms
- **Server Compromise**: May gain OS-level access

## How to Fix

1. **Use Parameterized Queries**:
   ```python
   # BAD
   cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

   # GOOD
   cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
   ```

2. **Use ORM Safely**:
   ```python
   # SQLAlchemy (GOOD)
   user = session.query(User).filter(User.id == user_id).first()
   ```

3. **Input Validation**:
   ```python
   if not user_id.isdigit():
       raise ValueError("Invalid user ID")
   ```

## References

- **OWASP**: A03:2021 – Injection
- **CWE**: CWE-89 (SQL Injection)
""",
        },
        "command-injection": {
            "title": "Command Injection",
            "severity": "CRITICAL",
            "description": """
# Command Injection

Command injection allows attackers to execute arbitrary system commands.

## Why It's Dangerous

- **Server Compromise**: Full control over the system
- **Data Exfiltration**: Can steal sensitive files
- **Malware Installation**: Can install backdoors
- **Denial of Service**: Can crash or disable services

## How to Fix

1. **Use Safe Alternatives**:
   ```python
   # BAD
   os.system(f"ping {host}")  # SECURITY: Use subprocess.run() instead  # SECURITY: Use subprocess.run() instead

   # GOOD
   subprocess.run(["ping", "-c", "1", host], check=True)
   ```

2. **Validate Input**:
   ```python
   import re
   if not re.match(r'^[a-zA-Z0-9.-]+$', host):
       raise ValueError("Invalid hostname")
   ```

3. **Use Built-in Functions**:
   ```python
   # Instead of `rm file`
   Path(file).unlink()

   # Instead of `mkdir dir`
   Path(dir).mkdir(exist_ok=True)
   ```

## References

- **OWASP**: A03:2021 – Injection
- **CWE**: CWE-78 (OS Command Injection)
""",
        },
        "eval-usage": {
            "title": "Dangerous Use of eval()",  # DANGEROUS: Avoid eval with untrusted input
            "severity": "HIGH",
            "description": """
# Dangerous Use of eval()

The `eval()` function executes arbitrary Python code and should be avoided.  # DANGEROUS: Avoid eval with untrusted input

## Why It's Dangerous

- **Code Injection**: Attackers can execute malicious code
- **Data Access**: Can access sensitive variables and modules
- **System Compromise**: Can import os/subprocess for system access

## How to Fix

1. **Use ast.literal_eval() for Data**:  # DANGEROUS: Avoid eval with untrusted input
   ```python
   # BAD
   data = eval(user_input)  # DANGEROUS: Avoid eval with untrusted input

   # GOOD (for literals only)
   import ast
   data = ast.literal_eval(user_input)  # DANGEROUS: Avoid eval with untrusted input
   ```

2. **Use json.loads() for JSON**:
   ```python
   import json
   data = json.loads(user_input)
   ```

3. **Use Specific Parsers**:
   - For math: `sympy.sympify()` with locals disabled
   - For config: `configparser`, `json`, `toml`

## References

- **CWE**: CWE-95 (Improper Neutralization of Directives in Dynamically Evaluated Code)
""",
        },
        "weak-crypto": {
            "title": "Weak Cryptographic Algorithm",
            "severity": "HIGH",
            "description": """
# Weak Cryptographic Algorithm

Using weak or outdated cryptographic algorithms compromises security.

## Weak Algorithms to Avoid

- **MD5**: Broken, collision attacks exist
- **SHA1**: Deprecated, collision attacks exist
- **DES/3DES**: Small key size, slow
- **RC4**: Biases in keystream

## How to Fix

1. **Use Strong Hash Functions**:
   ```python
   import hashlib

   # BAD
   hash = hashlib.md5(data).hexdigest()  # SECURITY: Consider using SHA256 or stronger

   # GOOD
   hash = hashlib.sha256(data).hexdigest()
   # or even better: blake2b, SHA-3
   ```

2. **Use Modern Encryption**:
   ```python
   from cryptography.fernet import Fernet

   # Generate key
   key = Fernet.generate_key()
   f = Fernet(key)

   # Encrypt
   encrypted = f.encrypt(data)
   ```

3. **For Passwords, Use Specialized Functions**:
   ```python
   import bcrypt

   # Hash
   hashed = bcrypt.hashpw(password, bcrypt.gensalt())

   # Verify
   if bcrypt.checkpw(password, hashed):
       print("Password matches")
   ```

## References

- **OWASP**: A02:2021 – Cryptographic Failures
- **CWE**: CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)
""",
        },
        "path-traversal": {
            "title": "Path Traversal",
            "severity": "HIGH",
            "description": """
# Path Traversal

Path traversal allows attackers to access files outside intended directories.

## Why It's Dangerous

- **Unauthorized File Access**: Read sensitive files (/etc/passwd)
- **Configuration Exposure**: Access config files
- **Code Disclosure**: Read source code
- **Potential RCE**: Overwrite critical files

## How to Fix

1. **Validate and Sanitize Paths**:
   ```python
   from pathlib import Path

   # BAD
   file_path = f"/app/uploads/{user_filename}"

   # GOOD
   base_dir = Path("/app/uploads").resolve()
   file_path = (base_dir / user_filename).resolve()

   if not file_path.is_relative_to(base_dir):
       raise ValueError("Path traversal detected")
   ```

2. **Use Allowlists**:
   ```python
   ALLOWED_FILES = {'report.pdf', 'invoice.pdf'}
   if filename not in ALLOWED_FILES:
       raise ValueError("File not allowed")
   ```

3. **Remove Dangerous Characters**:
   ```python
   import re
   safe_filename = re.sub(r'[^a-zA-Z0-9._-]', '', filename)
   ```

## References

- **OWASP**: A01:2021 – Broken Access Control
- **CWE**: CWE-22 (Path Traversal)
""",
        },
    }

    @staticmethod
    def add_parser(subparsers: argparse._SubParsersAction) -> None:
        """Add explain command parser."""
        parser = subparsers.add_parser(
            "explain",
            help="Explain security issues",
            description="Get detailed explanations of security issues and how to fix them",
        )
        parser.add_argument(
            "issue",
            nargs="?",
            help="Issue ID to explain (e.g., 'sql-injection', 'hardcoded-password')",
        )
        parser.add_argument(
            "--list",
            "-l",
            action="store_true",
            help="List all available explanations",
        )
        parser.set_defaults(func=ExplainCommand.run)

    @staticmethod
    def run(args: argparse.Namespace) -> int:
        """Execute explain command."""
        console = Console()

        if args.list or not args.issue:
            # List all available explanations
            console.print("[bold cyan]Available Explanations:[/bold cyan]")
            console.print()

            for issue_id, info in ExplainCommand.EXPLANATIONS.items():
                severity_color = {
                    "CRITICAL": "red",
                    "HIGH": "orange1",
                    "MEDIUM": "yellow",
                    "LOW": "blue",
                }
                color = severity_color.get(info["severity"], "white")
                console.print(
                    f"  [{color}]{info['severity']}[/{color}] [cyan]{issue_id}[/cyan] - {info['title']}"
                )

            console.print()
            console.print("Use [cyan]pyguard explain <issue-id>[/cyan] for details")
            return 0

        # Normalize issue ID
        issue_id = args.issue.lower().replace("_", "-")

        if issue_id not in ExplainCommand.EXPLANATIONS:
            console.print(f"[red]Unknown issue: {args.issue}[/red]")
            console.print()
            console.print("Use [cyan]pyguard explain --list[/cyan] to see available explanations")
            return 1

        # Show explanation
        info = ExplainCommand.EXPLANATIONS[issue_id]

        # Create panel with explanation
        md = Markdown(info["description"])
        panel = Panel(
            md,
            title=f"[bold]{info['title']}[/bold]",
            subtitle=f"Severity: {info['severity']}",
            border_style="cyan",
        )

        console.print(panel)
        return 0
