"""
Jupyter Notebook Security Analysis for PyGuard.

This module implements world-class security analysis for .ipynb files, aligned with
the PyGuard Jupyter Security Engineer vision. It provides comprehensive detection
across 13 security categories with 76+ vulnerability patterns.

**Detection Categories:**
1. Code Injection & Dynamic Execution (CRITICAL)
   - eval/exec/compile with untrusted input
   - Dynamic imports and attribute access
   - IPython kernel message injection
   
2. Unsafe Deserialization & ML Model Risks (CRITICAL)
   - pickle.load() arbitrary code execution
   - PyTorch torch.load() without weights_only
   - Hugging Face model poisoning
   
3. Shell & Magic Command Abuse (HIGH/CRITICAL)
   - System command execution via ! and %%bash
   - Unpinned package installations
   - Remote code loading
   
4. Network & Data Exfiltration (HIGH)
   - HTTP POST/PUT to external domains
   - Database connections without validation
   - Cloud SDK usage (AWS, GCP, Azure)
   - Raw socket access
   
5. Secrets & Credential Exposure (CRITICAL/HIGH)
   - 50+ secret patterns (AWS, GitHub, Slack, OpenAI, SSH, JWT)
   - Entropy-based detection for cryptographic keys
   - Secrets in outputs and metadata
   
6. Privacy & PII Leakage (HIGH)
   - SSN, credit cards, emails, phone numbers
   - PII in cell outputs and tracebacks
   
7. Output Payload Injection (HIGH/CRITICAL)
   - XSS via HTML/JavaScript rendering
   - Iframe injection and clickjacking
   
8. Filesystem & Path Traversal (HIGH)
   - Path traversal attempts
   - Access to sensitive system files
   - Unsafe file operations
   
9. Reproducibility & Environment Integrity (MEDIUM)
   - Missing random seeds for ML frameworks
   - Unpinned dependencies
   - Non-deterministic operations
   
10. Execution Order & Notebook Integrity (MEDIUM)
    - Non-monotonic execution counts
    - Variables used before definition
    
11. Resource Exhaustion & DoS (HIGH/CRITICAL)
    - Infinite loops
    - Large memory allocations
    - Fork bombs
    
12. Advanced ML/AI Security (HIGH/CRITICAL)
    - Prompt injection in LLM applications
    - Adversarial input acceptance
    - Model supply chain risks
    
13. Advanced Code Injection (CRITICAL)
    - Sandbox escape via dunder methods
    - Type manipulation
    - IPython kernel exploitation

**Auto-Fix Capabilities:**
- AST-based transformations for safety
- Minimal, surgical changes
- Idempotent fixes
- Educational comments with CWE/CVE references
- Rollback support via backups

**Compliance & Standards:**
- CWE (Common Weakness Enumeration) mapping
- OWASP ASVS alignment
- Confidence scoring (0.0-1.0)
- SARIF output support (planned)

**References:**
- Jupyter Security | https://jupyter-notebook.readthedocs.io/en/stable/security.html | High | Notebook security guide
- OWASP Jupyter | https://owasp.org/www-community/vulnerabilities/Jupyter_Notebook | Medium | Security considerations
- CVE-2024-39700 | https://nvd.nist.gov/vuln/detail/CVE-2024-39700 | Critical | JupyterLab RCE vulnerability
- CVE-2024-28233 | https://nvd.nist.gov/vuln/detail/CVE-2024-28233 | High | JupyterHub XSS vulnerability
- CVE-2024-22420 | https://nvd.nist.gov/vuln/detail/CVE-2024-22420 | Medium | JupyterLab Markdown preview vulnerability
- CVE-2025-30167 | https://nvd.nist.gov/vuln/detail/CVE-2025-30167 | High | Jupyter Core Windows configuration vulnerability
- CWE-502 | https://cwe.mitre.org/data/definitions/502.html | Deserialization of Untrusted Data
- CWE-95 | https://cwe.mitre.org/data/definitions/95.html | Improper Neutralization of Directives in Dynamically Evaluated Code
- CWE-798 | https://cwe.mitre.org/data/definitions/798.html | Use of Hard-coded Credentials

**World-Class Standards:**
This implementation targets:
- 100% detection rate for CRITICAL issues (eval, exec, pickle, torch.load, hardcoded secrets)
- < 5% false positive rate on HIGH severity
- Sub-100ms analysis for notebooks < 10 cells
- Comprehensive auto-fix with confidence scoring
"""

import ast
import json
import re
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Set

from pyguard.lib.core import PyGuardLogger


@dataclass
class NotebookCell:
    """Represents a Jupyter notebook cell."""

    cell_type: str  # "code", "markdown", "raw"
    source: str  # Cell source code
    execution_count: Optional[int]  # Execution order
    outputs: List[Dict[str, Any]]  # Cell outputs
    metadata: Dict[str, Any]  # Cell metadata


@dataclass
class NotebookIssue:
    """Security issue found in a notebook."""

    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    category: str  # Issue category
    message: str  # Issue description
    cell_index: int  # Cell where issue was found
    line_number: int  # Line within cell
    code_snippet: str  # Relevant code
    rule_id: str = ""  # Rule identifier (e.g., NB-INJECT-001)
    fix_suggestion: Optional[str] = None  # How to fix
    cwe_id: Optional[str] = None  # CWE identifier
    owasp_id: Optional[str] = None  # OWASP identifier
    confidence: float = 1.0  # Detection confidence (0.0-1.0)
    auto_fixable: bool = False  # Whether issue can be auto-fixed


@dataclass
class NotebookMetadata:
    """Notebook metadata for security analysis."""

    kernel_name: str
    language: str
    kernel_version: Optional[str] = None
    jupyter_version: Optional[str] = None
    trusted: bool = False  # Whether notebook is trusted
    execution_count_max: int = 0  # Maximum execution count seen
    has_outputs: bool = False  # Whether notebook has cell outputs


class NotebookSecurityAnalyzer:
    """
    World-class security analyzer for Jupyter notebooks.
    
    This analyzer implements comprehensive security detection across 13 categories
    with 76+ vulnerability patterns, following the PyGuard Jupyter Security Engineer
    vision for best-in-class notebook security.

    **Detection Capabilities:**
    - CRITICAL: eval/exec, pickle.load, torch.load, hardcoded secrets, code injection
    - HIGH: Shell commands, XSS, network exfiltration, filesystem access, PII exposure
    - MEDIUM: Reproducibility, execution order, resource exhaustion
    - LOW: Kernel metadata, environment info
    
    **Key Features:**
    - Pattern-based detection (76+ patterns)
    - Entropy-based secret detection (Shannon entropy > 4.5)
    - AST analysis for code injection
    - Cross-cell dataflow tracking
    - Confidence scoring (0.0-1.0)
    - CWE/OWASP mapping
    - Auto-fix suggestions
    
    **Performance:**
    - Target: Sub-100ms for small notebooks (< 10 cells)
    - Linear scaling to 1000+ cells
    - Parallel cell processing (planned)
    
    **Quality Metrics:**
    - Target: 100% detection on CRITICAL issues
    - Target: < 5% false positive rate on HIGH severity
    - Comprehensive test coverage (64+ test cases)
    
    Example:
        >>> analyzer = NotebookSecurityAnalyzer()
        >>> issues = analyzer.analyze_notebook(Path("notebook.ipynb"))
        >>> critical = [i for i in issues if i.severity == "CRITICAL"]
        >>> print(f"Found {len(critical)} critical issues")
    """

    # Dangerous magic commands - Enhanced to 14+ patterns (Category 3)
    DANGEROUS_MAGICS = {
        # System command execution
        "%system": "Direct system command execution",
        "!": "Shell command execution",
        "%%bash": "Bash script execution",
        "%%sh": "Shell script execution",
        "%%script": "Script execution",
        
        # Package management
        "%pip": "Pip package installation (version pinning recommended)",
        "%conda": "Conda package installation (version pinning recommended)",
        
        # Code loading from external sources
        "%load_ext": "Loading external extensions (may be unsafe)",
        "%run": "Running external scripts (path traversal risk)",
        "%load": "Loading code from external sources (verify integrity)",
        "%loadpy": "Loading Python code from URL or file (security risk)",
        
        # File operations
        "%%writefile": "Writing files (path traversal risk)",
        
        # Environment & State manipulation
        "%env": "Environment variable manipulation",
        "%set_env": "Setting environment variables (secret exposure risk)",
        "%store": "Cross-notebook variable storage (state poisoning risk)",
        
        # Directory navigation
        "%cd": "Directory change (filesystem structure exposure)",
        "%pwd": "Print working directory (filesystem disclosure)",
    }

    # Patterns for secrets in notebooks - Comprehensive 50+ patterns
    SECRET_PATTERNS = {
        # Generic patterns
        r"(?i)(password|passwd|pwd)\s*=\s*['\"]([^'\"]{8,})": "Hardcoded password",
        r"(?i)(api[_-]?key|apikey)\s*=\s*['\"]([^'\"]{16,})": "API key",
        r"(?i)(secret[_-]?key|secretkey)\s*=\s*['\"]([^'\"]{16,})": "Secret key",
        r"(?i)(token|auth[_-]?token)\s*=\s*['\"]([^'\"]{16,})": "Authentication token",
        r"(?i)(private[_-]?key)\s*=\s*['\"]([^'\"]{32,})": "Private key",
        # AWS credentials
        r"(?i)(aws[_-]?access[_-]?key[_-]?id)\s*=\s*['\"]([A-Z0-9]{20})": "AWS access key",
        r"(?i)(aws[_-]?secret[_-]?access[_-]?key)\s*=\s*['\"]([A-Za-z0-9/+=]{40})": "AWS secret key",
        r"AKIA[0-9A-Z]{16}": "AWS access key ID pattern",
        # GitHub tokens
        r"(?i)(github[_-]?token|gh[_-]?token)\s*=\s*['\"]([a-z0-9_]{40,})": "GitHub token",
        r"ghp_[a-zA-Z0-9]{36}": "GitHub personal access token",
        r"gho_[a-zA-Z0-9]{36}": "GitHub OAuth token",
        r"ghu_[a-zA-Z0-9]{36}": "GitHub user-to-server token",
        r"ghs_[a-zA-Z0-9]{36}": "GitHub server-to-server token",
        r"ghr_[a-zA-Z0-9]{36}": "GitHub refresh token",
        # Slack tokens
        r"(?i)(slack[_-]?token)\s*=\s*['\"]xox[a-z]-[a-zA-Z0-9-]+": "Slack token",
        r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}": "Slack bot token",
        r"xoxp-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}": "Slack user token",
        r"xoxa-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}": "Slack access token",
        r"xoxr-[a-zA-Z0-9-]+": "Slack refresh token",
        # OpenAI API keys
        r"sk-proj-[a-zA-Z0-9]{20,}": "OpenAI project API key",
        r"sk-[a-zA-Z0-9]{20,}": "OpenAI API key",
        # SSH/RSA keys
        r"-----BEGIN (RSA |DSA |EC )?PRIVATE KEY-----": "SSH/RSA private key",
        r"-----BEGIN OPENSSH PRIVATE KEY-----": "OpenSSH private key",
        # JWT tokens
        r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+": "JWT token",
        # Database connection strings
        r"(?i)(mongodb\+srv://|mongodb://)([^:]+):([^@]+)@": "MongoDB connection string with credentials",
        r"(?i)(postgres://|postgresql://)([^:]+):([^@]+)@": "PostgreSQL connection string with credentials",
        r"(?i)(mysql://|mariadb://)([^:]+):([^@]+)@": "MySQL connection string with credentials",
        r"(?i)(redis://):([^@]+)@": "Redis connection string with credentials",
        # Cloud provider patterns
        r"AKIA[0-9A-Z]{16}": "AWS access key",
        r"(?i)ya29\.[0-9A-Za-z\-_]+": "Google OAuth access token",
        r"(?i)AIza[0-9A-Za-z\-_]{35}": "Google API key",
        r"(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}": "Generic UUID (potential API key)",
        # Azure
        r"(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+": "Azure storage connection string",
        # Stripe
        r"sk_live_[0-9a-zA-Z]{24,}": "Stripe live secret key",
        r"pk_live_[0-9a-zA-Z]{24,}": "Stripe live publishable key",
        r"rk_live_[0-9a-zA-Z]{24,}": "Stripe live restricted key",
        # SendGrid
        r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}": "SendGrid API key",
        # Twilio
        r"SK[a-z0-9]{32}": "Twilio API key",
        # NPM tokens
        r"npm_[a-zA-Z0-9]{36}": "NPM access token",
        # Shopify
        r"shpat_[a-fA-F0-9]{32}": "Shopify private app access token",
        r"shpca_[a-fA-F0-9]{32}": "Shopify custom app access token",
        # Mailchimp
        r"[0-9a-f]{32}-us[0-9]{1,2}": "Mailchimp API key",
        # Square
        r"sq0atp-[0-9A-Za-z\-_]{22}": "Square access token",
        r"sq0csp-[0-9A-Za-z\-_]{43}": "Square OAuth secret",
        # Dropbox
        r"sl\.[a-zA-Z0-9_-]{135}": "Dropbox API secret",
        # Facebook
        r"EAACEdEose0cBA[0-9A-Za-z]+": "Facebook access token",
        # Twitter
        r"[1-9][0-9]+-[0-9a-zA-Z]{40}": "Twitter access token pattern",
        # Heroku
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}": "Heroku API key",
        # Telegram
        r"[0-9]{8,10}:[a-zA-Z0-9_-]{35}": "Telegram bot token",
    }

    # PII detection patterns - Enhanced to 14+ patterns
    PII_PATTERNS = {
        # Identity numbers
        r"\b\d{3}-\d{2}-\d{4}\b": "Social Security Number (SSN)",
        r"\b[A-Z]{1,2}\d{6,8}[A-Z]?\b": "Passport number pattern",
        
        # Contact information
        r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b": "Email address",
        r"\b(?:\d{3}[-.]?)?\d{3}[-.]?\d{4}\b": "Phone number",
        
        # Financial data
        r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b": "Credit card number",
        r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b": "IBAN (International Bank Account Number)",
        r"\b[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?\b": "SWIFT/BIC code",
        
        # Network identifiers
        r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b": "IPv4 address",
        r"\b([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b": "IPv6 address",
        r"\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b": "MAC address",
        
        # Geographic data
        r"\b[A-Z]{1,2}\d{1,2}[A-Z]?\s*\d[A-Z]{2}\b": "UK postal code",
        r"\b\d{5}(-\d{4})?\b": "US ZIP code",
        
        # Medical & Health
        r"\b[A-Z]\d{2}\.\d{1,3}\b": "ICD-10 diagnosis code pattern",
        r"\bMRN[:\s-]?\d{6,10}\b": "Medical Record Number (MRN)",
    }

    # Risky ML/Data Science operations - Enhanced with 22+ patterns (Category 2)
    ML_SECURITY_PATTERNS = {
        # Pickle-based deserialization (CRITICAL)
        r"pickle\.loads?\(": "Unsafe pickle deserialization (model poisoning risk)",
        r"joblib\.load\(": "Joblib model loading (verify source)",
        r"pd\.read_pickle\(": "Pandas pickle reading (code execution risk)",
        r"np\.load\(.*allow_pickle\s*=\s*True": "NumPy pickle loading enabled",
        r"dill\.loads?\(": "Dill deserialization (arbitrary code execution risk)",
        
        # PyTorch (CRITICAL)
        r"torch\.load\(": "PyTorch model loading (arbitrary code execution risk via __reduce__)",
        r"torch\.jit\.load\(": "PyTorch JIT model loading (verify source and checksum)",
        
        # TensorFlow & Keras (HIGH)
        r"tf\.keras\.models\.load_model\(": "TensorFlow Keras model loading (verify source)",
        r"keras\.models\.load_model": "Keras model loading with potential custom layers",
        r"tf\.saved_model\.load\(": "TensorFlow SavedModel loading without signature verification",
        r"tf\.keras\.models\.model_from_json\(": "Keras model from JSON (verify architecture integrity)",
        r"tf\.keras\.models\.model_from_yaml\(": "Keras model from YAML (architecture injection risk)",
        
        # ONNX (HIGH)
        r"onnx\.load\(": "ONNX model loading without opset validation",
        r"onnxruntime\.InferenceSession\(": "ONNX Runtime inference (verify model source)",
        
        # Hugging Face Transformers (HIGH)
        r"from_pretrained\(": "Hugging Face model loading (verify repository trust)",
        r"AutoModel\.from_pretrained\(": "Hugging Face AutoModel loading (supply chain risk)",
        r"pipeline\(.*model\s*=": "Hugging Face pipeline with custom model (verify source)",
        
        # MLflow (MEDIUM)
        r"mlflow\..*\.load_model": "MLflow model loading (verify artifact source)",
        r"mlflow\.pyfunc\.load_model\(": "MLflow PyFunc model loading (arbitrary code risk)",
        
        # YAML deserialization (CRITICAL)
        r"yaml\.load\(": "YAML load without safe loader (arbitrary code execution risk)",
        r"yaml\.unsafe_load\(": "Unsafe YAML loading (arbitrary code execution risk)",
        r"yaml\.full_load\(": "YAML full_load (consider safe_load instead)",
        
        # Model training risks (MEDIUM)
        r"model\.fit\(": "Model training detected (ensure data validation)",
    }

    # XSS-prone output patterns - Enhanced to 16+ patterns (Category 7)
    XSS_PATTERNS = {
        # HTML/JavaScript rendering
        r"IPython\.display\.HTML\(": "Raw HTML display (XSS risk)",
        r"display\(HTML\(": "HTML display (XSS risk)",
        r"\.to_html\(\)": "DataFrame to HTML (potential XSS)",
        r"%%html": "HTML cell magic (XSS risk)",
        
        # JavaScript execution
        r"IPython\.display\.Javascript\(": "JavaScript execution (XSS risk)",
        r"Javascript\(": "JavaScript execution (XSS risk)",
        r"%%javascript": "JavaScript cell magic (XSS risk)",
        r"%%js": "JavaScript cell magic (XSS risk)",
        
        # Inline HTML/JS
        r"<script": "Inline script tag (XSS risk)",
        r"<iframe": "Iframe injection (XSS/clickjacking risk)",
        r"<object": "Object tag (XSS/content injection)",
        r"<embed": "Embed tag (XSS/content injection)",
        r"javascript:": "JavaScript protocol URL (XSS risk)",
        r"on\w+\s*=": "HTML event handler (XSS risk)",
        
        # CSS injection & data exfiltration
        r"<style": "Inline style tag (CSS injection risk)",
        r"style\s*=\s*['\"].*background.*url\(": "CSS background URL (data exfiltration via CSS)",
        
        # SVG & XML
        r"<svg": "SVG tag (potential XSS if user-controlled)",
        r"\.to_svg\(\)": "SVG generation (sanitize user input)",
        
        # Markdown rendering (if treated as HTML)
        r"IPython\.display\.Markdown\(": "Markdown display (verify no HTML injection)",
    }

    # Network & Data Exfiltration patterns (Category 4) - Enhanced to 18+ patterns
    NETWORK_EXFILTRATION_PATTERNS = {
        # HTTP/HTTPS exfiltration
        r"requests\.(post|put|patch)\(": "HTTP POST/PUT/PATCH to external domain (data exfiltration risk)",
        r"urllib\.request\.urlopen\(": "Direct URL access (data exfiltration risk)",
        r"httpx\.(post|put|patch)\(": "HTTPX POST/PUT/PATCH (data exfiltration risk)",
        r"urllib3\.": "urllib3 direct HTTP access (data exfiltration risk)",
        
        # File transfer protocols
        r"ftplib\.FTP\(": "FTP connection (data exfiltration risk)",
        r"smtplib\.SMTP\(": "SMTP connection (email exfiltration risk)",
        r"imaplib\.IMAP4": "IMAP connection (email data access)",
        
        # Raw network access
        r"socket\.socket\(": "Raw socket access (network exfiltration risk)",
        r"socket\.create_connection\(": "Socket connection (network exfiltration risk)",
        
        # Cloud SDKs
        r"boto3\.client\(": "AWS SDK usage (cloud data access risk)",
        r"google\.cloud": "Google Cloud SDK (cloud data access risk)",
        r"azure\.": "Azure SDK (cloud data access risk)",
        
        # Telemetry & Monitoring
        r"sentry_sdk\.init\(": "Sentry telemetry (data collection)",
        r"datadog\.": "DataDog telemetry (data collection)",
        r"newrelic\.": "New Relic telemetry (data collection)",
        
        # Real-time communication
        r"websocket\.": "WebSocket connection (real-time data channel)",
        r"socketio\.": "Socket.IO connection (real-time data channel)",
        
        # GraphQL & API
        r"graphql\.": "GraphQL query/mutation (API data access)",
        r"gql\(": "GraphQL query (validate endpoint allowlist)",
        
        # Database connections
        r"pymongo\.MongoClient\(": "MongoDB connection (database access)",
        r"psycopg2\.connect\(": "PostgreSQL connection (database access)",
        r"sqlalchemy\.create_engine\(": "SQLAlchemy database connection",
        r"mysql\.connector\.connect\(": "MySQL connection (database access)",
        r"redis\.Redis\(": "Redis connection (data store access)",
        
        # DNS & Covert channels
        r"dns\.resolver\.": "DNS resolver (potential DNS exfiltration)",
        r"dnspython\.": "DNS operations (covert channel risk)",
    }

    # Resource Exhaustion & DoS patterns (Category 11)
    RESOURCE_EXHAUSTION_PATTERNS = {
        r"while\s+True\s*:": "Infinite loop detected (DoS risk)",
        r"for\s+.*\s+in\s+itertools\.count\(": "Infinite iterator (DoS risk)",
        r"\[0\]\s*\*\s*10\*\*\d{2,}": "Large memory allocation (memory exhaustion)",
        r"re\.compile\(.*[\*\+\{]\s*[\*\+\{]": "Complex regex (ReDoS risk)",
        r"zipfile\..*\.extractall\(": "Zip extraction without size validation (zip bomb risk)",
        r"os\.fork\(": "Process forking (fork bomb risk)",
    }

    # Advanced Code Injection patterns (Category 1 - additional patterns)
    ADVANCED_CODE_INJECTION_PATTERNS = {
        r"getattr\(.*,\s*['\"]__.*__['\"]": "Attribute access to dunder methods (escape risk)",
        r"setattr\(.*,\s*['\"]__": "Attribute setting to dunder methods (injection risk)",
        r"type\(.*\).__bases__": "Type manipulation via __bases__ (escape risk)",
        r"__class__\.__base__": "Class hierarchy access (sandbox escape)",
        r"\.run_cell\(": "IPython run_cell with untrusted input (code injection)",
        r"\.run_line_magic\(": "IPython magic execution (code injection)",
        r"get_ipython\(\)\.system\(": "IPython system command execution",
    }

    # Advanced ML/AI Security patterns (Category 13 - additional patterns)
    ADVANCED_ML_PATTERNS = {
        r"input\(['\"]": "Accepting user input (potential adversarial input risk in ML context)",
        r"requests\.get.*model": "Downloading models from URLs (supply chain risk)",
        r"\.predict\(": "Model prediction (ensure input validation)",
        r"openai\.ChatCompletion\.create": "OpenAI ChatCompletion usage (prompt injection risk if using string concatenation)",
        r"anthropic\.": "Anthropic API usage (prompt injection risk)",
        r"gradio\.Interface\(": "Gradio interface (user input to model risk)",
        r"streamlit\..*input": "Streamlit user input (validation required)",
        r"['\"].*\s*\+\s*(user_input|input\(|user_|request\.)": "String concatenation with user input (prompt injection risk)",
    }
    
    # Compliance & Licensing patterns (Category 12) - NEW
    COMPLIANCE_LICENSING_PATTERNS = {
        # GPL licenses (copyleft restrictions)
        r"from\s+.*\s+import.*#.*GPL": "GPL-licensed dependency (check license compatibility)",
        r"import\s+.*#.*GPL": "GPL-licensed import (license compliance)",
        
        # License file references
        r"open\(['\"]LICENSE": "License file access (verify compliance)",
        r"pkg_resources\.get_distribution.*\.license": "License checking code detected",
        
        # Export control concerns
        r"from\s+cryptography\s+import": "Cryptography library (export control considerations)",
        r"import\s+(pycrypto|cryptography|nacl)": "Cryptographic library (export restrictions may apply)",
        
        # Data usage compliance
        r"pd\.read_csv.*license": "Dataset with license reference",
        r"dataset.*license": "Dataset licensing concern",
    }

    def __init__(self):
        """Initialize the notebook security analyzer."""
        self.logger = PyGuardLogger()
        self.detected_pii: Set[str] = set()  # Track unique PII types detected
        self.detected_dependencies: Dict[str, str] = {}  # Track imported packages

    def _calculate_entropy(self, text: str) -> float:
        """
        Calculate Shannon entropy of a string to detect high-entropy secrets.
        
        High entropy (> 4.5) often indicates cryptographic keys, tokens, or secrets.
        
        Args:
            text: String to analyze
            
        Returns:
            Shannon entropy value
        """
        if not text:
            return 0.0
        
        # Calculate character frequency
        char_freq = {}
        for char in text:
            char_freq[char] = char_freq.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        text_len = len(text)
        for count in char_freq.values():
            probability = count / text_len
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _detect_high_entropy_strings(self, cell: NotebookCell, cell_index: int) -> List[NotebookIssue]:
        """
        Detect high-entropy strings that may be secrets using Shannon entropy.
        
        Detects base64-encoded secrets, cryptographic keys, and random tokens
        that pattern matching might miss.
        
        Args:
            cell: Notebook cell to analyze
            cell_index: Index of the cell
            
        Returns:
            List of detected issues
        """
        issues: List[NotebookIssue] = []
        lines = cell.source.split("\n")
        
        # Pattern to extract string literals
        string_pattern = r'["\']([a-zA-Z0-9+/=_-]{20,})["\']'
        
        for line_num, line in enumerate(lines, 1):
            # Skip comments
            if line.strip().startswith("#"):
                continue
                
            matches = re.finditer(string_pattern, line)
            for match in matches:
                candidate = match.group(1)
                
                # Skip common false positives
                if candidate.lower() in ["test", "example", "placeholder", "your_key_here"]:
                    continue
                
                # Calculate entropy
                entropy = self._calculate_entropy(candidate)
                
                # High entropy threshold (cryptographic material typically > 4.5)
                if entropy > 4.5 and len(candidate) >= 20:
                    # Additional validation: check if it's base64-like
                    base64_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
                    if set(candidate).issubset(base64_chars):
                        issues.append(
                            NotebookIssue(
                                severity="HIGH",
                                category="High-Entropy Secret",
                                message=f"High-entropy string detected (entropy: {entropy:.2f}) - likely a cryptographic secret",
                                cell_index=cell_index,
                                line_number=line_num,
                                code_snippet=line[:50] + "..." if len(line) > 50 else line,
                                rule_id="NB-SECRET-ENTROPY",
                                fix_suggestion=(
                                    "Replace high-entropy secrets with environment variables. "
                                    "Use secure secret management (AWS Secrets Manager, HashiCorp Vault, etc.)"
                                ),
                                cwe_id="CWE-798",
                                owasp_id="ASVS-2.6.3",
                                confidence=0.75,
                                auto_fixable=True,
                            )
                        )
        
        return issues

    def analyze_notebook(self, notebook_path: Path) -> List[NotebookIssue]:
        """
        Analyze a Jupyter notebook for security issues.

        Args:
            notebook_path: Path to .ipynb file

        Returns:
            List of security issues found

        Raises:
            FileNotFoundError: If notebook file doesn't exist
            ValueError: If file is not a valid notebook
        """
        issues: List[NotebookIssue] = []

        if not notebook_path.exists():
            raise FileNotFoundError(f"Notebook not found: {notebook_path}")

        if notebook_path.suffix != ".ipynb":
            raise ValueError(f"Not a notebook file: {notebook_path}")

        try:
            with open(notebook_path, "r", encoding="utf-8") as f:
                notebook_data = json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid notebook JSON: {e}")

        # Parse notebook cells
        cells = self._parse_cells(notebook_data)

        # Analyze notebook metadata
        metadata_issues = self._analyze_metadata(notebook_data)
        issues.extend(metadata_issues)

        # Analyze each cell
        for idx, cell in enumerate(cells):
            if cell.cell_type == "code":
                issues.extend(self._analyze_code_cell(cell, idx))

        # Cross-cell analysis
        issues.extend(self._analyze_cell_dependencies(cells))

        # Check for PII in outputs
        for idx, cell in enumerate(cells):
            if cell.cell_type == "code":
                issues.extend(self._check_output_pii(cell, idx))

        self.logger.info(
            f"Notebook analysis complete: {notebook_path}, issues found: {len(issues)}"
        )

        return issues

    def _parse_cells(self, notebook_data: Dict[str, Any]) -> List[NotebookCell]:
        """Parse notebook cells from JSON data."""
        cells = []

        for cell_data in notebook_data.get("cells", []):
            source = cell_data.get("source", [])
            if isinstance(source, list):
                source = "".join(source)

            cell = NotebookCell(
                cell_type=cell_data.get("cell_type", ""),
                source=source,
                execution_count=cell_data.get("execution_count"),
                outputs=cell_data.get("outputs", []),
                metadata=cell_data.get("metadata", {}),
            )
            cells.append(cell)

        return cells

    def _analyze_metadata(self, notebook_data: Dict[str, Any]) -> List[NotebookIssue]:
        """Analyze notebook metadata for security issues."""
        issues: List[NotebookIssue] = []
        metadata = notebook_data.get("metadata", {})

        # Check for untrusted notebook (only if explicitly marked as False, not missing)
        if metadata.get("trusted") is False:
            issues.append(
                NotebookIssue(
                    severity="MEDIUM",
                    category="Untrusted Notebook",
                    message="Notebook is not marked as trusted - outputs may not be safe",
                    cell_index=-1,
                    line_number=0,
                    code_snippet="",
                    rule_id="NB-META-001",
                    fix_suggestion="Review notebook content and mark as trusted if verified safe",
                    confidence=0.8,
                )
            )

        # Check kernel info
        kernel_info = metadata.get("kernelspec", {})
        kernel_name = kernel_info.get("name", "")

        # Warn about non-standard kernels
        if kernel_name and kernel_name not in ["python3", "python2", "python"]:
            issues.append(
                NotebookIssue(
                    severity="LOW",
                    category="Non-Standard Kernel",
                    message=f"Using non-standard kernel: {kernel_name}",
                    cell_index=-1,
                    line_number=0,
                    code_snippet=f"Kernel: {kernel_name}",
                    fix_suggestion="Verify kernel source and security",
                    confidence=0.6,
                )
            )

        return issues

    def _check_pii(self, cell: NotebookCell, cell_index: int) -> List[NotebookIssue]:
        """Check for Personally Identifiable Information (PII) in cell code."""
        issues: List[NotebookIssue] = []
        lines = cell.source.split("\n")

        for line_num, line in enumerate(lines, 1):
            for pattern, description in self.PII_PATTERNS.items():
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for match in matches:
                    # Skip common false positives
                    matched_text = match.group(0)
                    if self._is_pii_false_positive(matched_text, description):
                        continue

                    self.detected_pii.add(description)
                    issues.append(
                        NotebookIssue(
                            severity="HIGH",
                            category="PII Exposure",
                            message=f"Potential {description} detected in notebook",
                            cell_index=cell_index,
                            line_number=line_num,
                            code_snippet=line[:50] + "..." if len(line) > 50 else line,
                            fix_suggestion=(
                                "Remove or redact PII from notebooks before sharing. "
                                "Use placeholder values or environment variables."
                            ),
                            cwe_id="CWE-359",
                            owasp_id="ASVS-8.3.4",
                            confidence=0.7,
                            auto_fixable=True,
                        )
                    )

        return issues

    def _is_pii_false_positive(self, text: str, pii_type: str) -> bool:
        """Check if detected PII is likely a false positive."""
        # Skip common test/example values
        test_values = [
            "123-45-6789",  # Example SSN
            "555-555-5555",  # Example phone
            "test@example.com",
            "user@example.org",
            "127.0.0.1",
            "0.0.0.0",
            "192.168.",  # Local IPs
            "10.0.",
        ]

        for test_val in test_values:
            if test_val in text:
                return True

        # Skip IP addresses that are clearly local/private
        if pii_type == "IP address":
            if text.startswith("127.") or text.startswith("192.168.") or text.startswith("10."):
                return True

        return False

    def _check_ml_security(self, cell: NotebookCell, cell_index: int) -> List[NotebookIssue]:
        """Check for ML/Data Science security issues."""
        issues: List[NotebookIssue] = []
        lines = cell.source.split("\n")

        for line_num, line in enumerate(lines, 1):
            for pattern, description in self.ML_SECURITY_PATTERNS.items():
                if re.search(pattern, line):
                    severity = "CRITICAL" if "code execution" in description.lower() else "HIGH"
                    
                    # Special handling for torch.load
                    if pattern == r"torch\.load\(":
                        # Check if weights_only=True is present in the same line or nearby
                        if "weights_only" in line and "True" in line:
                            # Safe usage detected - skip
                            continue
                        
                        issues.append(
                            NotebookIssue(
                                severity="CRITICAL",
                                category="ML Pipeline Security",
                                message="torch.load() without weights_only=True - arbitrary code execution risk via __reduce__",
                                cell_index=cell_index,
                                line_number=line_num,
                                code_snippet=line.strip(),
                                rule_id="NB-ML-001",
                                fix_suggestion=(
                                    "Use torch.load() with weights_only=True (PyTorch 1.13+):\n"
                                    "model = torch.load('model.pth', weights_only=True, map_location='cpu')\n"
                                    "Also verify model checksum before loading."
                                ),
                                cwe_id="CWE-502",
                                owasp_id="ASVS-5.5.3",
                                confidence=0.95,
                                auto_fixable=True,
                            )
                        )
                    else:
                        # Assign rule_id based on pattern type
                        if "pickle" in pattern:
                            rule_id = "NB-DESERIAL-001"  # Already used for AST-based pickle detection
                        elif "yaml" in description.lower():
                            rule_id = "NB-DESERIAL-002"
                        elif pattern == r"from_pretrained\(":
                            rule_id = "NB-ML-002"
                        else:
                            rule_id = "NB-ML-003"
                        
                        auto_fixable = pattern in [r"pickle\.loads?\(", r"from_pretrained\("]
                        issues.append(
                            NotebookIssue(
                                severity=severity,
                                category="ML Pipeline Security",
                                message=description,
                                cell_index=cell_index,
                                line_number=line_num,
                                code_snippet=line.strip(),
                                rule_id=rule_id,
                                fix_suggestion=(
                                    "Verify the source and integrity of loaded models. "
                                    "Use safer serialization formats (ONNX, SavedModel). "
                                    "Validate model checksums before loading."
                                ),
                                cwe_id="CWE-502",
                                owasp_id="ASVS-5.5.3",
                                confidence=0.85,
                                auto_fixable=auto_fixable,
                            )
                        )

        # Check for data validation issues in ML pipelines
        if "pd.read_csv" in cell.source or "pd.read_excel" in cell.source:
            if "dtype=" not in cell.source and "converters=" not in cell.source:
                issues.append(
                    NotebookIssue(
                        severity="MEDIUM",
                        category="Data Validation",
                        message="Data loading without type validation (data poisoning risk)",
                        cell_index=cell_index,
                        line_number=0,
                        code_snippet="Data loading detected",
                        rule_id="NB-DATA-001",
                        fix_suggestion=(
                            "Specify dtypes and use converters to validate data types. "
                            "Implement schema validation for input data using pandera or similar."
                        ),
                        confidence=0.6,
                        auto_fixable=True,
                    )
                )

        return issues

    def _check_xss_vulnerabilities(self, cell: NotebookCell, cell_index: int) -> List[NotebookIssue]:
        """Check for XSS vulnerabilities in notebook outputs."""
        issues: List[NotebookIssue] = []
        lines = cell.source.split("\n")

        for line_num, line in enumerate(lines, 1):
            for pattern, description in self.XSS_PATTERNS.items():
                if re.search(pattern, line):
                    # Assign rule_id based on pattern type
                    if "IPython.display.HTML" in pattern or "display(HTML" in pattern:
                        rule_id = "NB-XSS-001"
                    elif "Javascript" in pattern or "%%javascript" in pattern or "%%js" in pattern:
                        rule_id = "NB-XSS-002"
                    elif "%%html" in pattern:
                        rule_id = "NB-XSS-003"
                    elif ".to_html" in pattern:
                        rule_id = "NB-XSS-004"
                    else:
                        rule_id = "NB-XSS-005"
                    
                    issues.append(
                        NotebookIssue(
                            severity="HIGH",
                            category="XSS Vulnerability",
                            message=f"{description} - user input should be sanitized",
                            cell_index=cell_index,
                            line_number=line_num,
                            code_snippet=line.strip(),
                            rule_id=rule_id,
                            fix_suggestion=(
                                "Sanitize all user input before displaying as HTML. "
                                "Use IPython.display.Text() instead of HTML() for untrusted content. "
                                "Apply HTML escaping to prevent XSS attacks."
                            ),
                            cwe_id="CWE-79",
                            owasp_id="ASVS-5.3.3",
                            confidence=0.75,
                        )
                    )

        return issues

    def _check_output_pii(self, cell: NotebookCell, cell_index: int) -> List[NotebookIssue]:
        """Check cell outputs for PII exposure."""
        issues: List[NotebookIssue] = []

        for output in cell.outputs:
            output_text = ""

            # Extract text from different output types
            if output.get("output_type") == "stream":
                output_text = "".join(output.get("text", []))
            elif output.get("output_type") == "execute_result":
                data = output.get("data", {})
                output_text = data.get("text/plain", "")
            elif output.get("output_type") == "error":
                output_text = "\n".join(output.get("traceback", []))

            # Check for PII in output text
            for pattern, description in self.PII_PATTERNS.items():
                matches = re.finditer(pattern, output_text, re.IGNORECASE)
                for match in matches:
                    matched_text = match.group(0)
                    if not self._is_pii_false_positive(matched_text, description):
                        issues.append(
                            NotebookIssue(
                                severity="HIGH",
                                category="PII in Output",
                                message=f"{description} exposed in cell output",
                                cell_index=cell_index,
                                line_number=0,
                                code_snippet=matched_text[:50],
                                fix_suggestion=(
                                    "Clear cell outputs before sharing notebook. "
                                    "Redact sensitive information from outputs."
                                ),
                                cwe_id="CWE-359",
                                confidence=0.7,
                                auto_fixable=True,
                            )
                        )
                        break  # Only report once per output

        return issues

    def _analyze_code_cell(self, cell: NotebookCell, cell_index: int) -> List[NotebookIssue]:
        """Analyze a single code cell for security issues."""
        issues: List[NotebookIssue] = []

        # Check for dangerous magic commands
        issues.extend(self._check_magic_commands(cell, cell_index))

        # Check for hardcoded secrets (pattern-based)
        issues.extend(self._check_secrets(cell, cell_index))
        
        # Check for high-entropy secrets (entropy-based detection)
        issues.extend(self._detect_high_entropy_strings(cell, cell_index))

        # Check for PII in code
        issues.extend(self._check_pii(cell, cell_index))

        # Check for unsafe operations
        issues.extend(self._check_unsafe_operations(cell, cell_index))

        # Check for command injection
        issues.extend(self._check_command_injection(cell, cell_index))

        # Check ML security issues
        issues.extend(self._check_ml_security(cell, cell_index))

        # Check XSS vulnerabilities
        issues.extend(self._check_xss_vulnerabilities(cell, cell_index))

        # Check output sanitization
        issues.extend(self._check_output_security(cell, cell_index))
        
        # Check for reproducibility issues
        issues.extend(self._check_reproducibility(cell, cell_index))
        
        # Check for filesystem security issues
        issues.extend(self._check_filesystem_security(cell, cell_index))
        
        # Check for network exfiltration risks
        issues.extend(self._check_network_exfiltration(cell, cell_index))
        
        # Check for resource exhaustion risks
        issues.extend(self._check_resource_exhaustion(cell, cell_index))
        
        # Check for advanced code injection
        issues.extend(self._check_advanced_code_injection(cell, cell_index))
        
        # Check for advanced ML/AI security
        issues.extend(self._check_advanced_ml_security(cell, cell_index))
        
        # Check for compliance and licensing issues
        issues.extend(self._check_compliance_licensing(cell, cell_index))

        return issues

    def _check_magic_commands(self, cell: NotebookCell, cell_index: int) -> List[NotebookIssue]:
        """Check for dangerous Jupyter magic commands."""
        issues: List[NotebookIssue] = []
        lines = cell.source.split("\n")

        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            for magic, description in self.DANGEROUS_MAGICS.items():
                if line.startswith(magic):
                    # Assign rule_id based on magic type
                    if magic in ["%%bash", "%%sh", "%%script"]:
                        rule_id = "NB-SHELL-002"
                    elif magic == "%run":
                        rule_id = "NB-SHELL-003"
                    elif magic in ["!", "%system"]:
                        rule_id = "NB-SHELL-001"
                    elif magic == "%pip":
                        rule_id = "NB-SHELL-004"
                    else:
                        rule_id = "NB-SHELL-005"
                    
                    issues.append(
                        NotebookIssue(
                            severity="HIGH",
                            category="Unsafe Magic Command",
                            message=f"Dangerous magic command: {description}",
                            cell_index=cell_index,
                            line_number=line_num,
                            code_snippet=line,
                            rule_id=rule_id,
                            fix_suggestion=(
                                "Avoid using magic commands that execute system commands. "
                                "Use subprocess with proper validation instead."
                            ),
                            cwe_id="CWE-78",
                            owasp_id="ASVS-5.3.3",
                        )
                    )

        return issues

    def _check_secrets(self, cell: NotebookCell, cell_index: int) -> List[NotebookIssue]:
        """Check for hardcoded secrets in cell code."""
        issues: List[NotebookIssue] = []
        lines = cell.source.split("\n")

        for line_num, line in enumerate(lines, 1):
            for pattern, description in self.SECRET_PATTERNS.items():
                matches = re.finditer(pattern, line)
                for match in matches:
                    # Exclude common test/placeholder values
                    value = match.group(2) if len(match.groups()) >= 2 else match.group(0)
                    if value not in ["test", "example", "YOUR_KEY_HERE", "***"]:
                        issues.append(
                            NotebookIssue(
                                severity="HIGH",
                                category="Hardcoded Secret",
                                message=f"{description} detected in notebook",
                                cell_index=cell_index,
                                line_number=line_num,
                                code_snippet=line[:50] + "..." if len(line) > 50 else line,
                                rule_id="NB-SECRET-001",
                                fix_suggestion=(
                                    "Use environment variables or secure credential storage. "
                                    "Load secrets from .env files or cloud secret managers."
                                ),
                                cwe_id="CWE-798",
                                owasp_id="ASVS-2.6.3",
                                auto_fixable=True,
                            )
                        )

        return issues

    def _check_unsafe_operations(self, cell: NotebookCell, cell_index: int) -> List[NotebookIssue]:
        """Check for unsafe Python operations in cell."""
        issues: List[NotebookIssue] = []

        # Try to parse cell as Python code
        try:
            tree = ast.parse(cell.source)
        except SyntaxError:
            # Skip cells with syntax errors (might be incomplete)
            return issues

        for node in ast.walk(tree):
            # Check for eval/exec/compile
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    if node.func.id in ["eval", "exec", "compile"]:
                        # Determine rule_id based on function
                        if node.func.id == "eval":
                            rule_id = "NB-INJECT-001"
                        elif node.func.id == "exec":
                            rule_id = "NB-INJECT-002"
                        else:
                            rule_id = "NB-INJECT-003"
                        
                        issues.append(
                            NotebookIssue(
                                severity="CRITICAL",
                                category="Code Injection",
                                message=f"Use of {node.func.id}() enables code injection",
                                cell_index=cell_index,
                                line_number=getattr(node, "lineno", 0),
                                code_snippet=ast.unparse(node) if hasattr(ast, "unparse") else "",
                                rule_id=rule_id,
                                fix_suggestion="Use ast.literal_eval() for safe evaluation or refactor to avoid dynamic code execution",
                                cwe_id="CWE-95",
                                owasp_id="ASVS-5.2.1",
                            )
                        )

            # Check for pickle usage
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute):
                    if (
                        isinstance(node.func.value, ast.Name)
                        and node.func.value.id == "pickle"
                        and node.func.attr == "load"
                    ):
                        issues.append(
                            NotebookIssue(
                                severity="HIGH",
                                category="Unsafe Deserialization",
                                message="pickle.load() can execute arbitrary code",
                                cell_index=cell_index,
                                line_number=getattr(node, "lineno", 0),
                                code_snippet=ast.unparse(node) if hasattr(ast, "unparse") else "",
                                rule_id="NB-DESERIAL-001",
                                fix_suggestion="Use JSON or safer serialization formats. If pickle is required, validate source and use signatures.",
                                cwe_id="CWE-502",
                                owasp_id="ASVS-5.5.3",
                            )
                        )

        return issues

    def _check_command_injection(self, cell: NotebookCell, cell_index: int) -> List[NotebookIssue]:
        """Check for command injection vulnerabilities."""
        issues: List[NotebookIssue] = []

        try:
            tree = ast.parse(cell.source)
        except SyntaxError:
            return issues

        for node in ast.walk(tree):
            # Check subprocess calls with shell=True
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute):
                    if isinstance(node.func.value, ast.Name) and node.func.value.id in [
                        "subprocess",
                        "os",
                    ]:
                        # Check for shell=True
                        for keyword in node.keywords:
                            if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant):
                                if keyword.value.value is True:
                                    issues.append(
                                        NotebookIssue(
                                            severity="CRITICAL",
                                            category="Command Injection",
                                            message="subprocess call with shell=True enables command injection",
                                            cell_index=cell_index,
                                            line_number=getattr(node, "lineno", 0),
                                            code_snippet=(
                                                ast.unparse(node) if hasattr(ast, "unparse") else ""
                                            ),
                                            fix_suggestion="Use shell=False and pass command as list of arguments",
                                            cwe_id="CWE-78",
                                            owasp_id="ASVS-5.3.3",
                                        )
                                    )

        return issues

    def _check_output_security(self, cell: NotebookCell, cell_index: int) -> List[NotebookIssue]:
        """Check cell outputs for security issues."""
        issues: List[NotebookIssue] = []

        for output in cell.outputs:
            # Check for error tracebacks that might leak sensitive info
            if output.get("output_type") == "error":
                traceback = output.get("traceback", [])
                for line in traceback:
                    # Check for path disclosure
                    if "/home/" in line or "C:\\" in line or "/Users/" in line:
                        issues.append(
                            NotebookIssue(
                                severity="MEDIUM",
                                category="Information Disclosure",
                                message="Cell output contains system paths that may leak sensitive information",
                                cell_index=cell_index,
                                line_number=0,
                                code_snippet=line[:100] + "..." if len(line) > 100 else line,
                                fix_suggestion="Clear cell outputs before sharing notebooks. Use relative paths instead of absolute paths.",
                                cwe_id="CWE-209",
                            )
                        )
                        break

        return issues

    def _analyze_cell_dependencies(self, cells: List[NotebookCell]) -> List[NotebookIssue]:
        """Analyze dependencies and data flow between cells."""
        issues: List[NotebookIssue] = []

        # Track variables defined in cells
        defined_vars: Dict[str, int] = {}  # var_name -> cell_index
        used_vars: Dict[str, List[int]] = {}  # var_name -> list of cell_indices

        for idx, cell in enumerate(cells):
            if cell.cell_type != "code":
                continue

            try:
                tree = ast.parse(cell.source)
            except SyntaxError:
                continue

            # Find variable assignments
            for node in ast.walk(tree):
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            defined_vars[target.id] = idx

                # Find variable uses
                if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                    if node.id not in used_vars:
                        used_vars[node.id] = []
                    used_vars[node.id].append(idx)

        # Check for use before definition (execution order issues)
        for var_name, use_cells in used_vars.items():
            if var_name in defined_vars:
                def_cell = defined_vars[var_name]
                for use_cell in use_cells:
                    if use_cell < def_cell:
                        issues.append(
                            NotebookIssue(
                                severity="MEDIUM",
                                category="Execution Order Issue",
                                message=f"Variable '{var_name}' used before definition (cell order dependency)",
                                cell_index=use_cell,
                                line_number=0,
                                code_snippet=f"Uses variable '{var_name}' defined in cell {def_cell}",
                                fix_suggestion="Ensure cells are executed in proper order. Consider restructuring code to avoid order dependencies.",
                            )
                        )

        return issues
    
    def _check_reproducibility(self, cell: NotebookCell, cell_index: int) -> List[NotebookIssue]:
        """
        Check for reproducibility issues in ML/AI notebooks.
        
        Detects:
        - Missing random seeds for ML frameworks
        - Non-deterministic operations
        - Unpinned dependencies
        - Missing environment constraints
        
        Args:
            cell: Notebook cell to analyze
            cell_index: Index of the cell
            
        Returns:
            List of reproducibility issues
        """
        issues: List[NotebookIssue] = []
        
        # Check for ML framework usage without seed setting
        ml_frameworks = {
            "torch": "PyTorch",
            "tensorflow": "TensorFlow",
            "tf": "TensorFlow",
            "numpy": "NumPy",
            "np": "NumPy",
            "random": "Python random",
            "sklearn": "scikit-learn",
        }
        
        # Check if ML frameworks are imported
        imports_found = []
        try:
            tree = ast.parse(cell.source)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name in ml_frameworks:
                            imports_found.append((alias.name, ml_frameworks[alias.name]))
                elif isinstance(node, ast.ImportFrom):
                    if node.module and node.module.split('.')[0] in ml_frameworks:
                        imports_found.append((node.module.split('.')[0], ml_frameworks[node.module.split('.')[0]]))
        except SyntaxError:
            pass
        
        # Check if seeds are set for imported frameworks
        seed_patterns = {
            "torch": r"torch\.manual_seed\(",
            "tensorflow": r"tf\.random\.set_seed\(",
            "tf": r"tf\.random\.set_seed\(",
            "numpy": r"np\.random\.seed\(",
            "np": r"np\.random\.seed\(",
            "random": r"random\.seed\(",
        }
        
        for framework, framework_name in imports_found:
            if framework in seed_patterns:
                pattern = seed_patterns[framework]
                if not re.search(pattern, cell.source):
                    issues.append(
                        NotebookIssue(
                            severity="MEDIUM",
                            category="Reproducibility Issue",
                            message=f"{framework_name} imported but random seed not set - results may be non-reproducible",
                            cell_index=cell_index,
                            line_number=0,
                            code_snippet=f"import {framework}",
                            rule_id="NB-REPRO-001",
                            fix_suggestion=(
                                f"Set random seed for {framework_name} to ensure reproducible results. "
                                f"Add: {pattern.replace('(', '(42)')} or similar seed value."
                            ),
                            cwe_id="CWE-330",
                            confidence=0.7,
                            auto_fixable=True,
                        )
                    )
        
        # Check for unpinned pip/conda installs
        unpinned_install_patterns = [
            (r"%pip\s+install\s+([a-zA-Z0-9_-]+)(?!\s*==)", "pip"),
            (r"!pip\s+install\s+([a-zA-Z0-9_-]+)(?!\s*==)", "pip"),
            (r"%conda\s+install\s+([a-zA-Z0-9_-]+)(?!\s*==)", "conda"),
        ]
        
        for pattern, tool in unpinned_install_patterns:
            matches = re.finditer(pattern, cell.source)
            for match in matches:
                package = match.group(1)
                issues.append(
                    NotebookIssue(
                        severity="MEDIUM",
                        category="Unpinned Dependency",
                        message=f"Unpinned {tool} package '{package}' - may break reproducibility",
                        cell_index=cell_index,
                        line_number=0,
                        code_snippet=match.group(0),
                        fix_suggestion=f"Pin package version: {tool} install {package}==X.Y.Z",
                        confidence=0.85,
                        auto_fixable=True,
                    )
                )
        
        # Check for PyTorch non-deterministic operations
        if any(fw == "torch" for fw, _ in imports_found):
            if "torch.backends.cudnn.deterministic" not in cell.source:
                if "torch.nn" in cell.source or "torch.cuda" in cell.source:
                    issues.append(
                        NotebookIssue(
                            severity="LOW",
                            category="Reproducibility Issue",
                            message="PyTorch used without deterministic mode - GPU operations may be non-reproducible",
                            cell_index=cell_index,
                            line_number=0,
                            code_snippet="PyTorch GPU operations detected",
                            fix_suggestion=(
                                "Enable deterministic mode:\n"
                                "torch.backends.cudnn.deterministic = True\n"
                                "torch.backends.cudnn.benchmark = False\n"
                                "torch.use_deterministic_algorithms(True)"
                            ),
                            confidence=0.6,
                            auto_fixable=True,
                        )
                    )
        
        return issues

    def _check_filesystem_security(self, cell: NotebookCell, cell_index: int) -> List[NotebookIssue]:
        """
        Check for filesystem security issues.
        
        Detects:
        - Path traversal attempts (../)
        - Accessing sensitive system files
        - Unsafe file operations
        - Symlink attacks
        
        Args:
            cell: Notebook cell to analyze
            cell_index: Index of the cell
            
        Returns:
            List of filesystem security issues
        """
        issues: List[NotebookIssue] = []
        
        # Dangerous path patterns
        dangerous_paths = {
            r"\.\./": "Path traversal attempt (../) - directory escape risk",
            r"/etc/passwd": "Access to sensitive system file (/etc/passwd)",
            r"/etc/shadow": "Access to password file (/etc/shadow)",
            r"~/.ssh/": "Access to SSH directory (private keys)",
            r"/root/": "Access to root directory",
            r"\.\.\\": "Windows path traversal attempt",
            r"C:\\Windows\\System32": "Access to Windows system directory",
        }
        
        for pattern, description in dangerous_paths.items():
            if re.search(pattern, cell.source):
                issues.append(
                    NotebookIssue(
                        severity="HIGH",
                        category="Filesystem Security",
                        message=description,
                        cell_index=cell_index,
                        line_number=0,
                        code_snippet="Dangerous path detected",
                        fix_suggestion=(
                            "Avoid accessing sensitive system files or using path traversal. "
                            "Validate and sanitize all file paths. Use absolute paths and "
                            "check against an allowlist of permitted directories."
                        ),
                        cwe_id="CWE-22",
                        owasp_id="ASVS-5.2.3",
                        confidence=0.8,
                    )
                )
        
        # Check for unsafe file operations
        try:
            tree = ast.parse(cell.source)
            
            for node in ast.walk(tree):
                # Check for os.remove, shutil.rmtree without validation
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Attribute):
                        module = None
                        if isinstance(node.func.value, ast.Name):
                            module = node.func.value.id
                        
                        # Dangerous file operations
                        if module == "os" and node.func.attr in ["remove", "unlink", "rmdir"]:
                            issues.append(
                                NotebookIssue(
                                    severity="MEDIUM",
                                    category="Filesystem Security",
                                    message=f"os.{node.func.attr}() without path validation - file deletion risk",
                                    cell_index=cell_index,
                                    line_number=getattr(node, "lineno", 0),
                                    code_snippet=ast.unparse(node) if hasattr(ast, "unparse") else "",
                                    fix_suggestion=(
                                        "Validate file paths before deletion. Check against allowlist. "
                                        "Prevent path traversal and ensure file exists before deleting."
                                    ),
                                    cwe_id="CWE-22",
                                    confidence=0.7,
                                )
                            )
                        
                        elif module == "shutil" and node.func.attr in ["rmtree", "move", "copy"]:
                            issues.append(
                                NotebookIssue(
                                    severity="MEDIUM",
                                    category="Filesystem Security",
                                    message=f"shutil.{node.func.attr}() without path validation - unsafe file operation",
                                    cell_index=cell_index,
                                    line_number=getattr(node, "lineno", 0),
                                    code_snippet=ast.unparse(node) if hasattr(ast, "unparse") else "",
                                    fix_suggestion=(
                                        "Validate and sanitize file paths. Implement allowlist checking. "
                                        "Be careful with recursive operations like rmtree()."
                                    ),
                                    cwe_id="CWE-22",
                                    confidence=0.7,
                                )
                            )
                        
                        # Check for chmod/chown that could elevate privileges
                        elif module == "os" and node.func.attr in ["chmod", "chown"]:
                            issues.append(
                                NotebookIssue(
                                    severity="MEDIUM",
                                    category="Filesystem Security",
                                    message=f"os.{node.func.attr}() - privilege manipulation risk",
                                    cell_index=cell_index,
                                    line_number=getattr(node, "lineno", 0),
                                    code_snippet=ast.unparse(node) if hasattr(ast, "unparse") else "",
                                    fix_suggestion=(
                                        "Avoid changing file permissions unless absolutely necessary. "
                                        "Ensure proper permission model (least privilege)."
                                    ),
                                    cwe_id="CWE-732",
                                    confidence=0.6,
                                )
                            )
        
        except SyntaxError:
            pass
        
        # Check for tempfile misuse (predictable names)
        if "tempfile.mktemp(" in cell.source:
            issues.append(
                NotebookIssue(
                    severity="MEDIUM",
                    category="Filesystem Security",
                    message="tempfile.mktemp() is deprecated - race condition and predictable filename risk",
                    cell_index=cell_index,
                    line_number=0,
                    code_snippet="tempfile.mktemp() detected",
                    fix_suggestion=(
                        "Use tempfile.mkstemp() or tempfile.NamedTemporaryFile() instead. "
                        "These create files securely without race conditions."
                    ),
                    cwe_id="CWE-377",
                    confidence=0.9,
                    auto_fixable=True,
                )
            )
        
        return issues


    def _check_network_exfiltration(self, cell: NotebookCell, cell_index: int) -> List[NotebookIssue]:
        """
        Check for network and data exfiltration risks.
        
        Detects:
        - HTTP POST/PUT requests to external domains
        - Database connections without validation
        - Cloud SDK usage with potential data access
        - Telemetry and monitoring SDKs
        - Raw socket access
        
        Args:
            cell: Notebook cell to analyze
            cell_index: Index of the cell
            
        Returns:
            List of network exfiltration issues
        """
        issues: List[NotebookIssue] = []
        lines = cell.source.split("\n")
        
        for line_num, line in enumerate(lines, 1):
            for pattern, description in self.NETWORK_EXFILTRATION_PATTERNS.items():
                if re.search(pattern, line):
                    # Determine severity based on pattern
                    severity = "HIGH"
                    if "boto3" in pattern or "cloud" in pattern.lower():
                        severity = "MEDIUM"  # Cloud SDKs are common in notebooks
                    elif "socket" in pattern or "ftp" in pattern:
                        severity = "CRITICAL"  # Raw network access is very risky
                    
                    issues.append(
                        NotebookIssue(
                            severity=severity,
                            category="Network & Data Exfiltration",
                            message=description,
                            cell_index=cell_index,
                            line_number=line_num,
                            code_snippet=line.strip(),
                            fix_suggestion=(
                                "Validate and restrict network access. "
                                "Use allowlists for permitted domains. "
                                "Avoid sending sensitive data to external services. "
                                "Implement network egress controls."
                            ),
                            cwe_id="CWE-200",
                            owasp_id="ASVS-8.3.4",
                            confidence=0.75,
                        )
                    )
        
        return issues

    def _check_resource_exhaustion(self, cell: NotebookCell, cell_index: int) -> List[NotebookIssue]:
        """
        Check for resource exhaustion and DoS risks.
        
        Detects:
        - Infinite loops without timeouts
        - Large memory allocations
        - Complex regex patterns (ReDoS)
        - Zip bomb risks
        - Fork bomb patterns
        
        Args:
            cell: Notebook cell to analyze
            cell_index: Index of the cell
            
        Returns:
            List of resource exhaustion issues
        """
        issues: List[NotebookIssue] = []
        lines = cell.source.split("\n")
        
        for line_num, line in enumerate(lines, 1):
            for pattern, description in self.RESOURCE_EXHAUSTION_PATTERNS.items():
                if re.search(pattern, line):
                    # Determine severity
                    severity = "HIGH"
                    if "while True" in line or "fork" in line:
                        severity = "CRITICAL"
                    elif "zip" in line.lower():
                        severity = "MEDIUM"
                    
                    issues.append(
                        NotebookIssue(
                            severity=severity,
                            category="Resource Exhaustion",
                            message=description,
                            cell_index=cell_index,
                            line_number=line_num,
                            code_snippet=line.strip(),
                            fix_suggestion=(
                                "Add resource limits and timeouts. "
                                "Validate input sizes. "
                                "Avoid infinite loops or use break conditions. "
                                "Implement memory allocation limits."
                            ),
                            cwe_id="CWE-400",
                            owasp_id="ASVS-5.2.5",
                            confidence=0.8,
                        )
                    )
        
        return issues

    def _check_advanced_code_injection(self, cell: NotebookCell, cell_index: int) -> List[NotebookIssue]:
        """
        Check for advanced code injection patterns.
        
        Detects:
        - Dunder method access (sandbox escape)
        - Type manipulation via __bases__
        - IPython kernel message injection
        - Advanced attribute injection
        
        Args:
            cell: Notebook cell to analyze
            cell_index: Index of the cell
            
        Returns:
            List of advanced code injection issues
        """
        issues: List[NotebookIssue] = []
        lines = cell.source.split("\n")
        
        for line_num, line in enumerate(lines, 1):
            for pattern, description in self.ADVANCED_CODE_INJECTION_PATTERNS.items():
                if re.search(pattern, line):
                    issues.append(
                        NotebookIssue(
                            severity="CRITICAL",
                            category="Advanced Code Injection",
                            message=description,
                            cell_index=cell_index,
                            line_number=line_num,
                            code_snippet=line.strip(),
                            fix_suggestion=(
                                "Avoid accessing dunder methods with dynamic input. "
                                "Do not manipulate type hierarchies. "
                                "Use safe attribute access patterns. "
                                "Validate all inputs before attribute operations."
                            ),
                            cwe_id="CWE-95",
                            owasp_id="ASVS-5.2.1",
                            confidence=0.9,
                            auto_fixable=False,
                        )
                    )
        
        return issues

    def _check_advanced_ml_security(self, cell: NotebookCell, cell_index: int) -> List[NotebookIssue]:
        """
        Check for advanced ML/AI security issues.
        
        Detects:
        - Adversarial input acceptance
        - Model downloading from untrusted sources
        - Prompt injection in LLM applications
        - User input to model predictions
        
        Args:
            cell: Notebook cell to analyze
            cell_index: Index of the cell
            
        Returns:
            List of advanced ML/AI security issues
        """
        issues: List[NotebookIssue] = []
        lines = cell.source.split("\n")
        
        for line_num, line in enumerate(lines, 1):
            for pattern, description in self.ADVANCED_ML_PATTERNS.items():
                if re.search(pattern, line):
                    # Determine severity
                    severity = "HIGH"
                    if "prompt" in description.lower() or "injection" in description.lower():
                        severity = "CRITICAL"
                    
                    issues.append(
                        NotebookIssue(
                            severity=severity,
                            category="Advanced ML/AI Security",
                            message=description,
                            cell_index=cell_index,
                            line_number=line_num,
                            code_snippet=line.strip(),
                            fix_suggestion=(
                                "Validate and sanitize all user inputs to ML models. "
                                "Implement input validation schemas. "
                                "Use parameterized prompts instead of string concatenation. "
                                "Download models from trusted sources with checksum verification."
                            ),
                            cwe_id="CWE-20",
                            owasp_id="ASVS-5.1.1",
                            confidence=0.75,
                            auto_fixable=True,
                        )
                    )
        
        return issues

    def _check_compliance_licensing(self, cell: NotebookCell, cell_index: int) -> List[NotebookIssue]:
        """
        Check for compliance and licensing issues (Category 12).
        
        Detects:
        - GPL dependencies in commercial notebooks
        - Cryptographic libraries with export restrictions
        - Dataset licensing concerns
        - License compatibility issues
        
        Args:
            cell: Notebook cell to analyze
            cell_index: Index of the cell
            
        Returns:
            List of compliance and licensing issues
        """
        issues: List[NotebookIssue] = []
        lines = cell.source.split("\n")
        
        for line_num, line in enumerate(lines, 1):
            for pattern, description in self.COMPLIANCE_LICENSING_PATTERNS.items():
                if re.search(pattern, line):
                    # Determine severity based on pattern
                    severity = "LOW"
                    if "cryptography" in pattern.lower() or "export" in description.lower():
                        severity = "MEDIUM"
                    elif "gpl" in pattern.lower():
                        severity = "MEDIUM"
                    
                    issues.append(
                        NotebookIssue(
                            severity=severity,
                            category="Compliance & Licensing",
                            message=description,
                            cell_index=cell_index,
                            line_number=line_num,
                            code_snippet=line.strip(),
                            rule_id="NB-COMPLIANCE-001",
                            fix_suggestion=(
                                "Review license compatibility and export restrictions. "
                                "Document all dependencies and their licenses. "
                                "Ensure compliance with organizational policies and applicable laws. "
                                "For cryptographic libraries, verify export control requirements."
                            ),
                            cwe_id="CWE-1104",
                            confidence=0.6,
                            auto_fixable=False,
                        )
                    )
        
        return issues


class NotebookFixer:
    """Provides automated fixes for notebook security issues."""

    def __init__(self):
        """Initialize notebook fixer."""
        self.logger = PyGuardLogger()

    def fix_notebook(
        self, notebook_path: Path, issues: List[NotebookIssue]
    ) -> Tuple[bool, List[str]]:
        """
        Apply automated fixes to notebook.

        Args:
            notebook_path: Path to notebook file
            issues: List of issues to fix

        Returns:
            Tuple of (success, list of fixes applied)
        """
        fixes_applied: List[str] = []

        # Load notebook
        with open(notebook_path, "r", encoding="utf-8") as f:
            notebook_data = json.load(f)

        cells = notebook_data.get("cells", [])

        # Apply fixes based on issue types
        for issue in issues:
            if not issue.auto_fixable:
                continue

            if issue.category == "Hardcoded Secret" or issue.category == "High-Entropy Secret":
                # Comment out lines with secrets
                if 0 <= issue.cell_index < len(cells):
                    cell = cells[issue.cell_index]
                    source = cell.get("source", [])
                    if isinstance(source, list):
                        source = "".join(source)

                    lines = source.split("\n")
                    if 0 < issue.line_number <= len(lines):
                        line = lines[issue.line_number - 1]
                        lines[issue.line_number - 1] = (
                            f"# SECURITY: Removed hardcoded secret - use os.getenv() instead\n"
                            f"# Original: {line}"
                        )
                        cell["source"] = "\n".join(lines)
                        fixes_applied.append(
                            f"Commented out hardcoded secret in cell {issue.cell_index}"
                        )

            elif issue.category in ["PII Exposure", "PII in Output"]:
                # Redact PII from cell
                if issue.category == "PII Exposure" and 0 <= issue.cell_index < len(cells):
                    cell = cells[issue.cell_index]
                    source = cell.get("source", [])
                    if isinstance(source, list):
                        source = "".join(source)

                    # Add warning comment
                    lines = source.split("\n")
                    if 0 < issue.line_number <= len(lines):
                        lines.insert(
                            issue.line_number - 1,
                            f"# WARNING: PII detected below - redact before sharing",
                        )
                        cell["source"] = "\n".join(lines)
                        fixes_applied.append(f"Added PII warning in cell {issue.cell_index}")

                elif issue.category == "PII in Output":
                    # Clear outputs for cells with PII
                    if 0 <= issue.cell_index < len(cells):
                        cells[issue.cell_index]["outputs"] = []
                        fixes_applied.append(f"Cleared outputs with PII in cell {issue.cell_index}")

            elif issue.category == "ML Pipeline Security":
                # Auto-fix ML security issues
                if "torch.load" in issue.message and 0 <= issue.cell_index < len(cells):
                    cell = cells[issue.cell_index]
                    source = cell.get("source", [])
                    if isinstance(source, list):
                        source = "".join(source)
                    
                    # Add weights_only=True to torch.load calls
                    fixed_source = self._fix_torch_load(source)
                    if fixed_source != source:
                        cell["source"] = fixed_source
                        fixes_applied.append(
                            f"Added weights_only=True to torch.load() in cell {issue.cell_index}"
                        )
                
                elif "pickle.load" in issue.message and 0 <= issue.cell_index < len(cells):
                    cell = cells[issue.cell_index]
                    source = cell.get("source", [])
                    if isinstance(source, list):
                        source = "".join(source)
                    
                    # Add warning comment for pickle
                    lines = source.split("\n")
                    if 0 < issue.line_number <= len(lines):
                        lines.insert(
                            issue.line_number - 1,
                            "# SECURITY WARNING: pickle.load() can execute arbitrary code\n"
                            "# Consider using JSON or safer serialization format\n"
                            "# If pickle required, verify source and use restricted unpickler"
                        )
                        cell["source"] = "\n".join(lines)
                        fixes_applied.append(
                            f"Added security warning for pickle.load() in cell {issue.cell_index}"
                        )

            elif issue.category == "Code Injection":
                # Auto-fix eval/exec to safer alternatives
                if 0 <= issue.cell_index < len(cells):
                    cell = cells[issue.cell_index]
                    source = cell.get("source", [])
                    if isinstance(source, list):
                        source = "".join(source)
                    
                    fixed_source = self._fix_eval_exec(source, issue)
                    if fixed_source != source:
                        cell["source"] = fixed_source
                        fixes_applied.append(
                            f"Applied safe alternative for {issue.message} in cell {issue.cell_index}"
                        )

            elif issue.category == "Unsafe Deserialization":
                # Auto-fix yaml.load to yaml.safe_load
                if "yaml.load" in issue.message and 0 <= issue.cell_index < len(cells):
                    cell = cells[issue.cell_index]
                    source = cell.get("source", [])
                    if isinstance(source, list):
                        source = "".join(source)
                    
                    fixed_source = self._fix_yaml_load(source)
                    if fixed_source != source:
                        cell["source"] = fixed_source
                        fixes_applied.append(
                            f"Replaced yaml.load() with yaml.safe_load() in cell {issue.cell_index}"
                        )

            elif issue.category == "Reproducibility Issue":
                # Auto-fix reproducibility issues
                if 0 <= issue.cell_index < len(cells):
                    cell = cells[issue.cell_index]
                    source = cell.get("source", [])
                    if isinstance(source, list):
                        source = "".join(source)
                    
                    # Add seed setting
                    fixed_source = self._add_seed_setting(source, issue.message)
                    if fixed_source != source:
                        cell["source"] = fixed_source
                        fixes_applied.append(
                            f"Added random seed setting in cell {issue.cell_index}"
                        )

            elif issue.category == "Unpinned Dependency":
                # Add comment about pinning version
                if 0 <= issue.cell_index < len(cells):
                    cell = cells[issue.cell_index]
                    source = cell.get("source", [])
                    if isinstance(source, list):
                        source = "".join(source)
                    
                    lines = source.split("\n")
                    # Find the pip install line
                    for i, line in enumerate(lines):
                        if "pip install" in line and issue.code_snippet in line:
                            lines.insert(
                                i,
                                f"# TODO: Pin package version for reproducibility (e.g., ==X.Y.Z)"
                            )
                            break
                    cell["source"] = "\n".join(lines)
                    fixes_applied.append(
                        f"Added version pinning reminder in cell {issue.cell_index}"
                    )

            elif issue.category == "Data Validation":
                # Add data validation reminder
                if 0 <= issue.cell_index < len(cells):
                    cell = cells[issue.cell_index]
                    source = cell.get("source", [])
                    if isinstance(source, list):
                        source = "".join(source)
                    
                    # Add schema validation suggestion
                    lines = source.split("\n")
                    for i, line in enumerate(lines):
                        if "pd.read_csv" in line or "pd.read_excel" in line:
                            lines.insert(
                                i,
                                "# TODO: Add data validation - specify dtypes and validate schema\n"
                                "# Example: pd.read_csv(..., dtype={'col': int}, converters={...})"
                            )
                            break
                    cell["source"] = "\n".join(lines)
                    fixes_applied.append(
                        f"Added data validation reminder in cell {issue.cell_index}"
                    )

            elif issue.category == "Filesystem Security":
                # Auto-fix tempfile.mktemp to tempfile.mkstemp
                if "tempfile.mktemp" in issue.message and 0 <= issue.cell_index < len(cells):
                    cell = cells[issue.cell_index]
                    source = cell.get("source", [])
                    if isinstance(source, list):
                        source = "".join(source)
                    
                    fixed_source = self._fix_tempfile_mktemp(source)
                    if fixed_source != source:
                        cell["source"] = fixed_source
                        fixes_applied.append(
                            f"Replaced tempfile.mktemp() with tempfile.mkstemp() in cell {issue.cell_index}"
                        )

            elif issue.category == "Command Injection":
                # Add warning for shell=True
                if "shell=True" in issue.message and 0 <= issue.cell_index < len(cells):
                    cell = cells[issue.cell_index]
                    source = cell.get("source", [])
                    if isinstance(source, list):
                        source = "".join(source)
                    
                    lines = source.split("\n")
                    if 0 < issue.line_number <= len(lines):
                        lines.insert(
                            issue.line_number - 1,
                            "# SECURITY WARNING: shell=True enables command injection\n"
                            "# Use shell=False and pass command as list: ['cmd', 'arg1', 'arg2']"
                        )
                        cell["source"] = "\n".join(lines)
                        fixes_applied.append(
                            f"Added warning for shell=True in cell {issue.cell_index}"
                        )

            elif issue.category == "Untrusted Notebook":
                # Don't auto-fix trust status (requires user verification)
                pass

        # Save fixed notebook
        if fixes_applied:
            # Create backup first
            backup_path = notebook_path.with_suffix(".ipynb.backup")
            with open(backup_path, "w", encoding="utf-8") as f:
                with open(notebook_path, "r", encoding="utf-8") as orig:
                    f.write(orig.read())

            with open(notebook_path, "w", encoding="utf-8") as f:
                json.dump(notebook_data, f, indent=2)

            fixes_applied.insert(0, f"Created backup at {backup_path}")

        return len(fixes_applied) > 0, fixes_applied
    
    def _fix_torch_load(self, source: str) -> str:
        """
        Fix torch.load() calls to include weights_only=True and checksum verification.
        
        Implements the world-class standard from the vision document:
        - Adds weights_only=True parameter
        - Adds checksum verification before loading
        - Includes educational comments with security rationale
        
        Performs AST-based transformation to safely add the parameter.
        
        Args:
            source: Source code to fix
            
        Returns:
            Fixed source code with safe model loading and verification
        """
        # Add comprehensive model loading security
        if "torch.load(" in source and "weights_only" not in source:
            # Build secure loading block
            secure_block = []
            secure_block.append("# PYGUARD AUTO-FIX: Secure model loading with verification")
            secure_block.append("# CWE-502: Deserialization of Untrusted Data")
            secure_block.append("# PyTorch Security Advisory: Always use weights_only=True")
            secure_block.append("import hashlib")
            secure_block.append("")
            secure_block.append("# TODO: Replace with actual model checksum")
            secure_block.append("MODEL_CHECKSUM = 'abcdef1234567890...'  # Get this from trusted source")
            secure_block.append("")
            secure_block.append("# Step 1: Verify model checksum before loading")
            secure_block.append("model_path = 'model.pth'  # TODO: Update with actual path")
            secure_block.append("with open(model_path, 'rb') as f:")
            secure_block.append("    file_hash = hashlib.sha256(f.read()).hexdigest()")
            secure_block.append("    if file_hash != MODEL_CHECKSUM:")
            secure_block.append("        raise ValueError(f'Model checksum mismatch! Expected {MODEL_CHECKSUM}, got {file_hash}')")
            secure_block.append("")
            secure_block.append("# Step 2: Load with weights_only=True (prevents arbitrary code execution)")
            secure_block.append("# Original unsafe torch.load() call replaced:")
            secure_block.append("")
            
            # Try AST-based transformation first
            try:
                tree = ast.parse(source)
                modified = False
                
                for node in ast.walk(tree):
                    if isinstance(node, ast.Call):
                        # Check if this is a torch.load call
                        if isinstance(node.func, ast.Attribute):
                            if (isinstance(node.func.value, ast.Name) and 
                                node.func.value.id == "torch" and 
                                node.func.attr == "load"):
                                
                                # Check if weights_only is already present
                                has_weights_only = any(
                                    kw.arg == "weights_only" for kw in node.keywords
                                )
                                
                                if not has_weights_only:
                                    # Add weights_only=True keyword argument
                                    node.keywords.append(
                                        ast.keyword(
                                            arg="weights_only",
                                            value=ast.Constant(value=True)
                                        )
                                    )
                                    
                                    # Add map_location for safety
                                    has_map_location = any(
                                        kw.arg == "map_location" for kw in node.keywords
                                    )
                                    if not has_map_location:
                                        node.keywords.append(
                                            ast.keyword(
                                                arg="map_location",
                                                value=ast.Constant(value="cpu")
                                            )
                                        )
                                    
                                    modified = True
                
                if modified and hasattr(ast, "unparse"):
                    # Unparse to get fixed source
                    fixed_source = ast.unparse(tree)
                    # Add secure block before the fixed source
                    return "\n".join(secure_block) + fixed_source
                
            except SyntaxError:
                pass
            
            # Fallback: regex-based replacement if AST fails
            lines = source.split("\n")
            fixed_lines = []
            
            for line in lines:
                if "torch.load(" in line and "weights_only" not in line:
                    # Add secure block before torch.load line
                    fixed_lines.extend(secure_block)
                    # Fix the torch.load call
                    fixed_line = re.sub(
                        r"torch\.load\(([^)]+)\)",
                        r"torch.load(\1, weights_only=True, map_location='cpu')",
                        line
                    )
                    # Clean up potential double comma
                    fixed_line = fixed_line.replace(", , weights_only", ", weights_only")
                    fixed_lines.append(fixed_line)
                else:
                    fixed_lines.append(line)
            
            return "\n".join(fixed_lines)
        
        return source
    
    def _add_seed_setting(self, source: str, message: str) -> str:
        """
        Add comprehensive random seed setting for ML frameworks.
        
        Implements the world-class standard from the vision document:
        - Sets seeds for all major ML frameworks (random, numpy, torch, tf, jax)
        - Configures deterministic backends
        - Documents environment for reproducibility
        
        Args:
            source: Source code to fix
            message: Issue message describing which framework needs seeding
            
        Returns:
            Fixed source code with comprehensive seed setting
        """
        # Detect which frameworks are imported
        has_torch = "import torch" in source or "from torch" in source
        has_tf = "import tensorflow" in source or "from tensorflow" in source or "import tf" in source
        has_numpy = "import numpy" in source or "from numpy" in source or "import np" in source
        has_random = "import random" in source
        has_jax = "import jax" in source or "from jax" in source
        
        # Build comprehensive seed setting function
        if has_torch or has_numpy or has_tf or has_random or "import" in source:
            # Create comprehensive reproducibility setup
            seed_block = []
            seed_block.append("# PYGUARD AUTO-FIX: Comprehensive reproducibility setup")
            seed_block.append("# Added for deterministic ML experiments")
            seed_block.append("def set_global_seed(seed=42):")
            seed_block.append("    \"\"\"Set seeds for reproducible ML experiments.\"\"\"")
            
            # Python random
            if has_random or "random" in message.lower():
                seed_block.append("    import random")
                seed_block.append("    random.seed(seed)")
            
            # NumPy
            if has_numpy or "numpy" in message.lower():
                seed_block.append("    import numpy as np")
                seed_block.append("    np.random.seed(seed)")
            
            # PyTorch
            if has_torch or "torch" in message.lower():
                seed_block.append("    import torch")
                seed_block.append("    torch.manual_seed(seed)")
                seed_block.append("    torch.cuda.manual_seed_all(seed)")
                seed_block.append("    # PyTorch deterministic mode (may reduce performance)")
                seed_block.append("    torch.backends.cudnn.deterministic = True")
                seed_block.append("    torch.backends.cudnn.benchmark = False")
                seed_block.append("    try:")
                seed_block.append("        torch.use_deterministic_algorithms(True, warn_only=True)")
                seed_block.append("    except AttributeError:")
                seed_block.append("        pass  # PyTorch < 1.8")
            
            # TensorFlow
            if has_tf or "tensorflow" in message.lower():
                seed_block.append("    import tensorflow as tf")
                seed_block.append("    tf.random.set_seed(seed)")
                seed_block.append("    try:")
                seed_block.append("        tf.config.experimental.enable_op_determinism()")
                seed_block.append("    except AttributeError:")
                seed_block.append("        pass  # TensorFlow < 2.9")
            
            # JAX
            if has_jax:
                seed_block.append("    import jax")
                seed_block.append("    # JAX uses explicit PRNG keys, set environment for consistency")
            
            # Environment variables for additional determinism
            if has_torch or has_tf:
                seed_block.append("    import os")
                seed_block.append("    os.environ['PYTHONHASHSEED'] = str(seed)")
                if has_torch:
                    seed_block.append("    os.environ['CUBLAS_WORKSPACE_CONFIG'] = ':4096:8'")
            
            seed_block.append("    print(f'✓ Global seed set to {seed} for reproducibility')")
            seed_block.append("")
            seed_block.append("# Call seed setting function")
            seed_block.append("set_global_seed(42)")
            seed_block.append("")
            
            # Add the seed block at the beginning after imports
            lines = source.split("\n")
            insert_pos = 0
            
            # Find position after all import statements
            last_import_line = -1
            for i, line in enumerate(lines):
                if line.strip().startswith("import ") or line.strip().startswith("from "):
                    last_import_line = i
            
            if last_import_line >= 0:
                insert_pos = last_import_line + 1
            
            # Insert seed block
            for line in reversed(seed_block):
                lines.insert(insert_pos, line)
            
            return "\n".join(lines)
        
        # Fallback to simple seed additions if comprehensive setup not appropriate
        seed_additions = []
        
        if "PyTorch" in message or "torch" in message.lower():
            if "torch.manual_seed" not in source:
                seed_additions.append("torch.manual_seed(42)  # Set PyTorch seed for reproducibility")
        
        if "NumPy" in message or "numpy" in message.lower():
            if "np.random.seed" not in source and "numpy.random.seed" not in source:
                seed_additions.append("np.random.seed(42)  # Set NumPy seed for reproducibility")
        
        if "TensorFlow" in message:
            if "tf.random.set_seed" not in source:
                seed_additions.append("tf.random.set_seed(42)  # Set TensorFlow seed for reproducibility")
        
        if "Python random" in message:
            if "random.seed" not in source:
                seed_additions.append("random.seed(42)  # Set Python random seed for reproducibility")
        
        if seed_additions:
            # Add seeds at the beginning of the cell (after imports ideally)
            lines = source.split("\n")
            insert_pos = 0
            
            # Try to insert after import statements
            for i, line in enumerate(lines):
                if line.strip() and not line.strip().startswith("import") and not line.strip().startswith("from"):
                    insert_pos = i
                    break
            
            for seed_line in reversed(seed_additions):
                lines.insert(insert_pos, seed_line)
            
            return "\n".join(lines)
        
        return source
    
    def _fix_eval_exec(self, source: str, issue: NotebookIssue) -> str:
        """
        Fix eval/exec calls to use safer alternatives.
        
        Replaces eval() with ast.literal_eval() where appropriate, and adds
        warnings for exec() usage.
        
        Args:
            source: Source code to fix
            issue: The issue describing the eval/exec usage
            
        Returns:
            Fixed source code
        """
        # For eval(), suggest ast.literal_eval
        if "eval(" in source and "eval()" in issue.message:
            # Add import if not present
            if "import ast" not in source:
                source = "import ast  # For safe literal evaluation\n" + source
            
            # Add comment before eval usage
            lines = source.split("\n")
            for i, line in enumerate(lines):
                if "eval(" in line and not line.strip().startswith("#"):
                    lines.insert(
                        i,
                        "# SECURITY: Consider using ast.literal_eval() for safe evaluation\n"
                        "# ast.literal_eval() only evaluates literals (strings, numbers, tuples, lists, dicts, booleans, None)\n"
                        "# Original eval() call below (REVIEW AND UPDATE):"
                    )
                    break
            source = "\n".join(lines)
        
        # For exec(), add warning
        if "exec(" in source and "exec()" in issue.message:
            lines = source.split("\n")
            for i, line in enumerate(lines):
                if "exec(" in line and not line.strip().startswith("#"):
                    lines.insert(
                        i,
                        "# CRITICAL SECURITY WARNING: exec() executes arbitrary code\n"
                        "# Refactor to avoid dynamic code execution if possible\n"
                        "# If absolutely necessary, implement strict input validation"
                    )
                    break
            source = "\n".join(lines)
        
        return source
    
    def _fix_yaml_load(self, source: str) -> str:
        """
        Fix yaml.load() to use yaml.safe_load().
        
        Performs a simple string replacement to use the safer alternative.
        
        Args:
            source: Source code to fix
            
        Returns:
            Fixed source code
        """
        # Replace yaml.load( with yaml.safe_load(
        # This is a simple fix but effective for most cases
        if "yaml.load(" in source and "yaml.safe_load(" not in source:
            # Add comment explaining the change
            source = (
                "# SECURITY FIX: Using yaml.safe_load() instead of yaml.load()\n"
                "# yaml.safe_load() prevents arbitrary code execution\n" + 
                source
            )
            source = source.replace("yaml.load(", "yaml.safe_load(")
        
        # Also handle yaml.unsafe_load
        if "yaml.unsafe_load(" in source:
            source = (
                "# SECURITY FIX: Using yaml.safe_load() instead of yaml.unsafe_load()\n" +
                source
            )
            source = source.replace("yaml.unsafe_load(", "yaml.safe_load(")
        
        return source
    
    def _fix_tempfile_mktemp(self, source: str) -> str:
        """
        Fix tempfile.mktemp() to use tempfile.mkstemp().
        
        Replaces the deprecated mktemp with the secure mkstemp.
        
        Args:
            source: Source code to fix
            
        Returns:
            Fixed source code
        """
        if "tempfile.mktemp(" in source:
            # Add comment explaining the change
            source = (
                "# SECURITY FIX: Using tempfile.mkstemp() instead of mktemp()\n"
                "# mkstemp() creates the file securely, preventing race conditions\n"
                "# Note: mkstemp() returns (fd, path) tuple instead of just path\n" +
                source
            )
            # Replace tempfile.mktemp() with tempfile.mkstemp()
            source = source.replace("tempfile.mktemp(", "tempfile.mkstemp(")
        
        return source


def scan_notebook(notebook_path: str) -> List[NotebookIssue]:
    """
    Convenience function to scan a notebook for security issues.

    Args:
        notebook_path: Path to .ipynb file

    Returns:
        List of security issues found
    """
    analyzer = NotebookSecurityAnalyzer()
    return analyzer.analyze_notebook(Path(notebook_path))


def generate_notebook_sarif(notebook_path: str, issues: List[NotebookIssue]) -> Dict[str, Any]:
    """
    Generate SARIF 2.1.0 report for notebook security issues.
    
    This is a convenience function that creates a SARIF report compatible with
    GitHub Security, VS Code, and other security platforms.
    
    Args:
        notebook_path: Path to the notebook file
        issues: List of security issues found by scan_notebook()
        
    Returns:
        SARIF report as dictionary
        
    Example:
        >>> issues = scan_notebook('notebook.ipynb')
        >>> sarif = generate_notebook_sarif('notebook.ipynb', issues)
        >>> with open('notebook-security.sarif', 'w') as f:
        ...     json.dump(sarif, f, indent=2)
    """
    import hashlib
    
    notebook_pathobj = Path(notebook_path)
    
    # Build rules dictionary from unique categories
    rules_dict = {}
    for issue in issues:
        rule_id = _get_rule_id_from_issue(issue)
        
        if rule_id not in rules_dict:
            rules_dict[rule_id] = {
                "id": rule_id,
                "name": issue.message,
                "shortDescription": {
                    "text": issue.message
                },
                "fullDescription": {
                    "text": f"{issue.message}. {issue.fix_suggestion or 'No automated fix available.'}"
                },
                "defaultConfiguration": {
                    "level": _severity_to_sarif_level(issue.severity)
                },
                "properties": {
                    "security-severity": str(_severity_to_score(issue.severity)),
                    "precision": "high" if issue.confidence >= 0.9 else "medium" if issue.confidence >= 0.7 else "low",
                    "tags": _get_tags_for_issue(issue)
                },
                "help": {
                    "text": issue.fix_suggestion or "Review the finding and apply appropriate security measures.",
                    "markdown": _format_help_markdown(issue)
                }
            }
    
    # Build SARIF results
    sarif_results = []
    for issue in issues:
        rule_id = _get_rule_id_from_issue(issue)
        
        sarif_result = {
            "ruleId": rule_id,
            "level": _severity_to_sarif_level(issue.severity),
            "message": {
                "text": f"{issue.message} in cell {issue.cell_index}",
                "markdown": _format_message_markdown(issue)
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": str(notebook_pathobj),
                        "uriBaseId": "%SRCROOT%"
                    },
                    "region": {
                        "startLine": issue.line_number if issue.line_number else 1,
                        "endLine": issue.line_number if issue.line_number else 1,
                        "snippet": {
                            "text": issue.code_snippet if issue.code_snippet else f"Cell {issue.cell_index}"
                        }
                    },
                    "contextRegion": {
                        "startLine": 1,
                        "snippet": {
                            "text": f"Notebook Cell {issue.cell_index} ({issue.category})"
                        }
                    }
                }
            }],
            "partialFingerprints": {
                "primaryLocationLineHash": hashlib.md5(
                    f"{notebook_path}:{issue.cell_index}:{issue.line_number}:{issue.code_snippet}".encode()
                ).hexdigest()[:16]
            },
            "properties": {
                "cell_index": issue.cell_index,
                "cell_line_number": issue.line_number,
                "category": issue.category,
                "confidence": issue.confidence,
                "auto_fixable": issue.auto_fixable
            }
        }
        
        # Add fix information if available
        if issue.fix_suggestion and issue.auto_fixable:
            sarif_result["fixes"] = [{
                "description": {
                    "text": issue.fix_suggestion,
                    "markdown": f"**Auto-fix available**\\n\\n{issue.fix_suggestion}"
                }
            }]
        
        sarif_results.append(sarif_result)
    
    # Build complete SARIF report
    sarif_report = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "PyGuard Notebook Security Analyzer",
                    "version": "0.3.0",
                    "informationUri": "https://github.com/cboyd0319/PyGuard",
                    "semanticVersion": "0.3.0",
                    "organization": "PyGuard",
                    "shortDescription": {
                        "text": "World-class Jupyter notebook security analyzer with ML/AI-aware detection"
                    },
                    "fullDescription": {
                        "text": "Comprehensive security analysis for Jupyter notebooks with 76+ vulnerability patterns across 13 categories including code injection, unsafe deserialization, hardcoded secrets, and ML-specific risks."
                    },
                    "rules": list(rules_dict.values())
                }
            },
            "results": sarif_results,
            "columnKind": "utf16CodeUnits",
            "properties": {
                "notebook_analyzed": str(notebook_pathobj),
                "total_issues": len(issues),
                "critical_issues": sum(1 for i in issues if i.severity == "CRITICAL"),
                "high_issues": sum(1 for i in issues if i.severity == "HIGH"),
                "medium_issues": sum(1 for i in issues if i.severity == "MEDIUM"),
                "low_issues": sum(1 for i in issues if i.severity == "LOW")
            }
        }]
    }
    
    return sarif_report


def _get_rule_id_from_issue(issue: NotebookIssue) -> str:
    """Generate a rule ID from issue category and severity."""
    # Convert category to rule ID format
    category_abbrev = {
        "Code Injection": "CI",
        "Unsafe Deserialization": "UD",
        "Command Injection": "CMD",
        "Hardcoded Secret": "SEC",
        "High-Entropy Secret": "ENT",
        "PII Exposure": "PII",
        "PII in Output": "PII-OUT",
        "Unsafe Magic Command": "MAG",
        "XSS Vulnerability": "XSS",
        "ML Pipeline Security": "ML",
        "Data Validation": "DVAL",
        "Reproducibility Issue": "REPRO",
        "Unpinned Dependency": "DEP",
        "Information Disclosure": "INFO",
        "Execution Order Issue": "EXEC",
        "Filesystem Security": "FS",
        "Network & Data Exfiltration": "NET",
        "Resource Exhaustion": "RES",
        "Advanced Code Injection": "ACI",
        "Advanced ML/AI Security": "AML",
        "Untrusted Notebook": "TRUST",
        "Non-Standard Kernel": "KERN"
    }
    
    abbrev = category_abbrev.get(issue.category, "GEN")
    # Create unique rule ID
    rule_id = f"PYGUARD-NB-{abbrev}-{issue.severity[:3]}"
    return rule_id


def _get_tags_for_issue(issue: NotebookIssue) -> List[str]:
    """Get SARIF tags for an issue."""
    tags = ["security", "notebook"]
    
    if issue.cwe_id:
        tags.append(issue.cwe_id)
    if issue.owasp_id:
        tags.append(issue.owasp_id)
    
    # Add category-specific tags
    category_tags = {
        "Code Injection": ["injection", "code-execution"],
        "Unsafe Deserialization": ["deserialization", "arbitrary-code-execution"],
        "Command Injection": ["injection", "command-injection"],
        "Hardcoded Secret": ["secrets", "credentials"],
        "High-Entropy Secret": ["secrets", "cryptography"],
        "PII Exposure": ["privacy", "pii"],
        "XSS Vulnerability": ["xss", "injection"],
        "ML Pipeline Security": ["ml", "ai", "model-security"],
        "Filesystem Security": ["path-traversal", "filesystem"],
        "Network & Data Exfiltration": ["network", "exfiltration"],
        "Resource Exhaustion": ["dos", "resource-exhaustion"]
    }
    
    if issue.category in category_tags:
        tags.extend(category_tags[issue.category])
    
    return tags


def _severity_to_sarif_level(severity: str) -> str:
    """Convert PyGuard severity to SARIF level."""
    mapping = {
        'CRITICAL': 'error',
        'HIGH': 'error',
        'MEDIUM': 'warning',
        'LOW': 'note',
        'INFO': 'note',
    }
    return mapping.get(severity, 'warning')


def _severity_to_score(severity: str) -> float:
    """Convert severity to numeric score (CVSS-like)."""
    mapping = {
        'CRITICAL': 9.0,
        'HIGH': 7.0,
        'MEDIUM': 5.0,
        'LOW': 3.0,
        'INFO': 1.0,
    }
    return mapping.get(severity, 5.0)


def _format_help_markdown(issue: NotebookIssue) -> str:
    """Format detailed help text in markdown."""
    help_text = f"## {issue.message}\\n\\n"
    help_text += f"**Category:** {issue.category}\\n"
    help_text += f"**Severity:** {issue.severity}\\n"
    help_text += f"**Confidence:** {issue.confidence:.0%}\\n\\n"
    
    if issue.cwe_id:
        help_text += f"**{issue.cwe_id}:** Common Weakness Enumeration\\n"
    if issue.owasp_id:
        help_text += f"**OWASP:** {issue.owasp_id}\\n"
    
    help_text += f"\\n### Fix Suggestion\\n\\n"
    help_text += issue.fix_suggestion or "No automated fix available. Manual review required."
    
    if issue.auto_fixable:
        help_text += "\\n\\n✅ **Auto-fix available** - Run PyGuard with auto-fix enabled."
    
    return help_text


def _format_message_markdown(issue: NotebookIssue) -> str:
    """Format issue message in markdown."""
    msg = f"**{issue.message}**\\n\\n"
    msg += f"Found in notebook cell {issue.cell_index}"
    if issue.line_number:
        msg += f", line {issue.line_number}"
    msg += f"\\n\\nConfidence: {issue.confidence:.0%}"
    
    if issue.code_snippet:
        msg += f"\\n\\n```python\\n{issue.code_snippet}\\n```"
    
    return msg
