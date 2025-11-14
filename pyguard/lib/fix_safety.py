"""
Fix Safety Classification System for PyGuard.

Classifies auto-fixes into safety categories to ensure appropriate application:
- SAFE: Can be applied automatically without risk
- UNSAFE: Requires manual review before application
- WARNING_ONLY: Only adds comments/warnings, no code modification

This prevents dangerous automated code changes while maximizing automation
for safe transformations.

References:
- OWASP ASVS v5.0 | https://owasp.org/ASVS | High | Security verification
- Refactoring Patterns | https://refactoring.com/ | High | Safe refactorings
"""

from dataclasses import dataclass
from enum import Enum


class FixSafety(Enum):
    """Safety level classification for auto-fixes."""

    SAFE = "safe"  # Can be applied automatically
    UNSAFE = "unsafe"  # Requires manual review
    WARNING_ONLY = "warning_only"  # Only adds comments


@dataclass
class FixClassification:
    """Classification details for a specific fix type."""

    fix_id: str
    safety: FixSafety
    category: str  # "security", "quality", "style", "performance"
    description: str
    reasoning: str
    examples: list[str] | None = None


class FixSafetyClassifier:
    """
    Classifier for determining the safety level of auto-fixes.

    Provides a centralized system for classifying and managing auto-fix safety,
    ensuring that potentially dangerous fixes are not applied automatically.
    """

    def __init__(self):
        """Initialize fix safety classifier with predefined classifications."""
        self._classifications: dict[str, FixClassification] = {}
        self._initialize_classifications()

    def _initialize_classifications(self) -> None:  # noqa: PLR0915 - Comprehensive fix classification requires many statements
        """Initialize predefined fix classifications."""

        # ===== SAFE FIXES =====
        # Style/Formatting fixes (always safe)
        self._add_safe_fix(
            "import_sorting",
            "style",
            "Sort imports alphabetically",
            "Pure reordering with no semantic changes",
        )

        self._add_safe_fix(
            "trailing_whitespace",
            "style",
            "Remove trailing whitespace",
            "Cosmetic change with no code impact",
        )

        self._add_safe_fix(
            "quote_normalization",
            "style",
            "Normalize quote styles",
            "Cosmetic change preserving string values",
        )

        self._add_safe_fix(
            "blank_line_normalization",
            "style",
            "Normalize blank lines per PEP 8",
            "Cosmetic change with no semantic impact",
        )

        self._add_safe_fix(
            "line_length", "style", "Break long lines", "Formatting change preserving semantics"
        )

        # Simple replacements (safe)
        self._add_safe_fix(
            "yaml_safe_load",
            "security",
            "Replace yaml.load() with yaml.safe_load()",
            "Direct replacement with safer alternative, no logic change",
        )

        self._add_safe_fix(
            "mkstemp_replacement",
            "security",
            "Replace mktemp() with mkstemp()",
            "Direct replacement with secure alternative",
        )

        self._add_safe_fix(
            "comparison_to_none",
            "quality",
            "Replace is None with is None",
            "Semantically equivalent, more Pythonic",
        )

        self._add_safe_fix(
            "comparison_to_bool",
            "quality",
            "Replace   # Use if var: instead/False with direct boolean check",
            "Semantically equivalent simplification",
        )

        self._add_safe_fix(
            "type_comparison",
            "quality",
            "Replace type(x) == Y with isinstance(x, Y)",  # Better: isinstance(x, Y)
            "More robust and Pythonic, handles inheritance",
        )

        # ===== UNSAFE FIXES =====
        # Security refactoring (requires review)
        self._add_unsafe_fix(
            "sql_parameterization",
            "security",
            "Convert SQL string concat to parameterized queries",
            "Requires understanding of SQL context and variable types. "
            "May need manual adjustment for complex queries.",
        )

        self._add_unsafe_fix(
            "command_subprocess",
            "security",
            "Replace os.system() with subprocess.run()",  # SECURITY: Use subprocess.run() instead  # SECURITY: Use subprocess.run() instead
            "Changes how command arguments are passed. "
            "Requires validation that command splitting is correct.",
        )

        self._add_unsafe_fix(
            "path_traversal_validation",
            "security",
            "Add path validation for user inputs",
            "May change program logic if path validation wasn't intended. "
            "Requires understanding of intended path restrictions.",
        )

        self._add_unsafe_fix(
            "exception_narrowing",
            "quality",
            "Replace bare except with specific exception",
            "Changes which exceptions are caught. May expose previously hidden errors.",
        )

        self._add_unsafe_fix(
            "mutable_default_arg",
            "quality",
            "Replace mutable default argument with None",
            "Changes function signature and behavior. Requires adding initialization code.",
        )

        # ===== WARNING ONLY =====
        # Security issues requiring manual intervention
        self._add_warning_only_fix(
            "hardcoded_secrets",
            "security",
            "Detect hardcoded secrets and suggest environment variables",
            "Cannot automatically determine correct environment variable names. "
            "Requires manual migration to config/secrets management.",
        )

        self._add_warning_only_fix(
            "weak_crypto_warning",
            "security",
            "Warn about weak cryptographic algorithms",
            "Replacement algorithm depends on use case (MD5 for checksums vs security). "
            "Cannot automatically determine correct algorithm.",
        )

        self._add_warning_only_fix(
            "pickle_warning",
            "security",
            "Warn about pickle usage with untrusted data",
            "Requires context about data source. "
            "Alternative depends on use case (JSON, protobuf, etc.).",
        )

        self._add_warning_only_fix(
            "eval_exec_warning",
            "security",
            "Warn about dangerous eval/exec usage",
            "No safe automatic replacement. Requires complete redesign of affected code.",
        )

        self._add_warning_only_fix(
            "sql_injection_warning",
            "security",
            "Warn about SQL injection via string formatting",
            "Complex transformations require understanding query structure. "
            "Use sql_parameterization fix with --unsafe-fixes flag.",
        )

        self._add_warning_only_fix(
            "command_injection_warning",
            "security",
            "Warn about command injection risks",
            "Transformations depend on command structure. "
            "Use command_subprocess fix with --unsafe-fixes flag.",
        )

        # ===== AI/ML SECURITY FIXES =====
        # Safe AI/ML security fixes
        self._add_safe_fix(
            "torch_load_weights_only",
            "security",
            "Add weights_only=True to torch.load()",
            "Direct parameter addition, prevents arbitrary code execution via pickle",
        )

        self._add_safe_fix(
            "from_pretrained_trust",
            "security",
            "Add trust_remote_code=False to from_pretrained()",
            "Direct parameter addition, prevents arbitrary code execution from models",
        )

        self._add_safe_fix(
            "api_key_exposure",
            "security",
            "Move hardcoded API keys to environment variables",
            "Replaces hardcoded values with os.getenv(), prevents credential exposure",
        )

        self._add_safe_fix(
            "gpu_memory_limits",
            "security",
            "Add GPU memory limits to prevent exhaustion",
            "Adds configuration without changing logic, prevents DoS attacks",
        )

        self._add_safe_fix(
            "llm_rate_limiting",
            "security",
            "Add rate limiting to LLM API calls",
            "Adds protective parameter without changing logic, prevents cost overflow",
        )

        self._add_safe_fix(
            "model_versioning",
            "security",
            "Replace 'latest' model tags with specific versions",
            "Comment-based suggestion for reproducibility",
        )

        # Stage 2 priority AI/ML fixes
        self._add_safe_fix(
            "api_parameter_validation",
            "security",
            "Validate LLM API parameters (temperature, top_p)",
            "Adds validation warnings for parameters outside valid ranges",
        )

        self._add_safe_fix(
            "missing_timeout",
            "security",
            "Add timeout configuration to LLM API calls",
            "Adds warning to prevent indefinite hangs on API calls",
        )

        self._add_safe_fix(
            "unhandled_api_errors",
            "security",
            "Add error handling for LLM API calls",
            "Adds warning to prevent information disclosure from unhandled exceptions",
        )

        self._add_safe_fix(
            "untrusted_url_loading",
            "security",
            "Add validation for loading models from untrusted URLs",
            "Adds warning to validate URLs before loading models",
        )

        self._add_safe_fix(
            "torch_jit_load",
            "security",
            "Add security parameters to torch.jit.load() calls",
            "Adds warning to use map_location for security",
        )

        self._add_safe_fix(
            "model_integrity_verification",
            "security",
            "Add model integrity verification using checksums",
            "Adds warning to verify model checksums",
        )

        self._add_safe_fix(
            "model_card_credentials",
            "security",
            "Remove credentials from model cards and metadata",
            "Detects and warns about API keys in model metadata",
        )

        # Unsafe AI/ML security fixes
        self._add_unsafe_fix(
            "pickle_to_safetensors",
            "security",
            "Replace pickle with safetensors for model serialization",
            "Changes serialization format (API breaking), requires safetensors dependency",
        )

        self._add_unsafe_fix(
            "training_data_validation",
            "security",
            "Add training data validation to prevent poisoning",
            "Modifies training pipeline, may affect training behavior",
        )

        # Warning-only AI/ML fixes
        self._add_warning_only_fix(
            "output_sanitization",
            "security",
            "Add output sanitization to LLM responses",
            "Complex transformation requiring context analysis. Manual implementation recommended.",
        )

        self._add_warning_only_fix(
            "prompt_injection_basic",
            "security",
            "Add basic prompt injection prevention",
            "Complex transformation requiring AST-based context analysis. Manual implementation recommended.",
        )

        # Group B: Context & Token Manipulation (AIML019-028) - Safe warning-only fixes
        self._add_warning_only_fix(
            "escape_sequence_injection",
            "security",
            "Detect escape sequence injection in prompts",
            "Adds warnings for newline/control character injection patterns",
        )

        self._add_warning_only_fix(
            "token_stuffing",
            "security",
            "Detect token stuffing attacks",
            "Adds warnings for context window exhaustion patterns",
        )

        self._add_warning_only_fix(
            "recursive_prompt_injection",
            "security",
            "Detect recursive prompt injection",
            "Adds warnings for nested prompt instruction patterns",
        )

        self._add_warning_only_fix(
            "template_literal_injection",
            "security",
            "Detect template literal injection",
            "Adds warnings for unsafe template substitution patterns",
        )

        self._add_warning_only_fix(
            "fstring_injection",
            "security",
            "Detect f-string injection",
            "Adds warnings for f-strings with user input",
        )

        self._add_warning_only_fix(
            "variable_substitution",
            "security",
            "Detect variable substitution attacks",
            "Adds warnings for unvalidated variable replacement in prompts",
        )

        # Group C: External Content Injection (AIML031-045) - Safe warning-only fixes
        self._add_warning_only_fix(
            "url_based_injection",
            "security",
            "Detect URL-based content injection",
            "Adds warnings for unvalidated external web content in prompts",
        )

        self._add_warning_only_fix(
            "api_response_injection",
            "security",
            "Detect API response injection",
            "Adds warnings for unvalidated 3rd party API data in prompts",
        )

        self._add_warning_only_fix(
            "database_content_injection",
            "security",
            "Detect database content injection",
            "Adds warnings for unvalidated database query results in prompts",
        )

        self._add_warning_only_fix(
            "rag_poisoning",
            "security",
            "Detect RAG poisoning risks",
            "Adds warnings for unvalidated retrieval-augmented generation content",
        )

        self._add_warning_only_fix(
            "vector_database_injection",
            "security",
            "Detect vector database injection",
            "Adds warnings for unvalidated vector similarity search results",
        )

        self._add_warning_only_fix(
            "conversation_history_injection",
            "security",
            "Detect conversation history injection",
            "Adds warnings for unvalidated chat history in prompts",
        )

        # Group D: LLM API Security (AIML046-060) - Safe warning-only fixes
        self._add_warning_only_fix(
            "max_tokens_manipulation",
            "security",
            "Detect missing or excessive max_tokens limits",
            "Adds warnings to prevent DoS via unbounded token generation",
        )

        self._add_warning_only_fix(
            "streaming_response_injection",
            "security",
            "Detect unvalidated streaming responses",
            "Adds warnings for streaming API calls without chunk validation",
        )

        self._add_warning_only_fix(
            "function_calling_injection",
            "security",
            "Detect unsafe function calling patterns",
            "Adds warnings for LLM-controlled function execution risks",
        )

        self._add_warning_only_fix(
            "tool_use_tampering",
            "security",
            "Detect unvalidated tool parameters",
            "Adds warnings for LLM-generated tool parameter risks",
        )

        self._add_warning_only_fix(
            "system_message_manipulation",
            "security",
            "Detect system message manipulation risks",
            "Adds warnings for user-controlled system prompts",
        )

        self._add_warning_only_fix(
            "model_selection_bypass",
            "security",
            "Detect unvalidated model selection",
            "Adds warnings for user-controlled model names",
        )

        self._add_warning_only_fix(
            "hardcoded_model_names",
            "security",
            "Detect hardcoded model names",
            "Adds warnings to use configuration for model names",
        )

        self._add_warning_only_fix(
            "token_counting_bypass",
            "security",
            "Detect missing token counting",
            "Adds warnings to implement token tracking for context management",
        )

        self._add_warning_only_fix(
            "cost_overflow_attacks",
            "security",
            "Detect cost overflow risks",
            "Adds warnings for API calls in loops without rate limiting",
        )

    def _add_safe_fix(self, fix_id: str, category: str, description: str, reasoning: str) -> None:
        """Add a SAFE fix classification."""
        self._classifications[fix_id] = FixClassification(
            fix_id=fix_id,
            safety=FixSafety.SAFE,
            category=category,
            description=description,
            reasoning=reasoning,
        )

    def _add_unsafe_fix(self, fix_id: str, category: str, description: str, reasoning: str) -> None:
        """Add an UNSAFE fix classification."""
        self._classifications[fix_id] = FixClassification(
            fix_id=fix_id,
            safety=FixSafety.UNSAFE,
            category=category,
            description=description,
            reasoning=reasoning,
        )

    def _add_warning_only_fix(
        # TODO: Add docstring
        self, fix_id: str, category: str, description: str, reasoning: str
    ) -> None:
        """Add a WARNING_ONLY fix classification."""
        self._classifications[fix_id] = FixClassification(
            fix_id=fix_id,
            safety=FixSafety.WARNING_ONLY,
            category=category,
            description=description,
            reasoning=reasoning,
        )

    def get_classification(self, fix_id: str) -> FixClassification | None:
        """
        Get classification for a specific fix.

        Args:
            fix_id: Identifier for the fix

        Returns:
            FixClassification if found, None otherwise
        """
        return self._classifications.get(fix_id)

    def is_safe(self, fix_id: str) -> bool:
        """
        Check if a fix is classified as SAFE.

        Args:
            fix_id: Identifier for the fix

        Returns:
            True if fix is SAFE, False otherwise
        """
        classification = self.get_classification(fix_id)
        return classification is not None and classification.safety == FixSafety.SAFE

    def is_unsafe(self, fix_id: str) -> bool:
        """
        Check if a fix is classified as UNSAFE.

        Args:
            fix_id: Identifier for the fix

        Returns:
            True if fix is UNSAFE, False otherwise
        """
        classification = self.get_classification(fix_id)
        return classification is not None and classification.safety == FixSafety.UNSAFE

    def is_warning_only(self, fix_id: str) -> bool:
        """
        Check if a fix is classified as WARNING_ONLY.

        Args:
            fix_id: Identifier for the fix

        Returns:
            True if fix is WARNING_ONLY, False otherwise
        """
        classification = self.get_classification(fix_id)
        return classification is not None and classification.safety == FixSafety.WARNING_ONLY

    def should_apply_fix(self, fix_id: str, allow_unsafe: bool = False) -> bool:
        """
        Determine if a fix should be applied given the safety settings.

        Args:
            fix_id: Identifier for the fix
            allow_unsafe: Whether to allow unsafe fixes

        Returns:
            True if fix should be applied, False otherwise
        """
        classification = self.get_classification(fix_id)
        if classification is None:
            # Unknown fixes default to not being applied
            return False

        if classification.safety == FixSafety.SAFE:
            return True
        if classification.safety == FixSafety.UNSAFE:
            return allow_unsafe
        # WARNING_ONLY fixes add warning comments (no semantic changes)
        # They can be applied safely to alert developers to issues
        return True

    def get_all_safe_fixes(self) -> set[str]:
        """Get IDs of all SAFE fixes."""
        return {
            fix_id
            for fix_id, classification in self._classifications.items()
            if classification.safety == FixSafety.SAFE
        }

    def get_all_unsafe_fixes(self) -> set[str]:
        """Get IDs of all UNSAFE fixes."""
        return {
            fix_id
            for fix_id, classification in self._classifications.items()
            if classification.safety == FixSafety.UNSAFE
        }

    def get_all_warning_only_fixes(self) -> set[str]:
        """Get IDs of all WARNING_ONLY fixes."""
        return {
            fix_id
            for fix_id, classification in self._classifications.items()
            if classification.safety == FixSafety.WARNING_ONLY
        }

    def get_fixes_by_category(self, category: str) -> dict[str, FixClassification]:
        """
        Get all fixes in a specific category.

        Args:
            category: Category name ("security", "quality", "style", "performance")

        Returns:
            Dictionary of fix_id -> FixClassification for the category
        """
        return {
            fix_id: classification
            for fix_id, classification in self._classifications.items()
            if classification.category == category
        }

    def get_statistics(self) -> dict[str, int]:
        """
        Get statistics about fix classifications.

        Returns:
            Dictionary with counts of fixes by safety level and category
        """
        stats = {
            "total": len(self._classifications),
            "safe": len(self.get_all_safe_fixes()),
            "unsafe": len(self.get_all_unsafe_fixes()),
            "warning_only": len(self.get_all_warning_only_fixes()),
        }

        # Count by category
        for category in ["security", "quality", "style", "performance"]:
            stats[f"category_{category}"] = len(self.get_fixes_by_category(category))

        return stats
