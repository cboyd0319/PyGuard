"""
AI/ML Security Analysis.

Detects security vulnerabilities in AI/ML applications including prompt injection,
model serialization risks, training data poisoning, and GPU memory leakage.

Security Areas Covered:
- Prompt injection in LLM applications
- System prompt override attempts (delimiter injection) - AIML011
- Unicode/homoglyph injection (zero-width characters, bi-directional overrides) - AIML012
- Role confusion attacks (DAN mode, jailbreaks) - AIML013
- Instruction concatenation bypasses - AIML014
- Multi-language prompt injection (non-English) - AIML015
- Markdown injection in prompts - AIML016
- XML/JSON payload injection - AIML017
- SQL-style comment injection - AIML018
- Escape sequence injection - AIML019
- Token stuffing attacks (context window exhaustion) - AIML020
- Recursive prompt injection (prompts containing prompts) - AIML021
- Base64 encoded injection attempts - AIML022
- ROT13/Caesar cipher obfuscation - AIML023
- Invisible character injection (zero-width spaces) - AIML024
- Right-to-left override attacks (Unicode bidi) - AIML025
- Prompt template literal injection - AIML026
- F-string injection in prompts - AIML027
- Variable substitution attacks - AIML028
- Context window overflow - AIML029
- Attention mechanism manipulation - AIML030
- Model inversion attack vectors
- Training data poisoning risks
- Adversarial input acceptance
- Model extraction vulnerabilities
- AI bias detection in code
- Insecure model serialization (PyTorch, TensorFlow)
- Missing input validation for ML models
- GPU memory leakage
- Federated learning privacy risks

Total Security Checks: 30 (v0.7.0 - AI/ML Security Dominance Plan Phase 1)

References:
- OWASP LLM Top 10 | https://owasp.org/www-project-top-10-for-large-language-model-applications/ | Critical
- NIST AI Risk Management | https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf | High
- CWE-94 (Code Injection) | https://cwe.mitre.org/data/definitions/94.html | Critical
- CWE-502 (Deserialization of Untrusted Data) | https://cwe.mitre.org/data/definitions/502.html | Critical
- CWE-400 (Resource Exhaustion) | https://cwe.mitre.org/data/definitions/400.html | High
- CWE-327 (Broken Cryptographic Algorithm) | https://cwe.mitre.org/data/definitions/327.html | High
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
)


class AIMLSecurityVisitor(ast.NodeVisitor):
    """AST visitor for detecting AI/ML security vulnerabilities."""

    def __init__(self, file_path: Path, code: str):
        self.file_path = file_path
        self.code = code
        self.lines = code.splitlines()
        self.violations: List[RuleViolation] = []
        self.has_llm_framework = False
        self.has_ml_framework = False
        self.has_pytorch = False
        self.has_tensorflow = False
        self.has_transformers = False
        self.model_loads: Set[str] = set()

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Track AI/ML framework imports."""
        if node.module:
            # LLM frameworks
            if any(x in node.module for x in ["openai", "langchain", "llama", "anthropic"]):
                self.has_llm_framework = True
            # ML frameworks
            elif "torch" in node.module or "pytorch" in node.module:
                self.has_pytorch = True
            elif "tensorflow" in node.module or "tf" in node.module:
                self.has_tensorflow = True
            elif "transformers" in node.module or "huggingface" in node.module:
                self.has_transformers = True
            elif any(x in node.module for x in ["sklearn", "keras", "jax"]):
                self.has_ml_framework = True
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        """Track AI/ML framework imports (import statements)."""
        for alias in node.names:
            if any(x in alias.name for x in ["openai", "langchain", "llama", "anthropic"]):
                self.has_llm_framework = True
            elif "torch" in alias.name or "pytorch" in alias.name:
                self.has_pytorch = True
            elif "tensorflow" in alias.name:
                self.has_tensorflow = True
            elif "transformers" in alias.name:
                self.has_transformers = True
            elif any(x in alias.name for x in ["sklearn", "keras", "jax"]):
                self.has_ml_framework = True
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Check for AI/ML security vulnerabilities in function calls."""
        # AIML001: Prompt injection
        self._check_prompt_injection(node)
        
        # AIML011: System prompt override (delimiter injection)
        self._check_system_prompt_override(node)
        
        # AIML012: Unicode/homoglyph injection
        self._check_unicode_injection(node)
        
        # AIML013: Role confusion attacks (DAN mode)
        self._check_role_confusion(node)
        
        # AIML014: Instruction concatenation bypasses
        self._check_instruction_concatenation(node)
        
        # AIML015: Multi-language prompt injection
        self._check_multilanguage_injection(node)
        
        # AIML016: Markdown injection in prompts
        self._check_markdown_injection(node)
        
        # AIML017: XML/JSON payload injection
        self._check_payload_injection(node)
        
        # AIML018: SQL-style comment injection
        self._check_sql_comment_injection(node)
        
        # AIML019: Escape sequence injection
        self._check_escape_sequence_injection(node)
        
        # AIML020: Token stuffing attacks
        self._check_token_stuffing(node)
        
        # AIML021: Recursive prompt injection
        self._check_recursive_prompt_injection(node)
        
        # AIML022: Base64 encoded injection
        self._check_base64_injection(node)
        
        # AIML023: ROT13/Caesar cipher obfuscation
        self._check_rot13_obfuscation(node)
        
        # AIML024: Invisible character injection (zero-width spaces)
        self._check_invisible_char_injection(node)
        
        # AIML025: Right-to-left override attacks (Unicode bidi)
        self._check_bidi_override(node)
        
        # AIML026: Prompt template literal injection
        self._check_template_literal_injection(node)
        
        # AIML027: F-string injection in prompts
        self._check_fstring_injection(node)
        
        # AIML028: Variable substitution attacks
        self._check_variable_substitution(node)
        
        # AIML029: Context window overflow
        self._check_context_window_overflow(node)
        
        # AIML030: Attention mechanism manipulation
        self._check_attention_manipulation(node)
        
        # AIML007: Insecure model serialization
        self._check_insecure_serialization(node)
        
        # AIML008: Missing input validation
        self._check_missing_input_validation(node)
        
        # AIML009: GPU memory leakage
        self._check_gpu_memory_leakage(node)
        
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        """Check for AI/ML security issues in assignments."""
        # AIML001: Check for prompt injection in assignments (f-strings, .format())
        if self.has_llm_framework:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    var_name = target.id
                    # Check if this looks like a prompt variable
                    if "prompt" in var_name.lower() or "message" in var_name.lower() or "text" in var_name.lower() or "query" in var_name.lower() or "content" in var_name.lower() or "msg" in var_name.lower() or "input" in var_name.lower() or "user" in var_name.lower():
                        # Check if using f-string
                        if isinstance(node.value, ast.JoinedStr):
                            self.violations.append(
                                RuleViolation(
                                    rule_id="AIML001",
                                    category=RuleCategory.SECURITY,
                                    severity=RuleSeverity.CRITICAL,
                                    message="Potential prompt injection: F-string used for LLM prompt with user input",
                                    line_number=node.lineno,
                                    column=node.col_offset,
                                    end_line_number=getattr(node, "end_lineno", node.lineno),
                                    end_column=getattr(node, "end_col_offset", node.col_offset),
                                    file_path=str(self.file_path),
                                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                                    fix_applicability=FixApplicability.SAFE,
                                    fix_data=None,
                                    owasp_id="LLM01",
                                    cwe_id="CWE-94",
                                    source_tool="pyguard",
                                )
                            )
                        # Check if using .format()
                        elif isinstance(node.value, ast.Call):
                            if isinstance(node.value.func, ast.Attribute):
                                if node.value.func.attr == "format":
                                    self.violations.append(
                                        RuleViolation(
                                            rule_id="AIML001",
                                            category=RuleCategory.SECURITY,
                                            severity=RuleSeverity.CRITICAL,
                                            message="Potential prompt injection: .format() used for LLM prompt with user input",
                                            line_number=node.lineno,
                                            column=node.col_offset,
                                            end_line_number=getattr(node, "end_lineno", node.lineno),
                                            end_column=getattr(node, "end_col_offset", node.col_offset),
                                            file_path=str(self.file_path),
                                            code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                                            fix_applicability=FixApplicability.SAFE,
                                            fix_data=None,
                                            owasp_id="LLM01",
                                            cwe_id="CWE-94",
                                            source_tool="pyguard",
                                        )
                                    )
                        # AIML011-AIML022: Check for various prompt injection patterns in string constants
                        elif isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                            self._check_string_for_prompt_override(node.value.value, node)
                            self._check_string_for_unicode_injection(node.value.value, node)
                            self._check_string_for_role_confusion(node.value.value, node)
                            self._check_string_for_instruction_concatenation(node.value.value, node)
                            self._check_string_for_multilanguage_injection(node.value.value, node)
                            self._check_string_for_markdown_injection(node.value.value, node)
                            self._check_string_for_payload_injection(node.value.value, node)
                            self._check_string_for_sql_comment_injection(node.value.value, node)
                            self._check_string_for_escape_sequence_injection(node.value.value, node)
                            self._check_string_for_token_stuffing(node.value.value, node)
                            self._check_string_for_recursive_prompt_injection(node.value.value, node)
                            self._check_string_for_base64_injection(node.value.value, node)
                            self._check_string_for_rot13_obfuscation(node.value.value, node)
                            self._check_string_for_invisible_char_injection(node.value.value, node)
                            self._check_string_for_bidi_override(node.value.value, node)
                            self._check_string_for_template_literal_injection(node.value.value, node)
                            self._check_string_for_variable_substitution(node.value.value, node)
                            self._check_string_for_context_window_overflow(node.value.value, node)
                            self._check_string_for_attention_manipulation(node.value.value, node)
        
        # AIML002: Model inversion risks
        self._check_model_inversion(node)
        
        # AIML003: Training data poisoning
        self._check_training_data_poisoning(node)
        
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Check function definitions for AI/ML security issues."""
        # AIML005: Model extraction vulnerabilities
        self._check_model_extraction(node)
        
        # AIML006: AI bias detection
        self._check_ai_bias(node)
        
        # AIML010: Federated learning privacy
        self._check_federated_learning(node)
        
        self.generic_visit(node)

    def _check_prompt_injection(self, node: ast.Call) -> None:
        """AIML001: Detect prompt injection vulnerabilities in LLM applications."""
        if not self.has_llm_framework:
            return
            
        # Check for string formatting with user input in prompts
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in ["create", "complete", "generate", "chat"]:
                for arg in node.args:
                    if self._contains_user_input(arg):
                        violation = RuleViolation(
                            rule_id="AIML001",
                            category=RuleCategory.SECURITY,
                            severity=RuleSeverity.CRITICAL,
                            message="Potential prompt injection: User input concatenated directly into LLM prompt",
                            line_number=node.lineno,
                            column=node.col_offset,
                            end_line_number=getattr(node, "end_lineno", node.lineno),
                            end_column=getattr(node, "end_col_offset", node.col_offset),
                            file_path=str(self.file_path),
                            code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                            fix_applicability=FixApplicability.SAFE,
                            fix_data=None,
                            owasp_id="LLM01",
                            cwe_id="CWE-94",
                            source_tool="pyguard",
                        )
                        self.violations.append(violation)
    
    def _check_system_prompt_override(self, node: ast.Call) -> None:
        """AIML011: Detect system prompt override attempts (delimiter injection)."""
        if not self.has_llm_framework:
            return
        
        # Check for dangerous delimiter patterns in function call arguments
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                self._check_string_for_prompt_override(arg.value, node)
                    
        # Also check for delimiter injection in keyword arguments
        for keyword in node.keywords:
            if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                self._check_string_for_prompt_override(keyword.value.value, node)
    
    def _check_string_for_prompt_override(self, text: str, node: ast.AST) -> None:
        """Helper to check if a string contains prompt override patterns."""
        if not self.has_llm_framework:
            return
            
        # Check for dangerous delimiter patterns in string literals
        dangerous_patterns = [
            "ignore previous instructions",
            "ignore above",
            "ignore all previous",
            "new system message",
            "system:",
            "assistant:",
            "you are now",
            "forget everything",
            "disregard previous",
        ]
        
        lower_val = text.lower()
        if any(pattern in lower_val for pattern in dangerous_patterns):
            violation = RuleViolation(
                rule_id="AIML011",
                category=RuleCategory.SECURITY,
                severity=RuleSeverity.CRITICAL,
                message="System prompt override attempt detected: delimiter injection pattern",
                line_number=node.lineno,
                column=node.col_offset,
                end_line_number=getattr(node, "end_lineno", node.lineno),
                end_column=getattr(node, "end_col_offset", node.col_offset),
                file_path=str(self.file_path),
                code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                fix_applicability=FixApplicability.SAFE,
                fix_data=None,
                owasp_id="LLM01",
                cwe_id="CWE-94",
                source_tool="pyguard",
            )
            self.violations.append(violation)
            
    def _check_unicode_injection(self, node: ast.Call) -> None:
        """AIML012: Detect Unicode/homoglyph injection in prompts."""
        if not self.has_llm_framework:
            return
        
        # Check function call arguments
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                self._check_string_for_unicode_injection(arg.value, node)
                    
        # Check keyword arguments
        for keyword in node.keywords:
            if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                self._check_string_for_unicode_injection(keyword.value.value, node)
    
    def _check_string_for_unicode_injection(self, text: str, node: ast.AST) -> None:
        """Helper to check if a string contains Unicode injection patterns."""
        if not self.has_llm_framework:
            return
            
        # Check for Unicode/homoglyph patterns
        suspicious_unicode_ranges = [
            (0x200B, 0x200F),  # Zero-width characters
            (0x202A, 0x202E),  # Bi-directional text overrides
            (0xFEFF, 0xFEFF),  # Zero-width no-break space
        ]
        
        def contains_suspicious_unicode(text: str) -> bool:
            """Check if text contains suspicious Unicode characters."""
            for char in text:
                code_point = ord(char)
                for start, end in suspicious_unicode_ranges:
                    if start <= code_point <= end:
                        return True
            return False
        
        if contains_suspicious_unicode(text):
            violation = RuleViolation(
                rule_id="AIML012",
                category=RuleCategory.SECURITY,
                severity=RuleSeverity.HIGH,
                message="Unicode injection detected: suspicious zero-width or bi-directional characters",
                line_number=node.lineno,
                column=node.col_offset,
                end_line_number=getattr(node, "end_lineno", node.lineno),
                end_column=getattr(node, "end_col_offset", node.col_offset),
                file_path=str(self.file_path),
                code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                fix_applicability=FixApplicability.SAFE,
                fix_data=None,
                owasp_id="LLM01",
                cwe_id="CWE-94",
                source_tool="pyguard",
            )
            self.violations.append(violation)
    
    def _check_role_confusion(self, node: ast.Call) -> None:
        """AIML013: Detect role confusion attacks (DAN mode, jailbreaks)."""
        if not self.has_llm_framework:
            return
        
        # Check function call arguments
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                self._check_string_for_role_confusion(arg.value, node)
                    
        # Check keyword arguments
        for keyword in node.keywords:
            if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                self._check_string_for_role_confusion(keyword.value.value, node)
    
    def _check_string_for_role_confusion(self, text: str, node: ast.AST) -> None:
        """Helper to check if a string contains role confusion patterns."""
        if not self.has_llm_framework:
            return
        
        # Role confusion patterns - DAN mode, jailbreaks
        role_confusion_patterns = [
            "dan mode",
            "do anything now",
            "developer mode",
            "jailbreak",
            "unrestricted mode",
            "act as if",
            "pretend you are",
            "simulate being",
            "roleplay as",
            "you are now a",
            "switch to",
            "enable dev mode",
            "unlock",
        ]
        
        lower_text = text.lower()
        if any(pattern in lower_text for pattern in role_confusion_patterns):
            violation = RuleViolation(
                rule_id="AIML013",
                category=RuleCategory.SECURITY,
                severity=RuleSeverity.CRITICAL,
                message="Role confusion attack detected: DAN mode or jailbreak attempt",
                line_number=node.lineno,
                column=node.col_offset,
                end_line_number=getattr(node, "end_lineno", node.lineno),
                end_column=getattr(node, "end_col_offset", node.col_offset),
                file_path=str(self.file_path),
                code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                fix_applicability=FixApplicability.SAFE,
                fix_data=None,
                owasp_id="LLM01",
                cwe_id="CWE-94",
                source_tool="pyguard",
            )
            self.violations.append(violation)
    
    def _check_instruction_concatenation(self, node: ast.Call) -> None:
        """AIML014: Detect instruction concatenation bypasses."""
        if not self.has_llm_framework:
            return
        
        # Check function call arguments
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                self._check_string_for_instruction_concatenation(arg.value, node)
                    
        # Check keyword arguments
        for keyword in node.keywords:
            if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                self._check_string_for_instruction_concatenation(keyword.value.value, node)
    
    def _check_string_for_instruction_concatenation(self, text: str, node: ast.AST) -> None:
        """Helper to check if a string contains instruction concatenation patterns."""
        if not self.has_llm_framework:
            return
        
        # Instruction concatenation patterns - multiple newlines or delimiter sequences
        concatenation_indicators = [
            "\n\n\n",  # Multiple newlines
            "---",     # Delimiter sequence
            "###",     # Markdown header delimiters
            "===",     # Another delimiter
            "***",     # Another delimiter
        ]
        
        # Also check for instruction keywords after delimiters
        instruction_keywords = ["new instruction:", "new task:", "new prompt:", "override:", "update:"]
        
        has_delimiter = any(delimiter in text for delimiter in concatenation_indicators)
        has_instruction = any(keyword in text.lower() for keyword in instruction_keywords)
        
        if has_delimiter and has_instruction:
            violation = RuleViolation(
                rule_id="AIML014",
                category=RuleCategory.SECURITY,
                severity=RuleSeverity.HIGH,
                message="Instruction concatenation bypass detected: delimiter followed by instruction keywords",
                line_number=node.lineno,
                column=node.col_offset,
                end_line_number=getattr(node, "end_lineno", node.lineno),
                end_column=getattr(node, "end_col_offset", node.col_offset),
                file_path=str(self.file_path),
                code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                fix_applicability=FixApplicability.SAFE,
                fix_data=None,
                owasp_id="LLM01",
                cwe_id="CWE-94",
                source_tool="pyguard",
            )
            self.violations.append(violation)
    
    def _check_multilanguage_injection(self, node: ast.Call) -> None:
        """AIML015: Detect multi-language prompt injection (non-English)."""
        if not self.has_llm_framework:
            return
        
        # Check function call arguments
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                self._check_string_for_multilanguage_injection(arg.value, node)
                    
        # Check keyword arguments
        for keyword in node.keywords:
            if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                self._check_string_for_multilanguage_injection(keyword.value.value, node)
    
    def _check_string_for_multilanguage_injection(self, text: str, node: ast.AST) -> None:
        """Helper to check if a string contains multi-language injection patterns."""
        if not self.has_llm_framework:
            return
        
        # Common prompt injection phrases in other languages
        multilang_patterns = [
            # Chinese (Simplified)
            "忽略以上",  # ignore above
            "忽略之前",  # ignore previous
            "新指令",    # new instruction
            # Spanish (case-insensitive)
            ("ignorar instrucciones anteriores", True),
            ("nueva instrucción", True),
            # French (case-insensitive)
            ("ignorer les instructions précédentes", True),
            ("nouvelle instruction", True),
            # German (case-insensitive)
            ("vorherige anweisungen ignorieren", True),
            ("neue anweisung", True),
            # Russian (Cyrillic)
            "игнорировать предыдущие",
            "новая инструкция",
            # Japanese
            "以前の指示を無視",
            "新しい指示",
            # Korean
            "이전 지시 무시",
            "새로운 지시",
        ]
        
        lower_text = text.lower()
        for pattern in multilang_patterns:
            # Handle tuple patterns (pattern, case_insensitive)
            if isinstance(pattern, tuple):
                pattern_text, case_insensitive = pattern
                if case_insensitive:
                    if pattern_text.lower() in lower_text:
                        matched = True
                        break
                else:
                    if pattern_text in text:
                        matched = True
                        break
            else:
                # Direct string match (for non-Latin scripts)
                if pattern in text:
                    matched = True
                    break
        else:
            matched = False
        
        if matched:
            violation = RuleViolation(
                rule_id="AIML015",
                category=RuleCategory.SECURITY,
                severity=RuleSeverity.HIGH,
                message="Multi-language prompt injection detected: non-English prompt manipulation attempt",
                line_number=node.lineno,
                column=node.col_offset,
                end_line_number=getattr(node, "end_lineno", node.lineno),
                end_column=getattr(node, "end_col_offset", node.col_offset),
                file_path=str(self.file_path),
                code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                fix_applicability=FixApplicability.SAFE,
                fix_data=None,
                owasp_id="LLM01",
                cwe_id="CWE-94",
                source_tool="pyguard",
            )
            self.violations.append(violation)
    
    def _check_markdown_injection(self, node: ast.Call) -> None:
        """AIML016: Detect Markdown injection in prompts."""
        if not self.has_llm_framework:
            return
        
        # Check function call arguments
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                self._check_string_for_markdown_injection(arg.value, node)
                    
        # Check keyword arguments
        for keyword in node.keywords:
            if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                self._check_string_for_markdown_injection(keyword.value.value, node)
    
    def _check_string_for_markdown_injection(self, text: str, node: ast.AST) -> None:
        """Helper to check if a string contains Markdown injection patterns."""
        if not self.has_llm_framework:
            return
        
        # Markdown patterns that could be used for injection
        markdown_injection_patterns = [
            "](javascript:",  # Markdown link with javascript protocol
            "](data:",        # Markdown link with data protocol
            "](file:",        # Markdown link with file protocol
            "![",             # Image embedding
            "<script",        # Script tag in markdown
            "<iframe",        # Iframe tag in markdown
            "```javascript",  # JavaScript code block
            "```html",        # HTML code block
        ]
        
        lower_text = text.lower()
        if any(pattern in lower_text for pattern in markdown_injection_patterns):
            violation = RuleViolation(
                rule_id="AIML016",
                category=RuleCategory.SECURITY,
                severity=RuleSeverity.HIGH,
                message="Markdown injection detected: potentially malicious markdown constructs in prompt",
                line_number=node.lineno,
                column=node.col_offset,
                end_line_number=getattr(node, "end_lineno", node.lineno),
                end_column=getattr(node, "end_col_offset", node.col_offset),
                file_path=str(self.file_path),
                code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                fix_applicability=FixApplicability.SAFE,
                fix_data=None,
                owasp_id="LLM01",
                cwe_id="CWE-94",
                source_tool="pyguard",
            )
            self.violations.append(violation)
    
    def _check_payload_injection(self, node: ast.Call) -> None:
        """AIML017: Detect XML/JSON payload injection."""
        if not self.has_llm_framework:
            return
        
        # Check function call arguments
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                self._check_string_for_payload_injection(arg.value, node)
                    
        # Check keyword arguments
        for keyword in node.keywords:
            if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                self._check_string_for_payload_injection(keyword.value.value, node)
    
    def _check_string_for_payload_injection(self, text: str, node: ast.AST) -> None:
        """Helper to check if a string contains XML/JSON payload injection patterns."""
        if not self.has_llm_framework:
            return
        
        # XML/JSON payload injection patterns
        payload_patterns = [
            "<system>",       # XML system tag
            "</system>",      # XML system closing tag
            "<instruction>",  # XML instruction tag
            '"role":',        # JSON role field
            '"system":',      # JSON system field
            '{"role": "system"',  # JSON system role
            "<assistant>",    # XML assistant tag
            '"content":',     # JSON content field
        ]
        
        lower_text = text.lower()
        
        # Count suspicious patterns
        suspicious_count = sum(1 for pattern in payload_patterns if pattern in lower_text)
        
        # Flag if multiple payload indicators present
        if suspicious_count >= 2:
            violation = RuleViolation(
                rule_id="AIML017",
                category=RuleCategory.SECURITY,
                severity=RuleSeverity.HIGH,
                message="XML/JSON payload injection detected: structured payload manipulation in prompt",
                line_number=node.lineno,
                column=node.col_offset,
                end_line_number=getattr(node, "end_lineno", node.lineno),
                end_column=getattr(node, "end_col_offset", node.col_offset),
                file_path=str(self.file_path),
                code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                fix_applicability=FixApplicability.SAFE,
                fix_data=None,
                owasp_id="LLM01",
                cwe_id="CWE-94",
                source_tool="pyguard",
            )
            self.violations.append(violation)
    
    def _check_sql_comment_injection(self, node: ast.Call) -> None:
        """AIML018: Detect SQL-style comment injection in prompts."""
        if not self.has_llm_framework:
            return
        
        # Check function call arguments
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                self._check_string_for_sql_comment_injection(arg.value, node)
                    
        # Check keyword arguments
        for keyword in node.keywords:
            if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                self._check_string_for_sql_comment_injection(keyword.value.value, node)
    
    def _check_string_for_sql_comment_injection(self, text: str, node: ast.AST) -> None:
        """Helper to check if a string contains SQL-style comment injection patterns."""
        if not self.has_llm_framework:
            return
        
        # SQL-style comment patterns used for prompt injection
        sql_comment_patterns = [
            "-- ",          # SQL single-line comment
            "--\n",         # SQL comment with newline
            "--\r",         # SQL comment with carriage return
            "/* ",          # SQL multi-line comment start
            " */",          # SQL multi-line comment end
            "#ignore",      # Hash comment with injection keyword
            "-- ignore",    # SQL comment with ignore
            "/* ignore",    # Multi-line comment with ignore
        ]
        
        # Also check for patterns that combine comments with instructions
        has_comment = any(pattern in text for pattern in sql_comment_patterns)
        has_instruction_after_comment = False
        
        if has_comment:
            # Check if there's an instruction keyword after the comment
            instruction_keywords = ["ignore", "bypass", "override", "new", "system", "admin"]
            lower_text = text.lower()
            has_instruction_after_comment = any(keyword in lower_text for keyword in instruction_keywords)
        
        if has_comment and has_instruction_after_comment:
            violation = RuleViolation(
                rule_id="AIML018",
                category=RuleCategory.SECURITY,
                severity=RuleSeverity.HIGH,
                message="SQL-style comment injection detected: comment syntax used for prompt manipulation",
                line_number=node.lineno,
                column=node.col_offset,
                end_line_number=getattr(node, "end_lineno", node.lineno),
                end_column=getattr(node, "end_col_offset", node.col_offset),
                file_path=str(self.file_path),
                code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                fix_applicability=FixApplicability.SAFE,
                fix_data=None,
                owasp_id="LLM01",
                cwe_id="CWE-94",
                source_tool="pyguard",
            )
            self.violations.append(violation)
    
    def _check_escape_sequence_injection(self, node: ast.Call) -> None:
        """AIML019: Detect escape sequence injection in prompts."""
        if not self.has_llm_framework:
            return
        
        # Check function call arguments
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                self._check_string_for_escape_sequence_injection(arg.value, node)
                    
        # Check keyword arguments
        for keyword in node.keywords:
            if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                self._check_string_for_escape_sequence_injection(keyword.value.value, node)
    
    def _check_string_for_escape_sequence_injection(self, text: str, node: ast.AST) -> None:
        """Helper to check if a string contains escape sequence injection patterns."""
        if not self.has_llm_framework:
            return
        
        # Escape sequence patterns that could be used for injection
        # Looking for patterns like actual newlines (Python has already processed escape sequences)
        # Check for multiple consecutive newlines
        has_multiple_newlines = "\n\n\n" in text
        has_multiple_crlf = "\r\n\r\n" in text
        has_null_byte = "\x00" in text
        has_escape_char = "\x1b" in text or "\033" in text
        
        # Count suspicious patterns
        suspicious_count = sum([
            has_multiple_newlines,
            has_multiple_crlf,
            has_null_byte,
            has_escape_char
        ])
        
        # Also check for these patterns followed by instruction keywords
        has_escape_with_instruction = False
        if suspicious_count > 0:
            instruction_keywords = ["new", "system", "ignore", "override", "instruction"]
            lower_text = text.lower()
            has_escape_with_instruction = any(keyword in lower_text for keyword in instruction_keywords)
        
        if suspicious_count >= 1 and has_escape_with_instruction:
            violation = RuleViolation(
                rule_id="AIML019",
                category=RuleCategory.SECURITY,
                severity=RuleSeverity.HIGH,
                message="Escape sequence injection detected: suspicious escape sequences in prompt",
                line_number=node.lineno,
                column=node.col_offset,
                end_line_number=getattr(node, "end_lineno", node.lineno),
                end_column=getattr(node, "end_col_offset", node.col_offset),
                file_path=str(self.file_path),
                code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                fix_applicability=FixApplicability.SAFE,
                fix_data=None,
                owasp_id="LLM01",
                cwe_id="CWE-94",
                source_tool="pyguard",
            )
            self.violations.append(violation)
    
    def _check_token_stuffing(self, node: ast.Call) -> None:
        """AIML020: Detect token stuffing attacks (context window exhaustion)."""
        if not self.has_llm_framework:
            return
        
        # Check function call arguments for very long strings
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                self._check_string_for_token_stuffing(arg.value, node)
                    
        # Check keyword arguments
        for keyword in node.keywords:
            if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                self._check_string_for_token_stuffing(keyword.value.value, node)
    
    def _check_string_for_token_stuffing(self, text: str, node: ast.AST) -> None:
        """Helper to check if a string is attempting token stuffing."""
        if not self.has_llm_framework:
            return
        
        # Token stuffing indicators:
        # 1. Very long strings (>8000 chars is suspicious)
        # 2. Highly repetitive content
        text_length = len(text)
        
        if text_length > 8000:
            # Check for repetitiveness (same pattern repeated many times)
            # Simple heuristic: if the first 100 chars appear multiple times, it's repetitive
            if text_length > 200:
                sample = text[:100]
                occurrences = text.count(sample)
                if occurrences > 10:  # Very repetitive
                    violation = RuleViolation(
                        rule_id="AIML020",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.MEDIUM,
                        message=f"Token stuffing attack detected: very long ({text_length} chars) repetitive prompt",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.SAFE,
                        fix_data=None,
                        owasp_id="LLM01",
                        cwe_id="CWE-400",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)
    
    def _check_recursive_prompt_injection(self, node: ast.Call) -> None:
        """AIML021: Detect recursive prompt injection (prompts containing prompts)."""
        if not self.has_llm_framework:
            return
        
        # Check function call arguments
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                self._check_string_for_recursive_prompt_injection(arg.value, node)
                    
        # Check keyword arguments
        for keyword in node.keywords:
            if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                self._check_string_for_recursive_prompt_injection(keyword.value.value, node)
    
    def _check_string_for_recursive_prompt_injection(self, text: str, node: ast.AST) -> None:
        """Helper to check if a string contains recursive prompt injection patterns."""
        if not self.has_llm_framework:
            return
        
        # Recursive prompt injection patterns - prompts within prompts
        recursive_patterns = [
            "prompt:",
            "user:",
            "assistant:",
            "system:",
            "generate a prompt",
            "create a prompt",
            "write a prompt",
            "respond to:",
            "answer:",
        ]
        
        lower_text = text.lower()
        pattern_count = sum(1 for pattern in recursive_patterns if pattern in lower_text)
        
        # If multiple prompt-related keywords, likely recursive
        if pattern_count >= 2:
            violation = RuleViolation(
                rule_id="AIML021",
                category=RuleCategory.SECURITY,
                severity=RuleSeverity.MEDIUM,
                message="Recursive prompt injection detected: prompt contains nested prompt instructions",
                line_number=node.lineno,
                column=node.col_offset,
                end_line_number=getattr(node, "end_lineno", node.lineno),
                end_column=getattr(node, "end_col_offset", node.col_offset),
                file_path=str(self.file_path),
                code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                fix_applicability=FixApplicability.SAFE,
                fix_data=None,
                owasp_id="LLM01",
                cwe_id="CWE-94",
                source_tool="pyguard",
            )
            self.violations.append(violation)
    
    def _check_base64_injection(self, node: ast.Call) -> None:
        """AIML022: Detect Base64 encoded injection attempts."""
        if not self.has_llm_framework:
            return
        
        # Check function call arguments
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                self._check_string_for_base64_injection(arg.value, node)
                    
        # Check keyword arguments
        for keyword in node.keywords:
            if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                self._check_string_for_base64_injection(keyword.value.value, node)
    
    def _check_string_for_base64_injection(self, text: str, node: ast.AST) -> None:
        """Helper to check if a string contains Base64 encoded injection attempts."""
        if not self.has_llm_framework:
            return
        
        # Base64 pattern detection
        # Look for Base64-like strings (alphanumeric + / and + with = padding)
        import re
        base64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
        matches = re.findall(base64_pattern, text)
        
        if matches:
            # Try to decode and check for malicious patterns
            try:
                import base64
                for match in matches:
                    try:
                        decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
                        # Check if decoded text contains injection keywords
                        malicious_keywords = ["ignore", "system", "bypass", "override", "admin", "jailbreak"]
                        if any(keyword in decoded.lower() for keyword in malicious_keywords):
                            violation = RuleViolation(
                                rule_id="AIML022",
                                category=RuleCategory.SECURITY,
                                severity=RuleSeverity.HIGH,
                                message="Base64 encoded injection detected: encoded malicious content in prompt",
                                line_number=node.lineno,
                                column=node.col_offset,
                                end_line_number=getattr(node, "end_lineno", node.lineno),
                                end_column=getattr(node, "end_col_offset", node.col_offset),
                                file_path=str(self.file_path),
                                code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                                fix_applicability=FixApplicability.SAFE,
                                fix_data=None,
                                owasp_id="LLM01",
                                cwe_id="CWE-94",
                                source_tool="pyguard",
                            )
                            self.violations.append(violation)
                            break
                    except Exception:
                        # Invalid Base64, skip
                        continue
            except ImportError:
                # base64 module not available, skip
                pass

    def _check_rot13_obfuscation(self, node: ast.Call) -> None:
        """AIML023: Detect ROT13/Caesar cipher obfuscation in prompts."""
        if not self.has_llm_framework:
            return
        
        # Check function call arguments
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                self._check_string_for_rot13_obfuscation(arg.value, node)
                    
        # Check keyword arguments
        for keyword in node.keywords:
            if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                self._check_string_for_rot13_obfuscation(keyword.value.value, node)
    
    def _check_string_for_rot13_obfuscation(self, text: str, node: ast.AST) -> None:
        """Helper to check if a string contains ROT13 or Caesar cipher obfuscation."""
        if not self.has_llm_framework:
            return
        
        # Check for ROT13 encoded text by looking for patterns
        # ROT13 characteristic: high concentration of unusual letter patterns
        # Simple heuristic: check if decoding with ROT13 produces more common English words
        import codecs
        try:
            # Try ROT13 decode
            decoded = codecs.decode(text, 'rot_13')
            
            # Check if decoded text contains malicious keywords
            malicious_keywords = ["ignore", "system", "bypass", "override", "admin", "jailbreak", "instruction"]
            lower_decoded = decoded.lower()
            
            # Also check original text doesn't contain these keywords (to avoid false positives)
            lower_text = text.lower()
            has_keywords_in_decoded = any(keyword in lower_decoded for keyword in malicious_keywords)
            has_keywords_in_original = any(keyword in lower_text for keyword in malicious_keywords)
            
            # If decoded has keywords but original doesn't, likely ROT13 obfuscation
            if has_keywords_in_decoded and not has_keywords_in_original and len(text) > 10:
                violation = RuleViolation(
                    rule_id="AIML023",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.HIGH,
                    message="ROT13/Caesar cipher obfuscation detected: encoded malicious content in prompt",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="LLM01",
                    cwe_id="CWE-94",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
        except Exception:
            # ROT13 decode failed, skip
            pass
    
    def _check_invisible_char_injection(self, node: ast.Call) -> None:
        """AIML024: Detect invisible character injection (zero-width spaces)."""
        if not self.has_llm_framework:
            return
        
        # Check function call arguments
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                self._check_string_for_invisible_char_injection(arg.value, node)
                    
        # Check keyword arguments
        for keyword in node.keywords:
            if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                self._check_string_for_invisible_char_injection(keyword.value.value, node)
    
    def _check_string_for_invisible_char_injection(self, text: str, node: ast.AST) -> None:
        """Helper to check if a string contains invisible character injection."""
        if not self.has_llm_framework:
            return
        
        # Invisible/zero-width characters that can be used for injection
        invisible_chars = [
            '\u200b',  # Zero-width space
            '\u200c',  # Zero-width non-joiner
            '\u200d',  # Zero-width joiner
            '\u2060',  # Word joiner
            '\ufeff',  # Zero-width no-break space (BOM)
            '\u180e',  # Mongolian vowel separator
            '\u00ad',  # Soft hyphen
        ]
        
        # Count invisible characters
        invisible_count = sum(text.count(char) for char in invisible_chars)
        
        if invisible_count > 0:
            # Check if there are also instruction keywords (suggests malicious intent)
            malicious_keywords = ["ignore", "system", "bypass", "override", "instruction"]
            has_keywords = any(keyword in text.lower() for keyword in malicious_keywords)
            
            if has_keywords or invisible_count >= 3:
                violation = RuleViolation(
                    rule_id="AIML024",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.HIGH,
                    message=f"Invisible character injection detected: {invisible_count} zero-width characters in prompt",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="LLM01",
                    cwe_id="CWE-94",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_bidi_override(self, node: ast.Call) -> None:
        """AIML025: Detect right-to-left override attacks (Unicode bidi)."""
        if not self.has_llm_framework:
            return
        
        # Check function call arguments
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                self._check_string_for_bidi_override(arg.value, node)
                    
        # Check keyword arguments
        for keyword in node.keywords:
            if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                self._check_string_for_bidi_override(keyword.value.value, node)
    
    def _check_string_for_bidi_override(self, text: str, node: ast.AST) -> None:
        """Helper to check if a string contains Unicode bidi override attacks."""
        if not self.has_llm_framework:
            return
        
        # Unicode bidirectional text control characters
        bidi_chars = [
            '\u202a',  # Left-to-right embedding
            '\u202b',  # Right-to-left embedding
            '\u202c',  # Pop directional formatting
            '\u202d',  # Left-to-right override
            '\u202e',  # Right-to-left override
            '\u2066',  # Left-to-right isolate
            '\u2067',  # Right-to-left isolate
            '\u2068',  # First strong isolate
            '\u2069',  # Pop directional isolate
        ]
        
        # Count bidi control characters
        bidi_count = sum(text.count(char) for char in bidi_chars)
        
        if bidi_count > 0:
            violation = RuleViolation(
                rule_id="AIML025",
                category=RuleCategory.SECURITY,
                severity=RuleSeverity.HIGH,
                message=f"Unicode bidirectional override detected: {bidi_count} bidi control characters in prompt",
                line_number=node.lineno,
                column=node.col_offset,
                end_line_number=getattr(node, "end_lineno", node.lineno),
                end_column=getattr(node, "end_col_offset", node.col_offset),
                file_path=str(self.file_path),
                code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                fix_applicability=FixApplicability.SAFE,
                fix_data=None,
                owasp_id="LLM01",
                cwe_id="CWE-94",
                source_tool="pyguard",
            )
            self.violations.append(violation)
    
    def _check_template_literal_injection(self, node: ast.Call) -> None:
        """AIML026: Detect prompt template literal injection."""
        if not self.has_llm_framework:
            return
        
        # Check function call arguments
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                self._check_string_for_template_literal_injection(arg.value, node)
                    
        # Check keyword arguments
        for keyword in node.keywords:
            if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                self._check_string_for_template_literal_injection(keyword.value.value, node)
    
    def _check_string_for_template_literal_injection(self, text: str, node: ast.AST) -> None:
        """Helper to check if a string contains template literal injection patterns."""
        if not self.has_llm_framework:
            return
        
        # Template literal injection patterns
        template_patterns = [
            "${",          # JavaScript template literal
            "{{",          # Jinja2/Handlebars template
            "{%",          # Jinja2 control
            "<%",          # ERB/EJS template
            "[[",          # Custom template syntax
            "<<",          # Heredoc-style templates
        ]
        
        # Check for template patterns
        has_template = any(pattern in text for pattern in template_patterns)
        
        if has_template:
            # Check if there are also injection keywords
            injection_keywords = ["eval", "exec", "import", "system", "process", "require"]
            has_injection = any(keyword in text.lower() for keyword in injection_keywords)
            
            if has_injection:
                violation = RuleViolation(
                    rule_id="AIML026",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.HIGH,
                    message="Template literal injection detected: template syntax with dangerous code execution patterns",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="LLM01",
                    cwe_id="CWE-94",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_fstring_injection(self, node: ast.Call) -> None:
        """AIML027: Detect F-string injection in prompts."""
        if not self.has_llm_framework:
            return
        
        # Check for f-string usage in arguments
        for arg in node.args:
            if isinstance(arg, ast.JoinedStr):
                # This is an f-string
                violation = RuleViolation(
                    rule_id="AIML027",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.HIGH,
                    message="F-string injection in prompt: unvalidated user input in f-string can lead to injection",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="LLM01",
                    cwe_id="CWE-94",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
        
        # Check keyword arguments
        for keyword in node.keywords:
            if isinstance(keyword.value, ast.JoinedStr):
                violation = RuleViolation(
                    rule_id="AIML027",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.HIGH,
                    message="F-string injection in prompt: unvalidated user input in f-string can lead to injection",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="LLM01",
                    cwe_id="CWE-94",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_variable_substitution(self, node: ast.Call) -> None:
        """AIML028: Detect variable substitution attacks."""
        if not self.has_llm_framework:
            return
        
        # Check function call arguments
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                self._check_string_for_variable_substitution(arg.value, node)
                    
        # Check keyword arguments
        for keyword in node.keywords:
            if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                self._check_string_for_variable_substitution(keyword.value.value, node)
    
    def _check_string_for_variable_substitution(self, text: str, node: ast.AST) -> None:
        """Helper to check if a string contains variable substitution attacks."""
        if not self.has_llm_framework:
            return
        
        # Variable substitution patterns that could be exploited
        substitution_patterns = [
            "$(",          # Shell command substitution
            "`",           # Backtick command substitution
            "${env:",      # Environment variable access
            "${var:",      # Variable interpolation
            "$(whoami)",   # Common attack pattern
            "${PATH}",     # Environment variable
            "$USER",       # Environment variable
        ]
        
        # Check for substitution patterns
        has_substitution = any(pattern in text for pattern in substitution_patterns)
        
        if has_substitution:
            violation = RuleViolation(
                rule_id="AIML028",
                category=RuleCategory.SECURITY,
                severity=RuleSeverity.HIGH,
                message="Variable substitution attack detected: shell/environment variable substitution in prompt",
                line_number=node.lineno,
                column=node.col_offset,
                end_line_number=getattr(node, "end_lineno", node.lineno),
                end_column=getattr(node, "end_col_offset", node.col_offset),
                file_path=str(self.file_path),
                code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                fix_applicability=FixApplicability.SAFE,
                fix_data=None,
                owasp_id="LLM01",
                cwe_id="CWE-94",
                source_tool="pyguard",
            )
            self.violations.append(violation)
    
    def _check_context_window_overflow(self, node: ast.Call) -> None:
        """AIML029: Detect context window overflow attempts."""
        if not self.has_llm_framework:
            return
        
        # Check function call arguments
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                self._check_string_for_context_window_overflow(arg.value, node)
                    
        # Check keyword arguments
        for keyword in node.keywords:
            if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                self._check_string_for_context_window_overflow(keyword.value.value, node)
    
    def _check_string_for_context_window_overflow(self, text: str, node: ast.AST) -> None:
        """Helper to check if a string attempts context window overflow."""
        if not self.has_llm_framework:
            return
        
        # Context window overflow indicators:
        # 1. Extremely long text (>32000 chars is suspicious for most LLMs)
        # 2. Repetitive patterns designed to fill context
        text_length = len(text)
        
        if text_length > 32000:
            violation = RuleViolation(
                rule_id="AIML029",
                category=RuleCategory.SECURITY,
                severity=RuleSeverity.MEDIUM,
                message=f"Context window overflow detected: extremely long prompt ({text_length} chars)",
                line_number=node.lineno,
                column=node.col_offset,
                end_line_number=getattr(node, "end_lineno", node.lineno),
                end_column=getattr(node, "end_col_offset", node.col_offset),
                file_path=str(self.file_path),
                code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                fix_applicability=FixApplicability.SAFE,
                fix_data=None,
                owasp_id="LLM01",
                cwe_id="CWE-400",
                source_tool="pyguard",
            )
            self.violations.append(violation)
    
    def _check_attention_manipulation(self, node: ast.Call) -> None:
        """AIML030: Detect attention mechanism manipulation attempts."""
        if not self.has_llm_framework:
            return
        
        # Check function call arguments
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                self._check_string_for_attention_manipulation(arg.value, node)
                    
        # Check keyword arguments
        for keyword in node.keywords:
            if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                self._check_string_for_attention_manipulation(keyword.value.value, node)
    
    def _check_string_for_attention_manipulation(self, text: str, node: ast.AST) -> None:
        """Helper to check if a string attempts to manipulate attention mechanisms."""
        if not self.has_llm_framework:
            return
        
        # Attention manipulation patterns
        attention_patterns = [
            "pay attention to",
            "focus on",
            "most important",
            "critical:",
            "priority:",
            "emphasis:",
            "highlight:",
            "**important**",
            "!!!",
            "URGENT",
            "CRITICAL",
        ]
        
        # Check for attention manipulation combined with instruction changes
        has_attention = any(pattern in text.lower() for pattern in [p.lower() for p in attention_patterns])
        
        if has_attention:
            # Check if combined with instruction keywords
            instruction_keywords = ["ignore", "override", "bypass", "forget", "new instruction", "disregard"]
            has_instruction = any(keyword in text.lower() for keyword in instruction_keywords)
            
            if has_instruction:
                violation = RuleViolation(
                    rule_id="AIML030",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="Attention manipulation detected: emphasis markers combined with instruction override attempts",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="LLM01",
                    cwe_id="CWE-94",
                    source_tool="pyguard",
                )
                self.violations.append(violation)

    def _check_insecure_serialization(self, node: ast.Call) -> None:
        """AIML007: Detect insecure model serialization."""
        if isinstance(node.func, ast.Attribute):
            # PyTorch
            if node.func.attr == "load" and self._is_torch_module(node.func.value):
                # Check if weights_only parameter is missing or False
                has_weights_only = False
                for keyword in node.keywords:
                    if keyword.arg == "weights_only" and self._is_true_literal(keyword.value):
                        has_weights_only = True
                        
                if not has_weights_only:
                    violation = RuleViolation(
                        rule_id="AIML007",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.HIGH,
                        message="Insecure model deserialization: torch.load without weights_only=True",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.SAFE,
                        fix_data=None,
                        owasp_id="LLM03",
                        cwe_id="CWE-502",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)

    def _check_missing_input_validation(self, node: ast.Call) -> None:
        """AIML008: Detect missing input validation for ML models."""
        if not (self.has_ml_framework or self.has_pytorch or self.has_tensorflow):
            return
            
        # Check for model.predict() without validation
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in ["predict", "predict_proba", "forward", "call"]:
                # Check if there's input validation before the call
                if len(node.args) > 0:
                    violation = RuleViolation(
                        rule_id="AIML008",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.MEDIUM,
                        message="Missing input validation before ML model inference",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.MANUAL,
                        fix_data=None,
                        owasp_id="LLM03",
                        cwe_id="CWE-20",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)

    def _check_gpu_memory_leakage(self, node: ast.Call) -> None:
        """AIML009: Detect GPU memory leakage patterns."""
        if not (self.has_pytorch or self.has_tensorflow):
            return
            
        # Check for missing .detach() or .cpu() calls with tensors
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in ["cuda", "to"] and self.has_pytorch:
                violation = RuleViolation(
                    rule_id="AIML009",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="Potential GPU memory leak: Missing .detach() or .cpu() call",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="LLM04",
                    cwe_id="CWE-400",
                    source_tool="pyguard",
                )
                self.violations.append(violation)

    def _check_model_inversion(self, node: ast.Assign) -> None:
        """AIML002: Detect model inversion attack vectors."""
        # Check for exposed model parameters
        if isinstance(node.value, ast.Call):
            if isinstance(node.value.func, ast.Attribute):
                if node.value.func.attr in ["parameters", "state_dict", "get_weights"]:
                    violation = RuleViolation(
                        rule_id="AIML002",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.HIGH,
                        message="Model inversion risk: Exposed model parameters may allow attacks",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.MANUAL,
                        fix_data=None,
                        owasp_id="LLM02",
                        cwe_id="CWE-200",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)

    def _check_training_data_poisoning(self, node: ast.Assign) -> None:
        """AIML003: Detect training data poisoning risks."""
        # Check for data loading without validation
        if isinstance(node.value, ast.Call):
            func_name = None
            # Check for function calls like dataset.load() or module.load_dataset()
            if isinstance(node.value.func, ast.Attribute):
                func_name = node.value.func.attr
            # Check for function calls like load_dataset()
            elif isinstance(node.value.func, ast.Name):
                func_name = node.value.func.id
                
            if func_name and func_name in ["load_dataset", "read_csv", "load_from_disk", "load_data"]:
                violation = RuleViolation(
                    rule_id="AIML003",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.HIGH,
                    message="Training data poisoning risk: Unvalidated data source",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="LLM03",
                    cwe_id="CWE-20",
                    source_tool="pyguard",
                )
                self.violations.append(violation)

    def _check_model_extraction(self, node: ast.FunctionDef) -> None:
        """AIML005: Detect model extraction vulnerabilities."""
        # Check if function returns model predictions without rate limiting
        if "api" in node.name.lower() or "endpoint" in node.name.lower():
            # Look for predict/inference calls in function
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    if isinstance(child.func, ast.Attribute):
                        if child.func.attr in ["predict", "predict_proba", "forward"]:
                            violation = RuleViolation(
                                rule_id="AIML005",
                                category=RuleCategory.SECURITY,
                                severity=RuleSeverity.HIGH,
                                message="Model extraction risk: API endpoint exposes model predictions without rate limiting",
                                line_number=node.lineno,
                                column=node.col_offset,
                                end_line_number=getattr(node, "end_lineno", node.lineno),
                                end_column=getattr(node, "end_col_offset", node.col_offset),
                                file_path=str(self.file_path),
                                code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                                fix_applicability=FixApplicability.MANUAL,
                                fix_data=None,
                                owasp_id="LLM09",
                                cwe_id="CWE-799",
                                source_tool="pyguard",
                            )
                            self.violations.append(violation)
                            break

    def _check_ai_bias(self, node: ast.FunctionDef) -> None:
        """AIML006: Detect potential AI bias in code."""
        # Check for training or prediction functions without fairness checks
        if any(keyword in node.name.lower() for keyword in ["train", "fit", "predict"]):
            has_fairness_check = False
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    if isinstance(child.func, ast.Attribute):
                        if any(x in child.func.attr.lower() for x in ["fairness", "bias", "demographic"]):
                            has_fairness_check = True
                            break
                            
            if not has_fairness_check and len(node.body) > 5:  # Only check substantial functions
                violation = RuleViolation(
                    rule_id="AIML006",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.LOW,
                    message="AI bias risk: ML pipeline missing fairness/bias checks",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.NONE,
                    fix_data=None,
                    owasp_id="LLM10",
                    cwe_id="CWE-1321",
                    source_tool="pyguard",
                )
                self.violations.append(violation)

    def _check_federated_learning(self, node: ast.FunctionDef) -> None:
        """AIML010: Detect federated learning privacy risks."""
        # Check for federated learning patterns without differential privacy
        if any(keyword in node.name.lower() for keyword in ["federated", "distributed", "aggregate"]):
            has_privacy = False
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    func_name = None
                    # Check for method calls (object.method())
                    if isinstance(child.func, ast.Attribute):
                        func_name = child.func.attr
                    # Check for function calls (function())
                    elif isinstance(child.func, ast.Name):
                        func_name = child.func.id
                    
                    if func_name and any(x in func_name.lower() for x in ["differential", "privacy", "noise", "clip"]):
                        has_privacy = True
                        break
                            
            if not has_privacy:
                violation = RuleViolation(
                    rule_id="AIML010",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.HIGH,
                    message="Federated learning privacy risk: Missing differential privacy or noise addition",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.NONE,
                    fix_data=None,
                    owasp_id="LLM06",
                    cwe_id="CWE-359",
                    source_tool="pyguard",
                )
                self.violations.append(violation)

    # Helper methods
    
    def _contains_user_input(self, node: ast.expr) -> bool:
        """Check if expression contains user input (simplified)."""
        if isinstance(node, ast.JoinedStr):  # f-string
            return True
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):  # string concatenation
            return True
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                if node.func.attr == "format":
                    return True
        return False

    def _is_torch_module(self, node: ast.expr) -> bool:
        """Check if node is a torch module."""
        if isinstance(node, ast.Name):
            return node.id == "torch"
        if isinstance(node, ast.Attribute):
            return "torch" in ast.unparse(node)
        return False

    def _is_true_literal(self, node: ast.expr) -> bool:
        """Check if node is a True literal."""
        return isinstance(node, ast.Constant) and node.value is True


def analyze_ai_ml_security(file_path: Path, code: str) -> List[RuleViolation]:
    """
    Analyze AI/ML security vulnerabilities in Python code.
    
    Args:
        file_path: Path to the file being analyzed
        code: Source code to analyze
        
    Returns:
        List of security violations found
    """
    try:
        tree = ast.parse(code)
        visitor = AIMLSecurityVisitor(file_path, code)
        visitor.visit(tree)
        return visitor.violations
    except SyntaxError:
        return []


# Define AI/ML security rules
AIML_SECURITY_RULES = [
    Rule(
        rule_id="AIML001",
        name="prompt-injection",
        description="Detects potential prompt injection vulnerabilities in LLM applications",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.CRITICAL,
        message_template="Prompt injection risk: User input concatenated directly into LLM prompt",
        explanation="User input concatenated directly into LLM prompts can allow attackers to manipulate the model's behavior",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-94",
        owasp_mapping="LLM01",
        tags={"ai", "llm", "injection", "security"},
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    Rule(
        rule_id="AIML002",
        name="model-inversion",
        description="Detects exposure of model parameters that could enable inversion attacks",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        message_template="Model inversion risk: Exposed model parameters may allow attacks",
        explanation="Exposing model parameters allows attackers to reverse-engineer training data",
        fix_applicability=FixApplicability.MANUAL,
        cwe_mapping="CWE-200",
        owasp_mapping="LLM02",
        tags={"ai", "ml", "privacy", "security"},
        references=["https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf"],
    ),
    Rule(
        rule_id="AIML003",
        name="training-data-poisoning",
        description="Detects unvalidated training data sources that could be poisoned",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        message_template="Training data poisoning risk: Unvalidated data source",
        explanation="Loading training data without validation can allow attackers to poison the model",
        fix_applicability=FixApplicability.MANUAL,
        cwe_mapping="CWE-20",
        owasp_mapping="LLM03",
        tags={"ai", "ml", "training", "security"},
        references=["https://owasp.org/www-project-machine-learning-security/"],
    ),
    Rule(
        rule_id="AIML004",
        name="adversarial-input",
        description="Detects missing adversarial robustness checks",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.MEDIUM,
        message_template="Adversarial input risk: Missing robustness checks",
        explanation="Models without adversarial robustness can be fooled by crafted inputs",
        fix_applicability=FixApplicability.NONE,
        cwe_mapping="CWE-20",
        owasp_mapping="LLM03",
        tags={"ai", "ml", "robustness", "security"},
        references=["https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf"],
    ),
    Rule(
        rule_id="AIML005",
        name="model-extraction",
        description="Detects API endpoints that could enable model extraction attacks",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        message_template="Model extraction risk: API endpoint exposes model predictions without rate limiting",
        explanation="Unrestricted access to model predictions can allow attackers to steal the model",
        fix_applicability=FixApplicability.MANUAL,
        cwe_mapping="CWE-799",
        owasp_mapping="LLM09",
        tags={"ai", "ml", "api", "security"},
        references=["https://owasp.org/www-project-machine-learning-security/"],
    ),
    Rule(
        rule_id="AIML006",
        name="ai-bias",
        description="Detects ML pipelines missing fairness and bias checks",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.LOW,
        message_template="AI bias risk: ML pipeline missing fairness/bias checks",
        explanation="ML models without bias checks can perpetuate or amplify discrimination",
        fix_applicability=FixApplicability.NONE,
        cwe_mapping="CWE-1321",
        owasp_mapping="LLM10",
        tags={"ai", "ml", "fairness", "ethics"},
        references=["https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf"],
    ),
    Rule(
        rule_id="AIML007",
        name="insecure-model-serialization",
        description="Detects insecure deserialization of ML models (PyTorch, TensorFlow)",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        message_template="Insecure model deserialization: torch.load without weights_only=True",
        explanation="Loading untrusted model files can execute arbitrary code",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-502",
        owasp_mapping="LLM03",
        tags={"ai", "ml", "serialization", "security"},
        references=["https://pytorch.org/docs/stable/generated/torch.load.html"],
    ),
    Rule(
        rule_id="AIML008",
        name="missing-input-validation",
        description="Detects missing input validation before ML model inference",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.MEDIUM,
        message_template="Missing input validation before ML model inference",
        explanation="ML models should validate inputs to prevent unexpected behavior",
        fix_applicability=FixApplicability.MANUAL,
        cwe_mapping="CWE-20",
        owasp_mapping="LLM03",
        tags={"ai", "ml", "validation", "security"},
        references=["https://owasp.org/www-project-machine-learning-security/"],
    ),
    Rule(
        rule_id="AIML009",
        name="gpu-memory-leak",
        description="Detects potential GPU memory leaks in tensor operations",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.MEDIUM,
        message_template="Potential GPU memory leak: Missing .detach() or .cpu() call",
        explanation="Missing .detach() or .cpu() calls can cause GPU memory exhaustion",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-400",
        owasp_mapping="LLM04",
        tags={"ai", "ml", "gpu", "performance"},
        references=["https://pytorch.org/docs/stable/notes/autograd.html"],
    ),
    Rule(
        rule_id="AIML010",
        name="federated-learning-privacy",
        description="Detects missing privacy-preserving mechanisms in federated learning",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        message_template="Federated learning privacy risk: Missing differential privacy or noise addition",
        explanation="Federated learning without differential privacy can leak sensitive information",
        fix_applicability=FixApplicability.NONE,
        cwe_mapping="CWE-359",
        owasp_mapping="LLM06",
        tags={"ai", "ml", "privacy", "federated"},
        references=["https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf"],
    ),
    Rule(
        rule_id="AIML011",
        name="system-prompt-override",
        description="Detects system prompt override attempts via delimiter injection",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.CRITICAL,
        message_template="System prompt override attempt: delimiter injection pattern detected",
        explanation="Delimiter injection can allow attackers to override system prompts and manipulate LLM behavior",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-94",
        owasp_mapping="LLM01",
        tags={"ai", "llm", "injection", "prompt", "security"},
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    Rule(
        rule_id="AIML012",
        name="unicode-homoglyph-injection",
        description="Detects Unicode/homoglyph injection attempts in LLM prompts",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        message_template="Unicode injection: suspicious zero-width or bi-directional characters detected",
        explanation="Unicode injection using zero-width characters or bi-directional overrides can manipulate LLM behavior invisibly",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-94",
        owasp_mapping="LLM01",
        tags={"ai", "llm", "injection", "unicode", "security"},
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    Rule(
        rule_id="AIML023",
        name="rot13-obfuscation",
        description="Detects ROT13/Caesar cipher obfuscation in LLM prompts",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        message_template="ROT13/Caesar cipher obfuscation detected: encoded malicious content in prompt",
        explanation="ROT13 or Caesar cipher obfuscation can be used to hide malicious instructions from detection",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-94",
        owasp_mapping="LLM01",
        tags={"ai", "llm", "injection", "obfuscation", "security"},
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    Rule(
        rule_id="AIML024",
        name="invisible-char-injection",
        description="Detects invisible character injection (zero-width spaces) in LLM prompts",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        message_template="Invisible character injection detected: zero-width characters in prompt",
        explanation="Zero-width and invisible characters can be used to hide malicious instructions in prompts",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-94",
        owasp_mapping="LLM01",
        tags={"ai", "llm", "injection", "invisible", "security"},
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    Rule(
        rule_id="AIML025",
        name="bidi-override-attack",
        description="Detects Unicode bidirectional override attacks in LLM prompts",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        message_template="Unicode bidirectional override detected: bidi control characters in prompt",
        explanation="Unicode bidirectional text control characters can manipulate text rendering to hide malicious content",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-94",
        owasp_mapping="LLM01",
        tags={"ai", "llm", "injection", "unicode", "bidi", "security"},
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    Rule(
        rule_id="AIML026",
        name="template-literal-injection",
        description="Detects template literal injection in LLM prompts",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        message_template="Template literal injection detected: template syntax with dangerous code execution patterns",
        explanation="Template literal injection can allow code execution through template engines in LLM-generated content",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-94",
        owasp_mapping="LLM01",
        tags={"ai", "llm", "injection", "template", "security"},
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    Rule(
        rule_id="AIML027",
        name="fstring-injection",
        description="Detects F-string injection in LLM prompts",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        message_template="F-string injection in prompt: unvalidated user input in f-string can lead to injection",
        explanation="F-string formatting with unvalidated user input can lead to prompt injection vulnerabilities",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-94",
        owasp_mapping="LLM01",
        tags={"ai", "llm", "injection", "fstring", "security"},
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    Rule(
        rule_id="AIML028",
        name="variable-substitution-attack",
        description="Detects variable substitution attacks in LLM prompts",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        message_template="Variable substitution attack detected: shell/environment variable substitution in prompt",
        explanation="Variable substitution patterns can be exploited to execute commands or access environment variables",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-94",
        owasp_mapping="LLM01",
        tags={"ai", "llm", "injection", "substitution", "security"},
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    Rule(
        rule_id="AIML029",
        name="context-window-overflow",
        description="Detects context window overflow attempts in LLM prompts",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.MEDIUM,
        message_template="Context window overflow detected: extremely long prompt",
        explanation="Extremely long prompts can overflow the context window causing DoS or bypassing security controls",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-400",
        owasp_mapping="LLM01",
        tags={"ai", "llm", "dos", "overflow", "security"},
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    Rule(
        rule_id="AIML030",
        name="attention-manipulation",
        description="Detects attention mechanism manipulation attempts in LLM prompts",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.MEDIUM,
        message_template="Attention manipulation detected: emphasis markers combined with instruction override attempts",
        explanation="Attention manipulation using emphasis markers can be combined with instruction overrides to bypass security",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-94",
        owasp_mapping="LLM01",
        tags={"ai", "llm", "injection", "attention", "security"},
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
]
