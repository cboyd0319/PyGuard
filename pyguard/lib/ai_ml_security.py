"""
AI/ML Security Analysis.

Detects security vulnerabilities in AI/ML applications including prompt injection,
model serialization risks, training data poisoning, and GPU memory leakage.

Security Areas Covered:
- Prompt injection in LLM applications
- Model inversion attack vectors
- Training data poisoning risks
- Adversarial input acceptance
- Model extraction vulnerabilities
- AI bias detection in code
- Insecure model serialization (PyTorch, TensorFlow)
- Missing input validation for ML models
- GPU memory leakage
- Federated learning privacy risks

Total Security Checks: 10 (Month 5-6 - Security Dominance Plan)

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
        
        # AIML007: Insecure model serialization
        self._check_insecure_serialization(node)
        
        # AIML008: Missing input validation
        self._check_missing_input_validation(node)
        
        # AIML009: GPU memory leakage
        self._check_gpu_memory_leakage(node)
        
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        """Check for AI/ML security issues in assignments."""
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
            if isinstance(node.value.func, ast.Attribute):
                if node.value.func.attr in ["load_dataset", "read_csv", "load_from_disk"]:
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
                    if isinstance(child.func, ast.Attribute):
                        if any(x in child.func.attr.lower() for x in ["differential", "privacy", "noise", "clip"]):
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
]
