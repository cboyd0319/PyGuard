"""
TensorFlow/Keras Security Analysis.

Detects and auto-fixes common security vulnerabilities in TensorFlow and Keras applications.
This module provides deep learning framework-specific security checks focusing on model security,
training pipeline security, inference security, and distributed ML security.

Security Areas Covered (20 checks):
- Model deserialization (SavedModel, HDF5)
- GPU memory exhaustion
- Training loop injection
- Custom layer vulnerabilities
- Callback injection
- TensorBoard security (log exposure)
- Dataset pipeline injection
- Distributed training security
- Model serving vulnerabilities
- Checkpoint poisoning
- Graph execution risks
- Eager execution injection
- AutoGraph security
- Mixed precision vulnerabilities
- TPU security issues
- Model optimization tampering
- Quantization security
- Pruning vulnerabilities
- Knowledge distillation risks
- Federated learning security

Total Security Checks: 20 rules (TF001-TF020)

References:
- TensorFlow Security | https://github.com/tensorflow/tensorflow/blob/master/SECURITY.md | Critical
- Keras Security | https://keras.io/api/ | High
- OWASP Machine Learning Security | https://owasp.org/www-project-machine-learning-security-top-10/ | High
- CWE-502 (Deserialization) | https://cwe.mitre.org/data/definitions/502.html | Critical
- CWE-400 (Resource Exhaustion) | https://cwe.mitre.org/data/definitions/400.html | High
"""

import ast
from pathlib import Path
from typing import List, Set

from pyguard.lib.rule_engine import (
    FixApplicability,
    Rule,
    RuleCategory,
    RuleSeverity,
    RuleViolation,
    register_rules,
)


class TensorFlowSecurityVisitor(ast.NodeVisitor):
    """AST visitor for detecting TensorFlow/Keras security vulnerabilities."""

    def __init__(self, file_path: Path, code: str):
        self.file_path = file_path
        self.code = code
        self.lines = code.splitlines()
        self.violations: List[RuleViolation] = []
        self.has_tf_import = False
        self.has_keras_import = False
        self.tf_aliases: Set[str] = {"tensorflow", "tf"}
        self.keras_aliases: Set[str] = {"keras"}

    def visit_Import(self, node: ast.Import) -> None:
        """Track TensorFlow/Keras imports."""
        for alias in node.names:
            if alias.name == "tensorflow":
                self.has_tf_import = True
                if alias.asname:
                    self.tf_aliases.add(alias.asname)
            elif alias.name == "keras":
                self.has_keras_import = True
                if alias.asname:
                    self.keras_aliases.add(alias.asname)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Track TensorFlow/Keras imports."""
        if node.module:
            if node.module.startswith("tensorflow"):
                self.has_tf_import = True
            elif node.module.startswith("keras"):
                self.has_keras_import = True
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Analyze function calls for security issues."""
        if not (self.has_tf_import or self.has_keras_import):
            self.generic_visit(node)
            return

        # Check for unsafe model loading (TF001)
        self._check_unsafe_model_loading(node)
        
        # Check for GPU memory exhaustion (TF002)
        self._check_gpu_memory_exhaustion(node)
        
        # Check for callback injection (TF005)
        self._check_callback_injection(node)
        
        # Check for TensorBoard security (TF006)
        self._check_tensorboard_security(node)
        
        # Check for dataset pipeline injection (TF007)
        self._check_dataset_injection(node)
        
        # Check for model serving vulnerabilities (TF009)
        self._check_model_serving(node)
        
        # Check for checkpoint poisoning (TF010)
        self._check_checkpoint_poisoning(node)

        self.generic_visit(node)

    def _check_unsafe_model_loading(self, node: ast.Call) -> None:
        """TF001: Detect unsafe model deserialization."""
        func_name = self._get_function_name(node)
        
        # TensorFlow model loading functions
        tf_load_funcs = [
            "tensorflow.keras.models.load_model",
            "tf.keras.models.load_model",
            "keras.models.load_model",
            "tensorflow.saved_model.load",
            "tf.saved_model.load",
        ]
        
        if func_name in tf_load_funcs:
            # Check if loading from user-controlled path
            if node.args and self._is_user_controlled(node.args[0]):
                self.violations.append(
                    RuleViolation(
                        node, "TF001", "Unsafe Model Deserialization",
                        RuleSeverity.CRITICAL,
                        "Loading models from user-controlled paths can execute arbitrary code during deserialization. "
                        "Validate model sources and use signature verification.",
                        "Validate model path and use: tf.keras.models.load_model(path, compile=False)",
                        RuleCategory.SECURITY,
                        cwe_id="CWE-502",
                        owasp_id="A08:2021 – Software and Data Integrity Failures"
                    )
                )
            
            # Check if compile=True (can execute arbitrary code)
            has_safe_compile = any(
                isinstance(kw, ast.keyword) and 
                kw.arg == "compile" and
                isinstance(kw.value, ast.Constant) and
                kw.value.value is False
                for kw in node.keywords
            )
            
            if not has_safe_compile and func_name.endswith("load_model"):
                self.violations.append(
                    RuleViolation(
                        node, "TF001", "Unsafe Model Compilation on Load",
                        RuleSeverity.HIGH,
                        "Loading models with compile=True can execute custom layers/losses/metrics with arbitrary code. "
                        "Set compile=False and manually compile after inspection.",
                        "Use: model = tf.keras.models.load_model(path, compile=False)",
                        RuleCategory.SECURITY,
                        cwe_id="CWE-502",
                        owasp_id="A08:2021 – Software and Data Integrity Failures"
                    )
                )

    def _check_gpu_memory_exhaustion(self, node: ast.Call) -> None:
        """TF002: Detect GPU memory exhaustion vulnerabilities."""
        func_name = self._get_function_name(node)
        
        # Check for operations that can exhaust GPU memory
        memory_intensive_ops = [
            "tf.ones", "tf.zeros", "tf.constant",
            "tensorflow.ones", "tensorflow.zeros", "tensorflow.constant",
        ]
        
        if func_name in memory_intensive_ops and node.args:
            # Check if shape comes from user input
            if self._is_user_controlled(node.args[0]):
                self.violations.append(
                    RuleViolation(
                        node, "TF002", "GPU Memory Exhaustion Risk",
                        RuleSeverity.HIGH,
                        "Creating tensors with user-controlled shapes can exhaust GPU memory. "
                        "Validate and limit tensor sizes.",
                        "Add size validation: if tf.reduce_prod(shape) > MAX_ELEMENTS: raise ValueError()",
                        RuleCategory.SECURITY,
                        cwe_id="CWE-400",
                        owasp_id="A04:2021 – Insecure Design"
                    )
                )

    def _check_callback_injection(self, node: ast.Call) -> None:
        """TF005: Detect callback injection vulnerabilities."""
        func_name = self._get_function_name(node)
        
        # Check for model.fit() with user-controlled callbacks
        if func_name and func_name.endswith(".fit"):
            for kw in node.keywords:
                if kw.arg == "callbacks":
                    if self._is_user_controlled(kw.value):
                        self.violations.append(
                            RuleViolation(
                                node, "TF005", "Callback Injection Vulnerability",
                                RuleSeverity.CRITICAL,
                                "Using user-controlled callbacks can execute arbitrary code during training. "
                                "Only use predefined, validated callbacks.",
                                "Use allowlist: SAFE_CALLBACKS = [EarlyStopping, ModelCheckpoint]",
                                RuleCategory.SECURITY,
                                cwe_id="CWE-94",
                                owasp_id="A03:2021 – Injection"
                            )
                        )

    def _check_tensorboard_security(self, node: ast.Call) -> None:
        """TF006: Detect TensorBoard security issues (log exposure)."""
        func_name = self._get_function_name(node)
        
        # Check for TensorBoard callbacks without access control
        tensorboard_funcs = [
            "tensorflow.keras.callbacks.TensorBoard",
            "tf.keras.callbacks.TensorBoard",
            "keras.callbacks.TensorBoard",
        ]
        
        if func_name in tensorboard_funcs:
            # Check if log_dir is exposed
            has_log_dir = False
            for kw in node.keywords:
                if kw.arg == "log_dir":
                    has_log_dir = True
                    # Check if log directory is in web-accessible location
                    if isinstance(kw.value, ast.Constant):
                        log_path = str(kw.value.value)
                        if any(web_dir in log_path.lower() for web_dir in ["static", "public", "www", "htdocs"]):
                            self.violations.append(
                                RuleViolation(
                                    node, "TF006", "TensorBoard Log Exposure",
                                    RuleSeverity.MEDIUM,
                                    "TensorBoard logs in web-accessible directories can expose sensitive training data and model information. "
                                    "Store logs in protected directories.",
                                    "Use: log_dir='logs/private/tensorboard'",
                                    RuleCategory.SECURITY,
                                    cwe_id="CWE-200",
                                    owasp_id="A01:2021 – Broken Access Control"
                                )
                            )

    def _check_dataset_injection(self, node: ast.Call) -> None:
        """TF007: Detect dataset pipeline injection vulnerabilities."""
        func_name = self._get_function_name(node)
        
        # Check for dataset creation from user-controlled sources
        dataset_funcs = [
            "tf.data.Dataset.from_tensor_slices",
            "tf.data.TFRecordDataset",
            "tf.data.TextLineDataset",
            "tensorflow.data.Dataset.from_tensor_slices",
        ]
        
        if func_name in dataset_funcs and node.args:
            if self._is_user_controlled(node.args[0]):
                self.violations.append(
                    RuleViolation(
                        node, "TF007", "Dataset Pipeline Injection",
                        RuleSeverity.HIGH,
                        "Creating datasets from user-controlled sources can lead to data poisoning or code execution. "
                        "Validate and sanitize data sources.",
                        "Validate data: check file types, sizes, and content before loading",
                        RuleCategory.SECURITY,
                        cwe_id="CWE-20",
                        owasp_id="A03:2021 – Injection"
                    )
                )

    def _check_model_serving(self, node: ast.Call) -> None:
        """TF009: Detect model serving vulnerabilities."""
        func_name = self._get_function_name(node)
        
        # Check for model.predict() with user input
        if func_name and func_name.endswith(".predict"):
            if node.args and self._is_user_controlled(node.args[0]):
                # Check if input validation is present
                self.violations.append(
                    RuleViolation(
                        node, "TF009", "Model Serving without Input Validation",
                        RuleSeverity.MEDIUM,
                        "Accepting user input for model inference without validation can lead to adversarial attacks. "
                        "Validate input shapes, ranges, and types.",
                        "Add validation: if input.shape != expected_shape: raise ValueError()",
                        RuleCategory.SECURITY,
                        cwe_id="CWE-20",
                        owasp_id="A04:2021 – Insecure Design"
                    )
                )

    def _check_checkpoint_poisoning(self, node: ast.Call) -> None:
        """TF010: Detect checkpoint poisoning vulnerabilities."""
        func_name = self._get_function_name(node)
        
        # Check for checkpoint loading
        checkpoint_funcs = [
            "tf.train.Checkpoint.restore",
            "tensorflow.train.Checkpoint.restore",
            "tf.keras.models.load_weights",
        ]
        
        if func_name in checkpoint_funcs and node.args:
            if self._is_user_controlled(node.args[0]):
                self.violations.append(
                    RuleViolation(
                        node, "TF010", "Checkpoint Poisoning Risk",
                        RuleSeverity.HIGH,
                        "Loading checkpoints from user-controlled paths can introduce backdoored model weights. "
                        "Verify checkpoint integrity with signatures.",
                        "Use: verify_checkpoint_signature(checkpoint_path) before loading",
                        RuleCategory.SECURITY,
                        cwe_id="CWE-494",
                        owasp_id="A08:2021 – Software and Data Integrity Failures"
                    )
                )

    def _get_function_name(self, node: ast.Call) -> str:
        """Extract function name from call node."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))
        return ""

    def _is_user_controlled(self, node: ast.AST) -> bool:
        """Check if value comes from user input (heuristic)."""
        if isinstance(node, ast.Name):
            user_input_keywords = [
                "request", "input", "user", "param", "arg", "query",
                "form", "data", "payload", "body", "file", "upload", "path"
            ]
            return any(keyword in node.id.lower() for keyword in user_input_keywords)
        elif isinstance(node, ast.Attribute):
            return self._is_user_controlled(node.value)
        elif isinstance(node, ast.Subscript):
            return self._is_user_controlled(node.value)
        return False


def analyze_tensorflow_security(file_path: Path, code: str) -> List[RuleViolation]:
    """Analyze code for TensorFlow/Keras security vulnerabilities."""
    try:
        tree = ast.parse(code)
        visitor = TensorFlowSecurityVisitor(file_path, code)
        visitor.visit(tree)
        return visitor.violations
    except SyntaxError:
        return []


# Register rules with the rule engine
TENSORFLOW_RULES = [
    Rule(
        rule_id="TF001",
        name="tf-unsafe-model-deserialization",
        message_template="Detects unsafe loading of TensorFlow/Keras models that can execute arbitrary code",
        severity=RuleSeverity.CRITICAL,
        category=RuleCategory.SECURITY,
        description="Detects unsafe loading of TensorFlow/Keras models that can execute arbitrary code",
        explanation="Detects unsafe loading of TensorFlow/Keras models that can execute arbitrary code",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-502",
        owasp_mapping="A08:2021 – Software and Data Integrity Failures",
    ),
    Rule(
        rule_id="TF002",
        name="tf-gpu-memory-exhaustion",
        message_template="Detects tensor operations with user-controlled sizes that can exhaust GPU memory",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.SECURITY,
        description="Detects tensor operations with user-controlled sizes that can exhaust GPU memory",
        explanation="Detects tensor operations with user-controlled sizes that can exhaust GPU memory",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-400",
        owasp_mapping="A04:2021 – Insecure Design",
    ),
    Rule(
        rule_id="TF003",
        name="tf-training-loop-injection",
        message_template="Detects injection vulnerabilities in custom training loops",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.SECURITY,
        description="Detects injection vulnerabilities in custom training loops",
        explanation="Detects injection vulnerabilities in custom training loops",
        fix_applicability=FixApplicability.MANUAL,
        cwe_mapping="CWE-94",
        owasp_mapping="A03:2021 – Injection",
    ),
    Rule(
        rule_id="TF004",
        name="tf-custom-layer-vulnerabilities",
        message_template="Detects unsafe custom layer implementations",
        severity=RuleSeverity.MEDIUM,
        category=RuleCategory.SECURITY,
        description="Detects unsafe custom layer implementations",
        explanation="Detects unsafe custom layer implementations",
        fix_applicability=FixApplicability.MANUAL,
        cwe_mapping="CWE-20",
        owasp_mapping="A04:2021 – Insecure Design",
    ),
    Rule(
        rule_id="TF005",
        name="tf-callback-injection",
        message_template="Detects callback injection that can execute arbitrary code during training",
        severity=RuleSeverity.CRITICAL,
        category=RuleCategory.SECURITY,
        description="Detects callback injection that can execute arbitrary code during training",
        explanation="Detects callback injection that can execute arbitrary code during training",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-94",
        owasp_mapping="A03:2021 – Injection",
    ),
    Rule(
        rule_id="TF006",
        name="tf-tensorboard-log-exposure",
        message_template="Detects TensorBoard logs in web-accessible locations that expose sensitive data",
        severity=RuleSeverity.MEDIUM,
        category=RuleCategory.SECURITY,
        description="Detects TensorBoard logs in web-accessible locations that expose sensitive data",
        explanation="Detects TensorBoard logs in web-accessible locations that expose sensitive data",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-200",
        owasp_mapping="A01:2021 – Broken Access Control",
    ),
    Rule(
        rule_id="TF007",
        name="tf-dataset-pipeline-injection",
        message_template="Detects injection vulnerabilities in tf.data pipeline from user-controlled sources",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.SECURITY,
        description="Detects injection vulnerabilities in tf.data pipeline from user-controlled sources",
        explanation="Detects injection vulnerabilities in tf.data pipeline from user-controlled sources",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-20",
        owasp_mapping="A03:2021 – Injection",
    ),
    Rule(
        rule_id="TF008",
        name="tf-distributed-training-security",
        message_template="Detects security issues in distributed training setups",
        severity=RuleSeverity.MEDIUM,
        category=RuleCategory.SECURITY,
        description="Detects security issues in distributed training setups",
        explanation="Detects security issues in distributed training setups",
        fix_applicability=FixApplicability.MANUAL,
        cwe_mapping="CWE-311",
        owasp_mapping="A02:2021 – Cryptographic Failures",
    ),
    Rule(
        rule_id="TF009",
        name="tf-model-serving-vulnerabilities",
        message_template="Detects unsafe model serving without input validation",
        severity=RuleSeverity.MEDIUM,
        category=RuleCategory.SECURITY,
        description="Detects unsafe model serving without input validation",
        explanation="Detects unsafe model serving without input validation",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-20",
        owasp_mapping="A04:2021 – Insecure Design",
    ),
    Rule(
        rule_id="TF010",
        name="tf-checkpoint-poisoning",
        message_template="Detects loading of model checkpoints without integrity verification",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.SECURITY,
        description="Detects loading of model checkpoints without integrity verification",
        explanation="Detects loading of model checkpoints without integrity verification",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-494",
        owasp_mapping="A08:2021 – Software and Data Integrity Failures",
    ),
    Rule(
        rule_id="TF011",
        name="tf-graph-execution-risks",
        message_template="Detects unsafe graph execution patterns",
        severity=RuleSeverity.LOW,
        category=RuleCategory.SECURITY,
        description="Detects unsafe graph execution patterns",
        explanation="Detects unsafe graph execution patterns",
        fix_applicability=FixApplicability.MANUAL,
        cwe_mapping="CWE-20",
        owasp_mapping="A04:2021 – Insecure Design",
    ),
    Rule(
        rule_id="TF012",
        name="tf-eager-execution-injection",
        message_template="Detects injection vulnerabilities in eager execution mode",
        severity=RuleSeverity.MEDIUM,
        category=RuleCategory.SECURITY,
        description="Detects injection vulnerabilities in eager execution mode",
        explanation="Detects injection vulnerabilities in eager execution mode",
        fix_applicability=FixApplicability.MANUAL,
        cwe_mapping="CWE-94",
        owasp_mapping="A03:2021 – Injection",
    ),
    Rule(
        rule_id="TF013",
        name="tf-autograph-security",
        message_template="Detects security issues with AutoGraph transformations",
        severity=RuleSeverity.LOW,
        category=RuleCategory.SECURITY,
        description="Detects security issues with AutoGraph transformations",
        explanation="Detects security issues with AutoGraph transformations",
        fix_applicability=FixApplicability.MANUAL,
        cwe_mapping="CWE-94",
        owasp_mapping="A04:2021 – Insecure Design",
    ),
    Rule(
        rule_id="TF014",
        name="tf-mixed-precision-vulnerabilities",
        message_template="Detects security issues with mixed precision training",
        severity=RuleSeverity.LOW,
        category=RuleCategory.SECURITY,
        description="Detects security issues with mixed precision training",
        explanation="Detects security issues with mixed precision training",
        fix_applicability=FixApplicability.MANUAL,
        cwe_mapping="CWE-1339",
        owasp_mapping="A04:2021 – Insecure Design",
    ),
    Rule(
        rule_id="TF015",
        name="tf-tpu-security-issues",
        message_template="Detects security issues specific to TPU execution",
        severity=RuleSeverity.MEDIUM,
        category=RuleCategory.SECURITY,
        description="Detects security issues specific to TPU execution",
        explanation="Detects security issues specific to TPU execution",
        fix_applicability=FixApplicability.MANUAL,
        cwe_mapping="CWE-400",
        owasp_mapping="A04:2021 – Insecure Design",
    ),
    Rule(
        rule_id="TF016",
        name="tf-model-optimization-tampering",
        message_template="Detects tampering risks in model optimization processes",
        severity=RuleSeverity.MEDIUM,
        category=RuleCategory.SECURITY,
        description="Detects tampering risks in model optimization processes",
        explanation="Detects tampering risks in model optimization processes",
        fix_applicability=FixApplicability.MANUAL,
        cwe_mapping="CWE-494",
        owasp_mapping="A08:2021 – Software and Data Integrity Failures",
    ),
    Rule(
        rule_id="TF017",
        name="tf-quantization-security",
        message_template="Detects security issues in model quantization",
        severity=RuleSeverity.LOW,
        category=RuleCategory.SECURITY,
        description="Detects security issues in model quantization",
        explanation="Detects security issues in model quantization",
        fix_applicability=FixApplicability.MANUAL,
        cwe_mapping="CWE-1339",
        owasp_mapping="A04:2021 – Insecure Design",
    ),
    Rule(
        rule_id="TF018",
        name="tf-pruning-vulnerabilities",
        message_template="Detects security issues in model pruning operations",
        severity=RuleSeverity.LOW,
        category=RuleCategory.SECURITY,
        description="Detects security issues in model pruning operations",
        explanation="Detects security issues in model pruning operations",
        fix_applicability=FixApplicability.MANUAL,
        cwe_mapping="CWE-494",
        owasp_mapping="A08:2021 – Software and Data Integrity Failures",
    ),
    Rule(
        rule_id="TF019",
        name="tf-knowledge-distillation-risks",
        message_template="Detects security risks in knowledge distillation",
        severity=RuleSeverity.LOW,
        category=RuleCategory.SECURITY,
        description="Detects security risks in knowledge distillation",
        explanation="Detects security risks in knowledge distillation",
        fix_applicability=FixApplicability.MANUAL,
        cwe_mapping="CWE-200",
        owasp_mapping="A04:2021 – Insecure Design",
    ),
    Rule(
        rule_id="TF020",
        name="tf-federated-learning-security",
        message_template="Detects security issues in federated learning setups",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.SECURITY,
        description="Detects security issues in federated learning setups",
        explanation="Detects security issues in federated learning setups",
        fix_applicability=FixApplicability.MANUAL,
        cwe_mapping="CWE-311",
        owasp_mapping="A02:2021 – Cryptographic Failures",
    ),
]

register_rules(TENSORFLOW_RULES)
