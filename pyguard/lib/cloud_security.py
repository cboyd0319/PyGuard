"""
Cloud & Container Security Analysis.

Detects cloud-specific security vulnerabilities including credential exposure,
IAM misconfiguration, container security issues, and cloud service misuse patterns.

Security Areas Covered:
- AWS/Azure/GCP credential exposure (enhanced patterns)
- IAM role misconfiguration detection
- S3/Blob/Storage bucket security
- Docker secrets in environment variables
- Kubernetes secret mishandling
- Container privilege escalation
- Cloud function security issues
- Serverless vulnerabilities
- Infrastructure-as-Code security
- Terraform state file security
- Kubernetes RBAC misconfiguration

Total Security Checks: 15 (Week 3-4 COMPLETE ✅)

References:
- AWS Security Best Practices | https://aws.amazon.com/architecture/security-identity-compliance/ | High
- Azure Security Best Practices | https://learn.microsoft.com/en-us/azure/security/ | High
- GCP Security Best Practices | https://cloud.google.com/security/best-practices | High
- CWE-798 (Use of Hard-coded Credentials) | https://cwe.mitre.org/data/definitions/798.html | Critical
- CWE-522 (Insufficiently Protected Credentials) | https://cwe.mitre.org/data/definitions/522.html | High
- CWE-732 (Incorrect Permission Assignment) | https://cwe.mitre.org/data/definitions/732.html | High
"""

import ast
import re
from pathlib import Path

from pyguard.lib.rule_engine import (
    FixApplicability,
    Rule,
    RuleCategory,
    RuleSeverity,
    RuleViolation,
    register_rules,
)


class CloudSecurityVisitor(ast.NodeVisitor):
    """AST visitor for detecting cloud and container security vulnerabilities."""

    def __init__(self, file_path: Path, code: str):
        self.file_path = file_path
        self.code = code
        self.lines = code.splitlines()
        self.violations: list[RuleViolation] = []
        self.has_boto3 = False
        self.has_azure = False
        self.has_gcp = False
        self.has_docker = False
        self.has_kubernetes = False
        self.env_var_accesses: set[str] = set()

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Track cloud and container framework imports."""
        if node.module:
            if "boto" in node.module or "boto3" in node.module:
                self.has_boto3 = True
            elif "azure" in node.module:
                self.has_azure = True
            elif "google.cloud" in node.module or "googleapiclient" in node.module:
                self.has_gcp = True
            elif "docker" in node.module:
                self.has_docker = True
            elif "kubernetes" in node.module or "k8s" in node.module:
                self.has_kubernetes = True
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        """Track cloud and container framework imports (import statements)."""
        for alias in node.names:
            if "boto" in alias.name or "boto3" in alias.name:
                self.has_boto3 = True
            elif "azure" in alias.name:
                self.has_azure = True
            elif "google" in alias.name:
                self.has_gcp = True
            elif "docker" in alias.name:
                self.has_docker = True
            elif "kubernetes" in alias.name or "k8s" in alias.name:
                self.has_kubernetes = True
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        """Check for hardcoded cloud credentials and security issues."""
        # Check for hardcoded AWS credentials
        self._check_aws_credentials(node)

        # Check for hardcoded Azure credentials
        self._check_azure_credentials(node)

        # Check for hardcoded GCP credentials
        self._check_gcp_credentials(node)

        # Check for Docker secrets in environment variables
        self._check_docker_secrets(node)

        # Check for Kubernetes secrets
        self._check_k8s_secrets(node)

        # Check for Terraform state file secrets
        self._check_terraform_state_secrets(node)

        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Check for serverless function security issues."""
        # Check for serverless cold start vulnerabilities
        self._check_serverless_cold_start(node)

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Check for cloud API misuse and security issues."""
        # Check for S3 bucket ACL issues
        self._check_s3_acl_issues(node)

        # Check for IAM policy issues
        self._check_iam_misconfiguration(node)

        # Check for privileged container detection
        self._check_privileged_container(node)

        # Check for container escape risks
        self._check_container_escape_risks(node)

        # Check for container escape attempts
        self._check_container_escape_attempts(node)

        # Check for cloud storage public access
        self._check_storage_public_access(node)

        # Check for serverless timeout issues
        self._check_serverless_timeout_abuse(node)

        # Check for Kubernetes RBAC misconfiguration
        self._check_k8s_rbac_misconfiguration(node)

        self.generic_visit(node)

    def _check_aws_credentials(self, node: ast.Assign) -> None:
        """Detect hardcoded AWS credentials (enhanced patterns)."""
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()

                # Enhanced AWS credential patterns
                aws_patterns = [
                    "aws_access_key",
                    "aws_secret",
                    "aws_session_token",
                    "access_key_id",
                    "secret_access_key",
                    "aws_key",
                ]

                if any(pattern in var_name for pattern in aws_patterns):
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        # Check for AWS key patterns (AKIA*, ASIA*)
                        value = node.value.value
                        if re.match(r"^(AKIA|ASIA)[A-Z0-9]{16}$", value):
                            self.violations.append(
                                RuleViolation(
                                    file_path=self.file_path,
                                    rule_id="cloud-security-aws-credentials",
                                    message=f"Hardcoded AWS access key detected in variable '{target.id}'. "
                                    "Use AWS Secrets Manager or environment variables.",
                                    line_number=node.lineno,
                                    column=node.col_offset,
                                    severity=RuleSeverity.CRITICAL,
                                    category=RuleCategory.SECURITY,
                                    cwe_id="CWE-798",
                                    fix_applicability=FixApplicability.SAFE,
                                )
                            )

    def _check_azure_credentials(self, node: ast.Assign) -> None:
        """Detect hardcoded Azure credentials."""
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()

                azure_patterns = [
                    "azure_key",
                    "azure_secret",
                    "storage_account_key",
                    "azure_connection_string",
                    "cosmos_key",
                    "sas",
                    "azure_sas",
                ]

                if any(pattern in var_name for pattern in azure_patterns):
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        value = node.value.value
                        # Azure connection strings typically contain "AccountKey=" or "SharedAccessSignature="
                        if "AccountKey=" in value or "SharedAccessSignature=" in value:
                            self.violations.append(
                                RuleViolation(
                                    file_path=self.file_path,
                                    rule_id="cloud-security-azure-credentials",
                                    message=f"Hardcoded Azure credential detected in variable '{target.id}'. "
                                    "Use Azure Key Vault for credential management.",
                                    line_number=node.lineno,
                                    column=node.col_offset,
                                    severity=RuleSeverity.CRITICAL,
                                    category=RuleCategory.SECURITY,
                                    cwe_id="CWE-798",
                                    fix_applicability=FixApplicability.SAFE,
                                )
                            )

    def _check_gcp_credentials(self, node: ast.Assign) -> None:
        """Detect hardcoded GCP service account keys."""
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()

                gcp_patterns = [
                    "service_account_key",
                    "gcp_key",
                    "google_credentials",
                    "gcloud_key",
                    "firebase_key",
                ]

                if any(pattern in var_name for pattern in gcp_patterns):
                    if isinstance(node.value, (ast.Dict, ast.Constant)):
                        # GCP service account keys are JSON objects with specific fields
                        if isinstance(node.value, ast.Constant) and isinstance(
                            node.value.value, str
                        ):
                            if (
                                '"private_key":' in node.value.value
                                and '"type": "service_account"' in node.value.value
                            ):
                                self.violations.append(
                                    RuleViolation(
                                        file_path=self.file_path,
                                        rule_id="cloud-security-gcp-credentials",
                                        message=f"Hardcoded GCP service account key detected in variable '{target.id}'. "
                                        "Use Google Secret Manager or Workload Identity.",
                                        line_number=node.lineno,
                                        column=node.col_offset,
                                        severity=RuleSeverity.CRITICAL,
                                        category=RuleCategory.SECURITY,
                                        cwe_id="CWE-798",
                                        fix_applicability=FixApplicability.SAFE,
                                    )
                                )

    def _check_docker_secrets(self, node: ast.Assign) -> None:
        """Detect Docker secrets exposed in environment variables."""
        # Check for environment variable access patterns
        if isinstance(node.value, ast.Call):
            if (
                isinstance(node.value.func, ast.Attribute)
                and isinstance(node.value.func.value, ast.Name)
                and node.value.func.value.id == "os"
                and node.value.func.attr in ("getenv", "environ")
            ):
                # Check if secret-like names are used
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        var_name = target.id.lower()
                        if any(
                            secret in var_name for secret in ["secret", "key", "token", "password"]
                        ):
                            # Check if there's a default value (insecure)
                            if len(node.value.args) > 1:
                                default = node.value.args[1]
                                if isinstance(default, ast.Constant) and default.value:
                                    self.violations.append(
                                        RuleViolation(
                                            file_path=self.file_path,
                                            rule_id="cloud-security-docker-secret-env",
                                            message=f"Secret '{target.id}' has hardcoded default in os.getenv(). "
                                            "Use Docker secrets or remove default value.",
                                            line_number=node.lineno,
                                            column=node.col_offset,
                                            severity=RuleSeverity.HIGH,
                                            category=RuleCategory.SECURITY,
                                            cwe_id="CWE-522",
                                            fix_applicability=FixApplicability.SUGGESTED,
                                        )
                                    )

    def _check_k8s_secrets(self, node: ast.Assign) -> None:
        """Detect Kubernetes secret mishandling."""
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()

                # Check for hardcoded K8s secrets
                if "k8s_secret" in var_name or "kubernetes_secret" in var_name:
                    if isinstance(node.value, ast.Constant):
                        self.violations.append(
                            RuleViolation(
                                file_path=self.file_path,
                                rule_id="cloud-security-k8s-secret-hardcoded",
                                message=f"Hardcoded Kubernetes secret in variable '{target.id}'. "
                                "Use Kubernetes Secret objects or external secret management.",
                                line_number=node.lineno,
                                column=node.col_offset,
                                severity=RuleSeverity.HIGH,
                                category=RuleCategory.SECURITY,
                                cwe_id="CWE-798",
                                fix_applicability=FixApplicability.SAFE,
                            )
                        )

    def _check_s3_acl_issues(self, node: ast.Call) -> None:
        """Detect S3 bucket ACL configuration issues."""
        if not self.has_boto3:
            return

        # Check for S3 put_bucket_acl with public-read or public-read-write
        if isinstance(node.func, ast.Attribute):
            if node.func.attr == "put_bucket_acl":
                for keyword in node.keywords:
                    if keyword.arg == "ACL":
                        if isinstance(keyword.value, ast.Constant):
                            acl_value = keyword.value.value
                            # Convert bytes to string if needed
                            if isinstance(acl_value, bytes):
                                acl_value = acl_value.decode("utf-8", errors="ignore")
                            if isinstance(acl_value, str) and acl_value in (
                                "public-read",
                                "public-read-write",
                            ):
                                self.violations.append(
                                    RuleViolation(
                                        file_path=self.file_path,
                                        rule_id="cloud-security-s3-public-acl",
                                        message=f"S3 bucket ACL set to '{acl_value}' which allows public access. "
                                        "Use bucket policies with least privilege.",
                                        line_number=node.lineno,
                                        column=node.col_offset,
                                        severity=RuleSeverity.CRITICAL,
                                        category=RuleCategory.SECURITY,
                                        cwe_id="CWE-732",
                                        fix_applicability=FixApplicability.SUGGESTED,
                                    )
                                )

    def _check_iam_misconfiguration(self, node: ast.Call) -> None:
        """Detect IAM policy misconfigurations."""
        if not self.has_boto3:
            return

        # Check for overly permissive IAM policies (Action: "*")
        if isinstance(node.func, ast.Attribute):
            if "put_" in node.func.attr and "policy" in node.func.attr.lower():
                # Look for PolicyDocument argument
                for keyword in node.keywords:
                    if keyword.arg and "Policy" in keyword.arg:
                        # Check if policy contains wildcard actions
                        policy_str = ast.unparse(keyword.value)
                        if '"Action": "*"' in policy_str or "'Action': '*'" in policy_str:
                            self.violations.append(
                                RuleViolation(
                                    file_path=self.file_path,
                                    rule_id="cloud-security-iam-wildcard-action",
                                    message="IAM policy uses wildcard ('*') for Action. "
                                    "Specify explicit permissions for least privilege.",
                                    line_number=node.lineno,
                                    column=node.col_offset,
                                    severity=RuleSeverity.HIGH,
                                    category=RuleCategory.SECURITY,
                                    cwe_id="CWE-732",
                                    fix_applicability=FixApplicability.MANUAL,
                                )
                            )

    def _check_privileged_container(self, node: ast.Call) -> None:
        """Detect privileged container usage."""
        if not self.has_docker:
            return

        # Check for Docker container run with privileged=True
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in ("run", "create"):
                for keyword in node.keywords:
                    if keyword.arg == "privileged":
                        if isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                            self.violations.append(
                                RuleViolation(
                                    file_path=self.file_path,
                                    rule_id="cloud-security-privileged-container",
                                    message="Container running with privileged=True grants excessive permissions. "
                                    "Use specific capabilities instead (--cap-add).",
                                    line_number=node.lineno,
                                    column=node.col_offset,
                                    severity=RuleSeverity.HIGH,
                                    category=RuleCategory.SECURITY,
                                    cwe_id="CWE-732",
                                    fix_applicability=FixApplicability.SUGGESTED,
                                )
                            )

    def _check_container_escape_risks(self, node: ast.Call) -> None:
        """Detect container escape attempt patterns."""
        if not self.has_docker:
            return

        # Check for Docker socket mounting (/var/run/docker.sock)
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in ("run", "create"):
                for keyword in node.keywords:
                    if keyword.arg == "volumes":
                        # Check if docker.sock is mounted
                        volumes_str = ast.unparse(keyword.value)
                        if "/var/run/docker.sock" in volumes_str:
                            self.violations.append(
                                RuleViolation(
                                    file_path=self.file_path,
                                    rule_id="cloud-security-docker-socket-mount",
                                    message="Docker socket (/var/run/docker.sock) mounted in container. "
                                    "This allows container escape. Use Docker API with authentication.",
                                    line_number=node.lineno,
                                    column=node.col_offset,
                                    severity=RuleSeverity.CRITICAL,
                                    category=RuleCategory.SECURITY,
                                    cwe_id="CWE-250",
                                    fix_applicability=FixApplicability.MANUAL,
                                )
                            )

    def _check_storage_public_access(self, node: ast.Call) -> None:
        """Detect cloud storage public access configurations."""
        # Check for Azure Blob Storage public access
        if self.has_azure and isinstance(node.func, ast.Attribute):
            if "set_container_access_policy" in node.func.attr:
                for keyword in node.keywords:
                    if keyword.arg == "public_access":
                        if isinstance(keyword.value, ast.Constant):
                            if keyword.value.value in ("blob", "container"):
                                self.violations.append(
                                    RuleViolation(
                                        file_path=self.file_path,
                                        rule_id="cloud-security-azure-public-storage",
                                        message="Azure Blob Container configured with public access. "
                                        "Use SAS tokens or Azure AD authentication.",
                                        line_number=node.lineno,
                                        column=node.col_offset,
                                        severity=RuleSeverity.HIGH,
                                        category=RuleCategory.SECURITY,
                                        cwe_id="CWE-732",
                                        fix_applicability=FixApplicability.SUGGESTED,
                                    )
                                )

    def _check_serverless_timeout_abuse(self, node: ast.Call) -> None:
        """Detect serverless function timeout abuse risks."""
        # Check for AWS Lambda or Azure Functions with very long timeouts
        if isinstance(node.func, ast.Attribute):
            if "create_function" in node.func.attr or "update_function" in node.func.attr:
                for keyword in node.keywords:
                    if keyword.arg == "Timeout":
                        if isinstance(keyword.value, ast.Constant):
                            timeout = keyword.value.value
                            if isinstance(timeout, int) and timeout > 600:  # > 10 minutes
                                self.violations.append(
                                    RuleViolation(
                                        file_path=self.file_path,
                                        rule_id="cloud-security-serverless-long-timeout",
                                        message=f"Serverless function timeout set to {timeout}s (>10 min). "
                                        "Long timeouts can lead to resource exhaustion.",
                                        line_number=node.lineno,
                                        column=node.col_offset,
                                        severity=RuleSeverity.MEDIUM,
                                        category=RuleCategory.SECURITY,
                                        cwe_id="CWE-770",
                                        fix_applicability=FixApplicability.SAFE,
                                    )
                                )

    def _check_terraform_state_secrets(self, node: ast.Assign) -> None:
        """Detect Terraform state file secrets exposure."""
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()

                # Check for Terraform state file references with secrets
                if "terraform" in var_name and "state" in var_name:
                    if isinstance(node.value, ast.Constant):
                        if isinstance(node.value.value, str):
                            # Check for common secret patterns in Terraform state
                            secret_patterns = [
                                "password",
                                "secret",
                                "api_key",
                                "access_key",
                                "private_key",
                                "token",
                                "credential",
                            ]
                            value_lower = node.value.value.lower()
                            if any(pattern in value_lower for pattern in secret_patterns):
                                self.violations.append(
                                    RuleViolation(
                                        file_path=self.file_path,
                                        rule_id="cloud-security-terraform-state-secrets",
                                        message=f"Terraform state file may contain secrets in variable '{target.id}'. "
                                        "Use remote state with encryption and secret management.",
                                        line_number=node.lineno,
                                        column=node.col_offset,
                                        severity=RuleSeverity.HIGH,
                                        category=RuleCategory.SECURITY,
                                        cwe_id="CWE-798",
                                        fix_applicability=FixApplicability.MANUAL,
                                    )
                                )

    def _check_serverless_cold_start(self, node: ast.FunctionDef) -> None:
        """Detect serverless cold start vulnerabilities."""
        # Check for Lambda handlers with security issues during cold starts
        if "handler" in node.name or "lambda_handler" in node.name:
            # Look for global credential initialization (cold start issue)
            for stmt in node.body[:3]:  # Check first few statements
                if isinstance(stmt, ast.Assign):
                    for target in stmt.targets:
                        if isinstance(target, ast.Name):
                            var_name = target.id.lower()
                            if any(
                                cred in var_name
                                for cred in ["client", "session", "connection", "credentials"]
                            ):
                                # Check if it's initialized with credentials
                                if isinstance(stmt.value, ast.Call):
                                    self.violations.append(
                                        RuleViolation(
                                            file_path=self.file_path,
                                            rule_id="cloud-security-serverless-cold-start",
                                            message=f"Credentials/clients initialized in serverless handler '{node.name}'. "
                                            "Cold start vulnerabilities may expose credentials. Use lazy initialization.",
                                            line_number=stmt.lineno,
                                            column=stmt.col_offset,
                                            severity=RuleSeverity.MEDIUM,
                                            category=RuleCategory.SECURITY,
                                            cwe_id="CWE-522",
                                            fix_applicability=FixApplicability.SUGGESTED,
                                        )
                                    )
                                    break

    def _check_k8s_rbac_misconfiguration(self, node: ast.Call) -> None:
        """Detect Kubernetes RBAC misconfiguration."""
        if not self.has_kubernetes:
            return

        # Check for overly permissive RBAC rules
        if isinstance(node.func, ast.Attribute):
            if "create_role" in node.func.attr or "create_cluster_role" in node.func.attr:
                for keyword in node.keywords:
                    if keyword.arg == "rules":
                        # Check for wildcard permissions
                        rules_str = ast.unparse(keyword.value)
                        if '"*"' in rules_str or "'*'" in rules_str:
                            self.violations.append(
                                RuleViolation(
                                    file_path=self.file_path,
                                    rule_id="cloud-security-k8s-rbac-wildcard",
                                    message="Kubernetes RBAC rule uses wildcard ('*') permissions. "
                                    "Apply least privilege principle with specific resource permissions.",
                                    line_number=node.lineno,
                                    column=node.col_offset,
                                    severity=RuleSeverity.HIGH,
                                    category=RuleCategory.SECURITY,
                                    cwe_id="CWE-732",
                                    fix_applicability=FixApplicability.MANUAL,
                                )
                            )

    def _check_container_escape_attempts(self, node: ast.Call) -> None:
        """Detect container escape attempt patterns in code."""
        if not self.has_docker:
            return

        # Check for dangerous system calls that could enable container escape
        if isinstance(node.func, ast.Attribute):
            dangerous_calls = {
                "chroot": "chroot() can be used for container escape",
                "pivot_root": "pivot_root() can be used for container escape",
                "unshare": "unshare() with CLONE_NEWUSER can escalate privileges",
                "setns": "setns() can break namespace isolation",
            }

            if node.func.attr in dangerous_calls:
                self.violations.append(
                    RuleViolation(
                        file_path=self.file_path,
                        rule_id="cloud-security-container-escape-attempt",
                        message=f"Potential container escape: {dangerous_calls[node.func.attr]}. "
                        "Ensure proper security context and restrictions.",
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.CRITICAL,
                        category=RuleCategory.SECURITY,
                        cwe_id="CWE-250",
                        fix_applicability=FixApplicability.MANUAL,
                    )
                )


def check_cloud_security(file_path: Path, code: str) -> list[RuleViolation]:
    """
    Check for cloud and container security vulnerabilities.

    Args:
        file_path: Path to the file being analyzed
        code: Source code to analyze

    Returns:
        List of rule violations found
    """
    try:
        tree = ast.parse(code)
        visitor = CloudSecurityVisitor(file_path, code)
        visitor.visit(tree)
        return visitor.violations
    except SyntaxError:
        return []


# Register rules for documentation
CLOUD_SECURITY_RULES = [
    Rule(
        rule_id="cloud-security-aws-credentials",
        name="AWS Credential Hardcoding",
        message_template="Hardcoded AWS credential detected. Use environment variables or AWS Secrets Manager.",
        description="Detects hardcoded AWS access keys, secret keys, and session tokens",
        explanation="Hardcoded credentials in source code can be exposed through version control or logs, leading to unauthorized access",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.CRITICAL,
        cwe_mapping="CWE-798",
        owasp_mapping="A02:2021",
        fix_applicability=FixApplicability.SAFE,
        references=["https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html"],
    ),
    Rule(
        rule_id="cloud-security-azure-credentials",
        name="Azure Credential Hardcoding",
        message_template="Hardcoded Azure credential detected. Use Azure Key Vault for credential management.",
        description="Detects hardcoded Azure storage keys and connection strings",
        explanation="Azure credentials hardcoded in source code can be compromised through version control systems",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.CRITICAL,
        cwe_mapping="CWE-798",
        owasp_mapping="A02:2021",
        fix_applicability=FixApplicability.SAFE,
        references=["https://learn.microsoft.com/en-us/azure/key-vault/general/overview"],
    ),
    Rule(
        rule_id="cloud-security-gcp-credentials",
        name="GCP Service Account Key Hardcoding",
        message_template="Hardcoded GCP service account key detected. Use Google Secret Manager or Workload Identity.",
        description="Detects hardcoded GCP service account private keys",
        explanation="GCP service account keys in source code can be compromised, allowing unauthorized access to cloud resources",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.CRITICAL,
        cwe_mapping="CWE-798",
        owasp_mapping="A02:2021",
        fix_applicability=FixApplicability.SAFE,
        references=[
            "https://cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys"
        ],
    ),
    Rule(
        rule_id="cloud-security-docker-secret-env",
        name="Docker Secret in Environment Variable",
        message_template="Secret has hardcoded default in environment variable. Use Docker secrets or remove default value.",
        description="Detects secrets with hardcoded defaults in environment variables",
        explanation="Hardcoded defaults in environment variables defeat the purpose of using environment variables for secrets",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        cwe_mapping="CWE-522",
        owasp_mapping="A02:2021",
        fix_applicability=FixApplicability.SUGGESTED,
        references=["https://docs.docker.com/engine/swarm/secrets/"],
    ),
    Rule(
        rule_id="cloud-security-k8s-secret-hardcoded",
        name="Kubernetes Secret Hardcoding",
        message_template="Hardcoded Kubernetes secret detected. Use Kubernetes Secret objects or external secret management.",
        description="Detects hardcoded Kubernetes secrets in code",
        explanation="Hardcoded K8s secrets in code bypass the security benefits of Kubernetes secret management",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        cwe_mapping="CWE-798",
        owasp_mapping="A02:2021",
        fix_applicability=FixApplicability.SAFE,
        references=["https://kubernetes.io/docs/concepts/configuration/secret/"],
    ),
    Rule(
        rule_id="cloud-security-s3-public-acl",
        name="S3 Bucket Public ACL",
        message_template="S3 bucket ACL allows public access. Use bucket policies with least privilege.",
        description="Detects S3 buckets configured with public-read or public-read-write ACLs",
        explanation="Public S3 ACLs expose data to the internet, leading to potential data breaches",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.CRITICAL,
        cwe_mapping="CWE-732",
        owasp_mapping="A01:2021",
        fix_applicability=FixApplicability.SUGGESTED,
        references=[
            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-best-practices.html"
        ],
    ),
    Rule(
        rule_id="cloud-security-iam-wildcard-action",
        name="IAM Policy Wildcard Action",
        message_template="IAM policy uses wildcard ('*') for Action. Specify explicit permissions for least privilege.",
        description="Detects IAM policies using wildcard ('*') for Action",
        explanation="Wildcard actions in IAM policies grant excessive permissions, violating least privilege principle",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        cwe_mapping="CWE-732",
        owasp_mapping="A01:2021",
        fix_applicability=FixApplicability.MANUAL,
        references=["https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html"],
    ),
    Rule(
        rule_id="cloud-security-privileged-container",
        name="Privileged Container Execution",
        message_template="Container running with privileged=True. Use specific capabilities instead (--cap-add).",
        description="Detects containers running with privileged=True",
        explanation="Privileged containers have full access to host resources, increasing attack surface",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        cwe_mapping="CWE-732",
        owasp_mapping="A01:2021",
        fix_applicability=FixApplicability.SUGGESTED,
        references=[
            "https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities"
        ],
    ),
    Rule(
        rule_id="cloud-security-docker-socket-mount",
        name="Docker Socket Mount",
        message_template="Docker socket (/var/run/docker.sock) mounted in container. Use Docker API with authentication.",
        description="Detects mounting of /var/run/docker.sock which allows container escape",
        explanation="Mounting Docker socket allows container to control host Docker daemon, enabling container escape",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.CRITICAL,
        cwe_mapping="CWE-250",
        owasp_mapping="A01:2021",
        fix_applicability=FixApplicability.MANUAL,
        references=["https://docs.docker.com/engine/security/protect-access/"],
    ),
    Rule(
        rule_id="cloud-security-azure-public-storage",
        name="Azure Public Storage Access",
        message_template="Azure Blob Container configured with public access. Use SAS tokens or Azure AD authentication.",
        description="Detects Azure Blob Storage containers with public access enabled",
        explanation="Public access to Azure storage containers exposes data to the internet",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        cwe_mapping="CWE-732",
        owasp_mapping="A01:2021",
        fix_applicability=FixApplicability.SUGGESTED,
        references=[
            "https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-overview"
        ],
    ),
    Rule(
        rule_id="cloud-security-serverless-long-timeout",
        name="Serverless Function Long Timeout",
        message_template="Serverless function timeout set too high. Long timeouts can lead to resource exhaustion.",
        description="Detects serverless functions with excessively long timeout values",
        explanation="Excessive timeouts in serverless functions can lead to resource exhaustion and high costs",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.MEDIUM,
        cwe_mapping="CWE-770",
        owasp_mapping="A04:2021",
        fix_applicability=FixApplicability.SAFE,
        references=[
            "https://docs.aws.amazon.com/lambda/latest/dg/configuration-function-common.html"
        ],
    ),
    Rule(
        rule_id="cloud-security-terraform-state-secrets",
        name="Terraform State File Secrets",
        message_template="Terraform state file may contain secrets. Use remote state with encryption and secret management.",
        description="Detects Terraform state files that may contain hardcoded secrets",
        explanation="Terraform state files can contain sensitive data. Use remote backends with encryption (S3+KMS, Azure Blob+encryption) and never commit state files to version control.",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        cwe_mapping="CWE-798",
        owasp_mapping="A02:2021",
        fix_applicability=FixApplicability.MANUAL,
        references=["https://developer.hashicorp.com/terraform/language/state/sensitive-data"],
    ),
    Rule(
        rule_id="cloud-security-serverless-cold-start",
        name="Serverless Cold Start Vulnerability",
        message_template="Credentials initialized in serverless handler may be exposed during cold starts. Use lazy initialization.",
        description="Detects credential initialization patterns that may be vulnerable during serverless cold starts",
        explanation="Initializing credentials at the module level in serverless functions can expose them during cold starts. Use lazy initialization and proper secret management.",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.MEDIUM,
        cwe_mapping="CWE-522",
        owasp_mapping="A02:2021",
        fix_applicability=FixApplicability.SUGGESTED,
        references=["https://docs.aws.amazon.com/lambda/latest/dg/best-practices.html"],
    ),
    Rule(
        rule_id="cloud-security-k8s-rbac-wildcard",
        name="Kubernetes RBAC Wildcard Permissions",
        message_template="Kubernetes RBAC rule uses wildcard permissions. Apply least privilege with specific resources.",
        description="Detects Kubernetes RBAC rules using wildcard ('*') permissions",
        explanation="Wildcard permissions in Kubernetes RBAC violate the principle of least privilege. Specify explicit resource permissions and verbs.",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        cwe_mapping="CWE-732",
        owasp_mapping="A01:2021",
        fix_applicability=FixApplicability.MANUAL,
        references=["https://kubernetes.io/docs/concepts/security/rbac-good-practices/"],
    ),
    Rule(
        rule_id="cloud-security-container-escape-attempt",
        name="Container Escape Attempt Detection",
        message_template="Potential container escape attempt detected using dangerous system calls. Ensure proper security context.",
        description="Detects dangerous system calls that could be used for container escape (chroot, pivot_root, unshare, setns)",
        explanation="System calls like chroot(), pivot_root(), unshare(), and setns() can be used to escape container isolation. Ensure proper security contexts, AppArmor/SELinux policies, and syscall filtering (seccomp).",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.CRITICAL,
        cwe_mapping="CWE-250",
        owasp_mapping="A01:2021",
        fix_applicability=FixApplicability.MANUAL,
        references=[
            "https://docs.docker.com/engine/security/seccomp/",
            "https://kubernetes.io/docs/concepts/security/pod-security-standards/",
        ],
    ),
]

register_rules(CLOUD_SECURITY_RULES)
