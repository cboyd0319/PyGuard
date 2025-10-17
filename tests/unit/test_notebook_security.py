"""Tests for Jupyter notebook security analysis."""

import json
import tempfile
from pathlib import Path

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
                    "password = 'SuperSecret123'\n",
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
                    "source": ["user_input = input()\n", "eval(user_input)"],
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
                        "    data = pickle.load(f)",
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
        assert pickle_issues[0].severity == "HIGH"
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
        with open(temp_notebook, "r") as f:
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

        assert not success
        assert len(fixes) == 0

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
        with open(temp_notebook, "r") as f:
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

        github_issues = [i for i in issues if "GitHub" in i.message or "github" in i.message.lower()]
        assert len(github_issues) >= 1

        temp_notebook.unlink()
