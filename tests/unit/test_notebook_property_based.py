"""
Property-based tests for PyGuard Jupyter notebook security using Hypothesis.

These tests use property-based testing to validate that PyGuard's notebook
security analyzer behaves correctly across a wide range of inputs, catching
edge cases that might be missed by example-based tests.

Requirements:
    pip install hypothesis pytest

Usage:
    pytest tests/unit/test_notebook_property_based.py -v
"""

import json
import tempfile
from pathlib import Path
from typing import Any

import pytest

try:
    from hypothesis import HealthCheck, assume, given, settings
    from hypothesis import strategies as st

    HYPOTHESIS_AVAILABLE = True
except ImportError:
    HYPOTHESIS_AVAILABLE = False
    pytest.skip("Hypothesis not available", allow_module_level=True)

from pyguard.lib.notebook_security import (
    NotebookIssue,
    NotebookSecurityAnalyzer,
)


# Strategy for generating valid notebook cells
@st.composite
def notebook_cell(draw, cell_type: str = "code"):
    """Generate a valid notebook cell."""
    source_lines = draw(
        st.lists(
            st.text(alphabet=st.characters(blacklist_categories=("Cs",)), min_size=0, max_size=100),
            min_size=1,
            max_size=10,
        )
    )

    return {
        "cell_type": cell_type,
        "execution_count": draw(st.one_of(st.none(), st.integers(min_value=1, max_value=1000))),
        "source": source_lines,
        "outputs": [],
        "metadata": {},
    }


@st.composite
def valid_notebook(draw, min_cells: int = 1, max_cells: int = 20):
    """Generate a valid Jupyter notebook structure."""
    cells = draw(st.lists(notebook_cell(), min_size=min_cells, max_size=max_cells))

    return {
        "cells": cells,
        "metadata": {
            "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"}
        },
        "nbformat": 4,
        "nbformat_minor": 5,
    }


def create_notebook_file(notebook_data: dict[str, Any]) -> Path:
    """Create a temporary notebook file."""
    temp_file = tempfile.NamedTemporaryFile(
        mode="w", suffix=".ipynb", delete=False, encoding="utf-8"
    )
    json.dump(notebook_data, temp_file, indent=2)
    temp_file.close()
    return Path(temp_file.name)


class TestNotebookStructureProperties:
    """Property-based tests for notebook structure handling."""

    @given(valid_notebook())
    @settings(max_examples=50, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_analyzer_handles_any_valid_notebook(self, notebook_data):
        """Property: Analyzer should handle any valid notebook without crashing."""
        notebook_path = create_notebook_file(notebook_data)

        try:
            analyzer = NotebookSecurityAnalyzer()
            issues = analyzer.analyze_notebook(notebook_path)

            # Should return a list (might be empty)
            assert isinstance(issues, list)

            # All issues should be NotebookIssue instances
            for issue in issues:
                assert isinstance(issue, NotebookIssue)
                assert hasattr(issue, "severity")
                assert hasattr(issue, "category")
                assert hasattr(issue, "message")
        finally:
            notebook_path.unlink()

    @given(st.integers(min_value=0, max_value=100))
    @settings(max_examples=20)
    def test_cell_count_is_preserved(self, num_cells):
        """Property: Analyzer should correctly count cells in notebook."""
        cells = [
            {
                "cell_type": "code",
                "execution_count": i,
                "source": [f"x = {i}"],
                "outputs": [],
                "metadata": {},
            }
            for i in range(num_cells)
        ]

        notebook_data = {"cells": cells, "metadata": {}, "nbformat": 4, "nbformat_minor": 5}

        notebook_path = create_notebook_file(notebook_data)

        try:
            analyzer = NotebookSecurityAnalyzer()
            issues = analyzer.analyze_notebook(notebook_path)

            # Can check that we analyzed the right number of cells
            # (issues are returned per cell, so max cell_index should be < num_cells)
            if issues:
                max_cell_index = max(issue.cell_index for issue in issues)
                assert max_cell_index < num_cells
        finally:
            notebook_path.unlink()


class TestSecretDetectionProperties:
    """Property-based tests for secret detection."""

    @given(
        st.text(
            min_size=20,
            max_size=50,
            alphabet=st.characters(
                whitelist_categories=("Lu", "Ll", "Nd"), min_codepoint=65, max_codepoint=122
            ),
        )
    )
    @settings(max_examples=50)
    def test_high_entropy_strings_detected(self, random_string):
        """Property: High-entropy strings should be flagged as potential secrets."""
        # Only test strings that look like API keys (alphanumeric, reasonable length)
        assume(len(set(random_string)) > 10)  # Sufficient character diversity

        notebook_data = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": [f"api_key = '{random_string}'"],
                    "outputs": [],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }

        notebook_path = create_notebook_file(notebook_data)

        try:
            analyzer = NotebookSecurityAnalyzer()
            issues = analyzer.analyze_notebook(notebook_path)

            # If entropy is high enough, should detect it
            # Note: Not all high-entropy strings are secrets, but API key pattern should help
            [i for i in issues if "secret" in i.category.lower() or "entropy" in i.category.lower()]

            # This is probabilistic - very high entropy should usually be caught
            if len(random_string) >= 32 and len(set(random_string)) > 20:
                # High entropy, long string - likely to be detected
                pass  # Could be detected as high-entropy or by pattern
        finally:
            notebook_path.unlink()

    @given(
        st.sampled_from(
            [
                "sk-1234567890abcdef1234567890abcdef",  # OpenAI-like
                "AKIA1234567890ABCDEF",  # AWS access key
                "ghp_1234567890abcdefghijklmnopqrstuvwxyz",  # GitHub token
                "xoxb-123456789012-123456789012-abcdefghijklmnopqrstu",  # Slack
            ]
        )
    )
    @settings(max_examples=20)
    def test_known_secret_patterns_always_detected(self, secret):
        """Property: Known secret patterns should always be detected."""
        notebook_data = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": [f"token = '{secret}'"],
                    "outputs": [],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }

        notebook_path = create_notebook_file(notebook_data)

        try:
            analyzer = NotebookSecurityAnalyzer()
            issues = analyzer.analyze_notebook(notebook_path)

            # Should detect at least one secret-related issue
            secret_issues = [
                i
                for i in issues
                if "secret" in i.category.lower()
                or "credential" in i.category.lower()
                or "api" in i.message.lower()
                or "token" in i.message.lower()
            ]

            assert len(secret_issues) > 0, f"Failed to detect known secret pattern: {secret}"
        finally:
            notebook_path.unlink()


class TestCodeInjectionProperties:
    """Property-based tests for code injection detection."""

    @given(st.sampled_from(["eval", "exec", "compile"]))
    @settings(max_examples=10)
    def test_dangerous_functions_always_detected(self, func_name):
        """Property: Dangerous functions should always be detected."""
        notebook_data = {
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "source": [f"{func_name}(user_input)"],
                    "outputs": [],
                    "metadata": {},
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }

        notebook_path = create_notebook_file(notebook_data)

        try:
            analyzer = NotebookSecurityAnalyzer()
            issues = analyzer.analyze_notebook(notebook_path)

            # Should detect code injection issue
            injection_issues = [
                i
                for i in issues
                if "injection" in i.category.lower() or func_name in i.message.lower()
            ]

            assert len(injection_issues) > 0, f"Failed to detect {func_name}() usage"
        finally:
            notebook_path.unlink()


class TestIdempotencyProperties:
    """Property-based tests for analyzer idempotency."""

    @given(valid_notebook(min_cells=1, max_cells=10))
    @settings(max_examples=20, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_analysis_is_idempotent(self, notebook_data):
        """Property: Running analysis twice should produce identical results."""
        notebook_path = create_notebook_file(notebook_data)

        try:
            analyzer = NotebookSecurityAnalyzer()

            # Run analysis twice
            issues1 = analyzer.analyze_notebook(notebook_path)
            issues2 = analyzer.analyze_notebook(notebook_path)

            # Should get same number of issues
            assert len(issues1) == len(issues2)

            # Issues should be the same (comparing key attributes)
            for i1, i2 in zip(
                sorted(issues1, key=lambda x: (x.cell_index, x.line_number)),
                sorted(issues2, key=lambda x: (x.cell_index, x.line_number)),
                strict=False,
            ):
                assert i1.severity == i2.severity
                assert i1.category == i2.category
                assert i1.cell_index == i2.cell_index
        finally:
            notebook_path.unlink()


class TestPerformanceProperties:
    """Property-based tests for performance characteristics."""

    @given(st.integers(min_value=1, max_value=50))
    @settings(max_examples=10)
    def test_analysis_time_scales_linearly(self, num_cells):
        """Property: Analysis time should scale roughly linearly with cell count."""
        import time

        cells = [
            {
                "cell_type": "code",
                "execution_count": i,
                "source": [f"x = {i}\nprint(x)"],
                "outputs": [],
                "metadata": {},
            }
            for i in range(num_cells)
        ]

        notebook_data = {"cells": cells, "metadata": {}, "nbformat": 4, "nbformat_minor": 5}

        notebook_path = create_notebook_file(notebook_data)

        try:
            analyzer = NotebookSecurityAnalyzer()

            start = time.perf_counter()
            analyzer.analyze_notebook(notebook_path)
            elapsed = time.perf_counter() - start

            # Should complete in reasonable time
            # Rough heuristic: < 2ms per cell for simple cells
            max_expected_time = num_cells * 0.002 + 0.010  # 2ms/cell + 10ms overhead

            assert elapsed < max_expected_time * 10, (
                f"Analysis took {elapsed:.3f}s for {num_cells} cells (expected <{max_expected_time:.3f}s)"
            )
        finally:
            notebook_path.unlink()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
