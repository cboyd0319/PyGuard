#!/usr/bin/env python3
"""
Performance benchmarks for PyGuard Jupyter notebook security analysis.

This module provides benchmarks to validate that PyGuard meets the world-class
performance targets outlined in PYGUARD_JUPYTER_SECURITY_ENGINEER.md:

- Sub-100ms analysis for small notebooks (< 10 cells)
- Linear scaling to 1000+ cells
- Streaming analysis for large outputs

Usage:
    python -m benchmarks.notebook_performance
    
    # Or with pytest-benchmark:
    pytest benchmarks/notebook_performance.py --benchmark-only
"""

import json
import tempfile
import time
from pathlib import Path
from typing import Dict, List

try:
    import pytest
    PYTEST_AVAILABLE = True
except ImportError:
    PYTEST_AVAILABLE = False

from pyguard.lib.notebook_security import NotebookSecurityAnalyzer, scan_notebook


def create_test_notebook(num_cells: int, cell_complexity: str = "simple") -> Path:
    """
    Create a test notebook with specified number of cells and complexity.
    
    Args:
        num_cells: Number of code cells to create
        cell_complexity: "simple", "medium", or "complex"
        
    Returns:
        Path to temporary notebook file
    """
    cells = []
    
    for i in range(num_cells):
        if cell_complexity == "simple":
            source = [
                f"# Cell {i}\n",
                f"x = {i}\n",
                f"print(x)\n"
            ]
        elif cell_complexity == "medium":
            source = [
                f"# Cell {i} - Medium complexity\n",
                f"import numpy as np\n",
                f"data = np.random.rand(100)\n",
                f"result = data.mean()\n",
                f"print(f'Result: {{result}}')\n"
            ]
        else:  # complex
            source = [
                f"# Cell {i} - Complex\n",
                f"import torch\n",
                f"import pandas as pd\n",
                f"model = torch.nn.Linear(10, 1)\n",
                f"df = pd.DataFrame(np.random.rand(1000, 10))\n",
                f"output = model(torch.tensor(df.values, dtype=torch.float32))\n",
                f"print(f'Output shape: {{output.shape}}')\n"
            ]
        
        cells.append({
            "cell_type": "code",
            "execution_count": i + 1,
            "source": source,
            "outputs": [],
            "metadata": {}
        })
    
    notebook = {
        "cells": cells,
        "metadata": {
            "kernelspec": {
                "display_name": "Python 3",
                "language": "python",
                "name": "python3"
            }
        },
        "nbformat": 4,
        "nbformat_minor": 5
    }
    
    # Write to temp file
    temp_file = tempfile.NamedTemporaryFile(
        mode='w', suffix='.ipynb', delete=False, encoding='utf-8'
    )
    json.dump(notebook, temp_file, indent=2)
    temp_file.close()
    
    return Path(temp_file.name)


def benchmark_analysis(num_cells: int, complexity: str = "simple") -> Dict[str, float]:
    """
    Benchmark analysis for a notebook with specified parameters.
    
    Args:
        num_cells: Number of cells in test notebook
        complexity: Cell complexity level
        
    Returns:
        Dictionary with timing metrics
    """
    # Create test notebook
    notebook_path = create_test_notebook(num_cells, complexity)
    
    try:
        # Warm up (first run may involve imports, caching, etc.)
        analyzer = NotebookSecurityAnalyzer()
        _ = analyzer.analyze_notebook(notebook_path)
        
        # Actual timed run
        start_time = time.perf_counter()
        analyzer = NotebookSecurityAnalyzer()
        issues = analyzer.analyze_notebook(notebook_path)
        end_time = time.perf_counter()
        
        elapsed_ms = (end_time - start_time) * 1000
        
        return {
            "num_cells": num_cells,
            "complexity": complexity,
            "elapsed_ms": elapsed_ms,
            "ms_per_cell": elapsed_ms / num_cells if num_cells > 0 else 0,
            "issues_found": len(issues),
        }
    finally:
        # Cleanup
        notebook_path.unlink()


def run_benchmark_suite() -> List[Dict[str, float]]:
    """
    Run complete benchmark suite and return results.
    
    Returns:
        List of benchmark results
    """
    results = []
    
    # Test different notebook sizes
    test_configs = [
        (5, "simple"),     # Small notebook
        (10, "simple"),    # Target size for <100ms
        (25, "simple"),    # Medium notebook
        (50, "medium"),    # Medium-large
        (100, "medium"),   # Large notebook
        (10, "complex"),   # Complex cells
    ]
    
    print("=" * 70)
    print("PyGuard Jupyter Notebook Security - Performance Benchmarks")
    print("=" * 70)
    print(f"Target: <100ms for notebooks with <10 cells")
    print(f"Target: Linear scaling for larger notebooks")
    print("=" * 70)
    print()
    
    for num_cells, complexity in test_configs:
        print(f"Benchmarking {num_cells} cells ({complexity})...", end=" ")
        result = benchmark_analysis(num_cells, complexity)
        results.append(result)
        
        # Determine if target met
        status = ""
        if num_cells < 10 and result["elapsed_ms"] < 100:
            status = "✅ PASS"
        elif num_cells < 10:
            status = "⚠️ SLOW"
        else:
            status = "📊 INFO"
        
        print(f"{result['elapsed_ms']:.2f}ms ({result['ms_per_cell']:.2f}ms/cell) {status}")
    
    print()
    print("=" * 70)
    print("Summary")
    print("=" * 70)
    
    # Calculate averages
    small_notebooks = [r for r in results if r["num_cells"] < 10]
    if small_notebooks:
        avg_small = sum(r["elapsed_ms"] for r in small_notebooks) / len(small_notebooks)
        print(f"Average for <10 cells: {avg_small:.2f}ms")
        if avg_small < 100:
            print("✅ Target achieved: <100ms for small notebooks")
        else:
            print(f"⚠️ Target missed: {avg_small:.2f}ms (target: <100ms)")
    
    # Check linearity
    if len(results) >= 3:
        print(f"\nScaling characteristics:")
        for i, result in enumerate(results):
            print(f"  {result['num_cells']:3d} cells: {result['elapsed_ms']:7.2f}ms "
                  f"({result['ms_per_cell']:.2f}ms/cell)")
    
    print("=" * 70)
    
    return results


# Pytest-benchmark integration (if pytest available)
if PYTEST_AVAILABLE:
    @pytest.mark.benchmark
    def test_benchmark_small_notebook(benchmark):
        """Benchmark analysis of small notebook (< 10 cells)."""
        notebook_path = create_test_notebook(5, "simple")
        try:
            analyzer = NotebookSecurityAnalyzer()
            result = benchmark(analyzer.analyze_notebook, notebook_path)
            # Target: <100ms for small notebooks
            assert benchmark.stats.mean < 0.1, "Analysis took too long for small notebook"
        finally:
            notebook_path.unlink()
    
    @pytest.mark.benchmark
    def test_benchmark_medium_notebook(benchmark):
        """Benchmark analysis of medium notebook (~50 cells)."""
        notebook_path = create_test_notebook(50, "medium")
        try:
            analyzer = NotebookSecurityAnalyzer()
            result = benchmark(analyzer.analyze_notebook, notebook_path)
            # Should complete in reasonable time
            assert benchmark.stats.mean < 1.0, "Analysis took too long for medium notebook"
        finally:
            notebook_path.unlink()
    
    @pytest.mark.benchmark
    def test_benchmark_large_notebook(benchmark):
        """Benchmark analysis of large notebook (~100 cells)."""
        notebook_path = create_test_notebook(100, "medium")
        try:
            analyzer = NotebookSecurityAnalyzer()
            result = benchmark(analyzer.analyze_notebook, notebook_path)
            # Should scale linearly
            assert benchmark.stats.mean < 5.0, "Analysis took too long for large notebook"
        finally:
            notebook_path.unlink()


def main():
    """Run benchmark suite if executed directly."""
    results = run_benchmark_suite()
    
    # Write results to file for tracking
    results_file = Path(__file__).parent / "benchmark_results.json"
    with open(results_file, 'w') as f:
        json.dump({
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "results": results
        }, f, indent=2)
    print(f"\nResults saved to: {results_file}")


if __name__ == "__main__":
    main()
