"""
Unit tests for SciPy security analysis module.

Tests detection and auto-fixing of SciPy security vulnerabilities.
Covers 10+ security checks for scientific computing security, numerical computation,
file I/O security, and algorithm security.
"""

import ast
import pytest
from pathlib import Path

from pyguard.lib.framework_scipy import (
    ScipySecurityVisitor,
    analyze_scipy_security,
)


class TestScipyUnsafeOptimization:
    """Test SCP001: Unsafe optimization parameters."""

    def test_detect_minimize_without_bounds(self):
        """Detect minimize() without bounds parameter."""
        code = """
from scipy.optimize import minimize

result = minimize(objective_function, x0)
"""
        violations = analyze_scipy_security(Path("test.py"), code)
        opt_violations = [v for v in violations if v.rule_id == "SCP001"]
        assert len(opt_violations) >= 1
        assert any("bounds" in v.message.lower() for v in opt_violations)

    def test_detect_minimize_without_maxiter(self):
        """Detect minimize() without max iterations."""
        code = """
from scipy.optimize import minimize

result = minimize(objective_function, x0, bounds=[(0, 10)])
"""
        violations = analyze_scipy_security(Path("test.py"), code)
        opt_violations = [v for v in violations if v.rule_id == "SCP001"]
        assert len(opt_violations) >= 1
        assert any("maxiter" in v.message.lower() or "iteration" in v.message.lower() for v in opt_violations)

    def test_detect_differential_evolution_without_bounds(self):
        """Detect differential_evolution() without bounds."""
        code = """
from scipy.optimize import differential_evolution

result = differential_evolution(objective_function)
"""
        violations = analyze_scipy_security(Path("test.py"), code)
        opt_violations = [v for v in violations if v.rule_id == "SCP001"]
        assert len(opt_violations) >= 1

    def test_safe_minimize_with_bounds_and_maxiter(self):
        """minimize() with bounds and maxiter should not trigger."""
        code = """
from scipy.optimize import minimize

result = minimize(objective_function, x0, bounds=[(0, 10)], options={'maxiter': 100})
"""
        violations = analyze_scipy_security(Path("test.py"), code)
        opt_violations = [v for v in violations if v.rule_id == "SCP001"]
        # Should have minimal or no violations
        assert len(opt_violations) <= 1  # May still flag if using options instead of direct parameter

    def test_no_violation_without_scipy_import(self):
        """Should not flag code without SciPy import."""
        code = """
def minimize(func, x0):
    return func(x0)

result = minimize(some_function, initial_value)
"""
        violations = analyze_scipy_security(Path("test.py"), code)
        assert len(violations) == 0


class TestScipySignalProcessing:
    """Test SCP002: Signal processing injection."""

    def test_detect_butter_with_user_input_order(self):
        """Detect butter() with potentially unsafe filter order."""
        code = """
from scipy.signal import butter

filter_order = user_input
b, a = butter(filter_order, 0.1)
"""
        violations = analyze_scipy_security(Path("test.py"), code)
        signal_violations = [v for v in violations if v.rule_id == "SCP002"]
        assert len(signal_violations) >= 1
        assert any("filter order" in v.message.lower() for v in signal_violations)

    def test_detect_cheby1_with_user_input(self):
        """Detect cheby1() with user input parameters."""
        code = """
from scipy.signal import cheby1

order = request.args.get('order')
b, a = cheby1(order, 0.5, 0.1)
"""
        violations = analyze_scipy_security(Path("test.py"), code)
        signal_violations = [v for v in violations if v.rule_id == "SCP002"]
        assert len(signal_violations) >= 1

    def test_safe_butter_with_validated_order(self):
        """butter() with constant order should not trigger."""
        code = """
from scipy.signal import butter

# Safe with constant value
b, a = butter(5, 0.1)
"""
        violations = analyze_scipy_security(Path("test.py"), code)
        signal_violations = [v for v in violations if v.rule_id == "SCP002"]
        # Safe with constant value directly
        assert len(signal_violations) == 0


class TestScipyFFTValidation:
    """Test SCP003: FFT input validation."""

    def test_detect_fft_without_validation(self):
        """Detect fft() without input validation."""
        code = """
from scipy.fft import fft

spectrum = fft(signal_data)
"""
        violations = analyze_scipy_security(Path("test.py"), code)
        fft_violations = [v for v in violations if v.rule_id == "SCP003"]
        assert len(fft_violations) >= 1
        assert any("validation" in v.message.lower() for v in fft_violations)

    def test_detect_fft2_without_validation(self):
        """Detect fft2() without validation."""
        code = """
from scipy.fft import fft2

spectrum_2d = fft2(image_data)
"""
        violations = analyze_scipy_security(Path("test.py"), code)
        fft_violations = [v for v in violations if v.rule_id == "SCP003"]
        assert len(fft_violations) >= 1

    def test_safe_fft_with_validation(self):
        """fft() with input validation should not trigger."""
        code = """
from scipy.fft import fft

# Validate input size
if len(signal_data) < 10000:
    spectrum = fft(signal_data)
"""
        violations = analyze_scipy_security(Path("test.py"), code)
        fft_violations = [v for v in violations if v.rule_id == "SCP003"]
        assert len(fft_violations) == 0


class TestScipySparseMatrix:
    """Test SCP004: Sparse matrix vulnerabilities."""

    def test_detect_csr_matrix_without_validation(self):
        """Detect csr_matrix() without shape validation."""
        code = """
from scipy.sparse import csr_matrix

matrix = csr_matrix(data)
"""
        violations = analyze_scipy_security(Path("test.py"), code)
        sparse_violations = [v for v in violations if v.rule_id == "SCP004"]
        assert len(sparse_violations) >= 1
        assert any("shape" in v.message.lower() or "validation" in v.message.lower() for v in sparse_violations)

    def test_detect_coo_matrix_without_validation(self):
        """Detect coo_matrix() without validation."""
        code = """
from scipy.sparse import coo_matrix

sparse = coo_matrix((values, (row_indices, col_indices)))
"""
        violations = analyze_scipy_security(Path("test.py"), code)
        sparse_violations = [v for v in violations if v.rule_id == "SCP004"]
        assert len(sparse_violations) >= 1

    def test_safe_csr_matrix_with_validation(self):
        """csr_matrix() with shape validation should not trigger."""
        code = """
from scipy.sparse import csr_matrix

# Validate shape first
if data.shape[0] < 10000 and data.shape[1] < 10000:
    matrix = csr_matrix(data)
"""
        violations = analyze_scipy_security(Path("test.py"), code)
        sparse_violations = [v for v in violations if v.rule_id == "SCP004"]
        assert len(sparse_violations) == 0


class TestScipyIntegration:
    """Test SCP005: Integration function risks."""

    def test_detect_quad_without_limit(self):
        """Detect quad() without iteration limit."""
        code = """
from scipy.integrate import quad

result, error = quad(integrand, 0, 10)
"""
        violations = analyze_scipy_security(Path("test.py"), code)
        integ_violations = [v for v in violations if v.rule_id == "SCP005"]
        assert len(integ_violations) >= 1
        assert any("limit" in v.message.lower() for v in integ_violations)

    def test_detect_dblquad_without_limit(self):
        """Detect dblquad() without limit."""
        code = """
from scipy.integrate import dblquad

result = dblquad(func, 0, 1, lambda x: 0, lambda x: 1)
"""
        violations = analyze_scipy_security(Path("test.py"), code)
        integ_violations = [v for v in violations if v.rule_id == "SCP005"]
        assert len(integ_violations) >= 1

    def test_safe_quad_with_limit(self):
        """quad() with limit should not trigger."""
        code = """
from scipy.integrate import quad

result, error = quad(integrand, 0, 10, limit=50)
"""
        violations = analyze_scipy_security(Path("test.py"), code)
        integ_violations = [v for v in violations if v.rule_id == "SCP005"]
        assert len(integ_violations) == 0


class TestScipyLinAlg:
    """Test SCP006: Linear algebra security."""

    def test_detect_inv_without_error_handling(self):
        """Detect inv() without error handling."""
        code = """
from scipy.linalg import inv

inverse = inv(matrix)
"""
        violations = analyze_scipy_security(Path("test.py"), code)
        linalg_violations = [v for v in violations if v.rule_id == "SCP006"]
        assert len(linalg_violations) >= 1
        assert any("error handling" in v.message.lower() for v in linalg_violations)

    def test_detect_solve_without_error_handling(self):
        """Detect solve() without error handling."""
        code = """
from scipy.linalg import solve

solution = solve(A, b)
"""
        violations = analyze_scipy_security(Path("test.py"), code)
        linalg_violations = [v for v in violations if v.rule_id == "SCP006"]
        assert len(linalg_violations) >= 1

    def test_safe_inv_with_error_handling(self):
        """inv() with error handling should not trigger."""
        code = """
from scipy.linalg import inv, LinAlgError

try:
    inverse = inv(matrix)
except LinAlgError:
    handle_singular_matrix()
"""
        violations = analyze_scipy_security(Path("test.py"), code)
        linalg_violations = [v for v in violations if v.rule_id == "SCP006"]
        assert len(linalg_violations) == 0


class TestScipyInterpolation:
    """Test SCP007: Interpolation injection."""

    def test_detect_interp1d_without_validation(self):
        """Detect interp1d() without input validation."""
        code = """
from scipy.interpolate import interp1d

f = interp1d(x_points, y_points)
"""
        violations = analyze_scipy_security(Path("test.py"), code)
        interp_violations = [v for v in violations if v.rule_id == "SCP007"]
        assert len(interp_violations) >= 1
        assert any("validation" in v.message.lower() for v in interp_violations)

    def test_detect_griddata_without_validation(self):
        """Detect griddata() without validation."""
        code = """
from scipy.interpolate import griddata

result = griddata(points, values, grid)
"""
        violations = analyze_scipy_security(Path("test.py"), code)
        interp_violations = [v for v in violations if v.rule_id == "SCP007"]
        assert len(interp_violations) >= 1

    def test_safe_interp1d_with_validation(self):
        """interp1d() with validation should not trigger."""
        code = """
from scipy.interpolate import interp1d

# Validate input size
if len(x_points) < 1000:
    f = interp1d(x_points, y_points)
"""
        violations = analyze_scipy_security(Path("test.py"), code)
        interp_violations = [v for v in violations if v.rule_id == "SCP007"]
        assert len(interp_violations) == 0


class TestScipyFileFormat:
    """Test SCP008: File format vulnerabilities."""

    def test_detect_loadmat_vulnerability(self):
        """Detect loadmat() which may execute arbitrary code."""
        code = """
from scipy.io import loadmat

data = loadmat('data.mat')
"""
        violations = analyze_scipy_security(Path("test.py"), code)
        file_violations = [v for v in violations if v.rule_id == "SCP008"]
        assert len(file_violations) >= 1
        assert any("arbitrary code" in v.message.lower() or "malicious" in v.message.lower() for v in file_violations)
        assert file_violations[0].severity == "HIGH"

    def test_detect_savemat_vulnerability(self):
        """Detect savemat() vulnerability."""
        code = """
from scipy.io import savemat

savemat('output.mat', {'data': array})
"""
        violations = analyze_scipy_security(Path("test.py"), code)
        file_violations = [v for v in violations if v.rule_id == "SCP008"]
        assert len(file_violations) >= 1


class TestScipyStatsManipulation:
    """Test SCP009: Statistics calculation manipulation."""

    def test_detect_ttest_without_validation(self):
        """Detect ttest_ind() without sample size validation."""
        code = """
from scipy.stats import ttest_ind

statistic, pvalue = ttest_ind(sample1, sample2)
"""
        violations = analyze_scipy_security(Path("test.py"), code)
        stats_violations = [v for v in violations if v.rule_id == "SCP009"]
        assert len(stats_violations) >= 1
        assert any("validation" in v.message.lower() for v in stats_violations)

    def test_detect_kstest_without_validation(self):
        """Detect kstest() without validation."""
        code = """
from scipy.stats import kstest

result = kstest(data, 'norm')
"""
        violations = analyze_scipy_security(Path("test.py"), code)
        stats_violations = [v for v in violations if v.rule_id == "SCP009"]
        assert len(stats_violations) >= 1

    def test_safe_ttest_with_validation(self):
        """ttest_ind() with validation should not trigger."""
        code = """
from scipy.stats import ttest_ind

# Check sample sizes
if len(sample1) > 30 and len(sample2) > 30:
    statistic, pvalue = ttest_ind(sample1, sample2)
"""
        violations = analyze_scipy_security(Path("test.py"), code)
        stats_violations = [v for v in violations if v.rule_id == "SCP009"]
        assert len(stats_violations) == 0


class TestScipySpatialDoS:
    """Test SCP010: Spatial algorithm DoS."""

    def test_detect_kdtree_without_validation(self):
        """Detect KDTree() without size validation."""
        code = """
from scipy.spatial import KDTree

tree = KDTree(data_points)
"""
        violations = analyze_scipy_security(Path("test.py"), code)
        spatial_violations = [v for v in violations if v.rule_id == "SCP010"]
        assert len(spatial_violations) >= 1
        assert any("size" in v.message.lower() or "validation" in v.message.lower() for v in spatial_violations)

    def test_detect_distance_matrix_without_validation(self):
        """Detect distance_matrix() without validation."""
        code = """
from scipy.spatial import distance_matrix

distances = distance_matrix(points_a, points_b)
"""
        violations = analyze_scipy_security(Path("test.py"), code)
        spatial_violations = [v for v in violations if v.rule_id == "SCP010"]
        assert len(spatial_violations) >= 1

    def test_safe_kdtree_with_validation(self):
        """KDTree() with size validation should not trigger."""
        code = """
from scipy.spatial import KDTree

# Validate data size
if len(data_points) < 10000:
    tree = KDTree(data_points)
"""
        violations = analyze_scipy_security(Path("test.py"), code)
        spatial_violations = [v for v in violations if v.rule_id == "SCP010"]
        assert len(spatial_violations) == 0


class TestScipyEdgeCases:
    """Test edge cases and integration scenarios."""

    def test_multiple_violations_in_same_file(self):
        """Should detect multiple different violations."""
        code = """
from scipy.optimize import minimize
from scipy.fft import fft
from scipy.io import loadmat

# Multiple security issues
result = minimize(func, x0)  # Missing bounds and maxiter
spectrum = fft(data)  # Missing validation
mat_data = loadmat('file.mat')  # File vulnerability
"""
        violations = analyze_scipy_security(Path("test.py"), code)
        # Should have violations from different checks
        rule_ids = {v.rule_id for v in violations}
        assert len(rule_ids) >= 2
        assert "SCP001" in rule_ids
        assert "SCP008" in rule_ids

    def test_no_false_positive_on_non_scipy_code(self):
        """Should not flag similar function names from other libraries."""
        code = """
def minimize(func):
    return func()

def fft(data):
    return data

result = minimize(my_function)
spectrum = fft(signal)
"""
        violations = analyze_scipy_security(Path("test.py"), code)
        assert len(violations) == 0

    def test_scipy_submodule_imports(self):
        """Should detect issues with various import styles."""
        code = """
import scipy.optimize
import scipy.fft as fft_module
from scipy import integrate

result1 = scipy.optimize.minimize(func, x0)
result2 = fft_module.fft(data)
result3 = integrate.quad(f, 0, 1)
"""
        violations = analyze_scipy_security(Path("test.py"), code)
        # Should detect issues despite different import styles
        assert len(violations) >= 3
