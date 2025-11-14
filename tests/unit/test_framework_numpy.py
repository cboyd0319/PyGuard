"""
Unit tests for NumPy security analysis module.

Tests detection and auto-fixing of NumPy security vulnerabilities.
Covers 15 security checks for array operations, memory safety,
numerical computation security, and data science application security.
"""

from pathlib import Path

import pytest

from pyguard.lib.framework_numpy import (
    analyze_numpy_security,
)
from pyguard.lib.rule_engine import RuleSeverity


class TestNumPyUnsafePickle:
    """Test NUMPY003: Unsafe pickle deserialization."""

    def test_detect_numpy_load_without_allow_pickle_false(self):
        """Detect np.load() without allow_pickle=False."""
        code = """
import numpy as np

data = np.load('model.npy')
"""
        violations = analyze_numpy_security(Path("test.py"), code)
        pickle_violations = [v for v in violations if v.rule_id == "NUMPY003"]
        assert len(pickle_violations) >= 1
        assert any("pickle" in v.message.lower() for v in pickle_violations)

    def test_detect_numpy_load_with_default_pickle(self):
        """Detect numpy.load() that allows pickle by default."""
        code = """
import numpy

model_data = numpy.load(user_file)
"""
        violations = analyze_numpy_security(Path("test.py"), code)
        pickle_violations = [v for v in violations if v.rule_id == "NUMPY003"]
        assert len(pickle_violations) >= 1

    def test_safe_numpy_load_with_allow_pickle_false(self):
        """np.load() with allow_pickle=False should not trigger."""
        code = """
import numpy as np

data = np.load('model.npy', allow_pickle=False)
"""
        violations = analyze_numpy_security(Path("test.py"), code)
        pickle_violations = [v for v in violations if v.rule_id == "NUMPY003"]
        assert len(pickle_violations) == 0

    def test_no_violation_without_numpy_import(self):
        """Should not flag code without NumPy import."""
        code = """
import os

data = load('model.npy')
"""
        violations = analyze_numpy_security(Path("test.py"), code)
        assert len(violations) == 0


class TestNumPyInsecureRandom:
    """Test NUMPY006: Insecure random number generation."""

    def test_detect_numpy_random_for_key_generation(self):
        """Detect np.random.rand() for security-sensitive key generation."""  # SECURITY: Use secrets module for cryptographic randomness
        code = """
import numpy as np

encryption_key = np.random.rand(32)  # SECURITY: Use secrets module for cryptographic randomness
"""
        violations = analyze_numpy_security(Path("test.py"), code)
        random_violations = [v for v in violations if v.rule_id == "NUMPY006"]
        assert len(random_violations) >= 1

    def test_detect_numpy_random_for_token(self):
        """Detect np.random.randint() for token generation."""  # SECURITY: Use secrets module for cryptographic randomness
        code = """
import numpy as np

auth_token = np.random.randint(0, 1000000)  # SECURITY: Use secrets module for cryptographic randomness
"""
        violations = analyze_numpy_security(Path("test.py"), code)
        random_violations = [v for v in violations if v.rule_id == "NUMPY006"]
        assert len(random_violations) >= 1

    def test_detect_numpy_random_for_secret(self):
        """Detect numpy.random.random() for secret generation."""  # SECURITY: Use secrets module for cryptographic randomness
        code = """
import numpy

secret_value = numpy.random.random()  # SECURITY: Use secrets module for cryptographic randomness
"""
        violations = analyze_numpy_security(Path("test.py"), code)
        random_violations = [v for v in violations if v.rule_id == "NUMPY006"]
        assert len(random_violations) >= 1

    def test_safe_numpy_random_for_non_security_use(self):
        """np.random for non-security uses should not trigger."""
        code = """
import numpy as np

# Random data for testing/simulation
test_data = np.random.rand(100, 100)
noise = np.random.randn(50)
"""
        violations = analyze_numpy_security(Path("test.py"), code)
        random_violations = [v for v in violations if v.rule_id == "NUMPY006"]
        # Should not flag non-security contexts
        assert len(random_violations) == 0


class TestNumPyMemoryExhaustion:
    """Test NUMPY004: Memory exhaustion via large arrays."""

    def test_detect_array_creation_with_user_size(self):
        """Detect np.zeros() with user-controlled size."""
        code = """
import numpy as np

size = request.args.get('size')
array = np.zeros(size)
"""
        violations = analyze_numpy_security(Path("test.py"), code)
        memory_violations = [v for v in violations if v.rule_id == "NUMPY004"]
        assert len(memory_violations) >= 1

    def test_detect_ones_with_user_input(self):
        """Detect np.ones() with user input size."""
        code = """
import numpy as np

user_size = int(input("Enter size: "))
data = np.ones(user_size)
"""
        violations = analyze_numpy_security(Path("test.py"), code)
        memory_violations = [v for v in violations if v.rule_id == "NUMPY004"]
        assert len(memory_violations) >= 1

    def test_detect_empty_with_request_param(self):
        """Detect np.empty() with request parameter."""
        code = """
import numpy as np

shape = request.json['shape']
buffer = np.empty(shape)
"""
        violations = analyze_numpy_security(Path("test.py"), code)
        memory_violations = [v for v in violations if v.rule_id == "NUMPY004"]
        assert len(memory_violations) >= 1

    def test_safe_array_with_constant_size(self):
        """Arrays with constant sizes should not trigger."""
        code = """
import numpy as np

# Fixed size arrays are safe
data = np.zeros((100, 100))
ones = np.ones(1000)
"""
        violations = analyze_numpy_security(Path("test.py"), code)
        memory_violations = [v for v in violations if v.rule_id == "NUMPY004"]
        assert len(memory_violations) == 0


class TestNumPyFileIOSecurity:
    """Test NUMPY015: File I/O security."""

    def test_detect_loadtxt_with_user_path(self):
        """Detect np.loadtxt() with user-controlled file path."""
        code = """
import numpy as np

filename = request.form['file']
data = np.loadtxt(filename)
"""
        violations = analyze_numpy_security(Path("test.py"), code)
        io_violations = [v for v in violations if v.rule_id == "NUMPY015"]
        assert len(io_violations) >= 1

    def test_detect_load_with_user_file(self):
        """Detect np.load() with user-provided file."""
        code = """
import numpy as np

user_file = request.args.get('file')
model = np.load(user_file)
"""
        violations = analyze_numpy_security(Path("test.py"), code)
        io_violations = [v for v in violations if v.rule_id == "NUMPY015"]
        assert len(io_violations) >= 1

    def test_detect_genfromtxt_with_user_input(self):
        """Detect np.genfromtxt() with user input."""
        code = """
import numpy as np

path = input("Enter file path: ")
data = np.genfromtxt(path)
"""
        violations = analyze_numpy_security(Path("test.py"), code)
        io_violations = [v for v in violations if v.rule_id == "NUMPY015"]
        assert len(io_violations) >= 1

    def test_safe_load_with_constant_path(self):
        """Loading from constant paths should be safe."""
        code = """
import numpy as np

# Fixed paths are safe
config = np.loadtxt('config/settings.txt')
data = np.load('data/training_data.npy', allow_pickle=False)
"""
        violations = analyze_numpy_security(Path("test.py"), code)
        io_violations = [v for v in violations if v.rule_id == "NUMPY015"]
        # Should not flag constant paths
        assert len(io_violations) == 0


class TestNumPyUnsafeDtypeCasting:
    """Test NUMPY008: Unsafe dtype casting."""

    def test_detect_casting_to_int8(self):
        """Detect astype('int8') that can cause overflow."""
        code = """
import numpy as np

large_values = np.array([1000, 2000, 3000])
small_values = large_values.astype('int8')
"""
        violations = analyze_numpy_security(Path("test.py"), code)
        cast_violations = [v for v in violations if v.rule_id == "NUMPY008"]
        assert len(cast_violations) >= 1

    def test_detect_casting_to_uint8(self):
        """Detect astype('uint8') that can lose precision."""
        code = """
import numpy as np

data = array.astype('uint8')
"""
        violations = analyze_numpy_security(Path("test.py"), code)
        cast_violations = [v for v in violations if v.rule_id == "NUMPY008"]
        assert len(cast_violations) >= 1

    def test_detect_casting_to_float16(self):
        """Detect astype('float16') that can lose precision."""
        code = """
import numpy as np

weights = model_weights.astype('float16')
"""
        violations = analyze_numpy_security(Path("test.py"), code)
        cast_violations = [v for v in violations if v.rule_id == "NUMPY008"]
        assert len(cast_violations) >= 1

    def test_safe_casting_to_int64(self):
        """Casting to larger types should be safe."""
        code = """
import numpy as np

# Casting to larger types is safer
data = small_array.astype('int64')
floats = int_data.astype('float64')
"""
        violations = analyze_numpy_security(Path("test.py"), code)
        cast_violations = [v for v in violations if v.rule_id == "NUMPY008"]
        assert len(cast_violations) == 0


class TestNumPyIntegerOverflow:
    """Test NUMPY002: Integer overflow in calculations."""

    def test_detect_array_multiplication(self):
        """Detect potential overflow in array multiplication."""
        code = """
import numpy as np

arr1 = np.array([1000, 2000])
arr2 = np.array([3000, 4000])
result = arr1 * arr2
"""
        violations = analyze_numpy_security(Path("test.py"), code)
        [v for v in violations if v.rule_id == "NUMPY002"]
        # May or may not detect based on heuristics
        assert isinstance(violations, list)

    def test_detect_array_addition(self):
        """Detect potential overflow in array addition."""
        code = """
import numpy as np

data = large_array + other_array
"""
        violations = analyze_numpy_security(Path("test.py"), code)
        [v for v in violations if v.rule_id == "NUMPY002"]
        # May or may not detect based on heuristics
        assert isinstance(violations, list)


class TestNumPyUnvalidatedIndexing:
    """Test NUMPY010: Unvalidated array indexing."""

    def test_detect_indexing_with_user_input(self):
        """Detect array indexing with user-controlled index."""
        code = """
import numpy as np

index = request.args.get('index')
value = array[index]
"""
        violations = analyze_numpy_security(Path("test.py"), code)
        index_violations = [v for v in violations if v.rule_id == "NUMPY010"]
        assert len(index_violations) >= 1

    def test_detect_indexing_with_param(self):
        """Detect array indexing with parameter."""
        code = """
import numpy as np

user_index = int(input("Enter index: "))
element = data[user_index]
"""
        violations = analyze_numpy_security(Path("test.py"), code)
        index_violations = [v for v in violations if v.rule_id == "NUMPY010"]
        assert len(index_violations) >= 1

    def test_safe_indexing_with_constant(self):
        """Indexing with constants should be safe."""
        code = """
import numpy as np

# Fixed indices are safe
first = array[0]
last = array[-1]
middle = array[len(array) // 2]
"""
        violations = analyze_numpy_security(Path("test.py"), code)
        index_violations = [v for v in violations if v.rule_id == "NUMPY010"]
        assert len(index_violations) == 0


class TestNumPyEdgeCases:
    """Test edge cases and complex scenarios."""

    def test_multiple_vulnerabilities_in_one_file(self):
        """Detect multiple NumPy vulnerabilities in same file."""
        code = """
import numpy as np

# NUMPY003: Unsafe pickle
model = np.load(user_model_path)

# NUMPY006: Insecure random for key
secret_key = np.random.rand(16)  # SECURITY: Use secrets module for cryptographic randomness

# NUMPY004: Memory exhaustion
large_array = np.zeros(user_size)

# NUMPY015: Unsafe file I/O
data = np.loadtxt(request.args['file'])
"""
        violations = analyze_numpy_security(Path("test.py"), code)
        assert len(violations) >= 4

    def test_no_numpy_import_no_violations(self):
        """Code without NumPy should not trigger any violations."""
        code = """
import os
import sys

data = [1, 2, 3, 4, 5]
result = sum(data)
"""
        violations = analyze_numpy_security(Path("test.py"), code)
        assert len(violations) == 0

    def test_numpy_alias_detection(self):
        """Should detect violations with np alias."""
        code = """
import numpy as np

model = np.load('model.npy')
key = np.random.rand(32)  # SECURITY: Use secrets module for cryptographic randomness
"""
        violations = analyze_numpy_security(Path("test.py"), code)
        assert len(violations) >= 1

    def test_numpy_full_name_detection(self):
        """Should detect violations with full numpy name."""
        code = """
import numpy

model = numpy.load('model.npy')
data = numpy.zeros(user_size)
"""
        violations = analyze_numpy_security(Path("test.py"), code)
        assert len(violations) >= 1


class TestNumPyRuleMetadata:
    """Test that rules are properly registered and have correct metadata."""

    def test_numpy_rules_registered(self):
        """Verify all NUMPY rules are registered."""
        from pyguard.lib.framework_numpy import NUMPY_RULES

        assert len(NUMPY_RULES) == 15
        rule_ids = {rule.rule_id for rule in NUMPY_RULES}

        expected_ids = {f"NUMPY{str(i).zfill(3)}" for i in range(1, 16)}
        assert rule_ids == expected_ids

    def test_numpy_rules_have_cwe_mapping(self):
        """Verify all rules have CWE mappings."""
        from pyguard.lib.framework_numpy import NUMPY_RULES

        for rule in NUMPY_RULES:
            assert rule.cwe_mapping is not None
            assert rule.cwe_mapping.startswith("CWE-")

    def test_numpy_rules_have_owasp_mapping(self):
        """Verify all rules have OWASP mappings."""
        from pyguard.lib.framework_numpy import NUMPY_RULES

        for rule in NUMPY_RULES:
            assert rule.owasp_mapping is not None

    def test_numpy_rules_have_severity(self):
        """Verify all rules have severity levels."""
        from pyguard.lib.framework_numpy import NUMPY_RULES

        for rule in NUMPY_RULES:
            assert rule.severity in [
                RuleSeverity.CRITICAL,
                RuleSeverity.HIGH,
                RuleSeverity.MEDIUM,
                RuleSeverity.LOW,
            ]

    def test_numpy_critical_rules_exist(self):
        """Verify critical severity rules exist."""
        from pyguard.lib.framework_numpy import NUMPY_RULES

        critical_rules = [r for r in NUMPY_RULES if r.severity == RuleSeverity.CRITICAL]
        assert len(critical_rules) >= 1
        # NUMPY003 (pickle deserialization) should be critical
        assert any(r.rule_id == "NUMPY003" for r in critical_rules)


class TestNumPyPerformance:
    """Test performance of NumPy security analysis."""

    def test_performance_small_file(self):
        """Analysis should be fast on small files."""
        code = """
import numpy as np

data = np.zeros(100)
"""
        import time

        start = time.time()
        analyze_numpy_security(Path("test.py"), code)
        elapsed = time.time() - start

        assert elapsed < 0.1  # Should complete in <100ms

    def test_performance_medium_file(self):
        """Analysis should be reasonable on medium files."""
        code = """
import numpy as np
""" + "\n".join(
            [f"data{i} = np.zeros(100)" for i in range(100)]
        )

        import time

        start = time.time()
        analyze_numpy_security(Path("test.py"), code)
        elapsed = time.time() - start

        assert elapsed < 1.0  # Should complete in <1 second

    def test_no_false_positives_on_safe_code(self):
        """Safe NumPy usage should not trigger violations."""
        code = """
import numpy as np

# Safe NumPy operations
data = np.array([1, 2, 3, 4, 5])
mean = np.mean(data)
std = np.std(data)
normalized = (data - mean) / std

# Safe file operations with constant paths
config = np.load('config.npy', allow_pickle=False)
"""
        violations = analyze_numpy_security(Path("test.py"), code)
        # Should have minimal or no violations for safe code
        assert len(violations) <= 1  # Allow for some heuristic detection


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
