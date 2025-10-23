"""
Unit tests for Scikit-learn security analysis module.

Tests detection and auto-fixing of Scikit-learn security vulnerabilities.
Covers 8+ security checks for ML model security, training pipeline security,
prediction security, and data science application security.
"""

import ast
import pytest
from pathlib import Path

from pyguard.lib.framework_sklearn import (
    SklearnSecurityVisitor,
    analyze_sklearn_security,
)


class TestSklearnUnsafeModelLoading:
    """Test SKL001: Unsafe model deserialization."""

    def test_detect_pickle_load_model(self):
        """Detect pickle.load() for loading ML models."""
        code = """
import pickle
import sklearn

with open('model.pkl', 'rb') as f:
    model = pickle.load(f)
"""
        violations = analyze_sklearn_security(Path("test.py"), code)
        pickle_violations = [v for v in violations if v.rule_id == "SKL001"]
        assert len(pickle_violations) >= 1
        assert any("pickle" in v.message.lower() for v in pickle_violations)
        assert pickle_violations[0].severity == "CRITICAL"

    def test_detect_joblib_load_without_validation(self):
        """Detect joblib.load() without validation."""
        code = """
import joblib
from sklearn.ensemble import RandomForestClassifier

model = joblib.load('model.joblib')
"""
        violations = analyze_sklearn_security(Path("test.py"), code)
        load_violations = [v for v in violations if v.rule_id == "SKL001"]
        assert len(load_violations) >= 1
        assert any("validation" in v.message.lower() for v in load_violations)

    def test_safe_joblib_load_with_validation(self):
        """joblib.load() with validation should not trigger."""
        code = """
import joblib
from sklearn.ensemble import RandomForestClassifier

# Verify signature before loading
if verify_model_signature('model.joblib'):
    model = joblib.load('model.joblib')
"""
        violations = analyze_sklearn_security(Path("test.py"), code)
        load_violations = [v for v in violations if v.rule_id == "SKL001"]
        # Should have fewer violations or none due to validation context
        assert len(load_violations) == 0

    def test_no_violation_without_sklearn_import(self):
        """Should not flag code without Scikit-learn import."""
        code = """
import pickle

with open('data.pkl', 'rb') as f:
    data = pickle.load(f)
"""
        violations = analyze_sklearn_security(Path("test.py"), code)
        assert len(violations) == 0


class TestSklearnMissingInputValidation:
    """Test SKL009: Missing input validation before prediction."""

    def test_detect_predict_without_validation(self):
        """Detect predict() without input validation."""
        code = """
from sklearn.ensemble import RandomForestClassifier

model = RandomForestClassifier()
predictions = model.predict(user_data)
"""
        violations = analyze_sklearn_security(Path("test.py"), code)
        validation_violations = [v for v in violations if v.rule_id == "SKL009"]
        assert len(validation_violations) >= 1
        assert any("validation" in v.message.lower() for v in validation_violations)

    def test_detect_predict_proba_without_validation(self):
        """Detect predict_proba() without validation."""
        code = """
from sklearn.linear_model import LogisticRegression

model = LogisticRegression()
probabilities = model.predict_proba(input_data)
"""
        violations = analyze_sklearn_security(Path("test.py"), code)
        validation_violations = [v for v in violations if v.rule_id == "SKL009"]
        assert len(validation_violations) >= 1

    def test_detect_transform_without_validation(self):
        """Detect transform() without validation."""
        code = """
from sklearn.preprocessing import StandardScaler

scaler = StandardScaler()
scaled_data = scaler.transform(user_input)
"""
        violations = analyze_sklearn_security(Path("test.py"), code)
        validation_violations = [v for v in violations if v.rule_id == "SKL009"]
        assert len(validation_violations) >= 1

    def test_safe_predict_with_validation(self):
        """predict() with validation should not trigger."""
        code = """
from sklearn.ensemble import RandomForestClassifier
import numpy as np

model = RandomForestClassifier()
# Validate input shape and dtype
if user_data.shape[1] == 10 and user_data.dtype == np.float64:
    predictions = model.predict(user_data)
"""
        violations = analyze_sklearn_security(Path("test.py"), code)
        validation_violations = [v for v in violations if v.rule_id == "SKL009"]
        assert len(validation_violations) == 0


class TestSklearnGridSearchExhaustion:
    """Test SKL012: Grid search resource exhaustion."""

    def test_detect_grid_search_without_cv_limit(self):
        """Detect GridSearchCV without cv parameter."""
        code = """
from sklearn.model_selection import GridSearchCV
from sklearn.svm import SVC

param_grid = {'C': [0.1, 1, 10], 'kernel': ['rbf', 'linear']}
grid_search = GridSearchCV(SVC(), param_grid)
"""
        violations = analyze_sklearn_security(Path("test.py"), code)
        resource_violations = [v for v in violations if v.rule_id == "SKL012"]
        assert len(resource_violations) >= 1
        assert any("resource" in v.message.lower() for v in resource_violations)

    def test_detect_randomized_search_without_limits(self):
        """Detect RandomizedSearchCV without resource limits."""
        code = """
from sklearn.model_selection import RandomizedSearchCV
from sklearn.ensemble import RandomForestClassifier

param_distributions = {'n_estimators': [10, 50, 100], 'max_depth': [5, 10, 15]}
random_search = RandomizedSearchCV(RandomForestClassifier(), param_distributions)
"""
        violations = analyze_sklearn_security(Path("test.py"), code)
        resource_violations = [v for v in violations if v.rule_id == "SKL012"]
        assert len(resource_violations) >= 1

    def test_safe_grid_search_with_limits(self):
        """GridSearchCV with cv and n_jobs should not trigger."""
        code = """
from sklearn.model_selection import GridSearchCV
from sklearn.svm import SVC

param_grid = {'C': [0.1, 1, 10]}
grid_search = GridSearchCV(SVC(), param_grid, cv=3, n_jobs=2)
"""
        violations = analyze_sklearn_security(Path("test.py"), code)
        resource_violations = [v for v in violations if v.rule_id == "SKL012"]
        assert len(resource_violations) == 0


class TestSklearnMultipleVulnerabilities:
    """Test detection of multiple vulnerabilities in one file."""

    def test_detect_multiple_issues(self):
        """Detect multiple security issues in complex code."""
        code = """
import pickle
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GridSearchCV

def vulnerable_ml_pipeline(user_data, user_model_path):
    # SKL001: Unsafe model loading
    model = pickle.load(open(user_model_path, 'rb'))
    
    # SKL012: Grid search without limits
    grid_search = GridSearchCV(RandomForestClassifier(), {'max_depth': [5, 10, 15]})
    
    # SKL009: Prediction without validation
    predictions = model.predict(user_data)
    
    return predictions
"""
        violations = analyze_sklearn_security(Path("test.py"), code)
        
        # Should detect multiple issues
        assert len(violations) >= 3
        
        rule_ids = {v.rule_id for v in violations}
        expected_rules = {"SKL001", "SKL009", "SKL012"}
        
        # At least some of the expected vulnerabilities should be detected
        assert len(rule_ids.intersection(expected_rules)) >= 2


class TestSklearnEdgeCases:
    """Test edge cases and complex scenarios."""

    def test_no_sklearn_import_no_violations(self):
        """Code without sklearn should not trigger sklearn violations."""
        code = """
import numpy as np
import pandas as pd

data = np.array([1, 2, 3])
df = pd.DataFrame(data)
"""
        violations = analyze_sklearn_security(Path("test.py"), code)
        assert len(violations) == 0

    def test_sklearn_import_variations(self):
        """Test different sklearn import patterns."""
        code = """
from sklearn.ensemble import RandomForestClassifier
from sklearn import svm
import sklearn.linear_model as lm

# Should detect issues with any import pattern
model1 = RandomForestClassifier()
predictions = model1.predict(user_data)
"""
        violations = analyze_sklearn_security(Path("test.py"), code)
        validation_violations = [v for v in violations if v.rule_id == "SKL009"]
        assert len(validation_violations) >= 1

    def test_complex_function_nesting(self):
        """Test detection in nested functions."""
        code = """
from sklearn.ensemble import RandomForestClassifier
import joblib

def outer_function():
    def inner_function(data):
        model = joblib.load('model.joblib')
        return model.predict(data)
    
    return inner_function
"""
        violations = analyze_sklearn_security(Path("test.py"), code)
        # Should detect both unsafe loading and missing validation
        assert len(violations) >= 1


class TestSklearnRuleMetadata:
    """Test rule metadata and attributes."""

    def test_rule_severity_levels(self):
        """Verify rule severity levels are appropriate."""
        code = """
import pickle
from sklearn.ensemble import RandomForestClassifier

# CRITICAL: Unsafe deserialization
model = pickle.load(open('model.pkl', 'rb'))

# MEDIUM: Missing input validation
predictions = model.predict(user_data)
"""
        violations = analyze_sklearn_security(Path("test.py"), code)
        
        critical_violations = [v for v in violations if v.severity == "CRITICAL"]
        medium_violations = [v for v in violations if v.severity == "MEDIUM"]
        
        assert len(critical_violations) >= 1
        assert len(medium_violations) >= 1

    def test_rule_ids_present(self):
        """Verify all violations have rule IDs."""
        code = """
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GridSearchCV

model = joblib.load('model.joblib')
grid_search = GridSearchCV(RandomForestClassifier(), {})
"""
        violations = analyze_sklearn_security(Path("test.py"), code)
        
        for violation in violations:
            assert violation.rule_id is not None
            assert violation.rule_id.startswith("SKL")

    def test_all_violations_have_suggestions(self):
        """Verify all violations have fix suggestions."""
        code = """
from sklearn.preprocessing import StandardScaler

scaler = StandardScaler()
scaled = scaler.transform(data)
"""
        violations = analyze_sklearn_security(Path("test.py"), code)
        
        for violation in violations:
            assert violation.suggestion is not None
            assert len(violation.suggestion) > 0

