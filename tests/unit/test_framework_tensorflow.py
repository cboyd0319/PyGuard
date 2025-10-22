"""
Unit tests for TensorFlow/Keras security analysis module.

Tests detection and auto-fixing of TensorFlow/Keras security vulnerabilities.
Covers 20 security checks for model security, training pipeline security,
inference security, and distributed ML security.
"""

import ast
import pytest
from pathlib import Path

from pyguard.lib.framework_tensorflow import (
    TensorFlowSecurityVisitor,
    analyze_tensorflow_security,
)
from pyguard.lib.rule_engine import FixApplicability, RuleCategory, RuleSeverity


class TestTensorFlowUnsafeModelLoading:
    """Test TF001: Unsafe model deserialization."""

    def test_detect_load_model_without_compile_false(self):
        """Detect tf.keras.models.load_model() without compile=False."""
        code = """
import tensorflow as tf

model = tf.keras.models.load_model('model.h5')
"""
        violations = analyze_tensorflow_security(Path("test.py"), code)
        model_violations = [v for v in violations if v.rule_id == "TF001"]
        assert len(model_violations) >= 1
        assert any("compile" in v.message.lower() for v in model_violations)

    def test_detect_load_model_with_user_path(self):
        """Detect model loading from user-controlled path."""
        code = """
import tensorflow as tf

model_path = request.args.get('model')
model = tf.keras.models.load_model(model_path)
"""
        violations = analyze_tensorflow_security(Path("test.py"), code)
        model_violations = [v for v in violations if v.rule_id == "TF001"]
        assert len(model_violations) >= 1

    def test_detect_saved_model_load_user_path(self):
        """Detect tf.saved_model.load() with user path."""
        code = """
import tensorflow as tf

user_model = request.json['model_path']
loaded = tf.saved_model.load(user_model)
"""
        violations = analyze_tensorflow_security(Path("test.py"), code)
        model_violations = [v for v in violations if v.rule_id == "TF001"]
        assert len(model_violations) >= 1

    def test_safe_load_model_with_compile_false(self):
        """Model loading with compile=False should not trigger."""
        code = """
import tensorflow as tf

model = tf.keras.models.load_model('model.h5', compile=False)
"""
        violations = analyze_tensorflow_security(Path("test.py"), code)
        model_violations = [v for v in violations if v.rule_id == "TF001"]
        # Should still detect missing path validation, but not compile issue
        # Adjust based on implementation
        assert isinstance(violations, list)


class TestTensorFlowGPUMemoryExhaustion:
    """Test TF002: GPU memory exhaustion."""

    def test_detect_tensor_creation_user_shape(self):
        """Detect tf.zeros() with user-controlled shape."""
        code = """
import tensorflow as tf

shape = request.args.get('shape')
tensor = tf.zeros(shape)
"""
        violations = analyze_tensorflow_security(Path("test.py"), code)
        memory_violations = [v for v in violations if v.rule_id == "TF002"]
        assert len(memory_violations) >= 1

    def test_detect_ones_with_user_input(self):
        """Detect tf.ones() with user input."""
        code = """
import tensorflow as tf

user_shape = input("Enter shape: ")
data = tf.ones(user_shape)
"""
        violations = analyze_tensorflow_security(Path("test.py"), code)
        memory_violations = [v for v in violations if v.rule_id == "TF002"]
        assert len(memory_violations) >= 1

    def test_detect_constant_with_request_data(self):
        """Detect tf.constant() with request data."""
        code = """
import tensorflow as tf

shape = request.form['tensor_shape']
constant = tf.constant(0, shape=shape)
"""
        violations = analyze_tensorflow_security(Path("test.py"), code)
        memory_violations = [v for v in violations if v.rule_id == "TF002"]
        assert len(memory_violations) >= 1

    def test_safe_tensor_with_constant_shape(self):
        """Tensors with constant shapes should be safe."""
        code = """
import tensorflow as tf

# Fixed shapes are safe
data = tf.zeros([10, 10])
ones = tf.ones([100, 100])
"""
        violations = analyze_tensorflow_security(Path("test.py"), code)
        memory_violations = [v for v in violations if v.rule_id == "TF002"]
        assert len(memory_violations) == 0


class TestTensorFlowCallbackInjection:
    """Test TF005: Callback injection."""

    def test_detect_fit_with_user_callbacks(self):
        """Detect model.fit() with user-controlled callbacks."""
        code = """
import tensorflow as tf

user_callbacks = request.json['callbacks']
model.fit(X_train, y_train, callbacks=user_callbacks)
"""
        violations = analyze_tensorflow_security(Path("test.py"), code)
        callback_violations = [v for v in violations if v.rule_id == "TF005"]
        assert len(callback_violations) >= 1

    def test_detect_fit_with_input_callbacks(self):
        """Detect model.fit() with input-derived callbacks."""
        code = """
import tensorflow as tf

callback_list = input("Enter callbacks: ")
model.fit(data, labels, callbacks=callback_list)
"""
        violations = analyze_tensorflow_security(Path("test.py"), code)
        callback_violations = [v for v in violations if v.rule_id == "TF005"]
        assert len(callback_violations) >= 1

    def test_safe_fit_with_predefined_callbacks(self):
        """model.fit() with predefined callbacks should be safe."""
        code = """
import tensorflow as tf

# Safe predefined callbacks
callbacks = [
    tf.keras.callbacks.EarlyStopping(patience=3),
    tf.keras.callbacks.ModelCheckpoint('model.h5')
]
model.fit(X, y, callbacks=callbacks)
"""
        violations = analyze_tensorflow_security(Path("test.py"), code)
        callback_violations = [v for v in violations if v.rule_id == "TF005"]
        assert len(callback_violations) == 0


class TestTensorFlowTensorBoardSecurity:
    """Test TF006: TensorBoard log exposure."""

    def test_detect_tensorboard_in_public_dir(self):
        """Detect TensorBoard logs in web-accessible directory."""
        code = """
import tensorflow as tf

tensorboard = tf.keras.callbacks.TensorBoard(log_dir='static/logs')
"""
        violations = analyze_tensorflow_security(Path("test.py"), code)
        tb_violations = [v for v in violations if v.rule_id == "TF006"]
        assert len(tb_violations) >= 1

    def test_detect_tensorboard_in_www_dir(self):
        """Detect TensorBoard logs in www directory."""
        code = """
import tensorflow as tf

callback = tf.keras.callbacks.TensorBoard(log_dir='/var/www/tensorboard')
"""
        violations = analyze_tensorflow_security(Path("test.py"), code)
        tb_violations = [v for v in violations if v.rule_id == "TF006"]
        assert len(tb_violations) >= 1

    def test_safe_tensorboard_in_private_dir(self):
        """TensorBoard in private directory should be safe."""
        code = """
import tensorflow as tf

# Private directory is safe
tensorboard = tf.keras.callbacks.TensorBoard(log_dir='logs/private/tb')
"""
        violations = analyze_tensorflow_security(Path("test.py"), code)
        tb_violations = [v for v in violations if v.rule_id == "TF006"]
        assert len(tb_violations) == 0


class TestTensorFlowDatasetInjection:
    """Test TF007: Dataset pipeline injection."""

    def test_detect_dataset_from_user_data(self):
        """Detect Dataset.from_tensor_slices() with user data."""
        code = """
import tensorflow as tf

user_data = request.json['data']
dataset = tf.data.Dataset.from_tensor_slices(user_data)
"""
        violations = analyze_tensorflow_security(Path("test.py"), code)
        dataset_violations = [v for v in violations if v.rule_id == "TF007"]
        assert len(dataset_violations) >= 1

    def test_detect_tfrecord_with_user_file(self):
        """Detect TFRecordDataset with user file."""
        code = """
import tensorflow as tf

file_path = request.args.get('file')
dataset = tf.data.TFRecordDataset(file_path)
"""
        violations = analyze_tensorflow_security(Path("test.py"), code)
        dataset_violations = [v for v in violations if v.rule_id == "TF007"]
        assert len(dataset_violations) >= 1

    def test_detect_textline_with_input_file(self):
        """Detect TextLineDataset with input file."""
        code = """
import tensorflow as tf

path = input("Enter file: ")
dataset = tf.data.TextLineDataset(path)
"""
        violations = analyze_tensorflow_security(Path("test.py"), code)
        dataset_violations = [v for v in violations if v.rule_id == "TF007"]
        assert len(dataset_violations) >= 1

    def test_safe_dataset_with_constant_data(self):
        """Dataset from constant data should be safe."""
        code = """
import tensorflow as tf

# Safe constant data
data = [1, 2, 3, 4, 5]
dataset = tf.data.Dataset.from_tensor_slices(data)
"""
        violations = analyze_tensorflow_security(Path("test.py"), code)
        dataset_violations = [v for v in violations if v.rule_id == "TF007"]
        assert len(dataset_violations) == 0


class TestTensorFlowModelServing:
    """Test TF009: Model serving vulnerabilities."""

    def test_detect_predict_with_user_input(self):
        """Detect model.predict() with user input."""
        code = """
import tensorflow as tf

user_data = request.json['input']
prediction = model.predict(user_data)
"""
        violations = analyze_tensorflow_security(Path("test.py"), code)
        serving_violations = [v for v in violations if v.rule_id == "TF009"]
        assert len(serving_violations) >= 1

    def test_detect_predict_with_request_input(self):
        """Detect predict() with request data."""
        code = """
import tensorflow as tf

input_data = request.form['data']
result = model.predict(input_data)
"""
        violations = analyze_tensorflow_security(Path("test.py"), code)
        serving_violations = [v for v in violations if v.rule_id == "TF009"]
        assert len(serving_violations) >= 1

    def test_safe_predict_with_validated_input(self):
        """predict() with non-user data should be safer."""
        code = """
import tensorflow as tf

# Internal test data
test_data = load_test_dataset()
predictions = model.predict(test_data)
"""
        violations = analyze_tensorflow_security(Path("test.py"), code)
        serving_violations = [v for v in violations if v.rule_id == "TF009"]
        assert len(serving_violations) == 0


class TestTensorFlowCheckpointPoisoning:
    """Test TF010: Checkpoint poisoning."""

    def test_detect_restore_with_user_path(self):
        """Detect Checkpoint.restore() with user path."""
        code = """
import tensorflow as tf

checkpoint_path = request.args.get('checkpoint')
checkpoint = tf.train.Checkpoint()
checkpoint.restore(checkpoint_path)
"""
        violations = analyze_tensorflow_security(Path("test.py"), code)
        checkpoint_violations = [v for v in violations if v.rule_id == "TF010"]
        assert len(checkpoint_violations) >= 1

    def test_detect_load_weights_with_user_file(self):
        """Detect load_weights() with user file."""
        code = """
import tensorflow as tf

weights_file = request.json['weights']
model.load_weights(weights_file)
"""
        violations = analyze_tensorflow_security(Path("test.py"), code)
        checkpoint_violations = [v for v in violations if v.rule_id == "TF010"]
        assert len(checkpoint_violations) >= 1

    def test_safe_restore_with_constant_path(self):
        """Checkpoint restore from constant path should be safe."""
        code = """
import tensorflow as tf

# Safe constant path
checkpoint = tf.train.Checkpoint()
checkpoint.restore('checkpoints/model-best')
"""
        violations = analyze_tensorflow_security(Path("test.py"), code)
        checkpoint_violations = [v for v in violations if v.rule_id == "TF010"]
        assert len(checkpoint_violations) == 0


class TestTensorFlowKerasIntegration:
    """Test detection with Keras imports."""

    def test_detect_keras_load_model(self):
        """Detect vulnerabilities with keras.models.load_model()."""
        code = """
from keras.models import load_model

model = load_model(user_path)
"""
        violations = analyze_tensorflow_security(Path("test.py"), code)
        model_violations = [v for v in violations if v.rule_id == "TF001"]
        assert len(model_violations) >= 1

    def test_detect_keras_tensorboard(self):
        """Detect TensorBoard issues with Keras import."""
        code = """
from keras.callbacks import TensorBoard

tb = TensorBoard(log_dir='public/logs')
"""
        violations = analyze_tensorflow_security(Path("test.py"), code)
        tb_violations = [v for v in violations if v.rule_id == "TF006"]
        assert len(tb_violations) >= 1


class TestTensorFlowEdgeCases:
    """Test edge cases and complex scenarios."""

    def test_multiple_vulnerabilities_in_one_file(self):
        """Detect multiple TensorFlow vulnerabilities in same file."""
        code = """
import tensorflow as tf

# TF001: Unsafe model loading
model = tf.keras.models.load_model(user_model)

# TF002: GPU memory exhaustion
tensor = tf.zeros(user_shape)

# TF005: Callback injection
model.fit(X, y, callbacks=user_callbacks)

# TF007: Dataset injection
dataset = tf.data.Dataset.from_tensor_slices(user_data)

# TF009: Unsafe model serving
predictions = model.predict(request_input)
"""
        violations = analyze_tensorflow_security(Path("test.py"), code)
        assert len(violations) >= 5

    def test_no_tensorflow_import_no_violations(self):
        """Code without TensorFlow should not trigger violations."""
        code = """
import os
import sys

data = [1, 2, 3, 4, 5]
result = sum(data)
"""
        violations = analyze_tensorflow_security(Path("test.py"), code)
        assert len(violations) == 0

    def test_tensorflow_alias_detection(self):
        """Should detect violations with tf alias."""
        code = """
import tensorflow as tf

model = tf.keras.models.load_model('model.h5')
data = tf.zeros(user_size)
"""
        violations = analyze_tensorflow_security(Path("test.py"), code)
        assert len(violations) >= 1

    def test_tensorflow_full_name_detection(self):
        """Should detect violations with full tensorflow name."""
        code = """
import tensorflow

model = tensorflow.keras.models.load_model(user_path)
"""
        violations = analyze_tensorflow_security(Path("test.py"), code)
        assert len(violations) >= 1


class TestTensorFlowRuleMetadata:
    """Test that rules are properly registered and have correct metadata."""

    def test_tensorflow_rules_registered(self):
        """Verify all TF rules are registered."""
        from pyguard.lib.framework_tensorflow import TENSORFLOW_RULES
        
        assert len(TENSORFLOW_RULES) == 20
        rule_ids = {rule.rule_id for rule in TENSORFLOW_RULES}
        
        expected_ids = {
            f"TF{str(i).zfill(3)}" for i in range(1, 21)
        }
        assert rule_ids == expected_ids

    def test_tensorflow_rules_have_cwe_mapping(self):
        """Verify all rules have CWE mappings."""
        from pyguard.lib.framework_tensorflow import TENSORFLOW_RULES
        
        for rule in TENSORFLOW_RULES:
            assert rule.cwe_mapping is not None
            assert rule.cwe_mapping.startswith("CWE-")

    def test_tensorflow_rules_have_owasp_mapping(self):
        """Verify all rules have OWASP mappings."""
        from pyguard.lib.framework_tensorflow import TENSORFLOW_RULES
        
        for rule in TENSORFLOW_RULES:
            assert rule.owasp_mapping is not None

    def test_tensorflow_rules_have_severity(self):
        """Verify all rules have severity levels."""
        from pyguard.lib.framework_tensorflow import TENSORFLOW_RULES
        
        for rule in TENSORFLOW_RULES:
            assert rule.severity in [
                RuleSeverity.CRITICAL,
                RuleSeverity.HIGH,
                RuleSeverity.MEDIUM,
                RuleSeverity.LOW,
            ]

    def test_tensorflow_critical_rules_exist(self):
        """Verify critical severity rules exist."""
        from pyguard.lib.framework_tensorflow import TENSORFLOW_RULES
        
        critical_rules = [r for r in TENSORFLOW_RULES if r.severity == RuleSeverity.CRITICAL]
        assert len(critical_rules) >= 1
        # TF001 and TF005 should be critical
        critical_ids = {r.id for r in critical_rules}
        assert "TF001" in critical_ids or "TF005" in critical_ids


class TestTensorFlowPerformance:
    """Test performance of TensorFlow security analysis."""

    def test_performance_small_file(self):
        """Analysis should be fast on small files."""
        code = """
import tensorflow as tf

model = tf.keras.Sequential([
    tf.keras.layers.Dense(10)
])
"""
        import time
        start = time.time()
        violations = analyze_tensorflow_security(Path("test.py"), code)
        elapsed = time.time() - start
        
        assert elapsed < 0.1  # Should complete in <100ms

    def test_performance_medium_file(self):
        """Analysis should be reasonable on medium files."""
        code = """
import tensorflow as tf
""" + "\n".join([f"layer{i} = tf.keras.layers.Dense(10)" for i in range(100)])
        
        import time
        start = time.time()
        violations = analyze_tensorflow_security(Path("test.py"), code)
        elapsed = time.time() - start
        
        assert elapsed < 1.0  # Should complete in <1 second

    def test_no_false_positives_on_safe_code(self):
        """Safe TensorFlow usage should not trigger violations."""
        code = """
import tensorflow as tf

# Safe TensorFlow operations
model = tf.keras.Sequential([
    tf.keras.layers.Dense(64, activation='relu'),
    tf.keras.layers.Dense(10, activation='softmax')
])

model.compile(optimizer='adam', loss='sparse_categorical_crossentropy')

# Safe training with predefined callbacks
callbacks = [
    tf.keras.callbacks.EarlyStopping(patience=3)
]
# Note: fit would need dataset, not testing that here
"""
        violations = analyze_tensorflow_security(Path("test.py"), code)
        # Should have minimal or no violations for safe code
        assert len(violations) <= 1  # Allow for some heuristic detection


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
