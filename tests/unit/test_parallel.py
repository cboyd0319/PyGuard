"""Tests for parallel processing module."""

import tempfile
import unittest
from pathlib import Path

from pyguard.lib.parallel import BatchProcessor, ParallelProcessor, ProcessingResult


class TestProcessingResult(unittest.TestCase):
    """Test cases for ProcessingResult dataclass."""

    def test_processing_result_creation(self):
        """Test creation of ProcessingResult."""
        result = ProcessingResult(
            file_path=Path("test.py"),
            success=True,
            fixes_applied=["fix1", "fix2"],
            error=None,
            processing_time_ms=123.45,
        )

        self.assertEqual(result.file_path, Path("test.py"))
        self.assertTrue(result.success)
        self.assertEqual(result.fixes_applied, ["fix1", "fix2"])
        self.assertIsNone(result.error)
        self.assertEqual(result.processing_time_ms, 123.45)

    def test_processing_result_with_error(self):
        """Test ProcessingResult with error."""
        result = ProcessingResult(
            file_path=Path("test.py"), success=False, fixes_applied=[], error="Test error message"
        )

        self.assertFalse(result.success)
        self.assertEqual(result.error, "Test error message")
        self.assertEqual(result.fixes_applied, [])


class TestParallelProcessor(unittest.TestCase):
    """Test cases for ParallelProcessor class."""

    def setUp(self):
        """Set up test fixtures."""
        self.processor = ParallelProcessor(max_workers=2)

    def test_init(self):
        """Test ParallelProcessor initialization."""
        self.assertIsNotNone(self.processor)
        self.assertEqual(self.processor.max_workers, 2)

    def test_init_default_workers(self):
        """Test initialization with default workers."""
        processor = ParallelProcessor()
        self.assertGreater(processor.max_workers, 0)

    def test_process_files_success(self):
        """Test processing files successfully."""
        # Create test files
        with tempfile.TemporaryDirectory() as tmpdir:
            test_files = []
            for i in range(3):
                file_path = Path(tmpdir) / f"test{i}.py"
                file_path.write_text(f"# Test file {i}")
                test_files.append(file_path)

            # Mock processor function
            def mock_processor(file_path):
                return (True, [f"fix_{file_path.name}"])

            # Process files
            results = self.processor.process_files(test_files, mock_processor, show_progress=False)

            # Verify results
            self.assertEqual(len(results), 3)
            for result in results:
                self.assertTrue(result.success)
                self.assertGreater(len(result.fixes_applied), 0)

    def test_process_files_with_progress(self):
        """Test processing files with progress updates."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_files = []
            for i in range(20):  # More files to trigger progress updates
                file_path = Path(tmpdir) / f"test{i}.py"
                file_path.write_text(f"# Test file {i}")
                test_files.append(file_path)

            def mock_processor(file_path):
                return (True, [])

            results = self.processor.process_files(test_files, mock_processor, show_progress=True)
            self.assertEqual(len(results), 20)

    def test_process_files_with_errors(self):
        """Test processing files with errors."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_files = [
                Path(tmpdir) / "test1.py",
                Path(tmpdir) / "test2.py",
            ]
            for file_path in test_files:
                file_path.write_text("# Test")

            def mock_processor(file_path):
                if "test1" in str(file_path):
                    raise ValueError("Test error")
                return (True, ["fix"])

            results = self.processor.process_files(test_files, mock_processor, show_progress=False)

            # Should have 2 results (one error, one success)
            self.assertEqual(len(results), 2)

            # Find the error result
            error_results = [r for r in results if not r.success]
            self.assertEqual(len(error_results), 1)
            self.assertIn("Test error", error_results[0].error)

    def test_process_single_file_success(self):
        """Test processing a single file successfully."""
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "test.py"
            file_path.write_text("# Test")

            def mock_processor(path):
                return (True, ["fix1"])

            result = self.processor._process_single_file(file_path, mock_processor)

            self.assertTrue(result.success)
            self.assertEqual(result.fixes_applied, ["fix1"])
            self.assertIsNone(result.error)
            self.assertGreater(result.processing_time_ms, 0)

    def test_process_single_file_error(self):
        """Test processing a single file with error."""
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "test.py"
            file_path.write_text("# Test")

            def mock_processor(path):
                raise RuntimeError("Processing failed")

            result = self.processor._process_single_file(file_path, mock_processor)

            self.assertFalse(result.success)
            self.assertEqual(result.fixes_applied, [])
            self.assertIsNotNone(result.error)
            self.assertIn("Processing failed", result.error)
            self.assertGreater(result.processing_time_ms, 0)

    def test_process_empty_file_list(self):
        """Test processing empty file list."""

        def mock_processor(path):
            return (True, [])

        results = self.processor.process_files([], mock_processor, show_progress=False)
        self.assertEqual(len(results), 0)


class TestBatchProcessor(unittest.TestCase):
    """Test cases for BatchProcessor class."""

    def setUp(self):
        """Set up test fixtures."""
        self.processor = BatchProcessor(batch_size=5)

    def test_init(self):
        """Test BatchProcessor initialization."""
        self.assertIsNotNone(self.processor)
        self.assertEqual(self.processor.batch_size, 5)
        self.assertIsNotNone(self.processor.parallel_processor)

    def test_init_default_batch_size(self):
        """Test initialization with default batch size."""
        processor = BatchProcessor()
        self.assertEqual(processor.batch_size, 100)

    def test_process_in_batches_single_batch(self):
        """Test processing files in a single batch."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_files = []
            for i in range(3):
                file_path = Path(tmpdir) / f"test{i}.py"
                file_path.write_text(f"# Test file {i}")
                test_files.append(file_path)

            def mock_processor(file_path):
                return (True, [f"fix_{file_path.name}"])

            results = self.processor.process_in_batches(test_files, mock_processor)

            self.assertEqual(len(results), 3)
            for result in results:
                self.assertTrue(result.success)

    def test_process_in_batches_multiple_batches(self):
        """Test processing files in multiple batches."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_files = []
            for i in range(12):  # More than batch_size (5)
                file_path = Path(tmpdir) / f"test{i}.py"
                file_path.write_text(f"# Test file {i}")
                test_files.append(file_path)

            def mock_processor(file_path):
                return (True, [f"fix_{file_path.name}"])

            results = self.processor.process_in_batches(test_files, mock_processor)

            # Should process all files across 3 batches (5 + 5 + 2)
            self.assertEqual(len(results), 12)
            for result in results:
                self.assertTrue(result.success)

    def test_process_in_batches_with_errors(self):
        """Test batch processing with some errors."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_files = []
            for i in range(8):
                file_path = Path(tmpdir) / f"test{i}.py"
                file_path.write_text(f"# Test file {i}")
                test_files.append(file_path)

            def mock_processor(file_path):
                # Fail on every other file
                if int(file_path.stem[-1]) % 2 == 0:
                    raise ValueError("Test error")
                return (True, ["fix"])

            results = self.processor.process_in_batches(test_files, mock_processor)

            self.assertEqual(len(results), 8)

            # Count successful and failed
            successful = sum(1 for r in results if r.success)
            failed = sum(1 for r in results if not r.success)

            self.assertEqual(successful, 4)
            self.assertEqual(failed, 4)

    def test_process_in_batches_empty_list(self):
        """Test batch processing with empty file list."""

        def mock_processor(path):
            return (True, [])

        results = self.processor.process_in_batches([], mock_processor)
        self.assertEqual(len(results), 0)

    def test_process_in_batches_exact_batch_size(self):
        """Test processing when file count equals batch size."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_files = []
            for i in range(5):  # Exactly batch_size
                file_path = Path(tmpdir) / f"test{i}.py"
                file_path.write_text(f"# Test file {i}")
                test_files.append(file_path)

            def mock_processor(file_path):
                return (True, ["fix"])

            results = self.processor.process_in_batches(test_files, mock_processor)

            self.assertEqual(len(results), 5)
            for result in results:
                self.assertTrue(result.success)


if __name__ == "__main__":
    unittest.main()
