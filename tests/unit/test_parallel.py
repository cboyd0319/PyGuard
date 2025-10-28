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

        assert result.file_path == Path("test.py")
        assert result.success
        assert result.fixes_applied == ["fix1", "fix2"]
        assert result.error is None
        assert result.processing_time_ms == 123.45

    def test_processing_result_with_error(self):
        """Test ProcessingResult with error."""
        result = ProcessingResult(
            file_path=Path("test.py"), success=False, fixes_applied=[], error="Test error message"
        )

        assert not result.success
        assert result.error == "Test error message"
        assert result.fixes_applied == []


class TestParallelProcessor(unittest.TestCase):
    """Test cases for ParallelProcessor class."""

    def setUp(self):
        """Set up test fixtures."""
        self.processor = ParallelProcessor(max_workers=2)

    def test_init(self):
        """Test ParallelProcessor initialization."""
        assert self.processor is not None
        assert self.processor.max_workers == 2

    def test_init_default_workers(self):
        """Test initialization with default workers."""
        processor = ParallelProcessor()
        assert processor.max_workers > 0

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
            assert len(results) == 3
            for result in results:
                assert result.success
                assert len(result.fixes_applied) > 0

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
            assert len(results) == 20

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
            assert len(results) == 2

            # Find the error result
            error_results = [r for r in results if not r.success]
            assert len(error_results) == 1
            assert "Test error" in error_results[0].error

    def test_process_single_file_success(self):
        """Test processing a single file successfully."""
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "test.py"
            file_path.write_text("# Test")

            def mock_processor(path):
                return (True, ["fix1"])

            result = self.processor._process_single_file(file_path, mock_processor)

            assert result.success
            assert result.fixes_applied == ["fix1"]
            assert result.error is None
            assert result.processing_time_ms > 0

    def test_process_single_file_error(self):
        """Test processing a single file with error."""
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "test.py"
            file_path.write_text("# Test")

            def mock_processor(path):
                raise RuntimeError("Processing failed")

            result = self.processor._process_single_file(file_path, mock_processor)

            assert not result.success
            assert result.fixes_applied == []
            assert result.error is not None
            assert "Processing failed" in result.error
            assert result.processing_time_ms > 0

    def test_process_empty_file_list(self):
        """Test processing empty file list."""

        def mock_processor(path):
            return (True, [])

        results = self.processor.process_files([], mock_processor, show_progress=False)
        assert len(results) == 0


class TestBatchProcessor(unittest.TestCase):
    """Test cases for BatchProcessor class."""

    def setUp(self):
        """Set up test fixtures."""
        self.processor = BatchProcessor(batch_size=5)

    def test_init(self):
        """Test BatchProcessor initialization."""
        assert self.processor is not None
        assert self.processor.batch_size == 5
        assert self.processor.parallel_processor is not None

    def test_init_default_batch_size(self):
        """Test initialization with default batch size."""
        processor = BatchProcessor()
        assert processor.batch_size == 100

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

            assert len(results) == 3
            for result in results:
                assert result.success

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
            assert len(results) == 12
            for result in results:
                assert result.success

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

            assert len(results) == 8

            # Count successful and failed
            successful = sum(1 for r in results if r.success)
            failed = sum(1 for r in results if not r.success)

            assert successful == 4
            assert failed == 4

    def test_process_in_batches_empty_list(self):
        """Test batch processing with empty file list."""

        def mock_processor(path):
            return (True, [])

        results = self.processor.process_in_batches([], mock_processor)
        assert len(results) == 0

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

            assert len(results) == 5
            for result in results:
                assert result.success


if __name__ == "__main__":
    unittest.main()
