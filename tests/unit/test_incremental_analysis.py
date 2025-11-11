"""Tests for incremental analysis with file caching."""

from pathlib import Path
import tempfile
import time

import pytest

from pyguard.lib.incremental_analysis import (
    CacheStatistics,
    FileFingerprint,
    IncrementalAnalyzer,
    create_incremental_analyzer,
)


class TestFileFingerprint:
    """Test FileFingerprint dataclass."""

    def test_create_fingerprint(self):
        """Test creating a file fingerprint."""
        fp = FileFingerprint(
            file_path="/test/file.py",
            content_hash="abc123",
            size_bytes=1024,
            mtime=123456.789,
            last_analyzed="2024-11-04T10:30:00Z",
            issues_count=5,
            fixes_applied=["fix1", "fix2"],
            analysis_time_ms=150.5,
        )

        assert fp.file_path == "/test/file.py"
        assert fp.content_hash == "abc123"
        assert fp.size_bytes == 1024
        assert fp.issues_count == 5
        assert len(fp.fixes_applied) == 2


class TestCacheStatistics:
    """Test CacheStatistics dataclass."""

    def test_hit_rate_calculation(self):
        """Test cache hit rate calculation."""
        stats = CacheStatistics(total_files=100, cache_hits=75, cache_misses=25)
        assert stats.hit_rate == 75.0

    def test_hit_rate_zero_files(self):
        """Test hit rate with zero files."""
        stats = CacheStatistics(total_files=0, cache_hits=0, cache_misses=0)
        assert stats.hit_rate == 0.0

    def test_time_saved_tracking(self):
        """Test time saved tracking."""
        stats = CacheStatistics(files_skipped=10, time_saved_ms=5000.0)
        assert stats.time_saved_ms == 5000.0
        assert stats.files_skipped == 10


class TestIncrementalAnalyzer:
    """Test incremental analyzer functionality."""

    @pytest.fixture
    def temp_cache_dir(self):
        """Create temporary cache directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def analyzer(self, temp_cache_dir):
        """Create analyzer with temporary cache."""
        return IncrementalAnalyzer(cache_dir=temp_cache_dir)

    @pytest.fixture
    def sample_file(self, tmp_path):
        """Create a sample Python file."""
        file_path = tmp_path / "sample.py"
        file_path.write_text('print("Hello, World!")\n')
        return file_path

    def test_initialization(self, analyzer, temp_cache_dir):
        """Test analyzer initialization."""
        assert analyzer.cache_dir == temp_cache_dir
        assert analyzer.cache_file == temp_cache_dir / "file_cache.json"
        assert isinstance(analyzer.cache, dict)
        assert len(analyzer.cache) == 0

    def test_should_analyze_new_file(self, analyzer, sample_file):
        """Test that new files should be analyzed."""
        should_analyze = analyzer.should_analyze_file(sample_file)
        assert should_analyze is True
        assert analyzer.stats.cache_misses == 1
        assert analyzer.stats.cache_hits == 0

    def test_update_cache(self, analyzer, sample_file):
        """Test updating cache after analysis."""
        analyzer.update_cache(
            sample_file,
            issues_count=3,
            fixes_applied=["fix1", "fix2"],
            analysis_time_ms=100.5,
        )

        file_str = str(sample_file.resolve())
        assert file_str in analyzer.cache
        assert analyzer.cache[file_str].issues_count == 3
        assert len(analyzer.cache[file_str].fixes_applied) == 2

    def test_should_skip_unchanged_file(self, analyzer, sample_file):
        """Test that unchanged files are skipped."""
        # First analysis
        analyzer.should_analyze_file(sample_file)
        analyzer.update_cache(sample_file, issues_count=0, analysis_time_ms=50.0)

        # Second analysis - file unchanged
        should_analyze = analyzer.should_analyze_file(sample_file)
        assert should_analyze is False
        assert analyzer.stats.cache_hits == 1
        assert analyzer.stats.files_skipped == 1
        assert analyzer.stats.time_saved_ms == 50.0

    def test_should_analyze_changed_file(self, analyzer, sample_file):
        """Test that changed files are analyzed."""
        # First analysis
        analyzer.should_analyze_file(sample_file)
        analyzer.update_cache(sample_file)

        # Modify file
        time.sleep(0.01)  # Ensure mtime changes
        sample_file.write_text('print("Modified!")\n')

        # Second analysis - file changed
        should_analyze = analyzer.should_analyze_file(sample_file)
        assert should_analyze is True
        assert analyzer.stats.cache_misses == 2

    def test_filter_changed_files(self, analyzer, tmp_path):
        """Test filtering changed files."""
        # Create three files
        file1 = tmp_path / "file1.py"
        file2 = tmp_path / "file2.py"
        file3 = tmp_path / "file3.py"

        for f in [file1, file2, file3]:
            f.write_text('print("test")\n')

        # Update cache for file1 and file2
        analyzer.update_cache(file1)
        analyzer.update_cache(file2)

        # Modify file2
        time.sleep(0.01)
        file2.write_text('print("modified")\n')

        # Filter files
        files = [file1, file2, file3]
        changed = analyzer.filter_changed_files(files)

        # file1 unchanged (skipped), file2 changed, file3 new
        assert len(changed) == 2
        assert file1 not in changed
        assert file2 in changed
        assert file3 in changed

    def test_save_and_load_cache(self, temp_cache_dir, sample_file):
        """Test saving and loading cache from disk."""
        # Create analyzer and update cache
        analyzer1 = IncrementalAnalyzer(cache_dir=temp_cache_dir)
        analyzer1.update_cache(
            sample_file,
            issues_count=5,
            fixes_applied=["fix1"],
            analysis_time_ms=75.0,
        )
        analyzer1.save()

        # Create new analyzer with same cache dir
        analyzer2 = IncrementalAnalyzer(cache_dir=temp_cache_dir)
        file_str = str(sample_file.resolve())
        assert file_str in analyzer2.cache
        assert analyzer2.cache[file_str].issues_count == 5
        assert analyzer2.cache[file_str].analysis_time_ms == 75.0

    def test_clear_cache(self, analyzer, sample_file):
        """Test clearing cache."""
        analyzer.update_cache(sample_file)
        assert len(analyzer.cache) == 1

        analyzer.clear_cache()
        assert len(analyzer.cache) == 0
        assert not analyzer.cache_file.exists()

    def test_prune_cache(self, analyzer, tmp_path):
        """Test pruning stale cache entries."""
        # Create files and update cache
        file1 = tmp_path / "file1.py"
        file2 = tmp_path / "file2.py"
        file1.write_text("test")
        file2.write_text("test")

        analyzer.update_cache(file1)
        analyzer.update_cache(file2)
        assert len(analyzer.cache) == 2

        # Remove file2
        file2.unlink()

        # Prune cache
        removed = analyzer.prune_cache({file1})
        assert removed == 1
        assert len(analyzer.cache) == 1
        assert str(file1.resolve()) in analyzer.cache

    def test_get_statistics(self, analyzer, sample_file):
        """Test getting statistics."""
        analyzer.should_analyze_file(sample_file)
        stats = analyzer.get_statistics()

        assert isinstance(stats, CacheStatistics)
        assert stats.total_files == 1
        assert stats.cache_misses == 1

    def test_print_statistics(self, analyzer, sample_file):
        """Test printing statistics (should not raise)."""
        analyzer.should_analyze_file(sample_file)
        # Should not raise exception
        analyzer.print_statistics()

    def test_calculate_file_hash(self, analyzer, sample_file):
        """Test file hash calculation."""
        hash1 = analyzer._calculate_file_hash(sample_file)
        assert len(hash1) == 64  # SHA256 hex digest

        # Same file should give same hash
        hash2 = analyzer._calculate_file_hash(sample_file)
        assert hash1 == hash2

        # Modified file should give different hash
        sample_file.write_text('print("different")\n')
        hash3 = analyzer._calculate_file_hash(sample_file)
        assert hash1 != hash3

    def test_nonexistent_file(self, analyzer):
        """Test handling nonexistent file."""
        fake_file = Path("/nonexistent/file.py")
        # Should return True (analyze to be safe)
        should_analyze = analyzer.should_analyze_file(fake_file)
        assert should_analyze is True

    def test_corrupted_cache_file(self, temp_cache_dir):
        """Test handling corrupted cache file."""
        cache_file = temp_cache_dir / "file_cache.json"
        cache_file.write_text("invalid json {{{")

        # Should handle gracefully and start fresh
        analyzer = IncrementalAnalyzer(cache_dir=temp_cache_dir)
        assert len(analyzer.cache) == 0

    def test_multiple_files_statistics(self, analyzer, tmp_path):
        """Test statistics with multiple files."""
        files = []
        for i in range(5):
            f = tmp_path / f"file{i}.py"
            f.write_text(f'print("{i}")\n')
            files.append(f)

        # First pass - all cache misses
        for f in files:
            analyzer.should_analyze_file(f)
            analyzer.update_cache(f, analysis_time_ms=100.0)

        # Reset stats
        analyzer.stats = CacheStatistics()

        # Second pass - all cache hits
        for f in files:
            analyzer.should_analyze_file(f)

        stats = analyzer.get_statistics()
        assert stats.total_files == 5
        assert stats.cache_hits == 5
        assert stats.cache_misses == 0
        assert stats.files_skipped == 5
        assert stats.time_saved_ms == 500.0  # 5 files * 100ms each


class TestIncrementalAnalyzerFactory:
    """Test factory function."""

    def test_create_incremental_analyzer(self):
        """Test factory function creates analyzer."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_dir = Path(tmpdir)
            analyzer = create_incremental_analyzer(cache_dir=cache_dir)
            assert isinstance(analyzer, IncrementalAnalyzer)
            assert analyzer.cache_dir == cache_dir

    def test_create_with_default_cache_dir(self):
        """Test factory with default cache directory."""
        analyzer = create_incremental_analyzer()
        assert isinstance(analyzer, IncrementalAnalyzer)
        assert analyzer.cache_dir == Path.cwd() / ".pyguard_cache"


class TestIncrementalAnalysisIntegration:
    """Integration tests for incremental analysis."""

    @pytest.fixture
    def test_project(self, tmp_path):
        """Create a small test project."""
        files = []
        for i in range(10):
            f = tmp_path / f"module{i}.py"
            f.write_text(f"""
# Module {i}
def function_{i}():
    return {i}
""")
            files.append(f)
        return files

    def test_incremental_analysis_workflow(self, test_project, tmp_path):
        """Test complete incremental analysis workflow."""
        cache_dir = tmp_path / ".cache"
        analyzer = IncrementalAnalyzer(cache_dir=cache_dir)

        # First run - analyze all files
        files_to_analyze = analyzer.filter_changed_files(test_project)
        assert len(files_to_analyze) == 10

        # Update cache for all files
        for f in test_project:
            analyzer.update_cache(f, issues_count=1, analysis_time_ms=100.0)
        analyzer.save()

        # Reset statistics
        analyzer.stats = CacheStatistics()

        # Second run - no files changed
        files_to_analyze = analyzer.filter_changed_files(test_project)
        assert len(files_to_analyze) == 0
        assert analyzer.stats.files_skipped == 10
        assert analyzer.stats.time_saved_ms == 1000.0

        # Modify one file
        time.sleep(0.01)
        test_project[5].write_text('print("modified")\n')

        # Reset statistics again
        analyzer.stats = CacheStatistics()

        # Third run - only one file should be analyzed
        files_to_analyze = analyzer.filter_changed_files(test_project)
        assert len(files_to_analyze) == 1
        assert test_project[5] in files_to_analyze
        assert analyzer.stats.files_skipped == 9

    def test_persistence_across_sessions(self, test_project, tmp_path):
        """Test cache persists across analyzer sessions."""
        cache_dir = tmp_path / ".cache"

        # First session
        analyzer1 = IncrementalAnalyzer(cache_dir=cache_dir)
        for f in test_project:
            analyzer1.update_cache(f)
        analyzer1.save()

        # Second session
        analyzer2 = IncrementalAnalyzer(cache_dir=cache_dir)
        files_to_analyze = analyzer2.filter_changed_files(test_project)
        assert len(files_to_analyze) == 0  # All files cached from first session
