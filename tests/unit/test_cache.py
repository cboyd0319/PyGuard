"""Unit tests for cache module."""

import tempfile
from pathlib import Path

import pytest

from pyguard.lib.cache import AnalysisCache, ConfigCache


class TestAnalysisCache:
    """Test cases for AnalysisCache class."""

    def setup_method(self):
        """Set up test fixtures."""
        # Use temporary directory for cache
        self.temp_dir = tempfile.mkdtemp()
        self.cache_dir = Path(self.temp_dir) / "cache"
        self.cache = AnalysisCache(cache_dir=self.cache_dir)

        # Create a test file
        self.test_file = Path(self.temp_dir) / "test.py"
        self.test_file.write_text("print('hello')")

    def teardown_method(self):
        """Clean up test fixtures."""
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_cache_miss(self):
        """Test cache miss for uncached file."""
        assert not self.cache.is_cached(self.test_file)
        assert self.cache.get(self.test_file) is None

    def test_cache_hit(self):
        """Test cache hit for cached file."""
        # Cache some results
        results = {"issues": [], "fixes": []}
        self.cache.set(self.test_file, results)

        # Should be cached now
        assert self.cache.is_cached(self.test_file)
        cached_results = self.cache.get(self.test_file)
        assert cached_results == results

    def test_cache_invalidation_on_file_change(self):
        """Test that cache is invalidated when file changes."""
        # Cache initial results
        results = {"issues": [], "fixes": []}
        self.cache.set(self.test_file, results)
        assert self.cache.is_cached(self.test_file)

        # Modify file
        self.test_file.write_text("print('modified')")

        # Cache should be invalid now
        assert not self.cache.is_cached(self.test_file)

    def test_explicit_invalidation(self):
        """Test explicit cache invalidation."""
        # Cache results
        results = {"issues": [], "fixes": []}
        self.cache.set(self.test_file, results)
        assert self.cache.is_cached(self.test_file)

        # Explicitly invalidate
        self.cache.invalidate(self.test_file)

        # Should be invalid now
        assert not self.cache.is_cached(self.test_file)

    def test_cache_clear(self):
        """Test clearing all cache entries."""
        # Cache multiple files
        file1 = Path(self.temp_dir) / "file1.py"
        file2 = Path(self.temp_dir) / "file2.py"
        file1.write_text("code1")
        file2.write_text("code2")

        self.cache.set(file1, {"data": 1})
        self.cache.set(file2, {"data": 2})

        assert self.cache.is_cached(file1)
        assert self.cache.is_cached(file2)

        # Clear cache
        self.cache.clear()

        # Both should be invalid
        assert not self.cache.is_cached(file1)
        assert not self.cache.is_cached(file2)

    def test_cache_stats(self):
        """Test cache statistics."""
        stats = self.cache.get_stats()
        assert "entries" in stats
        assert "size_bytes" in stats
        assert "size_mb" in stats
        assert stats["entries"] == 0

        # Add some entries
        self.cache.set(self.test_file, {"data": "test"})

        stats = self.cache.get_stats()
        assert stats["entries"] == 1
        assert stats["size_bytes"] > 0

    def test_nonexistent_file(self):
        """Test caching behavior with nonexistent file."""
        fake_file = Path(self.temp_dir) / "nonexistent.py"
        assert not self.cache.is_cached(fake_file)
        assert self.cache.get(fake_file) is None

    def test_cache_persistence(self):
        """Test that cache persists across instances."""
        # Cache with first instance
        results = {"data": "test"}
        self.cache.set(self.test_file, results)

        # Create new cache instance with same directory
        new_cache = AnalysisCache(cache_dir=self.cache_dir)

        # Should still be cached
        assert new_cache.is_cached(self.test_file)
        assert new_cache.get(self.test_file) == results


class TestConfigCache:
    """Test cases for ConfigCache class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.cache = ConfigCache()
        self.temp_dir = tempfile.mkdtemp()
        self.config_file = Path(self.temp_dir) / "config.toml"
        self.config_file.write_text("[settings]\nvalue = 1")

    def teardown_method(self):
        """Clean up test fixtures."""
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_config_cache_miss(self):
        """Test cache miss for uncached config."""
        assert self.cache.get(self.config_file) is None

    def test_config_cache_hit(self):
        """Test cache hit for cached config."""
        config = {"settings": {"value": 1}}
        self.cache.set(self.config_file, config)

        cached_config = self.cache.get(self.config_file)
        assert cached_config == config

    def test_config_cache_invalidation(self):
        """Test that config cache is invalidated on file modification."""
        import time

        config = {"settings": {"value": 1}}
        self.cache.set(self.config_file, config)

        # Ensure different mtime
        time.sleep(0.01)

        # Modify config file
        self.config_file.write_text("[settings]\nvalue = 2")

        # Cache should be invalid
        assert self.cache.get(self.config_file) is None

    def test_config_cache_clear(self):
        """Test clearing config cache."""
        config = {"settings": {"value": 1}}
        self.cache.set(self.config_file, config)

        assert self.cache.get(self.config_file) == config

        self.cache.clear()

        assert self.cache.get(self.config_file) is None
