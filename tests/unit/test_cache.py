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


class TestAnalysisCacheEdgeCases:
    """Test edge cases for AnalysisCache."""

    def setup_method(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.cache_dir = Path(self.temp_dir) / "cache"
        self.cache = AnalysisCache(cache_dir=self.cache_dir)

    def teardown_method(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_cache_with_corrupted_cache_file(self):
        """Test cache handles corrupted cache file gracefully."""
        # Create corrupted cache file
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        cache_file = self.cache_dir / "analysis_cache.json"
        cache_file.write_text("corrupted json {]")
        
        # Create new cache instance - should handle corruption gracefully
        cache = AnalysisCache(cache_dir=self.cache_dir)
        
        # Cache should be empty
        stats = cache.get_stats()
        assert stats["entries"] == 0

    def test_cache_save_error_handling(self, monkeypatch):
        """Test cache save error handling."""
        test_file = Path(self.temp_dir) / "test.py"
        test_file.write_text("print('test')")
        
        # Add entry
        self.cache.set(test_file, {"data": "test"})
        
        # Make cache directory read-only to trigger save error
        import os
        import stat
        self.cache_dir.chmod(stat.S_IRUSR | stat.S_IXUSR)
        
        try:
            # Try to save - should handle error gracefully
            self.cache._save_cache()
        finally:
            # Restore permissions
            self.cache_dir.chmod(stat.S_IRWXU)

    def test_cache_expiration(self):
        """Test cache entry expiration based on age."""
        import time
        
        test_file = Path(self.temp_dir) / "test.py"
        test_file.write_text("print('test')")
        
        # Create cache with very short max age (1 second = 1/3600 hours)
        cache = AnalysisCache(cache_dir=self.cache_dir, max_age_hours=1/3600)
        
        # Add entry
        cache.set(test_file, {"data": "test"})
        assert cache.is_cached(test_file)
        
        # Wait for expiration
        time.sleep(1.5)
        
        # Trigger cleanup by checking cache
        cache._clean_expired()
        
        # Entry should be expired
        assert not cache.is_cached(test_file)

    def test_cache_with_entry_data_attribute(self):
        """Test cache handles entries with data attribute correctly."""
        test_file = Path(self.temp_dir) / "test.py"
        test_file.write_text("print('test')")
        
        # Set data
        data = {"result": "value"}
        self.cache.set(test_file, data)
        
        # Save and reload
        self.cache._save_cache()
        
        # Create new instance
        new_cache = AnalysisCache(cache_dir=self.cache_dir)
        
        # Should load with data attribute
        cached_data = new_cache.get(test_file)
        assert cached_data == data

    def test_cache_invalidate_nonexistent_file(self):
        """Test invalidating a file that's not in cache."""
        fake_file = Path(self.temp_dir) / "nonexistent.py"
        
        # Should not raise error
        self.cache.invalidate(fake_file)

    def test_cache_get_file_hash_nonexistent(self):
        """Test getting file hash for nonexistent file."""
        fake_file = Path(self.temp_dir) / "nonexistent.py"
        
        # Should return None
        hash_value = self.cache.get_file_hash(fake_file)
        assert hash_value is None

    def test_cache_with_multiple_expired_entries(self):
        """Test cleaning multiple expired entries."""
        import time
        
        # Create cache with short expiration (1 second = 1/3600 hours)
        cache = AnalysisCache(cache_dir=self.cache_dir, max_age_hours=1/3600)
        
        # Add multiple entries
        for i in range(5):
            test_file = Path(self.temp_dir) / f"test{i}.py"
            test_file.write_text(f"print('{i}')")
            cache.set(test_file, {"data": i})
        
        # Verify all are cached
        stats = cache.get_stats()
        assert stats["entries"] == 5
        
        # Wait for expiration
        time.sleep(1.5)
        
        # Clean expired
        cache._clean_expired()
        
        # All should be gone
        stats = cache.get_stats()
        assert stats["entries"] == 0


class TestConfigCacheEdgeCases:
    """Test edge cases for ConfigCache."""

    def setup_method(self):
        """Set up test fixtures."""
        self.cache = ConfigCache()
        self.temp_dir = tempfile.mkdtemp()

    def teardown_method(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_config_cache_nonexistent_file(self):
        """Test getting config for nonexistent file."""
        fake_file = Path(self.temp_dir) / "nonexistent.toml"
        
        # Should return None
        assert self.cache.get(fake_file) is None

    def test_config_cache_set_none_value(self):
        """Test setting None value in config cache."""
        config_file = Path(self.temp_dir) / "config.toml"
        config_file.write_text("[settings]")
        
        # Set None value
        self.cache.set(config_file, None)
        
        # Should be able to retrieve None
        assert self.cache.get(config_file) is None

    def test_config_cache_multiple_files(self):
        """Test caching multiple config files."""
        configs = []
        for i in range(3):
            config_file = Path(self.temp_dir) / f"config{i}.toml"
            config_file.write_text(f"[settings]\nvalue = {i}")
            config = {"settings": {"value": i}}
            self.cache.set(config_file, config)
            configs.append((config_file, config))
        
        # Verify all are cached correctly
        for config_file, expected_config in configs:
            cached_config = self.cache.get(config_file)
            assert cached_config == expected_config

    def test_config_cache_overwrite(self):
        """Test overwriting cached config."""
        config_file = Path(self.temp_dir) / "config.toml"
        config_file.write_text("[settings]")
        
        # Set initial config
        config1 = {"settings": {"value": 1}}
        self.cache.set(config_file, config1)
        assert self.cache.get(config_file) == config1
        
        # Overwrite with new config
        config2 = {"settings": {"value": 2}}
        self.cache.set(config_file, config2)
        assert self.cache.get(config_file) == config2
