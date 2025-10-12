"""
Caching system for PyGuard to improve performance.

Implements file-based caching to skip analysis of unchanged files.
Aligned with performance optimization best practices from Google SRE.

References:
- Google SRE | https://sre.google | Medium | Product-focused reliability engineering
"""

import hashlib
import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Optional

from pyguard.lib.core import PyGuardLogger


@dataclass
class CacheEntry:
    """Cache entry for analyzed file."""

    file_hash: str
    timestamp: float
    security_issues_count: int
    quality_issues_count: int
    complexity_scores: Dict[str, int]
    analysis_time_ms: float


class AnalysisCache:
    """
    Cache for analysis results to improve performance.

    Caches analysis results based on file content hash, allowing PyGuard to skip
    re-analysis of unchanged files. Implements TTL-based expiration and size limits.
    """

    def __init__(self, cache_dir: Optional[Path] = None, max_age_hours: int = 24):
        """
        Initialize analysis cache.

        Args:
            cache_dir: Directory to store cache files (default: .pyguard_cache)
            max_age_hours: Maximum age of cache entries in hours (default: 24)
        """
        self.logger = PyGuardLogger()
        self.cache_dir = cache_dir or Path.home() / ".pyguard_cache"
        self.max_age_seconds = max_age_hours * 3600
        self.cache: Dict[str, CacheEntry] = {}

        # Create cache directory if it doesn't exist
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_file = self.cache_dir / "analysis_cache.json"

        # Load existing cache
        self._load_cache()

    def _load_cache(self):
        """Load cache from disk."""
        try:
            if self.cache_file.exists():
                with open(self.cache_file, "r") as f:
                    data = json.load(f)
                    for file_path, entry_dict in data.items():
                        # Extract data if it exists
                        cached_data = entry_dict.pop("data", None)
                        entry = CacheEntry(**entry_dict)
                        if cached_data is not None:
                            entry.data = cached_data  # type: ignore
                        self.cache[file_path] = entry

                # Clean expired entries
                self._clean_expired()

                self.logger.debug(f"Loaded {len(self.cache)} cache entries", category="Cache")
        except Exception as e:
            self.logger.warning(f"Failed to load cache: {str(e)}", category="Cache")
            self.cache = {}

    def _save_cache(self):
        """Save cache to disk."""
        try:
            data = {}
            for file_path, entry in self.cache.items():
                entry_dict = asdict(entry)
                # Add the data field if it exists
                if hasattr(entry, "data"):
                    entry_dict["data"] = entry.data
                data[file_path] = entry_dict

            with open(self.cache_file, "w") as f:
                json.dump(data, f, indent=2)

            self.logger.debug(f"Saved {len(self.cache)} cache entries", category="Cache")
        except Exception as e:
            self.logger.error(f"Failed to save cache: {str(e)}", category="Cache")

    def _clean_expired(self):
        """Remove expired cache entries."""
        current_time = time.time()
        expired_keys = [
            key
            for key, entry in self.cache.items()
            if current_time - entry.timestamp > self.max_age_seconds
        ]

        for key in expired_keys:
            del self.cache[key]

        if expired_keys:
            self.logger.debug(
                f"Removed {len(expired_keys)} expired cache entries", category="Cache"
            )

    def get_file_hash(self, file_path: Path) -> Optional[str]:
        """
        Calculate hash of file content.

        Args:
            file_path: Path to file

        Returns:
            SHA256 hash of file content or None if file not found
        """
        try:
            with open(file_path, "rb") as f:
                content = f.read()
                return hashlib.sha256(content).hexdigest()
        except Exception as e:
            self.logger.warning(f"Failed to hash file {file_path}: {str(e)}", category="Cache")
            return None

    def is_cached(self, file_path: Path) -> bool:
        """
        Check if a file has a valid cache entry.

        Args:
            file_path: Path to file

        Returns:
            True if valid cache exists, False otherwise
        """
        return self.get(file_path) is not None

    def get(self, file_path: Path) -> Optional[Any]:
        """
        Get cached data for a file if it's still valid.

        Args:
            file_path: Path to file

        Returns:
            Cached data if valid cache exists, None otherwise
        """
        file_path_str = str(file_path)

        # Check if entry exists in cache
        if file_path_str not in self.cache:
            return None

        entry = self.cache[file_path_str]

        # Check if entry is expired
        if time.time() - entry.timestamp > self.max_age_seconds:
            del self.cache[file_path_str]
            return None

        # Check if file content has changed
        current_hash = self.get_file_hash(file_path)
        if current_hash is None or current_hash != entry.file_hash:
            del self.cache[file_path_str]
            return None

        self.logger.debug(f"Cache hit for {file_path}", category="Cache")
        # Return the actual cached data (stored in complexity_scores as a hack for now)
        # In a real implementation, we'd add a 'data' field to CacheEntry
        return getattr(entry, "data", entry)

    def set(self, file_path: Path, data: Any):
        """
        Store cache entry for a file.

        Args:
            file_path: Path to file
            data: Data to cache (can be dict, list, or any serializable object)
        """
        file_path_str = str(file_path)
        file_hash = self.get_file_hash(file_path)

        if file_hash is None:
            return

        # Create cache entry
        entry = CacheEntry(
            file_hash=file_hash,
            timestamp=time.time(),
            security_issues_count=0,
            quality_issues_count=0,
            complexity_scores={},
            analysis_time_ms=0.0,
        )
        # Store the actual data as an attribute (hack for compatibility)
        entry.data = data  # type: ignore

        self.cache[file_path_str] = entry
        self._save_cache()

        self.logger.debug(f"Cached analysis for {file_path}", category="Cache")

    def invalidate(self, file_path: Path):
        """
        Invalidate cache entry for a file.

        Args:
            file_path: Path to file
        """
        file_path_str = str(file_path)
        if file_path_str in self.cache:
            del self.cache[file_path_str]
            self._save_cache()

            self.logger.debug(f"Invalidated cache for {file_path}", category="Cache")

    def clear(self):
        """Clear all cache entries."""
        self.cache.clear()
        self._save_cache()

        self.logger.info("Cleared all cache entries", category="Cache")

    def get_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics.

        Returns:
            Dictionary with cache statistics
        """
        try:
            cache_size = self.cache_file.stat().st_size if self.cache_file.exists() else 0
        except Exception:
            cache_size = 0

        return {
            "entries": len(self.cache),
            "size_bytes": cache_size,
            "size_mb": cache_size / (1024 * 1024) if cache_size > 0 else 0.0,
        }


class ConfigCache:
    """
    Cache for configuration files to avoid repeated parsing.

    Implements simple in-memory caching with file modification time tracking.
    """

    def __init__(self):
        """Initialize configuration cache."""
        self.logger = PyGuardLogger()
        self.cache: Dict[str, tuple[float, Any]] = {}  # path -> (mtime, config)

    def get(self, config_path: Path) -> Optional[Any]:
        """
        Get cached configuration if file hasn't been modified.

        Args:
            config_path: Path to configuration file

        Returns:
            Cached configuration or None if not cached or modified
        """
        config_path_str = str(config_path)

        if config_path_str not in self.cache:
            return None

        try:
            current_mtime = config_path.stat().st_mtime
            cached_mtime, cached_config = self.cache[config_path_str]

            if current_mtime == cached_mtime:
                self.logger.debug(f"Config cache hit for {config_path}", category="Cache")
                return cached_config
            else:
                # File modified, invalidate cache
                del self.cache[config_path_str]
                return None

        except Exception as e:
            self.logger.warning(f"Error checking config cache: {str(e)}", category="Cache")
            return None

    def set(self, config_path: Path, config: Any):
        """
        Cache configuration with current modification time.

        Args:
            config_path: Path to configuration file
            config: Configuration object to cache
        """
        try:
            mtime = config_path.stat().st_mtime
            config_path_str = str(config_path)
            self.cache[config_path_str] = (mtime, config)

            self.logger.debug(f"Cached config for {config_path}", category="Cache")
        except Exception as e:
            self.logger.warning(f"Error caching config: {str(e)}", category="Cache")

    def invalidate(self, config_path: Path):
        """
        Invalidate cache entry for a configuration file.

        Args:
            config_path: Path to configuration file
        """
        config_path_str = str(config_path)
        if config_path_str in self.cache:
            del self.cache[config_path_str]

            self.logger.debug(f"Invalidated config cache for {config_path}", category="Cache")

    def clear(self):
        """Clear all cached configurations."""
        self.cache.clear()

        self.logger.info("Cleared all config cache entries", category="Cache")
