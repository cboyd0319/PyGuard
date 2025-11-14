"""
Incremental analysis with intelligent file caching for PyGuard.

This module implements smart caching to skip analysis of unchanged files,
dramatically improving performance on large codebases with frequent re-scans.

References:
- Google SRE | https://sre.google | Medium | Performance optimization patterns
- OWASP ASVS v5.0 | https://owasp.org/ASVS | Medium | Secure development practices
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path

from pyguard.lib.core import FileOperations, PyGuardLogger


@dataclass
class FileFingerprint:
    """
    Fingerprint of a file for change detection.

    Tracks file hash, modification time, and last analysis results.
    """

    file_path: str
    content_hash: str
    size_bytes: int
    mtime: float
    last_analyzed: str
    issues_count: int = 0
    fixes_applied: list[str] = field(default_factory=list)
    analysis_time_ms: float = 0.0


@dataclass
class CacheStatistics:
    """Statistics about cache usage."""

    total_files: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    files_skipped: int = 0
    time_saved_ms: float = 0.0

    @property
    def hit_rate(self) -> float:
        """Calculate cache hit rate as percentage."""
        if self.total_files == 0:
            return 0.0
        return (self.cache_hits / self.total_files) * 100


class IncrementalAnalyzer:
    """
    Incremental analyzer with intelligent file caching.

    Maintains a cache of file fingerprints and only analyzes files that have
    changed since the last run, dramatically improving performance.
    """

    def __init__(self, cache_dir: Path | None = None):
        """
        Initialize incremental analyzer.

        Args:
            cache_dir: Directory to store cache files (default: .pyguard_cache)
        """
        self.logger = PyGuardLogger()
        self.cache_dir = cache_dir or Path.cwd() / ".pyguard_cache"
        self.cache_file = self.cache_dir / "file_cache.json"
        self.file_ops = FileOperations()

        # Create cache directory if it doesn't exist
        self.cache_dir.mkdir(exist_ok=True)

        # Load existing cache
        self.cache: dict[str, FileFingerprint] = self._load_cache()

        # Statistics
        self.stats = CacheStatistics()

        self.logger.info(
            f"Initialized incremental analyzer with cache at {self.cache_dir}",
            category="Incremental",
        )

    def _load_cache(self) -> dict[str, FileFingerprint]:
        """
        Load cache from disk.

        Returns:
            Dictionary of file path to fingerprint
        """
        if not self.cache_file.exists():
            self.logger.debug("No existing cache found, starting fresh", category="Incremental")
            return {}

        try:
            with open(self.cache_file, encoding="utf-8") as f:
                data = json.load(f)

            cache = {}
            for file_path, fingerprint_data in data.items():
                cache[file_path] = FileFingerprint(**fingerprint_data)

            self.logger.success(
                f"Loaded cache with {len(cache)} entries", category="Incremental"
            )
            return cache

        except (json.JSONDecodeError, OSError) as e:
            self.logger.warning(
                f"Failed to load cache, starting fresh: {e}", category="Incremental"
            )
            return {}

    def _save_cache(self) -> None:
        """Save cache to disk."""
        try:
            # Convert fingerprints to dictionaries
            data = {
                file_path: {
                    "file_path": fp.file_path,
                    "content_hash": fp.content_hash,
                    "size_bytes": fp.size_bytes,
                    "mtime": fp.mtime,
                    "last_analyzed": fp.last_analyzed,
                    "issues_count": fp.issues_count,
                    "fixes_applied": fp.fixes_applied,
                    "analysis_time_ms": fp.analysis_time_ms,
                }
                for file_path, fp in self.cache.items()
            }

            with open(self.cache_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)

            self.logger.success(
                f"Saved cache with {len(self.cache)} entries", category="Incremental"
            )

        except OSError as e:
            self.logger.error(f"Failed to save cache: {e}", category="Incremental")

    def _calculate_file_hash(self, file_path: Path) -> str:
        """
        Calculate SHA256 hash of file contents.

        Args:
            file_path: Path to file

        Returns:
            Hex-encoded SHA256 hash
        """
        hasher = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                # Read in chunks for memory efficiency
                for chunk in iter(lambda: f.read(8192), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except OSError as e:
            self.logger.warning(f"Failed to hash {file_path}: {e}", category="Incremental")
            return ""

    def should_analyze_file(self, file_path: Path) -> bool:
        """
        Determine if a file should be analyzed.

        Checks if file has changed since last analysis by comparing:
        1. Content hash (SHA256)
        2. Modification time
        3. File size

        Args:
            file_path: Path to file to check

        Returns:
            True if file should be analyzed, False if can be skipped
        """
        self.stats.total_files += 1

        file_str = str(file_path.resolve())

        # File doesn't exist in cache - must analyze
        if file_str not in self.cache:
            self.logger.debug(f"Cache miss: {file_path.name} (new file)", category="Incremental")
            self.stats.cache_misses += 1
            return True

        # Get current file stats
        try:
            stat = file_path.stat()
            current_hash = self._calculate_file_hash(file_path)
            cached = self.cache[file_str]

            # Check if file has changed
            if (
                current_hash != cached.content_hash
                or stat.st_size != cached.size_bytes
                or stat.st_mtime != cached.mtime
            ):
                self.logger.debug(
                    f"Cache miss: {file_path.name} (file changed)", category="Incremental"
                )
                self.stats.cache_misses += 1
                return True

            # File unchanged - can skip
            self.logger.debug(
                f"Cache hit: {file_path.name} (unchanged, skipping)", category="Incremental"
            )
            self.stats.cache_hits += 1
            self.stats.files_skipped += 1
            self.stats.time_saved_ms += cached.analysis_time_ms
            return False

        except OSError as e:
            self.logger.warning(f"Error checking {file_path}: {e}", category="Incremental")
            # If we can't check, analyze to be safe
            self.stats.cache_misses += 1
            return True

    def update_cache(
        # TODO: Add docstring
        self,
        file_path: Path,
        issues_count: int = 0,
        fixes_applied: list[str] | None = None,
        analysis_time_ms: float = 0.0,
    ) -> None:
        """
        Update cache entry for a file after analysis.

        Args:
            file_path: Path to analyzed file
            issues_count: Number of issues found
            fixes_applied: List of fixes applied
            analysis_time_ms: Time taken to analyze in milliseconds
        """
        if fixes_applied is None:
            fixes_applied = []

        try:
            stat = file_path.stat()
            content_hash = self._calculate_file_hash(file_path)

            fingerprint = FileFingerprint(
                file_path=str(file_path.resolve()),
                content_hash=content_hash,
                size_bytes=stat.st_size,
                mtime=stat.st_mtime,
                last_analyzed=datetime.now(UTC).isoformat(),
                issues_count=issues_count,
                fixes_applied=fixes_applied,
                analysis_time_ms=analysis_time_ms,
            )

            self.cache[str(file_path.resolve())] = fingerprint

            self.logger.debug(
                f"Updated cache for {file_path.name}", category="Incremental"
            )

        except OSError as e:
            self.logger.warning(f"Failed to update cache for {file_path}: {e}", category="Incremental")

    def filter_changed_files(self, files: list[Path]) -> list[Path]:
        """
        Filter list of files to only those that need analysis.

        Args:
            files: List of all files to consider

        Returns:
            List of files that have changed and need analysis
        """
        changed_files = [f for f in files if self.should_analyze_file(f)]

        total = len(files)
        skipped = total - len(changed_files)

        if skipped > 0:
            self.logger.success(
                f"Incremental analysis: {skipped}/{total} files unchanged, analyzing {len(changed_files)}",
                category="Incremental",
                details={
                    "total": total,
                    "unchanged": skipped,
                    "to_analyze": len(changed_files),
                    "time_saved_sec": self.stats.time_saved_ms / 1000,
                },
            )

        return changed_files

    def clear_cache(self) -> None:
        """Clear all cache entries."""
        self.cache = {}
        if self.cache_file.exists():
            self.cache_file.unlink()
        self.logger.info("Cache cleared", category="Incremental")

    def prune_cache(self, existing_files: set[Path]) -> int:
        """
        Remove cache entries for files that no longer exist.

        Args:
            existing_files: Set of files that currently exist

        Returns:
            Number of entries removed
        """
        existing_paths = {str(f.resolve()) for f in existing_files}
        cached_paths = set(self.cache.keys())
        stale_paths = cached_paths - existing_paths

        for path in stale_paths:
            del self.cache[path]

        if stale_paths:
            self.logger.info(
                f"Pruned {len(stale_paths)} stale cache entries", category="Incremental"
            )

        return len(stale_paths)

    def get_statistics(self) -> CacheStatistics:
        """
        Get cache usage statistics.

        Returns:
            CacheStatistics object
        """
        return self.stats

    def print_statistics(self) -> None:
        """Print cache usage statistics to log."""
        stats = self.get_statistics()

        self.logger.info(
            "Incremental analysis statistics:",
            category="Incremental",
            details={
                "total_files": stats.total_files,
                "cache_hits": stats.cache_hits,
                "cache_misses": stats.cache_misses,
                "files_skipped": stats.files_skipped,
                "hit_rate": f"{stats.hit_rate:.1f}%",
                "time_saved": f"{stats.time_saved_ms / 1000:.2f}s",
            },
        )

    def save(self) -> None:
        """Save cache to disk."""
        self._save_cache()


def create_incremental_analyzer(cache_dir: Path | None = None) -> IncrementalAnalyzer:
    """
    Factory function to create an incremental analyzer.

    Args:
        cache_dir: Directory to store cache files

    Returns:
        IncrementalAnalyzer instance
    """
    return IncrementalAnalyzer(cache_dir=cache_dir)
