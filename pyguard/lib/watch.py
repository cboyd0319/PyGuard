"""Watch mode for real-time file monitoring and analysis.

This module provides file system watching capabilities for PyGuard,
enabling real-time analysis when files change.
"""

import time
from pathlib import Path
from typing import Callable, Set
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent

from pyguard.lib.core import PyGuardLogger


class PyGuardWatcher(FileSystemEventHandler):
    """File system event handler for PyGuard watch mode."""

    def __init__(self, callback: Callable[[Path], None], patterns: Set[str] | None = None):
        """Initialize the watcher.

        Args:
            callback: Function to call when a file changes
            patterns: Set of file patterns to watch (e.g., {"*.py"})
        """
        super().__init__()
        self.callback = callback
        self.patterns = patterns or {"*.py"}
        self.logger = PyGuardLogger()
        self._processing: Set[str] = set()

    def on_modified(self, event: FileSystemEvent) -> None:
        """Handle file modification events.

        Args:
            event: File system event
        """
        if event.is_directory:
            return

        path = Path(str(event.src_path))

        # Check if file matches our patterns
        if not self._should_process(path):
            return

        # Avoid processing the same file multiple times rapidly
        path_str = str(path)
        if path_str in self._processing:
            return

        try:
            self._processing.add(path_str)
            self.logger.info("File modified, re-analyzing", file_path=path_str)
            self.callback(path)
        finally:
            # Remove from processing set after a short delay
            time.sleep(0.1)
            self._processing.discard(path_str)

    def _should_process(self, path: Path) -> bool:
        """Check if file should be processed.

        Args:
            path: File path to check

        Returns:
            True if file should be processed
        """
        # Skip backup files
        if ".pyguard_backups" in str(path):
            return False

        # Skip hidden files and common directories
        if any(part.startswith(".") for part in path.parts):
            return False

        # Check file extension matches patterns
        for pattern in self.patterns:
            if pattern == "*.py" and path.suffix == ".py":
                return True
            elif path.match(pattern):
                return True

        return False


class WatchMode:
    """Watch mode manager for PyGuard."""

    def __init__(self, paths: list[Path], callback: Callable[[Path], None]):
        """Initialize watch mode.

        Args:
            paths: List of paths to watch
            callback: Function to call when files change
        """
        self.paths = paths
        self.callback = callback
        self.logger = PyGuardLogger()
        self.observer = Observer()

    def start(self) -> None:
        """Start watching for file changes."""
        event_handler = PyGuardWatcher(self.callback)

        for path in self.paths:
            if not path.exists():
                self.logger.warning("Path does not exist, skipping", category="Watch", file_path=str(path))
                continue

            if path.is_file():
                # Watch the parent directory for file changes
                watch_path = path.parent
                self.logger.info("Watching file", category="Watch", details={"file": str(path), "dir": str(watch_path)})
            else:
                # Watch the directory
                watch_path = path
                self.logger.info("Watching directory", category="Watch", details={"dir": str(watch_path)})

            self.observer.schedule(event_handler, str(watch_path), recursive=True)

        self.observer.start()
        self.logger.info("Watch mode started - Press Ctrl+C to stop", category="Watch")

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.logger.info("Watch mode stopped", category="Watch")
            self.stop()

    def stop(self) -> None:
        """Stop watching for file changes."""
        self.observer.stop()
        self.observer.join()


def run_watch_mode(paths: list[Path], analyze_func: Callable[[Path], None]) -> None:
    """Run PyGuard in watch mode.

    Args:
        paths: Paths to watch for changes
        analyze_func: Function to call to analyze files
    """
    logger = PyGuardLogger()
    logger.info("Starting watch mode", category="Watch", details={"paths": [str(p) for p in paths]})

    watcher = WatchMode(paths, analyze_func)
    watcher.start()
