"""Tests for watch mode functionality."""

import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

from pyguard.lib.watch import PyGuardWatcher, WatchMode, run_watch_mode


class TestPyGuardWatcher(unittest.TestCase):
    """Test cases for PyGuardWatcher class."""

    def setUp(self):
        """Set up test fixtures."""
        self.callback = Mock()
        self.watcher = PyGuardWatcher(self.callback)

    def test_init(self):
        """Test watcher initialization."""
        self.assertIsNotNone(self.watcher.callback)
        self.assertEqual(self.watcher.patterns, {"*.py"})
        self.assertEqual(len(self.watcher._processing), 0)

    def test_init_with_custom_patterns(self):
        """Test watcher initialization with custom patterns."""
        patterns = {"*.py", "*.pyi"}
        watcher = PyGuardWatcher(self.callback, patterns=patterns)
        self.assertEqual(watcher.patterns, patterns)

    def test_should_process_python_file(self):
        """Test that Python files are processed."""
        path = Path("/tmp/test.py")
        self.assertTrue(self.watcher._should_process(path))

    def test_should_not_process_backup_files(self):
        """Test that backup files are not processed."""
        path = Path("/tmp/.pyguard_backups/test.py")
        self.assertFalse(self.watcher._should_process(path))

    def test_should_not_process_hidden_files(self):
        """Test that hidden files are not processed."""
        path = Path("/tmp/.hidden/test.py")
        self.assertFalse(self.watcher._should_process(path))

    def test_should_not_process_non_python_files(self):
        """Test that non-Python files are not processed."""
        path = Path("/tmp/test.txt")
        self.assertFalse(self.watcher._should_process(path))

    def test_on_modified_ignores_directories(self):
        """Test that directory events are ignored."""
        from watchdog.events import FileSystemEvent

        event = Mock(spec=FileSystemEvent)
        event.is_directory = True
        event.src_path = "/tmp/some_dir"

        self.watcher.on_modified(event)
        self.callback.assert_not_called()

    def test_on_modified_calls_callback_for_python_files(self):
        """Test that callback is called for Python file modifications."""
        from watchdog.events import FileSystemEvent

        with TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.py"
            test_file.write_text("print('hello')")

            event = Mock(spec=FileSystemEvent)
            event.is_directory = False
            event.src_path = str(test_file)

            self.watcher.on_modified(event)
            
            # Wait a bit for processing
            time.sleep(0.2)
            
            self.callback.assert_called_once()
            call_args = self.callback.call_args[0]
            self.assertEqual(str(call_args[0]), str(test_file))

    def test_on_modified_ignores_non_python_files(self):
        """Test that non-Python files don't trigger callback."""
        from watchdog.events import FileSystemEvent

        event = Mock(spec=FileSystemEvent)
        event.is_directory = False
        event.src_path = "/tmp/test.txt"

        self.watcher.on_modified(event)
        self.callback.assert_not_called()


class TestWatchMode(unittest.TestCase):
    """Test cases for WatchMode class."""

    def setUp(self):
        """Set up test fixtures."""
        self.callback = Mock()
        self.tmpdir = TemporaryDirectory()
        self.test_dir = Path(self.tmpdir.name)
        self.test_file = self.test_dir / "test.py"
        self.test_file.write_text("print('test')")

    def tearDown(self):
        """Clean up test fixtures."""
        self.tmpdir.cleanup()

    def test_init(self):
        """Test WatchMode initialization."""
        paths = [self.test_file]
        watcher = WatchMode(paths, self.callback)
        
        self.assertEqual(watcher.paths, paths)
        self.assertEqual(watcher.callback, self.callback)
        self.assertIsNotNone(watcher.observer)

    def test_init_warns_for_nonexistent_path(self):
        """Test that nonexistent paths are handled."""
        nonexistent = Path("/nonexistent/path.py")
        watcher = WatchMode([nonexistent], self.callback)
        
        # Just verify it initializes without error
        self.assertIsNotNone(watcher.observer)

    @patch('pyguard.lib.watch.Observer')
    def test_start_and_stop(self, mock_observer_class):
        """Test starting and stopping watch mode."""
        mock_observer = Mock()
        mock_observer_class.return_value = mock_observer

        watcher = WatchMode([self.test_dir], self.callback)
        
        # Test that we can call stop without starting
        watcher.stop()
        mock_observer.stop.assert_called_once()
        mock_observer.join.assert_called_once()


class TestRunWatchMode(unittest.TestCase):
    """Test cases for run_watch_mode function."""

    @patch('pyguard.lib.watch.WatchMode')
    def test_run_watch_mode(self, mock_watch_mode_class):
        """Test run_watch_mode function."""
        mock_watcher = Mock()
        mock_watch_mode_class.return_value = mock_watcher

        callback = Mock()
        paths = [Path("/tmp/test.py")]

        run_watch_mode(paths, callback)

        mock_watch_mode_class.assert_called_once_with(paths, callback)
        mock_watcher.start.assert_called_once()


if __name__ == "__main__":
    unittest.main()
