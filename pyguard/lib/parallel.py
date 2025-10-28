"""
Parallel processing support for PyGuard.

Implements multi-threaded file analysis for improved performance on multi-core systems.
Aligned with performance optimization best practices from Google SRE.

References:
- Google SRE | https://sre.google | Medium | Scalability and performance patterns
"""

import concurrent.futures
import multiprocessing
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from pyguard.lib.core import PyGuardLogger


@dataclass
class ProcessingResult:
    """Result from processing a single file."""

    file_path: Path
    success: bool
    fixes_applied: list[str]
    error: str | None = None
    processing_time_ms: float = 0.0


class ParallelProcessor:
    """
    Parallel file processor for PyGuard.

    Uses ThreadPoolExecutor for I/O-bound operations (most PyGuard operations).
    Provides progress tracking and error handling.
    """

    def __init__(self, max_workers: int | None = None):
        """
        Initialize parallel processor.

        Args:
            max_workers: Maximum number of worker threads (default: CPU count)
        """
        self.logger = PyGuardLogger()
        self.max_workers = max_workers or min(32, (multiprocessing.cpu_count() or 1) + 4)

        self.logger.info(
            f"Initialized parallel processor with {self.max_workers} workers", category="Parallel"
        )

    def process_files(
        self,
        files: list[Path],
        processor_func: Callable[[Path], tuple[bool, list[str]]],
        show_progress: bool = True,
    ) -> list[ProcessingResult]:
        """
        Process multiple files in parallel.

        Args:
            files: List of file paths to process
            processor_func: Function to process each file (returns tuple: (success, fixes))
            show_progress: Whether to show progress updates

        Returns:
            List of ProcessingResult objects
        """
        results = []
        total = len(files)

        self.logger.info(f"Starting parallel processing of {total} files", category="Parallel")

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tasks
            future_to_file = {
                executor.submit(self._process_single_file, file_path, processor_func): file_path
                for file_path in files
            }

            # Collect results as they complete
            completed = 0
            # Cannot use enumerate() here because as_completed() yields futures in completion order, not original order
            for future in concurrent.futures.as_completed(future_to_file):
                file_path = future_to_file[future]
                completed += 1

                try:
                    result = future.result()
                    results.append(result)

                    if show_progress and completed % max(1, total // 10) == 0:
                        self.logger.info(
                            f"Progress: {completed}/{total} files processed ({completed * 100 // total}%)",
                            category="Parallel",
                        )

                except Exception as e:
                    error_msg = f"Error processing {file_path}: {e!s}"
                    self.logger.error(error_msg, category="Parallel")
                    results.append(
                        ProcessingResult(
                            file_path=file_path, success=False, fixes_applied=[], error=error_msg
                        )
                    )

        self.logger.success(
            f"Completed processing {total} files",
            category="Parallel",
            details={
                "total": total,
                "successful": sum(1 for r in results if r.success),
                "failed": sum(1 for r in results if not r.success),
            },
        )

        return results

    def _process_single_file(
        self, file_path: Path, processor_func: Callable[[Path], tuple[bool, list[str]]]
    ) -> ProcessingResult:
        """
        Process a single file with timing.

        Args:
            file_path: Path to file to process
            processor_func: Function to process the file

        Returns:
            ProcessingResult object
        """

        start_time = time.time()

        try:
            success, fixes = processor_func(file_path)
            elapsed_ms = (time.time() - start_time) * 1000

            return ProcessingResult(
                file_path=file_path,
                success=success,
                fixes_applied=fixes,
                processing_time_ms=elapsed_ms,
            )

        except Exception as e:
            elapsed_ms = (time.time() - start_time) * 1000
            error_msg = str(e)

            self.logger.error(f"Error processing {file_path}: {error_msg}", category="Parallel")

            return ProcessingResult(
                file_path=file_path,
                success=False,
                fixes_applied=[],
                error=error_msg,
                processing_time_ms=elapsed_ms,
            )


class BatchProcessor:
    """
    Batch processor for handling large numbers of files efficiently.

    Implements batching and chunking strategies to optimize memory usage
    and processing throughput.
    """

    def __init__(self, batch_size: int = 100):
        """
        Initialize batch processor.

        Args:
            batch_size: Number of files to process in each batch
        """
        self.logger = PyGuardLogger()
        self.batch_size = batch_size
        self.parallel_processor = ParallelProcessor()

    def process_in_batches(
        self, files: list[Path], processor_func: Callable[[Path], tuple[bool, list[str]]]
    ) -> list[ProcessingResult]:
        """
        Process files in batches to manage memory usage.

        Args:
            files: List of file paths to process
            processor_func: Function to process each file

        Returns:
            List of ProcessingResult objects
        """
        all_results = []
        total_files = len(files)
        num_batches = (total_files + self.batch_size - 1) // self.batch_size

        self.logger.info(
            f"Processing {total_files} files in {num_batches} batches", category="Batch"
        )

        for batch_num in range(num_batches):
            start_idx = batch_num * self.batch_size
            end_idx = min(start_idx + self.batch_size, total_files)
            batch = files[start_idx:end_idx]

            self.logger.info(
                f"Processing batch {batch_num + 1}/{num_batches} ({len(batch)} files)",
                category="Batch",
            )

            batch_results = self.parallel_processor.process_files(
                batch, processor_func, show_progress=False
            )

            all_results.extend(batch_results)

            # Log batch completion
            successful = sum(1 for r in batch_results if r.success)
            self.logger.info(
                f"Batch {batch_num + 1} complete: {successful}/{len(batch)} successful",
                category="Batch",
            )

        return all_results
