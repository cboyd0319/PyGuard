"""
Performance tracking and benchmarking for PyGuard.

Tracks analysis performance metrics across different codebases and features,
enabling data-driven performance optimization.

References:
- Google SRE | https://sre.google | Medium | Performance monitoring
- OWASP ASVS v5.0 | https://owasp.org/ASVS | Low | Performance considerations
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
import time
from typing import Any


class AnalysisPhase(str, Enum):
    """Different phases of PyGuard analysis."""

    FILE_DISCOVERY = "file_discovery"
    AST_PARSING = "ast_parsing"
    SECURITY_ANALYSIS = "security_analysis"
    CODE_QUALITY = "code_quality"
    AUTO_FIX = "auto_fix"
    REPORT_GENERATION = "report_generation"
    TOTAL = "total"


@dataclass
class PerformanceMetrics:
    """Performance metrics for a single analysis run."""

    timestamp: str
    total_files: int
    total_lines: int
    duration_ms: float
    files_per_second: float
    lines_per_second: float
    phase_timings: dict[str, float] = field(default_factory=dict)
    cache_hit_rate: float = 0.0
    parallel_workers: int = 1
    incremental_enabled: bool = False
    ripgrep_enabled: bool = False
    memory_mb: float = 0.0


@dataclass
class PerformanceBenchmark:
    """Benchmark results for comparison."""

    name: str
    description: str
    metrics: PerformanceMetrics
    baseline_metrics: PerformanceMetrics | None = None

    def speedup_factor(self) -> float:
        """Calculate speedup compared to baseline."""
        if not self.baseline_metrics:
            return 1.0
        if self.baseline_metrics.duration_ms == 0:
            return 1.0
        return self.baseline_metrics.duration_ms / self.metrics.duration_ms

    def improvement_percentage(self) -> float:
        """Calculate percentage improvement over baseline."""
        return (self.speedup_factor() - 1.0) * 100


class PerformanceTracker:
    """
    Track and report performance metrics during analysis.

    Provides timing context managers and reporting capabilities for
    understanding and optimizing PyGuard performance.
    """

    def __init__(self):
        """Initialize performance tracker."""
        self.metrics = PerformanceMetrics(
            timestamp=datetime.now(UTC).isoformat(),
            total_files=0,
            total_lines=0,
            duration_ms=0.0,
            files_per_second=0.0,
            lines_per_second=0.0,
        )
        self._start_times: dict[str, float] = {}
        self._phase_start: float | None = None
        self._total_start: float | None = None

    def start_phase(self, phase: AnalysisPhase) -> None:
        """
        Start timing a phase.

        Args:
            phase: Analysis phase to track
        """
        self._start_times[phase.value] = time.perf_counter()

    def end_phase(self, phase: AnalysisPhase) -> float:
        """
        End timing a phase.

        Args:
            phase: Analysis phase being tracked

        Returns:
            Duration in milliseconds
        """
        if phase.value not in self._start_times:
            return 0.0

        duration = (time.perf_counter() - self._start_times[phase.value]) * 1000
        self.metrics.phase_timings[phase.value] = duration
        return duration

    def start_total(self) -> None:
        """Start timing total analysis."""
        self._total_start = time.perf_counter()
        self.start_phase(AnalysisPhase.TOTAL)

    def end_total(self) -> float:
        """
        End timing total analysis.

        Returns:
            Total duration in milliseconds
        """
        if self._total_start is None:
            return 0.0

        duration = self.end_phase(AnalysisPhase.TOTAL)
        self.metrics.duration_ms = duration

        # Calculate throughput metrics
        if duration > 0:
            duration_sec = duration / 1000
            self.metrics.files_per_second = self.metrics.total_files / duration_sec
            self.metrics.lines_per_second = self.metrics.total_lines / duration_sec

        return duration

    def set_file_count(self, count: int) -> None:
        """Set total files analyzed."""
        self.metrics.total_files = count

    def set_line_count(self, count: int) -> None:
        """Set total lines analyzed."""
        self.metrics.total_lines = count

    def set_cache_hit_rate(self, rate: float) -> None:
        """Set cache hit rate percentage."""
        self.metrics.cache_hit_rate = rate

    def set_parallel_workers(self, workers: int) -> None:
        """Set number of parallel workers used."""
        self.metrics.parallel_workers = workers

    def enable_incremental(self) -> None:
        """Mark that incremental analysis was used."""
        self.metrics.incremental_enabled = True

    def enable_ripgrep(self) -> None:
        """Mark that RipGrep was used."""
        self.metrics.ripgrep_enabled = True

    def set_memory_usage(self, mb: float) -> None:
        """Set memory usage in megabytes."""
        self.metrics.memory_mb = mb

    def get_metrics(self) -> PerformanceMetrics:
        """
        Get performance metrics.

        Returns:
            PerformanceMetrics object
        """
        return self.metrics

    def get_summary(self) -> dict[str, Any]:
        """
        Get human-readable summary of performance.

        Returns:
            Dictionary with summary statistics
        """
        m = self.metrics
        summary = {
            "timestamp": m.timestamp,
            "files": m.total_files,
            "lines": m.total_lines,
            "duration_sec": f"{m.duration_ms / 1000:.2f}",
            "throughput": {
                "files_per_sec": f"{m.files_per_second:.1f}",
                "lines_per_sec": f"{m.lines_per_second:.0f}",
            },
            "features": {
                "incremental": m.incremental_enabled,
                "ripgrep": m.ripgrep_enabled,
                "parallel_workers": m.parallel_workers,
            },
        }

        if m.cache_hit_rate > 0:
            summary["cache_hit_rate"] = f"{m.cache_hit_rate:.1f}%"

        if m.memory_mb > 0:
            summary["memory_mb"] = f"{m.memory_mb:.1f}"

        if m.phase_timings:
            summary["phases"] = {
                phase: f"{duration:.0f}ms" for phase, duration in m.phase_timings.items()
            }

        return summary

    def print_report(self) -> None:
        """Print performance report to console."""
        summary = self.get_summary()

        print("\n" + "=" * 70)
        print("PyGuard Performance Report")
        print("=" * 70)

        print("\n📊 Overall Statistics:")
        print(f"  Files analyzed:     {summary['files']}")
        print(f"  Total lines:        {summary['lines']}")
        print(f"  Duration:           {summary['duration_sec']}s")

        print("\n⚡ Throughput:")
        print(f"  Files per second:   {summary['throughput']['files_per_sec']}")
        print(f"  Lines per second:   {summary['throughput']['lines_per_sec']}")

        features = summary["features"]
        print("\n🔧 Features Used:")
        print(f"  Incremental:        {'✓' if features['incremental'] else '✗'}")
        print(f"  RipGrep:            {'✓' if features['ripgrep'] else '✗'}")
        print(f"  Parallel workers:   {features['parallel_workers']}")

        if "cache_hit_rate" in summary:
            print(f"  Cache hit rate:     {summary['cache_hit_rate']}")

        if "memory_mb" in summary:
            print(f"  Memory usage:       {summary['memory_mb']} MB")

        if "phases" in summary:
            print("\n⏱️  Phase Timings:")
            for phase, duration in summary["phases"].items():
                print(f"  {phase:20s} {duration:>10s}")

        print("\n" + "=" * 70 + "\n")


def create_benchmark(
    name: str,
    description: str,
    metrics: PerformanceMetrics,
    baseline: PerformanceMetrics | None = None,
) -> PerformanceBenchmark:
    """
    Create a performance benchmark.

    Args:
        name: Benchmark name
        description: Benchmark description
        metrics: Measured performance metrics
        baseline: Optional baseline metrics for comparison

    Returns:
        PerformanceBenchmark object
    """
    return PerformanceBenchmark(
        name=name, description=description, metrics=metrics, baseline_metrics=baseline
    )


def compare_benchmarks(benchmarks: list[PerformanceBenchmark]) -> None:
    """
    Compare multiple benchmarks and print results.

    Args:
        benchmarks: List of benchmarks to compare
    """
    if not benchmarks:
        return

    print("\n" + "=" * 80)
    print("PyGuard Performance Comparison")
    print("=" * 80)

    # Table header
    print(f"\n{'Benchmark':<30} {'Files':<10} {'Duration':<12} {'Speedup':<10}")
    print("-" * 80)

    for benchmark in benchmarks:
        m = benchmark.metrics
        duration = f"{m.duration_ms / 1000:.2f}s"
        speedup = ""

        if benchmark.baseline_metrics:
            factor = benchmark.speedup_factor()
            improvement = benchmark.improvement_percentage()
            speedup = f"{factor:.2f}x ({improvement:+.1f}%)"

        print(f"{benchmark.name:<30} {m.total_files:<10} {duration:<12} {speedup:<10}")

    print("\n" + "=" * 80 + "\n")


# Context manager for timing phases
class timed_phase:  # noqa: N801 - Intentionally lowercase to match Python's context manager conventions
    """Context manager for timing analysis phases."""

    def __init__(self, tracker: PerformanceTracker, phase: AnalysisPhase):
        """
        Initialize timed phase context manager.

        Args:
            tracker: Performance tracker to use
            phase: Analysis phase to time
        """
        self.tracker = tracker
        self.phase = phase

    def __enter__(self) -> "timed_phase":
        """Start timing phase."""
        self.tracker.start_phase(self.phase)
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """End timing phase."""
        self.tracker.end_phase(self.phase)


# Example usage
def example_usage() -> None:
    """Example of using performance tracker."""
    tracker = PerformanceTracker()

    # Start total timing
    tracker.start_total()

    # Time individual phases
    with timed_phase(tracker, AnalysisPhase.FILE_DISCOVERY):
        # Simulate file discovery
        time.sleep(0.1)

    with timed_phase(tracker, AnalysisPhase.SECURITY_ANALYSIS):
        # Simulate security analysis
        time.sleep(0.3)

    with timed_phase(tracker, AnalysisPhase.REPORT_GENERATION):
        # Simulate report generation
        time.sleep(0.05)

    # End total timing
    tracker.end_total()

    # Set metrics
    tracker.set_file_count(100)
    tracker.set_line_count(10000)
    tracker.enable_incremental()
    tracker.set_parallel_workers(8)
    tracker.set_cache_hit_rate(75.0)

    # Print report
    tracker.print_report()


if __name__ == "__main__":
    example_usage()
