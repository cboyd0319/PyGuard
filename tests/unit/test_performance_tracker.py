"""Tests for performance tracking and benchmarking."""

import time

import pytest

from pyguard.lib.performance_tracker import (
    AnalysisPhase,
    PerformanceBenchmark,
    PerformanceMetrics,
    PerformanceTracker,
    compare_benchmarks,
    create_benchmark,
    timed_phase,
)


class TestAnalysisPhase:
    """Test AnalysisPhase enum."""

    def test_phase_values(self):
        """Test that all phases have correct values."""
        assert AnalysisPhase.FILE_DISCOVERY == "file_discovery"
        assert AnalysisPhase.AST_PARSING == "ast_parsing"
        assert AnalysisPhase.SECURITY_ANALYSIS == "security_analysis"
        assert AnalysisPhase.CODE_QUALITY == "code_quality"
        assert AnalysisPhase.AUTO_FIX == "auto_fix"
        assert AnalysisPhase.REPORT_GENERATION == "report_generation"
        assert AnalysisPhase.TOTAL == "total"


class TestPerformanceMetrics:
    """Test PerformanceMetrics dataclass."""

    def test_create_metrics(self):
        """Test creating performance metrics."""
        metrics = PerformanceMetrics(
            timestamp="2024-11-04T10:30:00Z",
            total_files=100,
            total_lines=10000,
            duration_ms=1500.0,
            files_per_second=66.67,
            lines_per_second=6666.67,
        )

        assert metrics.total_files == 100
        assert metrics.total_lines == 10000
        assert metrics.duration_ms == 1500.0
        assert metrics.files_per_second == 66.67

    def test_default_values(self):
        """Test default values for optional fields."""
        metrics = PerformanceMetrics(
            timestamp="2024-11-04T10:30:00Z",
            total_files=10,
            total_lines=1000,
            duration_ms=100.0,
            files_per_second=100.0,
            lines_per_second=10000.0,
        )

        assert metrics.cache_hit_rate == 0.0
        assert metrics.parallel_workers == 1
        assert metrics.incremental_enabled is False
        assert metrics.ripgrep_enabled is False
        assert metrics.memory_mb == 0.0
        assert len(metrics.phase_timings) == 0


class TestPerformanceBenchmark:
    """Test PerformanceBenchmark dataclass."""

    @pytest.fixture
    def baseline_metrics(self):
        """Create baseline metrics."""
        return PerformanceMetrics(
            timestamp="2024-11-04T10:00:00Z",
            total_files=100,
            total_lines=10000,
            duration_ms=2000.0,
            files_per_second=50.0,
            lines_per_second=5000.0,
        )

    @pytest.fixture
    def improved_metrics(self):
        """Create improved metrics."""
        return PerformanceMetrics(
            timestamp="2024-11-04T10:30:00Z",
            total_files=100,
            total_lines=10000,
            duration_ms=1000.0,  # 2x faster
            files_per_second=100.0,
            lines_per_second=10000.0,
            incremental_enabled=True,
        )

    def test_speedup_calculation(self, baseline_metrics, improved_metrics):
        """Test speedup factor calculation."""
        benchmark = PerformanceBenchmark(
            name="Test",
            description="Test benchmark",
            metrics=improved_metrics,
            baseline_metrics=baseline_metrics,
        )

        speedup = benchmark.speedup_factor()
        assert speedup == 2.0  # 2x faster

    def test_improvement_percentage(self, baseline_metrics, improved_metrics):
        """Test improvement percentage calculation."""
        benchmark = PerformanceBenchmark(
            name="Test",
            description="Test benchmark",
            metrics=improved_metrics,
            baseline_metrics=baseline_metrics,
        )

        improvement = benchmark.improvement_percentage()
        assert improvement == 100.0  # 100% improvement (2x faster)

    def test_no_baseline(self, improved_metrics):
        """Test benchmark without baseline."""
        benchmark = PerformanceBenchmark(
            name="Test", description="Test benchmark", metrics=improved_metrics
        )

        speedup = benchmark.speedup_factor()
        improvement = benchmark.improvement_percentage()

        assert speedup == 1.0
        assert improvement == 0.0


class TestPerformanceTracker:
    """Test PerformanceTracker functionality."""

    @pytest.fixture
    def tracker(self):
        """Create a performance tracker."""
        return PerformanceTracker()

    def test_initialization(self, tracker):
        """Test tracker initialization."""
        assert tracker.metrics.total_files == 0
        assert tracker.metrics.total_lines == 0
        assert tracker.metrics.duration_ms == 0.0
        assert len(tracker._start_times) == 0

    def test_set_file_count(self, tracker):
        """Test setting file count."""
        tracker.set_file_count(100)
        assert tracker.metrics.total_files == 100

    def test_set_line_count(self, tracker):
        """Test setting line count."""
        tracker.set_line_count(10000)
        assert tracker.metrics.total_lines == 10000

    def test_set_cache_hit_rate(self, tracker):
        """Test setting cache hit rate."""
        tracker.set_cache_hit_rate(75.5)
        assert tracker.metrics.cache_hit_rate == 75.5

    def test_set_parallel_workers(self, tracker):
        """Test setting parallel workers."""
        tracker.set_parallel_workers(8)
        assert tracker.metrics.parallel_workers == 8

    def test_enable_incremental(self, tracker):
        """Test enabling incremental analysis."""
        tracker.enable_incremental()
        assert tracker.metrics.incremental_enabled is True

    def test_enable_ripgrep(self, tracker):
        """Test enabling RipGrep."""
        tracker.enable_ripgrep()
        assert tracker.metrics.ripgrep_enabled is True

    def test_set_memory_usage(self, tracker):
        """Test setting memory usage."""
        tracker.set_memory_usage(123.45)
        assert tracker.metrics.memory_mb == 123.45

    def test_phase_timing(self, tracker):
        """Test timing a single phase."""
        tracker.start_phase(AnalysisPhase.SECURITY_ANALYSIS)
        time.sleep(0.01)  # 10ms
        duration = tracker.end_phase(AnalysisPhase.SECURITY_ANALYSIS)

        assert duration >= 10.0  # At least 10ms
        assert AnalysisPhase.SECURITY_ANALYSIS.value in tracker.metrics.phase_timings

    def test_total_timing(self, tracker):
        """Test total timing."""
        tracker.set_file_count(100)
        tracker.set_line_count(10000)

        tracker.start_total()
        time.sleep(0.02)  # 20ms
        duration = tracker.end_total()

        assert duration >= 20.0
        assert tracker.metrics.duration_ms >= 20.0
        assert tracker.metrics.files_per_second > 0
        assert tracker.metrics.lines_per_second > 0

    def test_multiple_phases(self, tracker):
        """Test timing multiple phases."""
        tracker.start_phase(AnalysisPhase.FILE_DISCOVERY)
        time.sleep(0.01)
        tracker.end_phase(AnalysisPhase.FILE_DISCOVERY)

        tracker.start_phase(AnalysisPhase.SECURITY_ANALYSIS)
        time.sleep(0.01)
        tracker.end_phase(AnalysisPhase.SECURITY_ANALYSIS)

        assert len(tracker.metrics.phase_timings) == 2
        assert AnalysisPhase.FILE_DISCOVERY.value in tracker.metrics.phase_timings
        assert AnalysisPhase.SECURITY_ANALYSIS.value in tracker.metrics.phase_timings

    def test_get_metrics(self, tracker):
        """Test getting metrics."""
        tracker.set_file_count(50)
        metrics = tracker.get_metrics()

        assert isinstance(metrics, PerformanceMetrics)
        assert metrics.total_files == 50

    def test_get_summary(self, tracker):
        """Test getting summary."""
        tracker.set_file_count(100)
        tracker.set_line_count(10000)
        tracker.enable_incremental()
        tracker.set_parallel_workers(4)

        summary = tracker.get_summary()

        assert "files" in summary
        assert "lines" in summary
        assert "duration_sec" in summary
        assert "throughput" in summary
        assert "features" in summary
        assert summary["files"] == 100
        assert summary["lines"] == 10000
        assert summary["features"]["incremental"] is True
        assert summary["features"]["parallel_workers"] == 4

    def test_summary_with_cache(self, tracker):
        """Test summary includes cache hit rate."""
        tracker.set_cache_hit_rate(80.5)
        summary = tracker.get_summary()

        assert "cache_hit_rate" in summary
        assert "80.5%" in summary["cache_hit_rate"]

    def test_summary_with_memory(self, tracker):
        """Test summary includes memory usage."""
        tracker.set_memory_usage(256.75)
        summary = tracker.get_summary()

        assert "memory_mb" in summary
        assert "256.8" in summary["memory_mb"]  # Rounded to 1 decimal

    def test_print_report(self, tracker):
        """Test printing report (should not raise)."""
        tracker.set_file_count(100)
        tracker.set_line_count(10000)
        # Should not raise exception
        tracker.print_report()

    def test_end_phase_without_start(self, tracker):
        """Test ending phase that wasn't started."""
        duration = tracker.end_phase(AnalysisPhase.SECURITY_ANALYSIS)
        assert duration == 0.0

    def test_end_total_without_start(self, tracker):
        """Test ending total without start."""
        duration = tracker.end_total()
        assert duration == 0.0


class TestTimedPhaseContextManager:
    """Test timed_phase context manager."""

    def test_context_manager(self):
        """Test using timed_phase as context manager."""
        tracker = PerformanceTracker()

        with timed_phase(tracker, AnalysisPhase.SECURITY_ANALYSIS):
            time.sleep(0.01)

        assert AnalysisPhase.SECURITY_ANALYSIS.value in tracker.metrics.phase_timings
        duration = tracker.metrics.phase_timings[AnalysisPhase.SECURITY_ANALYSIS.value]
        assert duration >= 10.0

    def test_context_manager_with_exception(self):
        """Test context manager handles exceptions."""
        tracker = PerformanceTracker()

        with pytest.raises(ValueError):
            with timed_phase(tracker, AnalysisPhase.SECURITY_ANALYSIS):
                raise ValueError("Test error")

        # Phase should still be recorded
        assert AnalysisPhase.SECURITY_ANALYSIS.value in tracker.metrics.phase_timings


class TestBenchmarkFactory:
    """Test benchmark factory function."""

    def test_create_benchmark(self):
        """Test creating benchmark."""
        metrics = PerformanceMetrics(
            timestamp="2024-11-04T10:30:00Z",
            total_files=100,
            total_lines=10000,
            duration_ms=1500.0,
            files_per_second=66.67,
            lines_per_second=6666.67,
        )

        benchmark = create_benchmark(
            name="Test Benchmark", description="Testing benchmark creation", metrics=metrics
        )

        assert isinstance(benchmark, PerformanceBenchmark)
        assert benchmark.name == "Test Benchmark"
        assert benchmark.description == "Testing benchmark creation"
        assert benchmark.metrics == metrics
        assert benchmark.baseline_metrics is None

    def test_create_benchmark_with_baseline(self):
        """Test creating benchmark with baseline."""
        baseline = PerformanceMetrics(
            timestamp="2024-11-04T10:00:00Z",
            total_files=100,
            total_lines=10000,
            duration_ms=2000.0,
            files_per_second=50.0,
            lines_per_second=5000.0,
        )

        metrics = PerformanceMetrics(
            timestamp="2024-11-04T10:30:00Z",
            total_files=100,
            total_lines=10000,
            duration_ms=1000.0,
            files_per_second=100.0,
            lines_per_second=10000.0,
        )

        benchmark = create_benchmark(
            name="Test", description="Test with baseline", metrics=metrics, baseline=baseline
        )

        assert benchmark.baseline_metrics == baseline
        assert benchmark.speedup_factor() == 2.0


class TestBenchmarkComparison:
    """Test benchmark comparison functionality."""

    def test_compare_benchmarks(self):
        """Test comparing multiple benchmarks (should not raise)."""
        metrics1 = PerformanceMetrics(
            timestamp="2024-11-04T10:00:00Z",
            total_files=100,
            total_lines=10000,
            duration_ms=2000.0,
            files_per_second=50.0,
            lines_per_second=5000.0,
        )

        metrics2 = PerformanceMetrics(
            timestamp="2024-11-04T10:30:00Z",
            total_files=100,
            total_lines=10000,
            duration_ms=1000.0,
            files_per_second=100.0,
            lines_per_second=10000.0,
        )

        benchmark1 = create_benchmark("Baseline", "Baseline run", metrics1)
        benchmark2 = create_benchmark("Optimized", "With optimizations", metrics2, baseline=metrics1)

        # Should not raise
        compare_benchmarks([benchmark1, benchmark2])

    def test_compare_empty_benchmarks(self):
        """Test comparing empty list (should not raise)."""
        compare_benchmarks([])


class TestPerformanceTrackerIntegration:
    """Integration tests for performance tracker."""

    def test_complete_analysis_workflow(self):
        """Test complete workflow with all phases."""
        tracker = PerformanceTracker()

        # Configure
        tracker.set_file_count(150)
        tracker.set_line_count(15000)
        tracker.enable_incremental()
        tracker.enable_ripgrep()
        tracker.set_parallel_workers(8)
        tracker.set_cache_hit_rate(85.5)

        # Time analysis
        tracker.start_total()

        with timed_phase(tracker, AnalysisPhase.FILE_DISCOVERY):
            time.sleep(0.01)

        with timed_phase(tracker, AnalysisPhase.AST_PARSING):
            time.sleep(0.01)

        with timed_phase(tracker, AnalysisPhase.SECURITY_ANALYSIS):
            time.sleep(0.01)

        with timed_phase(tracker, AnalysisPhase.CODE_QUALITY):
            time.sleep(0.01)

        with timed_phase(tracker, AnalysisPhase.AUTO_FIX):
            time.sleep(0.01)

        with timed_phase(tracker, AnalysisPhase.REPORT_GENERATION):
            time.sleep(0.01)

        tracker.end_total()

        # Verify metrics
        metrics = tracker.get_metrics()
        assert metrics.total_files == 150
        assert metrics.total_lines == 15000
        assert metrics.incremental_enabled is True
        assert metrics.ripgrep_enabled is True
        assert metrics.parallel_workers == 8
        assert metrics.cache_hit_rate == 85.5
        assert len(metrics.phase_timings) >= 6  # All phases tracked

        # Verify throughput
        assert metrics.files_per_second > 0
        assert metrics.lines_per_second > 0

        # Get summary
        summary = tracker.get_summary()
        assert "phases" in summary
        assert len(summary["phases"]) >= 6
