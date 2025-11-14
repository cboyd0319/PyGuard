#!/usr/bin/env python3
"""
Performance Benchmarking Tool

Benchmarks PyGuard's performance across different project sizes and complexity levels.

Target: <5 seconds for 1,000 SLOC (v1.0.0 goal)

Usage:
    python tools/benchmark_performance.py --generate
    python tools/benchmark_performance.py --benchmark
    python tools/benchmark_performance.py --report
    python tools/benchmark_performance.py --all  # Run all steps
"""

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple
import statistics

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))


class PerformanceBenchmark:
    """Performance benchmarking for PyGuard"""

    def __init__(self, workspace_dir: str = "performance_workspace"):
        self.workspace = Path(workspace_dir)
        self.workspace.mkdir(exist_ok=True)
        self.test_projects_dir = self.workspace / "test_projects"
        self.test_projects_dir.mkdir(exist_ok=True)
        self.results_dir = self.workspace / "results"
        self.results_dir.mkdir(exist_ok=True)

    def generate_test_projects(self) -> Dict[str, Path]:
        """Generate test projects of various sizes"""
        print("=" * 80)
        print("GENERATING TEST PROJECTS")
        print("=" * 80)
        print()

        projects = {}

        # Small project: 500 SLOC
        projects['small'] = self._generate_project(
            name='small',
            num_files=10,
            sloc_per_file=50,
            description="Small project (500 SLOC, 10 files)"
        )

        # Medium project: 1,000 SLOC
        projects['medium'] = self._generate_project(
            name='medium',
            num_files=20,
            sloc_per_file=50,
            description="Medium project (1,000 SLOC, 20 files)"
        )

        # Large project: 5,000 SLOC
        projects['large'] = self._generate_project(
            name='large',
            num_files=100,
            sloc_per_file=50,
            description="Large project (5,000 SLOC, 100 files)"
        )

        # Extra large project: 10,000 SLOC
        projects['xlarge'] = self._generate_project(
            name='xlarge',
            num_files=200,
            sloc_per_file=50,
            description="Extra large project (10,000 SLOC, 200 files)"
        )

        # Complex project: Deep nesting, many imports
        projects['complex'] = self._generate_complex_project(
            name='complex',
            num_modules=30,
            description="Complex project (1,500 SLOC, 30 files, deep nesting)"
        )

        print(f"✅ Generated {len(projects)} test projects")
        print()

        return projects

    def _generate_project(self, name: str, num_files: int, sloc_per_file: int, description: str) -> Path:
        """Generate a test project with specified characteristics"""
        project_dir = self.test_projects_dir / name
        project_dir.mkdir(exist_ok=True)

        src_dir = project_dir / "src"
        src_dir.mkdir(exist_ok=True)

        print(f"[GENERATE] {name}")
        print(f"  {description}")
        print(f"  Path: {project_dir}")

        # Generate files
        for i in range(num_files):
            file_path = src_dir / f"module_{i:03d}.py"
            self._generate_python_file(file_path, sloc_per_file, module_index=i)

        # Generate __init__.py
        init_file = src_dir / "__init__.py"
        with open(init_file, 'w') as f:
            f.write('"""Test package"""\n')

        total_sloc = num_files * sloc_per_file
        print(f"  [OK] Generated {num_files} files, ~{total_sloc} SLOC")
        print()

        return project_dir

    def _generate_python_file(self, file_path: Path, sloc: int, module_index: int = 0):
        """Generate a Python file with realistic code patterns"""
        with open(file_path, 'w') as f:
            # Module docstring
            f.write(f'"""\nModule {module_index}: Generated test module\n"""\n\n')

            # Imports
            f.write('import os\n')
            f.write('import sys\n')
            f.write('from typing import List, Dict, Optional\n\n')

            # Calculate lines needed
            lines_written = 7  # docstring + imports
            lines_needed = sloc - lines_written

            # Generate classes and functions
            num_classes = max(1, lines_needed // 30)
            for class_idx in range(num_classes):
                class_lines = self._generate_class(f, class_idx, module_index)
                lines_written += class_lines

                if lines_written >= sloc:
                    break

            # Fill remaining with functions
            func_idx = 0
            while lines_written < sloc:
                func_lines = self._generate_function(f, func_idx, module_index)
                lines_written += func_lines
                func_idx += 1

    def _generate_class(self, f, class_idx: int, module_idx: int) -> int:
        """Generate a class with methods"""
        lines = 0

        # Class definition
        f.write(f'\nclass TestClass{class_idx}:\n')
        f.write(f'    """Test class {class_idx} in module {module_idx}"""\n\n')
        lines += 3

        # __init__
        f.write('    def __init__(self, name: str, value: int = 0):\n')
        f.write('        self.name = name\n')
        f.write('        self.value = value\n')
        f.write('        self.data: Dict[str, any] = {}\n\n')
        lines += 5

        # Methods
        for method_idx in range(2):
            method_lines = self._generate_method(f, method_idx)
            lines += method_lines

        return lines

    def _generate_method(self, f, method_idx: int) -> int:
        """Generate a class method"""
        lines = 0

        f.write(f'    def method_{method_idx}(self, param: str) -> str:\n')
        f.write(f'        """Method {method_idx} implementation"""\n')
        f.write('        result = param.upper()\n')
        f.write('        self.data[param] = result\n')
        f.write('        return result\n\n')
        lines += 6

        return lines

    def _generate_function(self, f, func_idx: int, module_idx: int) -> int:
        """Generate a module-level function"""
        lines = 0

        f.write(f'\ndef function_{func_idx}(x: int, y: int) -> int:\n')
        f.write(f'    """Function {func_idx} in module {module_idx}"""\n')
        f.write('    if x > y:\n')
        f.write('        return x + y\n')
        f.write('    else:\n')
        f.write('        return x * y\n\n')
        lines += 7

        return lines

    def _generate_complex_project(self, name: str, num_modules: int, description: str) -> Path:
        """Generate a complex project with deep nesting and imports"""
        project_dir = self.test_projects_dir / name
        project_dir.mkdir(exist_ok=True)

        print(f"[GENERATE] {name}")
        print(f"  {description}")
        print(f"  Path: {project_dir}")

        # Create nested package structure
        packages = ['core', 'utils', 'api', 'models', 'services']

        for package in packages:
            pkg_dir = project_dir / package
            pkg_dir.mkdir(exist_ok=True)

            # __init__.py
            init_file = pkg_dir / "__init__.py"
            with open(init_file, 'w') as f:
                f.write(f'"""{package.capitalize()} package"""\n')

            # Generate modules in this package
            modules_per_package = num_modules // len(packages)
            for i in range(modules_per_package):
                file_path = pkg_dir / f"{package}_module_{i}.py"
                self._generate_python_file(file_path, sloc=50, module_index=i)

        print(f"  [OK] Generated {num_modules} modules across {len(packages)} packages")
        print()

        return project_dir

    def run_benchmarks(self, runs_per_test: int = 5) -> Dict[str, Dict]:
        """Run performance benchmarks on all test projects"""
        print("=" * 80)
        print("RUNNING PERFORMANCE BENCHMARKS")
        print("=" * 80)
        print()
        print(f"Runs per test: {runs_per_test} (for statistical significance)")
        print()

        results = {}

        for project_name in ['small', 'medium', 'large', 'xlarge', 'complex']:
            project_dir = self.test_projects_dir / project_name

            if not project_dir.exists():
                print(f"[SKIP] {project_name} - not found")
                continue

            print(f"[BENCHMARK] {project_name}")
            print(f"  Path: {project_dir}")

            # Count files and SLOC
            file_count, sloc = self._count_sloc(project_dir)
            print(f"  Files: {file_count}, SLOC: {sloc}")

            # Run multiple times for statistical significance
            run_times = []
            run_data = []

            for run in range(runs_per_test):
                print(f"  Run {run + 1}/{runs_per_test}...", end=' ', flush=True)

                start_time = time.time()

                # Run PyGuard scan
                cmd = [
                    sys.executable,
                    "-m", "pyguard.cli",
                    str(project_dir),
                    "--scan-only",
                    "--no-color"
                ]

                try:
                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=300  # 5 minute timeout
                    )

                    elapsed = time.time() - start_time
                    run_times.append(elapsed)

                    run_data.append({
                        "run": run + 1,
                        "elapsed_seconds": elapsed,
                        "exit_code": result.returncode,
                        "success": result.returncode in [0, 1]
                    })

                    print(f"{elapsed:.3f}s")

                except subprocess.TimeoutExpired:
                    print("TIMEOUT")
                    run_data.append({
                        "run": run + 1,
                        "timeout": True
                    })
                except Exception as e:
                    print(f"ERROR: {e}")
                    run_data.append({
                        "run": run + 1,
                        "error": str(e)
                    })

            # Calculate statistics
            if run_times:
                mean_time = statistics.mean(run_times)
                median_time = statistics.median(run_times)
                stdev_time = statistics.stdev(run_times) if len(run_times) > 1 else 0
                min_time = min(run_times)
                max_time = max(run_times)

                # Calculate SLOC/second throughput
                throughput = sloc / mean_time if mean_time > 0 else 0

                # Time per 1K SLOC (target metric)
                time_per_1k = (mean_time / sloc) * 1000 if sloc > 0 else 0

                results[project_name] = {
                    "project": project_name,
                    "files": file_count,
                    "sloc": sloc,
                    "runs": runs_per_test,
                    "run_data": run_data,
                    "mean_time": mean_time,
                    "median_time": median_time,
                    "stdev_time": stdev_time,
                    "min_time": min_time,
                    "max_time": max_time,
                    "throughput_sloc_per_sec": throughput,
                    "time_per_1k_sloc": time_per_1k
                }

                print(f"  Mean: {mean_time:.3f}s, Median: {median_time:.3f}s, StDev: {stdev_time:.3f}s")
                print(f"  Throughput: {throughput:.0f} SLOC/s")
                print(f"  Time per 1K SLOC: {time_per_1k:.3f}s")

                # Goal assessment
                goal_time = 5.0  # seconds for 1K SLOC
                if time_per_1k <= goal_time:
                    status = f"✅ Below target (<{goal_time}s)"
                else:
                    status = f"⚠️ Above target (>{goal_time}s)"
                print(f"  {status}")

            print()

        # Save results
        results_file = self.results_dir / f"perf_benchmark_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2)

        print(f"✅ Benchmark complete. Results: {results_file}")
        print()

        return results

    def _count_sloc(self, directory: Path) -> Tuple[int, int]:
        """Count Python files and SLOC in directory"""
        file_count = 0
        sloc = 0

        for py_file in directory.rglob("*.py"):
            file_count += 1
            with open(py_file, 'r') as f:
                lines = f.readlines()
                # Count non-empty, non-comment lines
                sloc += sum(1 for line in lines if line.strip() and not line.strip().startswith('#'))

        return file_count, sloc

    def generate_report(self, results: Dict[str, Dict]) -> None:
        """Generate performance report"""
        print("=" * 80)
        print("PERFORMANCE BENCHMARK REPORT")
        print("=" * 80)
        print()

        print("RESULTS SUMMARY:")
        print()

        # Table header
        print(f"{'Project':<12} {'Files':<8} {'SLOC':<8} {'Mean Time':<12} {'Per 1K SLOC':<12} {'Throughput':<15} {'Status':<10}")
        print("-" * 100)

        goal_time = 5.0  # seconds for 1K SLOC

        for project_name, data in sorted(results.items(), key=lambda x: x[1]['sloc']):
            files = data['files']
            sloc = data['sloc']
            mean_time = data['mean_time']
            time_per_1k = data['time_per_1k_sloc']
            throughput = data['throughput_sloc_per_sec']

            if time_per_1k <= goal_time:
                status = "✅ PASS"
            else:
                status = "⚠️ SLOW"

            print(f"{project_name:<12} {files:<8} {sloc:<8} {mean_time:>8.3f}s    {time_per_1k:>8.3f}s    {throughput:>10.0f} SLOC/s {status:<10}")

        print()
        print("=" * 80)
        print(f"TARGET: <{goal_time}s for 1,000 SLOC (v1.0.0 goal)")
        print("=" * 80)
        print()

        # Assess overall performance
        all_pass = all(data['time_per_1k_sloc'] <= goal_time for data in results.values())

        if all_pass:
            print("✅ ALL TESTS PASS - Performance target achieved!")
        else:
            slow_projects = [name for name, data in results.items() if data['time_per_1k_sloc'] > goal_time]
            print(f"⚠️ NEEDS IMPROVEMENT - {len(slow_projects)} projects above target:")
            for project in slow_projects:
                print(f"  - {project}")

        print()

        # Performance trend analysis
        if len(results) > 1:
            print("PERFORMANCE SCALING:")
            print()

            # Analyze scaling with project size
            sizes = sorted([(data['sloc'], data['mean_time']) for data in results.values()])

            print(f"  Scaling factor (time relative to 500 SLOC baseline):")
            baseline_time = next((t for s, t in sizes if s >= 500), sizes[0][1])

            for sloc, time in sizes:
                scale = time / baseline_time if baseline_time > 0 else 0
                ideal_scale = sloc / 500  # Linear scaling
                efficiency = (ideal_scale / scale * 100) if scale > 0 else 100

                print(f"    {sloc:>6} SLOC: {scale:>5.2f}x actual, {ideal_scale:>5.2f}x ideal ({efficiency:>5.1f}% efficient)")

            print()

        # Save summary
        summary_file = self.results_dir / "performance_summary.json"
        summary = {
            "generated_at": datetime.now().isoformat(),
            "target_time_per_1k_sloc": goal_time,
            "all_pass": all_pass,
            "results": results
        }

        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)

        print(f"📊 Summary saved to: {summary_file}")
        print()


def main():
    parser = argparse.ArgumentParser(description="PyGuard Performance Benchmarking")
    parser.add_argument("--generate", action="store_true", help="Generate test projects")
    parser.add_argument("--benchmark", action="store_true", help="Run performance benchmarks")
    parser.add_argument("--report", action="store_true", help="Generate report from latest results")
    parser.add_argument("--all", action="store_true", help="Run all steps (generate, benchmark, report)")
    parser.add_argument("--workspace", default="performance_workspace", help="Workspace directory")
    parser.add_argument("--runs", type=int, default=5, help="Number of runs per test (default: 5)")

    args = parser.parse_args()

    if not any([args.generate, args.benchmark, args.report, args.all]):
        parser.print_help()
        return 1

    benchmark = PerformanceBenchmark(workspace_dir=args.workspace)

    if args.all or args.generate:
        benchmark.generate_test_projects()

    if args.all or args.benchmark:
        results = benchmark.run_benchmarks(runs_per_test=args.runs)

        if args.all:
            benchmark.generate_report(results)

    if args.report and not args.all:
        # Load latest results
        result_files = sorted(benchmark.results_dir.glob("perf_benchmark_*.json"))
        if result_files:
            latest_file = result_files[-1]
            with open(latest_file, 'r') as f:
                results = json.load(f)
            benchmark.generate_report(results)
        else:
            print("No benchmark results found. Run --benchmark first.")
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
