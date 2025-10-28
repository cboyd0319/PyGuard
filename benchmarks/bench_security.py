#!/usr/bin/env python3
"""
Security module performance benchmarks.

Measures the performance of security vulnerability detection and fixing.
"""

from pathlib import Path
import time

from pyguard.lib.security import SecurityFixer

# Sample code for benchmarking
SAMPLE_CODE = (
    """
import random
import yaml
import hashlib
password = "secret123"

def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    return query

token = random.random()
data = yaml.load(file)
hash = hashlib.md5(data)
"""
    * 10
)  # Repeat 10 times for more substantial content


def benchmark_security_scan(iterations=100):
    """Benchmark security vulnerability scanning."""
    fixer = SecurityFixer()
    temp_file = Path("/tmp/bench_security.py")
    temp_file.write_text(SAMPLE_CODE)

    start = time.perf_counter()
    for _ in range(iterations):
        fixer.scan_file_for_issues(temp_file)
    end = time.perf_counter()

    avg_time = (end - start) / iterations * 1000  # Convert to ms

    temp_file.unlink()
    return avg_time


def benchmark_security_fix(iterations=50):
    """Benchmark security fix application."""
    fixer = SecurityFixer()
    temp_file = Path("/tmp/bench_security_fix.py")

    start = time.perf_counter()
    for _ in range(iterations):
        temp_file.write_text(SAMPLE_CODE)
        fixer.fix_file(temp_file)
    end = time.perf_counter()

    avg_time = (end - start) / iterations * 1000  # Convert to ms

    temp_file.unlink()
    return avg_time


def main():
    """Run all security benchmarks."""

    benchmark_security_scan()
    benchmark_security_fix()


if __name__ == "__main__":
    main()
