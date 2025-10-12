"""Setup configuration for PyGuard."""
from setuptools import setup, find_packages

setup(
    packages=find_packages(exclude=["tests", "tests.*", "benchmarks", "docs"]),
    include_package_data=True,
    package_data={
        "pyguard": ["config/*.json", "config/*.toml"],
    },
)
