# GitHub Actions Workflows

This directory contains the CI/CD workflows for PyGuard. All workflows have been optimized for efficiency and cost-effectiveness.

## 📋 Workflows Overview

### 1. **test.yml** - Cross-Platform Testing
**Triggers:** Push/PR to `main` or `develop`

**What it does:**
- Tests on Ubuntu Linux with Python 3.8, 3.11, and 3.12
- Tests on macOS and Windows with Python 3.12 only
- Runs full test suite
- Validates CLI functionality

**Why optimized:** Reduced from 15 jobs (3 OS × 5 Python versions) to 5 jobs, focusing on critical version combinations.

### 2. **lint.yml** - Code Quality & Linting
**Triggers:** Push/PR to `main` or `develop`

**What it does:**
- **Code Quality Job:**
  - Black formatting check
  - isort import sorting check
  - Pylint analysis (non-blocking)
  - mypy type checking
  - flake8 linting
- **Security Job:**
  - Bandit security scanning
  - Safety dependency checking

**Why consolidated:** Merged `lint.yml` and `quality.yml` to eliminate duplication and reduce workflow overhead.

### 3. **coverage.yml** - Test Coverage
**Triggers:** Push/PR to `main`

**What it does:**
- Runs tests with coverage reporting
- Uploads coverage to Codecov
- Generates HTML coverage reports
- Adds coverage summary to workflow output

**Improvements:**
- Added proper Codecov token handling
- Added coverage summary to GitHub Actions summary
- Fixed artifact upload conditions

### 4. **benchmarks.yml** - Performance Benchmarks
**Triggers:** 
- Push/PR to `main`
- Weekly schedule (Monday 00:00 UTC)
- Manual workflow dispatch

**What it does:**
- Runs security module benchmarks
- Captures and saves benchmark results
- Adds results to workflow summary

**Improvements:**
- Fixed benchmark output capture with `tee`
- Added workflow summary output
- Added manual trigger capability

### 5. **release.yml** - Automated Releases
**Triggers:** Version tags (`v*.*.*`)

**What it does:**
- Builds distribution packages
- Publishes to Test PyPI (optional)
- Publishes to PyPI
- Creates GitHub release with changelog notes

**Improvements:**
- Fixed release notes extraction from CHANGELOG.md
- Simplified changelog parsing logic
- Updated to latest action versions

### 6. **codeql.yml** - Security Scanning
**Triggers:**
- Push/PR to `main`
- Weekly schedule (Monday 00:00 UTC)
- Manual workflow dispatch

**What it does:**
- Runs CodeQL security analysis
- Scans for security vulnerabilities
- Reports findings to Security tab

**Improvements:**
- Added security-and-quality queries
- Removed unnecessary autobuild step
- Added manual trigger capability

## 🎯 Design Principles

### Cost Optimization
- **Reduced test matrix:** From 15 to 5 jobs (-67% reduction)
- **Consolidated workflows:** Merged duplicate linting workflows
- **Strategic testing:** Full matrix on Linux, latest version on macOS/Windows

### Reliability
- **Proper error handling:** Critical checks fail builds, informational checks don't
- **Artifact persistence:** Results saved even on failures with `if: always()`
- **Token management:** Proper secrets handling for external services

### Developer Experience
- **Fast feedback:** Most checks complete in < 5 minutes
- **Clear reporting:** Summaries added to GitHub Actions UI
- **Manual triggers:** Key workflows can be triggered manually

## 📊 Workflow Statistics

| Workflow | Jobs | Avg Duration | Triggers |
|----------|------|--------------|----------|
| test.yml | 5 | ~3-5 min | Push, PR |
| lint.yml | 2 | ~2-3 min | Push, PR |
| coverage.yml | 1 | ~3-4 min | Push, PR (main) |
| benchmarks.yml | 1 | ~1-2 min | Push, PR, Schedule, Manual |
| release.yml | 1 | ~2-3 min | Tags |
| codeql.yml | 1 | ~5-10 min | Push, PR, Schedule, Manual |

**Total:** 11 jobs across 6 workflows (down from ~20+ jobs in 7 workflows)

## 🔧 Maintenance Notes

### Adding New Dependencies
When adding new linting tools or dependencies, update:
1. `pyproject.toml` - Add to `dependencies` or `dev` section
2. Relevant workflow file - Add installation/execution steps
3. This README - Document the change

### Workflow Best Practices
- Use `cache: 'pip'` for Python setup actions
- Set appropriate `timeout` values for long-running jobs
- Use `continue-on-error: true` only for informational checks
- Always add `if: always()` to artifact uploads
- Prefer workflow summaries over PR comments for results

### Testing Workflows
Before pushing workflow changes:
1. Test locally with `act` (if possible)
2. Review workflow syntax with GitHub's workflow validator
3. Test on a feature branch first
4. Monitor first runs carefully

## 📝 Change History

### 2025-10-12
- **Removed:** `quality.yml` (consolidated into `lint.yml`)
- **Optimized:** `test.yml` matrix from 15 to 5 jobs
- **Fixed:** `coverage.yml` token handling and summary output
- **Fixed:** `benchmarks.yml` output capture
- **Fixed:** `release.yml` changelog extraction
- **Enhanced:** `codeql.yml` with better queries and manual trigger
- **Updated:** All workflows to latest action versions

## 🔗 Related Documentation

- [Contributing Guide](../../CONTRIBUTING.md)
- [Repository Structure](../../docs/REPOSITORY_STRUCTURE.md)
- [Release Process](../../CHANGELOG.md#release-process)
