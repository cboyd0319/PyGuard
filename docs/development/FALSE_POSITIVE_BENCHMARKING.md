# False Positive Rate Benchmarking Guide

**Status:** ⚠️ Baseline Not Established
**Goal:** <1.5% for v0.7.0, <1% for v1.0.0
**Priority:** MEDIUM - Quality metric

---

## Overview

This guide explains how to measure and track PyGuard's false positive rate using the automated benchmarking tool.

### Why It Matters

False positives (FPs) hurt developer experience:
- **Developer frustration** - Time wasted investigating non-issues
- **Tool abandonment** - High FP rate leads to ignoring all warnings
- **Decreased trust** - Developers stop trusting the tool's judgement

### Target Rates

| Version | Target FP Rate | Status |
|---------|----------------|--------|
| v0.7.0 | <1.5% | ⚠️ Not measured |
| v1.0.0 | <1.0% | ⚠️ Not measured |

**Industry Comparison:**
- Bandit: ~3-5% FP rate (estimated)
- Semgrep: ~2-4% FP rate (varies by ruleset)
- SonarQube: ~2-3% FP rate (community rules)

---

## Quick Start

### Step 1: Clone Benchmark Projects (15 minutes)

```bash
python tools/benchmark_false_positives.py --clone
```

This clones 10 popular Python projects:
- Django, Flask, FastAPI (web frameworks)
- Requests, HTTPX (HTTP clients)
- NumPy, Pandas, Scikit-learn (data science)
- Pytest (testing), Black (formatting)

**Total:** ~7,000+ Python files, ~500K+ lines of code

### Step 2: Run Scans (30-60 minutes)

```bash
python tools/benchmark_false_positives.py --scan --severity MEDIUM
```

This scans all projects and saves results to `benchmark_workspace/results/`.

**Options:**
- `--severity LOW|MEDIUM|HIGH|CRITICAL` - Minimum severity threshold
- Default: MEDIUM (recommended for baseline)

### Step 3: Generate Review Templates (1 minute)

```bash
python tools/benchmark_false_positives.py --review
```

This creates `*_review.jsonl` files in `benchmark_workspace/review/`.

Each finding has fields for manual classification:
- `is_false_positive`: true/false/unsure
- `reason`: Why is it a false positive?
- `pattern`: Common FP pattern name
- `suggestion`: How to improve the rule

### Step 4: Manual Review (2-8 hours)

Open each `*_review.jsonl` file and classify findings:

```json
{
  "project": "django",
  "finding_id": 0,
  "rule_id": "PY001",
  "severity": "MEDIUM",
  "file": "django/core/handlers/base.py",
  "line": 123,
  "message": "Use of eval() detected",
  "code_snippet": "eval(expression)",

  // Manual review fields - FILL THESE IN:
  "is_false_positive": true,
  "reason": "False positive - this is ast.literal_eval, not eval",
  "pattern": "misidentified_safe_eval",
  "suggestion": "Improve rule to distinguish eval() from ast.literal_eval()"
}
```

**Review Guidelines:**

**True Positive (is_false_positive: false):**
- Actual security issue or code quality problem
- Should be flagged by PyGuard
- Developer should fix or suppress with justification

**False Positive (is_false_positive: true):**
- Not actually a security issue
- Safe pattern that looks unsafe
- Should NOT be flagged by PyGuard

**Unsure (is_false_positive: "unsure"):**
- Ambiguous - could be issue depending on context
- Needs deeper analysis
- Mark for team review

**Review Tips:**
1. Focus on HIGH/CRITICAL first (highest impact)
2. Look for patterns (same rule, same type of FP)
3. Check project context (test code vs production code)
4. Consult project maintainers if unsure
5. Take breaks - review fatigue leads to errors

### Step 5: Generate Report (1 minute)

```bash
python tools/benchmark_false_positives.py --report
```

Output example:
```
===========================================================================
FALSE POSITIVE RATE REPORT
===========================================================================

Total Findings: 1,245
Reviewed: 1,245 (100.0%)
Unreviewed: 0

CLASSIFICATION:
  True Positives:  1,156 (92.9%)
  False Positives:   78 (6.3%)
  Unsure:            11 (0.9%)

===========================================================================
FALSE POSITIVE RATE: 6.26%
===========================================================================
❌ NEEDS IMPROVEMENT - Above target (>2%)

TOP FALSE POSITIVE RULES:
  PY001-hardcoded-credentials                       23 (29.5%)
  PY015-sql-injection                              12 (15.4%)
  PY023-exec-usage                                  8 (10.3%)

FALSE POSITIVES BY SEVERITY:
  HIGH         45 (57.7%)
  MEDIUM       28 (35.9%)
  LOW           5 (6.4%)

COMMON FALSE POSITIVE PATTERNS:
  test_code_with_intentional_vuln                   18 (23.1%)
  example_code_in_docs                             12 (15.4%)
  safe_wrapper_function_misidentified               9 (11.5%)

📊 Full report saved to: benchmark_workspace/results/fp_report_20251114_120000.json
```

---

## Benchmark Projects

### Selection Criteria

Projects chosen based on:
1. **Popularity** - High GitHub stars, widely used
2. **Code Quality** - Well-maintained, high standards
3. **Diversity** - Different domains, frameworks, patterns
4. **Size** - Mix of small (100 files) and large (2,500 files)
5. **Activity** - Actively developed, not abandoned

### Project List

| Project | Description | Stars | Files | LOC |
|---------|-------------|-------|-------|-----|
| **Django** | Web framework | 75K+ | 2,500 | 300K |
| **Flask** | Micro framework | 65K+ | 100 | 15K |
| **FastAPI** | Modern API framework | 70K+ | 200 | 25K |
| **Requests** | HTTP library | 50K+ | 30 | 10K |
| **NumPy** | Scientific computing | 25K+ | 1,000 | 150K |
| **Pandas** | Data analysis | 40K+ | 1,500 | 200K |
| **Scikit-learn** | Machine learning | 55K+ | 1,000 | 180K |
| **Pytest** | Testing framework | 10K+ | 300 | 50K |
| **Black** | Code formatter | 35K+ | 100 | 15K |
| **HTTPX** | Async HTTP client | 12K+ | 100 | 12K |

**Total: ~7,000 files, ~950K lines of production-quality Python code**

---

## Interpreting Results

### False Positive Rate Calculation

```
FP Rate = (False Positives / Total Reviewed Findings) × 100
```

**Example:**
- Total findings: 1,000
- False positives: 25
- FP rate: 25 / 1,000 = 2.5%

### What's a Good FP Rate?

| FP Rate | Assessment | Action |
|---------|------------|--------|
| <1% | Excellent | Maintain quality, promote |
| 1-1.5% | Very Good | Minor tuning, mostly good |
| 1.5-2% | Good | Some improvements needed |
| 2-3% | Acceptable | Prioritize FP reduction |
| >3% | Poor | Major rule improvements needed |

### By Severity

Different tolerances by severity:

| Severity | Max Acceptable FP Rate |
|----------|------------------------|
| CRITICAL | <0.5% (very low tolerance) |
| HIGH | <1% (low tolerance) |
| MEDIUM | <2% (moderate tolerance) |
| LOW | <5% (higher tolerance) |

**Rationale:** Critical alerts must be highly accurate. Developers will investigate every critical finding, so FPs are very costly.

---

## Common False Positive Patterns

### 1. Test Code with Intentional Vulnerabilities

**Example:**
```python
# In tests/test_security.py
def test_sql_injection_detection():
    # This SHOULD be flagged by PyGuard, but it's a TEST
    query = f"SELECT * FROM users WHERE id = {user_id}"
    assert detect_sql_injection(query)
```

**Solution:**
- Exclude `tests/`, `test_*.py` by default
- Add configuration option to scan tests
- Use code comment context to identify test code

### 2. Example Code in Documentation

**Example:**
```python
# In docs/security_guide.py
# Example of WHAT NOT TO DO:
password = "hardcoded_password"  # DON'T DO THIS!
```

**Solution:**
- Exclude `docs/`, `examples/` by default
- Detect code comments indicating examples
- Lower severity for docs/examples

### 3. Safe Wrapper Functions Misidentified

**Example:**
```python
# This is ast.literal_eval, NOT eval()!
from ast import literal_eval as eval
result = eval(user_input)  # Actually safe
```

**Solution:**
- Improve AST analysis to track imports
- Recognize safe equivalents (ast.literal_eval, json.loads, etc.)
- Context-aware analysis

### 4. Framework-Specific Safe Patterns

**Example:**
```python
# Django ORM uses "safe" string formatting internally
# This is actually parameterized, not string formatting
User.objects.filter(name=name)
```

**Solution:**
- Framework-aware analysis (already implemented!)
- Recognize ORM patterns as safe
- Improve framework visitor detection

### 5. Suppressed or Acknowledged Issues

**Example:**
```python
# Security reviewed 2024-01-15: Risk accepted for admin-only endpoint
password = os.environ.get("ADMIN_PASSWORD")  # noqa: S105
```

**Solution:**
- Respect `# noqa` comments
- Support `# pyguard: ignore` comments
- Track acknowledged risks

---

## Improving False Positive Rate

### Quick Wins (Week 1)

1. **Exclude test directories by default**
   - `tests/`, `test_*.py`, `*_test.py`
   - Add `--include-tests` flag for opt-in

2. **Respect `# noqa` and `# type: ignore` comments**
   - Industry standard suppression
   - Already widely used in codebases

3. **Lower severity for docs/examples**
   - `docs/`, `examples/`, `samples/`
   - Informational warnings instead of errors

### Medium-Term (Weeks 2-4)

4. **Improve import tracking**
   - Track `from ast import literal_eval as eval`
   - Recognize safe equivalents

5. **Context-aware analysis**
   - Test code vs production code
   - Documentation vs implementation
   - Example code annotations

6. **Framework pattern improvements**
   - Better Django ORM detection
   - SQLAlchemy safe patterns
   - FastAPI dependency injection

### Long-Term (Months)

7. **Machine learning for FP reduction**
   - Train on reviewed findings
   - Learn project-specific patterns
   - Adaptive false positive reduction

8. **User feedback loop**
   - Allow users to report FPs
   - Track FP reports by rule
   - Prioritize rule improvements

9. **Project-specific tuning**
   - Per-project configuration
   - Learn from project history
   - Adaptive rule sensitivity

---

## Tracking Over Time

### Baseline Measurement (Now)

1. Run initial benchmark (this month)
2. Establish baseline FP rate
3. Identify top FP rules
4. Create improvement roadmap

### Monthly Monitoring

1. Re-run benchmark on same projects
2. Track FP rate trend
3. Measure improvement from rule changes
4. Update roadmap based on progress

### Release Gates

Before each release:
1. Run FP benchmark
2. Ensure FP rate meets target
3. Document any FP rate changes
4. Update release notes with FP improvements

---

## Reporting False Positives

### For Users

If you encounter a false positive:

1. **Verify it's actually a false positive**
   - Is the code truly safe?
   - Could there be a subtle security issue?

2. **Check if it's already known**
   - Search GitHub issues
   - Check FP patterns documentation

3. **Report with details**
   - Rule ID (e.g., `PY001`)
   - Code snippet (minimal reproducer)
   - Why it's a false positive
   - Suggested improvement

### Issue Template

```markdown
**Title:** False Positive: [Rule ID] [Brief description]

**Rule ID:** PY001

**Description:**
The rule flags this code as a security issue, but it's actually safe because...

**Code Example:**
```python
# Minimal code that triggers the false positive
from ast import literal_eval
result = literal_eval(user_input)  # Safe, not eval()
```

**Expected Behavior:**
This should not be flagged because ast.literal_eval is safe.

**Suggested Fix:**
Improve the rule to distinguish eval() from ast.literal_eval.

**Project:** [If from a real project, specify which one]
```

---

## Automation

### CI/CD Integration

```yaml
# .github/workflows/fp-benchmark.yml
name: False Positive Benchmark

on:
  schedule:
    - cron: '0 0 1 * *'  # Monthly
  workflow_dispatch:

jobs:
  benchmark:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install PyGuard
        run: pip install -e .

      - name: Run benchmark
        run: |
          python tools/benchmark_false_positives.py --clone
          python tools/benchmark_false_positives.py --scan
          python tools/benchmark_false_positives.py --review

      - name: Upload results
        uses: actions/upload-artifact@v4
        with:
          name: fp-benchmark-results
          path: benchmark_workspace/
```

---

## Success Metrics

### v0.7.0 Success Criteria

- [ ] Baseline FP rate established
- [ ] FP rate <1.5% on benchmark projects
- [ ] Top 5 FP rules identified and documented
- [ ] FP tracking system operational
- [ ] Monthly FP monitoring in place

### v1.0.0 Success Criteria

- [ ] FP rate <1.0% on benchmark projects
- [ ] FP rate <0.5% for CRITICAL severity
- [ ] User FP feedback loop operational
- [ ] Automated FP testing in CI
- [ ] FP improvements documented in release notes

---

## References

- **Benchmark Tool:** `tools/benchmark_false_positives.py`
- **Results Directory:** `benchmark_workspace/results/`
- **Review Templates:** `benchmark_workspace/review/`
- **Priority Actions:** `docs/reports/2025-11-14-priority-actions.md`

---

**Status:** Ready for baseline measurement
**Next Action:** Run initial benchmark and establish baseline
**Owner:** PyGuard Core Team
**Last Updated:** 2025-11-14
