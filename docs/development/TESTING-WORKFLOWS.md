# Testing PyGuard Workflows and GitHub Actions

This document describes the comprehensive testing strategy for PyGuard's workflows and GitHub Actions integration.

## Test Coverage

### Test Files

1. **`tests/integration/test_github_action_integration.py`** (13 tests)
   - SARIF generation and validation
   - GitHub Code Scanning compatibility
   - Action inputs/outputs
   - Security best practices

2. **`tests/integration/test_workflow_validation.py`** (28 tests)
   - Workflow configuration validation
   - Security best practices enforcement
   - Documentation completeness
   - Action.yml validation

3. **`tests/unit/test_sarif_reporter.py`** (18 tests)
   - SARIF 2.1.0 format compliance
   - CWE/OWASP mappings
   - Severity level handling
   - Report generation

**Total: 59 tests covering workflows and actions**

## Test Categories

### 1. SARIF Output Testing

Tests verify that PyGuard generates valid SARIF reports:

```python
def test_sarif_generation_with_issues(temp_dir):
    """Test SARIF generation when security issues are found."""
    # Creates file with vulnerabilities
    # Runs PyGuard with --sarif
    # Validates SARIF structure and content
```

**Validates:**
- SARIF 2.1.0 schema compliance
- CWE/OWASP vulnerability mappings
- Severity level correctness
- Location references accuracy
- Fix suggestions presence

### 2. GitHub Code Scanning Integration

Tests verify GitHub Security tab compatibility:

```python
def test_sarif_github_security_tab_format(temp_dir):
    """Test SARIF format is compatible with GitHub Security tab."""
    # Validates required fields for GitHub
    # Checks proper formatting
```

**Validates:**
- Required metadata fields
- Location format (file, line, column)
- Severity mapping (error, warning, note)
- Tool information completeness

### 3. Action Configuration Testing

Tests verify action.yml is properly configured:

```python
def test_action_inputs_defined():
    """Test all expected inputs are defined in action.yml."""
```

**Validates:**
- All inputs have descriptions
- Non-required inputs have defaults
- Outputs are properly defined
- Metadata is complete

### 4. Workflow Security Testing

Tests verify workflows follow security best practices:

```python
def test_workflows_use_pinned_actions(workflow_files):
    """Test workflows use SHA-pinned or versioned actions."""
```

**Validates:**
- Actions use SHA pins or version tags
- Minimal permissions declared
- No overly broad permissions (write-all)
- Proper error handling

### 5. Workflow Structure Testing

Tests verify workflows are well-structured:

```python
def test_workflows_have_job_names(workflow_files):
    """Test all jobs have descriptive names."""
```

**Validates:**
- Valid YAML syntax
- Proper trigger configuration
- Job and step naming
- Permission declarations

### 6. Documentation Testing

Tests verify documentation completeness:

```python
def test_workflows_readme_documents_all_workflows(workflows_readme):
    """Test workflows README documents all workflow files."""
```

**Validates:**
- Workflow README exists and is comprehensive
- All workflows documented (80%+ coverage)
- Example workflows available
- GitHub Action guide exists

## Running Tests

### Run All Workflow/Action Tests

```bash
pytest tests/integration/test_github_action_integration.py \
       tests/integration/test_workflow_validation.py \
       tests/unit/test_sarif_reporter.py -v
```

### Run Specific Test Categories

```bash
# SARIF generation tests
pytest tests/integration/test_github_action_integration.py::TestGitHubActionIntegration -v

# Workflow validation tests
pytest tests/integration/test_workflow_validation.py::TestWorkflowValidation -v

# Action.yml validation tests
pytest tests/integration/test_workflow_validation.py::TestActionYmlValidation -v

# SARIF reporter unit tests
pytest tests/unit/test_sarif_reporter.py -v
```

### Run with Coverage

```bash
pytest tests/integration/test_github_action_integration.py \
       tests/integration/test_workflow_validation.py \
       tests/unit/test_sarif_reporter.py --cov=pyguard/lib/sarif_reporter -v
```

## Test Scenarios Covered

### Scenario 1: Basic Security Scan

**Test:** `test_sarif_generation_with_issues`

**Simulates:**
```bash
pyguard vulnerable.py --scan-only --sarif --no-html
```

**Validates:**
- SARIF file created
- Issues detected and reported
- Proper severity levels
- CWE mappings present

### Scenario 2: Clean Code Scan

**Test:** `test_sarif_generation_without_issues`

**Simulates:** Scanning code with no security issues

**Validates:**
- SARIF file still created
- Empty results array
- Valid structure maintained

### Scenario 3: Multi-File Scan

**Test:** `test_multiple_files_sarif_output`

**Simulates:** Scanning multiple files in a directory

**Validates:**
- All files scanned
- Issues from all files reported
- Correct file references

### Scenario 4: GitHub Action Usage

**Test:** `test_action_security_best_practices`

**Simulates:** Using PyGuard as a GitHub Action

**Validates:**
- Action inputs properly configured
- Outputs accessible
- Security best practices followed

### Scenario 5: Workflow Integration

**Test:** `test_pyguard_workflow_configuration`

**Simulates:** PyGuard workflow running in CI

**Validates:**
- Proper permissions
- Correct triggers
- SARIF upload configured

## Continuous Integration

These tests run automatically in CI:

### On Pull Requests
```yaml
# .github/workflows/test.yml
- name: Run Workflow Tests
  run: |
    pytest tests/integration/test_github_action_integration.py \
           tests/integration/test_workflow_validation.py \
           tests/unit/test_sarif_reporter.py -v
```

### Pre-merge Validation

All tests must pass before merging:
- ✅ SARIF generation works
- ✅ GitHub Code Scanning compatible
- ✅ Workflows follow best practices
- ✅ Documentation complete

## Test Maintenance

### Adding New Workflow Tests

When adding a new workflow:

1. Add workflow file to `.github/workflows/`
2. Document in `.github/workflows/README.md`
3. Tests automatically validate:
   - Valid YAML syntax
   - Pinned action versions
   - Proper permissions
   - Job/step names

### Adding New SARIF Features

When enhancing SARIF output:

1. Update `pyguard/lib/sarif_reporter.py`
2. Add test in `test_sarif_reporter.py`:
   ```python
   def test_new_sarif_feature():
       reporter = SARIFReporter()
       report = reporter.generate_report(...)
       assert "new_feature" in report
   ```
3. Add integration test in `test_github_action_integration.py`

### Adding New Action Inputs

When adding new action.yml inputs:

1. Update `action.yml` with new input
2. Tests automatically validate:
   - Input has description
   - Non-required inputs have defaults
   - Documentation updated

## Manual Testing Checklist

While automated tests cover most scenarios, manual verification is needed for:

### 1. SARIF Upload to GitHub Security Tab

**Steps:**
1. Create PR with security issues
2. Wait for workflow to complete
3. Check Security tab: `https://github.com/OWNER/REPO/security/code-scanning`
4. Verify issues appear with:
   - Correct severity
   - CWE/OWASP mappings
   - Fix suggestions
   - Proper location references

### 2. Pull Request Annotations

**Steps:**
1. Create PR with vulnerable code
2. Wait for PyGuard scan
3. Check PR Files tab
4. Verify inline annotations appear on:
   - Correct lines
   - With issue descriptions
   - Proper severity indicators

### 3. Action in External Repository

**Steps:**
1. Use PyGuard action in test repository
2. Verify all inputs work:
   ```yaml
   uses: cboyd0319/PyGuard@main
   with:
     paths: 'src/'
     severity: 'HIGH'
     fail-on-issues: 'true'
   ```
3. Check outputs accessible:
   ```yaml
   - run: echo "${{ steps.pyguard.outputs.issues-found }}"
   ```

### 4. Workflow Matrix Testing

**Steps:**
1. Test with different Python versions
2. Test with different paths configurations
3. Test with different severity thresholds
4. Verify consistent results

## Troubleshooting Tests

### SARIF File Not Generated

**Symptom:** Tests fail with "SARIF file not found"

**Solution:**
```python
# Verify PyGuard is installed
assert subprocess.run(["pyguard", "--version"]).returncode == 0

# Check command execution
result = subprocess.run([...], capture_output=True, text=True)
print(result.stdout)
print(result.stderr)
```

### Invalid SARIF Format

**Symptom:** Tests fail on SARIF validation

**Solution:**
```python
# Validate JSON first
import json
with open("pyguard-report.sarif") as f:
    data = json.load(f)  # Will error if invalid JSON

# Then validate SARIF schema
assert data["version"] == "2.1.0"
assert "$schema" in data
```

### Workflow Validation Failures

**Symptom:** Tests fail on workflow structure

**Solution:**
```python
# Check YAML parsing
import yaml
with open(".github/workflows/workflow.yml") as f:
    workflow = yaml.safe_load(f)
    print(workflow)  # Inspect structure
```

## Test Metrics

Current test coverage for workflows/actions:

- **SARIF Reporter:** 97% coverage
- **Integration Tests:** 59 tests passing
- **Workflow Files:** 8 workflows validated
- **Example Workflows:** 4 templates provided
- **Documentation:** 3 comprehensive guides

## Future Enhancements

Potential test improvements:

1. **Performance Testing**
   - Benchmark SARIF generation time
   - Test with large codebases (1000+ files)

2. **Compatibility Testing**
   - Test with various GitHub Enterprise versions
   - Test with different SARIF consumers

3. **Error Recovery Testing**
   - Test behavior with malformed Python files
   - Test handling of permission errors

4. **Load Testing**
   - Test concurrent workflow runs
   - Test repository-wide scans

## References

- [SARIF 2.1.0 Specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
- [GitHub Code Scanning](https://docs.github.com/en/code-security/code-scanning)
- [GitHub Actions Best Practices](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
- [PyGuard GitHub Action Guide](../guides/github-action-guide.md)
- [PyGuard Workflows README](../../.github/workflows/README.md)
