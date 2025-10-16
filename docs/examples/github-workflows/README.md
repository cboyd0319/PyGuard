# PyGuard GitHub Workflow Examples

Ready-to-use GitHub Actions workflows for PyGuard security scanning.

## Quick Start

Copy any workflow file to your `.github/workflows/` directory and customize as needed.

## Available Workflows

### 1. basic-security-scan.yml
**Purpose:** Basic security scanning on every push and pull request.

**Features:**
- Scans all Python code
- Uploads results to GitHub Security tab
- Runs on push and PR events
- Non-blocking (won't fail builds)

**Best for:** Initial PyGuard setup, general security monitoring

### 2. security-gate.yml
**Purpose:** Enforce security standards by blocking PRs with critical issues.

**Features:**
- Fails workflow if high/critical issues found
- Adds comment to PR when issues detected
- Blocks merge until fixed
- Runs only on pull requests

**Best for:** Production deployments, security-critical projects

### 3. scheduled-audit.yml
**Purpose:** Daily security audits with long-term tracking.

**Features:**
- Runs daily at midnight UTC
- Archives SARIF reports for 90 days
- Can be triggered manually
- Tracks security trends over time

**Best for:** Continuous security monitoring, compliance reporting

### 4. multi-path-scan.yml
**Purpose:** Scan different parts of codebase with different policies.

**Features:**
- Multiple parallel scan jobs
- Different severity levels per path
- Separate SARIF files per component
- Configurable fail conditions

**Best for:** Monorepos, projects with varying security requirements

## Usage Instructions

### 1. Choose a Workflow

Select the workflow that matches your needs from the list above.

### 2. Copy to Your Repository

```bash
# Copy basic scan
cp examples/github-workflows/basic-security-scan.yml .github/workflows/

# Or security gate
cp examples/github-workflows/security-gate.yml .github/workflows/

# Or scheduled audit
cp examples/github-workflows/scheduled-audit.yml .github/workflows/
```

### 3. Customize Settings

Edit the workflow file to match your project:

```yaml
# Change scan paths
with:
  paths: 'src/ lib/'  # Your source directories

# Adjust severity threshold
severity: 'MEDIUM'  # LOW, MEDIUM, HIGH, or CRITICAL

# Configure exclusions
exclude: 'tests/* vendor/*'  # Paths to skip
```

### 4. Set Repository Permissions

Ensure your repository has required permissions:

1. Go to **Settings** → **Actions** → **General**
2. Under **Workflow permissions**, select:
   - "Read and write permissions" (recommended)
   - Or "Read repository contents and packages permissions" + enable "Allow GitHub Actions to create and approve pull requests"
3. Enable "Allow GitHub Actions to create and approve pull requests" if using PR comments

### 5. Enable Security Tab

Results will appear in your repository's **Security** tab:

1. Navigate to **Settings** → **Security** → **Code security and analysis**
2. Enable "Code scanning" if not already enabled
3. PyGuard results will appear under **Security** → **Code scanning alerts**

## Customization Examples

### Change Python Version

```yaml
- name: Run PyGuard
  uses: cboyd0319/PyGuard@main
  with:
    python-version: '3.11'  # Specify version
```

### Scan Specific Files Only

```yaml
with:
  paths: 'app.py utils.py models.py'
```

### Enable Code Quality Checks

```yaml
with:
  security-only: 'false'  # Include quality checks
```

### Custom SARIF File Location

```yaml
with:
  sarif-file: 'reports/pyguard-scan.sarif'
```

### Fail on Any Issues (Strict Mode)

```yaml
with:
  severity: 'LOW'
  fail-on-issues: 'true'
```

## Combining Workflows

You can use multiple workflows together:

```bash
# Basic scan for all pushes
cp basic-security-scan.yml .github/workflows/

# Security gate for PRs
cp security-gate.yml .github/workflows/

# Daily audit for trends
cp scheduled-audit.yml .github/workflows/
```

Each workflow runs independently and uploads separate SARIF reports.

## Testing Workflows

### Test Locally with act

```bash
# Install act (GitHub Actions local runner)
brew install act  # macOS
# or
sudo apt install act  # Linux

# Test workflow
act push -W .github/workflows/basic-security-scan.yml
```

### Test in a Branch

1. Create a test branch
2. Add workflow file
3. Create a test commit
4. Check Actions tab for results

## Viewing Results

### GitHub Security Tab

1. Go to your repository
2. Click **Security** tab
3. Click **Code scanning**
4. View PyGuard findings

### Pull Request Annotations

On PRs, PyGuard adds inline code annotations showing:
- Security issue location
- Severity level
- Description and fix suggestions

### Workflow Logs

Detailed logs available in:
1. **Actions** tab
2. Select workflow run
3. Click job name
4. View "Run PyGuard" step output

## Troubleshooting

### "Resource not accessible by integration"

**Cause:** Missing security-events permission

**Fix:** Add to workflow:
```yaml
permissions:
  security-events: write
```

### SARIF Not Uploaded

**Cause:** SARIF file not found or invalid

**Fix:** Ensure scan completes:
```yaml
- name: Upload SARIF
  if: always()  # Upload even if scan fails
```

### No Issues Shown

**Cause:** Severity filter too high

**Fix:** Lower threshold:
```yaml
severity: 'LOW'  # Report all issues
```

## Best Practices

### 1. Start with Basic Scan
Begin with `basic-security-scan.yml` to understand baseline security posture.

### 2. Add Security Gate Gradually
Once baseline is clean, add `security-gate.yml` to prevent regressions.

### 3. Monitor Trends
Use `scheduled-audit.yml` to track security improvements over time.

### 4. Customize Per Environment
Use different workflows for development vs. production with appropriate thresholds.

### 5. Review Regularly
Check Security tab weekly to address accumulating issues.

## Support

- **Documentation:** [docs/github-action-guide.md](../../guides/github-action-guide.md)
- **Full Capabilities:** [docs/capabilities-reference.md](../../reference/capabilities-reference.md)
- **Issues:** https://github.com/cboyd0319/PyGuard/issues

## Contributing

Found a useful workflow pattern? Share it!

1. Add workflow to `examples/github-workflows/`
2. Update this README
3. Submit a pull request

## License

These examples are part of PyGuard and licensed under the same terms as the main project.
