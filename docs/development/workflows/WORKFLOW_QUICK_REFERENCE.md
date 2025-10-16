# GitHub Actions Workflow Quick Reference

## 🚀 Quick Start

### Running Workflows Manually
Go to **Actions** tab → Select workflow → **Run workflow** button (workflows with `workflow_dispatch`)

### Workflows That Run Automatically

| Event | Workflows Triggered |
|-------|-------------------|
| **Push to main/develop** | test.yml, lint.yml, coverage.yml (main only), codeql.yml (main only) |
| **Pull Request** | test.yml, lint.yml, coverage.yml, codeql.yml |
| **Dependabot PR** | dependabot-auto-merge.yml + all PR workflows |
| **Daily (00:00 UTC)** | pyguard-security-scan.yml |
| **Weekly (Monday 00:00 UTC)** | benchmarks.yml, codeql.yml |
| **Tag push (v*.*.*)** | release.yml |
| **Workflow file changes** | workflow-lint.yml |

## 🔍 Workflow Status

### Check Workflow Status
```bash
# View recent workflow runs
gh run list --limit 10

# View specific workflow
gh run list --workflow=test.yml --limit 5

# Watch a running workflow
gh run watch <run-id>
```

### View Workflow Logs
```bash
# View logs for latest run
gh run view --log

# View logs for specific job
gh run view <run-id> --log --job=<job-id>
```

## 🛠️ Common Tasks

### Testing Workflow Changes Locally
```bash
# Install actionlint
brew install actionlint  # macOS
# or
curl -sSL https://raw.githubusercontent.com/rhysd/actionlint/main/scripts/download-actionlint.bash | bash

# Validate workflows
actionlint .github/workflows/*.yml
```

### Triggering Manual Workflows
```bash
# Trigger benchmarks manually
gh workflow run benchmarks.yml

# Trigger security scan manually
gh workflow run pyguard-security-scan.yml

# Trigger CodeQL scan manually
gh workflow run codeql.yml
```

### Canceling Workflows
```bash
# Cancel a specific run
gh run cancel <run-id>

# Cancel all runs for a workflow
gh run list --workflow=test.yml --json databaseId -q '.[].databaseId' | xargs -I {} gh run cancel {}
```

## 📊 Understanding Workflow Results

### Test Results (test.yml)
- ✅ **Green**: All tests passed on all platforms
- ❌ **Red**: Tests failed - check logs for details
- ⏭️ **Skipped**: Matrix job not required for this change

### Coverage Results (coverage.yml)
- View in **Codecov dashboard** (link in README)
- **Artifacts** contain HTML coverage report
- **Step summary** shows coverage percentage

### Security Scans
- **CodeQL**: View in **Security** tab → **Code scanning**
- **PyGuard**: View SARIF in **Security** tab or artifacts
- **No issues**: Workflow succeeds silently

## 🔧 Troubleshooting

### "Workflow not found" Error
**Cause:** Workflow file renamed or deleted  
**Fix:** Check `.github/workflows/` for correct filename

### "Action not found" Error
**Cause:** Composite action path incorrect  
**Fix:** Ensure workflow uses `./.github/actions/setup-python` (relative path)

### Timeout Errors
**Cause:** Job exceeded `timeout-minutes`  
**Fix:** Check logs for hanging processes; increase timeout if legitimate

### Cache Miss
**Cause:** Dependencies changed or cache expired  
**Fix:** Normal behavior; cache will rebuild on next run

### Permission Denied
**Cause:** Job needs higher permissions  
**Fix:** Add specific permissions to job (not workflow level)

### Dependabot Auto-Merge Not Working
**Cause:** Branch protection requires approvals  
**Fix:** Configure auto-approval in branch protection settings

## 🏗️ Adding New Workflows

### Golden Template
```yaml
name: My Workflow

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

defaults:
  run:
    shell: bash

jobs:
  my_job:
    name: Descriptive Job Name
    runs-on: ubuntu-latest
    timeout-minutes: 20
    permissions:
      contents: read

    steps:
      - name: Checkout code
        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          fetch-depth: 1

      - name: Setup Python
        uses: ./.github/actions/setup-python
        with:
          python-version: '3.13'
          install-dev: 'true'

      - name: Run task
        shell: bash
        run: |
          set -euo pipefail
          # Your commands here

      - name: Add summary
        if: always()
        shell: bash
        run: |
          {
            echo "## Summary"
            echo "Task completed"
          } >> "${GITHUB_STEP_SUMMARY}"
```

### Checklist for New Workflows
- [ ] Pin all actions by SHA (not tags)
- [ ] Set `timeout-minutes` (usually 10-30)
- [ ] Configure `concurrency` group
- [ ] Add `defaults: run: shell: bash`
- [ ] Use strict shell mode (`set -euo pipefail`)
- [ ] Use composite action for Python setup
- [ ] Add GITHUB_STEP_SUMMARY output
- [ ] Minimal permissions (escalate per-job only)
- [ ] Run `actionlint` before committing
- [ ] Test on feature branch first

## 🎯 Performance Tips

### Speeding Up CI
1. **Use caching**: Composite action includes multi-layer caching
2. **Fail fast**: Use `--maxfail=3` in pytest
3. **Matrix wisely**: Only cross-platform test what's necessary
4. **Schedule expensive tasks**: Benchmarks weekly, security scans daily
5. **Cancel duplicates**: Concurrency groups prevent duplicate runs

### Reducing Costs
1. **Limit scheduled workflows**: Only what's necessary
2. **Use timeouts**: Prevent runaway processes
3. **Cache aggressively**: Reduces download time and bandwidth
4. **Consolidate workflows**: Remove duplicate scans
5. **Consider self-hosted runners**: For high-volume repos

## 📚 Additional Resources

### Documentation
- [Workflow README](../../../.github/workflows/README.md) - Comprehensive guide
- [Optimization Summary](WORKFLOW_OPTIMIZATION_SUMMARY.md) - Before/after analysis
- [GitHub Actions Docs](https://docs.github.com/en/actions) - Official documentation

### Tools
- [actionlint](https://github.com/rhysd/actionlint) - Workflow validator
- [act](https://github.com/nektos/act) - Run workflows locally
- [GitHub CLI](https://cli.github.com/) - Command-line workflow management

### Support
- File issue with `ci/cd` label
- Tag @cboyd0319 for workflow questions
- Check `.github/CODEOWNERS` for code review

## 🔐 Security Notes

### Action Pinning
Always pin by SHA, never by tag:
```yaml
# ✅ GOOD - immutable reference
uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2

# ❌ BAD - mutable reference (security risk)
uses: actions/checkout@v4
```

### Permissions
Minimal by default, escalate per-job:
```yaml
# Workflow level - minimal
permissions:
  contents: read

jobs:
  release:
    # Job level - escalate only where needed
    permissions:
      contents: write
      packages: write
```

### Secrets
Never echo secrets in logs:
```yaml
# ✅ GOOD
env:
  TOKEN: ${{ secrets.TOKEN }}
run: some-command --token "${TOKEN}"

# ❌ BAD
run: echo "Token: ${{ secrets.TOKEN }}"
```

## 💡 Pro Tips

1. **Use workflow summaries**: Better than PR comments for CI results
2. **Artifacts expire**: Set appropriate `retention-days`
3. **Matrix includes**: Add special cases without full matrix expansion
4. **Concurrency for PRs**: Use `github.head_ref` for PR-specific cancellation
5. **Composite actions**: Extract repeated patterns to DRY
6. **Path filters**: Run workflows only when relevant files change
7. **Cache keys**: Include dependency file hashes for automatic invalidation
8. **Timeouts**: Set realistic timeouts to catch hangs early

---

**Last Updated:** 2025-10-15  
**Maintained By:** @cboyd0319  
**Status:** Production-Ready ✅
