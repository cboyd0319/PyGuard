# Setting Up Auto-Merge for Dependabot PRs

## Quick Setup Guide

Follow these steps to enable the Dependabot auto-merge workflow in your repository.

## Prerequisites

The following files should already be in place (included in this PR):
- `.github/dependabot.yml` - Dependabot configuration
- `.github/workflows/dependabot-auto-merge.yml` - Auto-merge workflow
- `docs/DEPENDABOT.md` - Full documentation

## Repository Settings

### 1. Enable Auto-Merge Feature

1. Go to your repository on GitHub
2. Navigate to **Settings** → **General**
3. Scroll down to **Pull Requests** section
4. ✅ Check **"Allow auto-merge"**
5. ✅ Check **"Automatically delete head branches"** (recommended)

### 2. Configure Branch Protection (Recommended)

To ensure PRs are only merged after passing all checks:

1. Go to **Settings** → **Branches**
2. Add or edit a branch protection rule for `main`
3. Enable:
   - ✅ **Require a pull request before merging**
   - ✅ **Require status checks to pass before merging**
     - Add required checks: `test`, `lint`, `coverage`, etc.
   - ✅ **Require branches to be up to date before merging**
4. Optional (if you want to require approvals):
   - Set **Required number of approvals before merging** to 1
   - ✅ Check **"Allow specified actors to bypass required pull requests"**
   - Add `dependabot[bot]` or the workflow bot to the bypass list

### 3. Workflow Permissions

The workflow uses `GITHUB_TOKEN` which should have sufficient permissions by default. If you encounter permission issues:

1. Go to **Settings** → **Actions** → **General**
2. Under **Workflow permissions**, select:
   - ✅ **Read and write permissions**
3. ✅ Check **"Allow GitHub Actions to create and approve pull requests"**

## Verification

Once configured, test the setup:

### Method 1: Wait for Dependabot
- Wait for Dependabot to create its first PR (will run weekly on Mondays)
- Check that the auto-merge workflow runs
- Verify patch/minor updates are auto-merged after CI passes

### Method 2: Trigger Manually
You can trigger Dependabot manually:

```bash
# Using GitHub CLI
gh api repos/:owner/:repo/dependabot/updates -X POST

# Or via the web interface:
# Go to Insights → Dependency graph → Dependabot → "Check for updates"
```

## Troubleshooting

### Auto-merge not working?

**Issue**: PRs are not being auto-merged

**Solutions**:
1. Verify **"Allow auto-merge"** is enabled in repository settings
2. Check that all required status checks are passing
3. Ensure workflow has proper permissions (see step 3 above)
4. Check workflow runs in the **Actions** tab for errors

### Workflow not running?

**Issue**: The workflow doesn't trigger on Dependabot PRs

**Solutions**:
1. Verify `.github/workflows/dependabot-auto-merge.yml` exists
2. Check that the workflow file is on the default branch (`main`)
3. Ensure the workflow has correct YAML syntax
4. Check **Actions** tab for any disabled workflows

### Permission errors?

**Issue**: Workflow fails with "Resource not accessible by integration"

**Solutions**:
1. Enable **"Read and write permissions"** in Settings → Actions → General
2. Enable **"Allow GitHub Actions to create and approve pull requests"**
3. Verify the workflow uses `${{ secrets.GITHUB_TOKEN }}`

### Major versions not being flagged?

**Issue**: Major version updates are being auto-merged

**Solutions**:
1. Check the workflow logic in `.github/workflows/dependabot-auto-merge.yml`
2. Verify the `dependabot/fetch-metadata` action is working correctly
3. Review the PR to see what `update-type` is being detected

## What Happens Next?

Once merged, this setup will:

1. **Weekly Scans** (Every Monday 00:00 UTC):
   - Dependabot scans for outdated Python packages
   - Dependabot scans for outdated GitHub Actions
   
2. **Automatic PRs**:
   - Dependabot creates PRs for available updates
   - PRs are labeled with `dependencies` and ecosystem tags
   
3. **Auto-Merge Flow** (for patch/minor updates):
   - PR triggers all CI workflows (test, lint, coverage, etc.)
   - Once all checks pass, the workflow auto-approves the PR
   - GitHub automatically merges the PR using squash merge
   - The branch is automatically deleted
   
4. **Manual Review** (for major updates):
   - Workflow adds a comment flagging the major update
   - You review the changes manually
   - You approve and merge when ready

## Customization

See [`docs/DEPENDABOT.md`](DEPENDABOT.md) for detailed customization options.

## Security Considerations

- **Trusted Source**: Only Dependabot (owned by GitHub) can trigger auto-merge
- **CI Required**: All tests must pass before merging
- **Conservative Approach**: Major updates require manual review
- **Audit Trail**: All changes are tracked in PRs with full diffs
- **Rollback**: Easy to revert if an update causes issues

## Additional Resources

- [GitHub Dependabot Documentation](https://docs.github.com/en/code-security/dependabot)
- [Auto-merge Documentation](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/incorporating-changes-from-a-pull-request/automatically-merging-a-pull-request)
- [Branch Protection Rules](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches)

## Support

If you encounter issues not covered here, please:
1. Check the [Actions tab](../../actions) for workflow run logs
2. Review [GitHub Status](https://www.githubstatus.com/) for platform issues
3. Open an issue in this repository with details

---

**Ready?** Merge this PR to activate the Dependabot auto-merge workflow! 🚀
