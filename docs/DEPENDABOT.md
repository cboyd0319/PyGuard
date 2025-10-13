# Dependabot Auto-Merge Setup

This document explains how PyGuard automatically manages dependency updates using GitHub's Dependabot.

## Overview

PyGuard uses Dependabot to automatically:
- Scan for outdated dependencies (Python packages and GitHub Actions)
- Create pull requests with version updates
- Auto-approve and merge safe updates (patch and minor versions)
- Flag major updates for manual review

## Configuration Files

### `.github/dependabot.yml`

Configures Dependabot to scan for updates:

- **Python Dependencies** (via pip):
  - Scans weekly on Mondays at 00:00 UTC
  - Groups minor and patch updates together to reduce PR noise
  - Labels: `dependencies`, `python`
  - Commit prefix: `chore`
  - Maximum 10 open PRs at once

- **GitHub Actions**:
  - Scans weekly on Mondays at 00:00 UTC
  - Labels: `dependencies`, `github-actions`
  - Commit prefix: `ci`
  - Maximum 5 open PRs at once

### `.github/workflows/dependabot-auto-merge.yml`

Automatically handles Dependabot PRs:

1. **Triggers**: When a Dependabot PR is opened, synchronized, or reopened
2. **Checks**: Waits for all CI status checks to pass
3. **Auto-merge logic**:
   - **Patch updates** (e.g., 1.0.0 → 1.0.1): Auto-approved and merged
   - **Minor updates** (e.g., 1.0.0 → 1.1.0): Auto-approved and merged
   - **Major updates** (e.g., 1.0.0 → 2.0.0): Commented for manual review

## How It Works

### For Safe Updates (Patch/Minor)

```
Dependabot creates PR
    ↓
All CI checks run (test, lint, coverage, etc.)
    ↓
All checks pass ✅
    ↓
Workflow auto-approves PR
    ↓
Workflow enables auto-merge (squash)
    ↓
PR automatically merges
```

### For Major Updates

```
Dependabot creates PR
    ↓
All CI checks run
    ↓
Workflow adds comment: "⚠️ This is a major version update. Please review and merge manually."
    ↓
Manual review required
```

## Safety Features

The auto-merge setup includes multiple safety layers:

1. **CI Requirements**: All tests, linting, and security checks must pass
2. **Version Control**: Only patch and minor updates are auto-merged
3. **Wait for Checks**: Uses `wait-on-check-action` to ensure all workflows complete
4. **Squash Merging**: Keeps git history clean
5. **Native Auto-Merge**: Uses GitHub's built-in auto-merge feature

## Benefits

- **Security**: Dependencies are kept up-to-date automatically
- **Reduced Maintenance**: No manual intervention needed for safe updates
- **Safety**: Major updates still require human review
- **Efficiency**: Grouped updates reduce PR noise
- **Transparency**: All changes are logged in pull requests

## Manual Override

You can always:
- Close a Dependabot PR if you don't want the update
- Comment `@dependabot ignore this major version` to skip a major version
- Comment `@dependabot ignore this minor version` to skip a minor version
- Comment `@dependabot ignore this dependency` to never update a specific dependency
- Disable Dependabot entirely by removing `.github/dependabot.yml`

## Monitoring

To monitor Dependabot activity:

1. Check the **Insights → Dependency graph → Dependabot** tab
2. View **Pull Requests** filtered by the `dependencies` label
3. Check **Security → Dependabot alerts** for security-related updates

## Customization

### Changing Update Frequency

Edit `.github/dependabot.yml`:

```yaml
schedule:
  interval: "daily"  # Options: daily, weekly, monthly
```

### Adjusting Auto-Merge Criteria

Edit `.github/workflows/dependabot-auto-merge.yml` to change which updates are auto-merged:

```yaml
# Example: Only auto-merge patch updates
if: steps.metadata.outputs.update-type == 'version-update:semver-patch'
```

### Adding More Ecosystems

Add to `.github/dependabot.yml`:

```yaml
- package-ecosystem: "docker"
  directory: "/"
  schedule:
    interval: "weekly"
```

## Troubleshooting

### Auto-merge not working?

Check:
1. Repository settings → General → Pull Requests → Allow auto-merge is enabled
2. Branch protection rules allow the workflow to approve PRs
3. All required status checks are passing
4. The PR is from Dependabot (not another bot or user)

### Too many PRs?

Reduce `open-pull-requests-limit` in `.github/dependabot.yml` or group more updates together.

### Want to disable auto-merge?

Delete or rename `.github/workflows/dependabot-auto-merge.yml`.

## References

- [Dependabot Documentation](https://docs.github.com/en/code-security/dependabot)
- [Dependabot Configuration Options](https://docs.github.com/en/code-security/dependabot/dependabot-version-updates/configuration-options-for-the-dependabot.yml-file)
- [GitHub Auto-Merge](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/incorporating-changes-from-a-pull-request/automatically-merging-a-pull-request)
