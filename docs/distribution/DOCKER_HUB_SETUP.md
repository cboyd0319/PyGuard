# Docker Hub Publishing Setup Guide

**Status:** ✅ Workflow Complete, ⚠️ Needs Secrets Configuration
**Priority:** HIGH - Quick Win
**Estimated Time:** 15-30 minutes

---

## Overview

The Docker publishing workflow is **100% ready** and just needs secrets configuration to go live. Once configured, Docker images will be automatically published to:
- **Docker Hub:** `docker.io/cboyd0319/pyguard`
- **GitHub Container Registry:** `ghcr.io/cboyd0319/pyguard`

---

## Prerequisites

1. **Docker Hub Account**
   - Sign up at https://hub.docker.com
   - Username will be used for `DOCKER_USERNAME` secret

2. **Docker Hub Access Token**
   - Go to https://hub.docker.com/settings/security
   - Click "New Access Token"
   - Name: "PyGuard GitHub Actions"
   - Permissions: Read, Write, Delete
   - Copy the token (you can only see it once!)

---

## Step 1: Configure GitHub Secrets

### Navigate to Secrets Settings
1. Go to https://github.com/cboyd0319/PyGuard/settings/secrets/actions
2. Click "New repository secret"

### Add DOCKER_USERNAME Secret
- **Name:** `DOCKER_USERNAME`
- **Value:** Your Docker Hub username (e.g., `cboyd0319`)
- Click "Add secret"

### Add DOCKER_TOKEN Secret
- **Name:** `DOCKER_TOKEN`
- **Value:** Paste the Docker Hub access token you created
- Click "Add secret"

---

## Step 2: Test the Workflow

### Option A: Manual Workflow Dispatch (Recommended for first test)

1. Go to https://github.com/cboyd0319/PyGuard/actions/workflows/docker-publish.yml
2. Click "Run workflow" dropdown
3. Select your branch
4. Enter a tag (e.g., `test-0.7.0`)
5. Click "Run workflow"
6. Monitor the workflow run (takes ~10-15 minutes)

### Option B: Tag-Based Automatic Trigger

```bash
# Create and push a test tag
git tag v0.7.0-test
git push origin v0.7.0-test

# Watch the workflow run at:
# https://github.com/cboyd0319/PyGuard/actions/workflows/docker-publish.yml
```

---

## Step 3: Verify Publication

### Check Docker Hub
1. Go to https://hub.docker.com/r/cboyd0319/pyguard
2. Verify the new tag appears
3. Check that both architectures are present:
   - `linux/amd64`
   - `linux/arm64`

### Check GitHub Container Registry
1. Go to https://github.com/cboyd0319/PyGuard/pkgs/container/pyguard
2. Verify the package appears
3. Check tags and architectures

### Test Pull and Run

```bash
# Pull from Docker Hub
docker pull cboyd0319/pyguard:latest

# Test basic command
docker run --rm cboyd0319/pyguard:latest --version

# Test scanning a local directory
docker run --rm -v $(pwd):/code:ro cboyd0319/pyguard:latest /code --scan-only
```

---

## Step 4: Update Documentation

Once verified working, update the main README.md with Docker installation instructions:

```markdown
### Docker

```bash
# Pull the latest image
docker pull cboyd0319/pyguard:latest

# Scan your code
docker run -v $(pwd):/code:ro cboyd0319/pyguard:latest /code

# Auto-fix issues
docker run -v $(pwd):/code cboyd0319/pyguard:latest /code --fix
```

---

## What the Workflow Does

The workflow (`.github/workflows/docker-publish.yml`) automatically:

1. **Multi-Architecture Builds**
   - Builds for `linux/amd64` (Intel/AMD)
   - Builds for `linux/arm64` (ARM/Apple Silicon)

2. **Publishes to Two Registries**
   - Docker Hub: `cboyd0319/pyguard`
   - GitHub Container Registry: `ghcr.io/cboyd0319/pyguard`

3. **Security Scanning**
   - Generates SBOM (Software Bill of Materials)
   - Runs Trivy vulnerability scanning
   - Uploads results to GitHub Security

4. **Testing**
   - Tests `--version` command
   - Tests `--help` command
   - Tests actual code scanning

5. **Documentation**
   - Updates Docker Hub README automatically
   - Adds release summary to GitHub Actions

---

## Troubleshooting

### Error: "denied: requested access to the resource is denied"
**Solution:** Check that:
- `DOCKER_USERNAME` secret matches your Docker Hub username exactly
- `DOCKER_TOKEN` secret is valid and has write permissions
- Docker Hub repository `cboyd0319/pyguard` exists (it will be auto-created on first push)

### Error: "manifest unknown"
**Solution:** First build may take longer. Wait for workflow to complete fully.

### Multi-arch build fails
**Solution:** This is usually a transient issue. Re-run the workflow.

---

## Maintenance

### Automatic Updates

The workflow is triggered automatically on:
- **Release Tags:** Any tag matching `v*.*.*` (e.g., `v0.7.0`)
- **Manual:** Via "Run workflow" button in Actions tab

### Adding New Architectures

To add more architectures (e.g., `linux/arm/v7`):

1. Edit `.github/workflows/docker-publish.yml`
2. Update the `platforms` field:
   ```yaml
   platforms: linux/amd64,linux/arm64,linux/arm/v7
   ```
3. Test the build

---

## Success Criteria

- [ ] Secrets configured in GitHub
- [ ] Test workflow run completed successfully
- [ ] Images visible on Docker Hub
- [ ] Images visible on GitHub Container Registry
- [ ] Both architectures present (amd64, arm64)
- [ ] `docker pull cboyd0319/pyguard:latest` works
- [ ] Docker README updated on Docker Hub
- [ ] Main README.md updated with Docker installation instructions

---

## Next Steps After Setup

1. **Announce Docker availability** in README.md
2. **Add Docker badge** to README:
   ```markdown
   [![Docker Pulls](https://img.shields.io/docker/pulls/cboyd0319/pyguard)](https://hub.docker.com/r/cboyd0319/pyguard)
   ```
3. **Test on different platforms:**
   - Intel/AMD Linux
   - ARM Linux (Raspberry Pi)
   - macOS with Apple Silicon
4. **Monitor Docker Hub analytics** for pull counts

---

## References

- **Workflow:** `.github/workflows/docker-publish.yml`
- **Dockerfile:** `Dockerfile`
- **Docker Hub Docs:** https://docs.docker.com/docker-hub/
- **GitHub Container Registry:** https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry

---

**Status:** Ready for implementation
**Last Updated:** 2025-11-14
**Next Action:** Configure secrets and test workflow
