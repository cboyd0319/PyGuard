# PyGuard Package Manager Support

This directory contains package definitions for various package managers to make PyGuard easily installable across different platforms.

## Supported Package Managers

### Windows

#### Chocolatey

Chocolatey is the most popular package manager for Windows.

**Installation:**
```powershell
choco install pyguard
```

**Files:**
- `chocolatey/pyguard.nuspec` - Package specification
- `chocolatey/tools/chocolateyinstall.ps1` - Installation script
- `chocolatey/tools/chocolateyuninstall.ps1` - Uninstallation script

**Publishing:**
```powershell
# Build package
cd packaging/chocolatey
choco pack

# Test locally
choco install pyguard -source .

# Publish to Chocolatey (requires API key)
choco push pyguard.0.6.0.nupkg --source https://push.chocolatey.org/ --api-key YOUR_API_KEY
```

**Documentation:** https://docs.chocolatey.org/en-us/create/create-packages

#### Scoop

Scoop is a command-line installer for Windows focused on developer tools.

**Installation:**
```powershell
scoop bucket add extras
scoop install pyguard
```

**Files:**
- `scoop/pyguard.json` - Scoop manifest

**Publishing:**

1. Fork https://github.com/ScoopInstaller/Main (or Extras bucket)
2. Add `pyguard.json` to the `bucket/` directory
3. Submit a pull request

**Documentation:** https://scoop.sh/

### Linux

#### Snap

Snap is a universal Linux package format supported across many distributions.

**Installation:**
```bash
sudo snap install pyguard
```

**Files:**
- `snap/snapcraft.yaml` - Snap package definition

**Building:**
```bash
# Install snapcraft
sudo snap install snapcraft --classic

# Build snap
cd packaging/snap
snapcraft

# Test locally
sudo snap install pyguard_0.6.0_amd64.snap --dangerous

# Publish to Snap Store (requires login)
snapcraft login
snapcraft upload pyguard_0.6.0_amd64.snap --release stable
```

**Documentation:** https://snapcraft.io/docs

## Requirements

All packages require Python 3.11 or higher to be installed on the system.

### Chocolatey Requirements
- Windows 7+ / Server 2003+
- PowerShell v2+
- .NET Framework 4.0+
- Python 3.11+

### Scoop Requirements
- Windows 10 / Server 2012+
- PowerShell 5+
- Python 3.11+

### Snap Requirements
- Ubuntu 16.04+ (or other Snap-compatible Linux distribution)
- Python 3.11+

## Package Maintenance

### Updating Package Versions

When releasing a new version of PyGuard:

1. **Update version numbers** in all package files:
   - `chocolatey/pyguard.nuspec` (version field)
   - `scoop/pyguard.json` (version field)
   - `snap/snapcraft.yaml` (version field)

2. **Update release notes/changelog** references in:
   - `chocolatey/pyguard.nuspec` (releaseNotes field)

3. **Update hashes** for Scoop:
   ```powershell
   # Get SHA256 hash of release archive
   $hash = (Get-FileHash -Path pyguard-0.6.0.zip -Algorithm SHA256).Hash
   # Update in scoop/pyguard.json
   ```

4. **Test packages locally** before publishing

5. **Publish to repositories** following their respective processes

### Testing Packages

Before publishing, always test packages locally:

**Chocolatey:**
```powershell
choco install pyguard -source . -y
pyguard --version
choco uninstall pyguard -y
```

**Scoop:**
```powershell
scoop install .\pyguard.json
pyguard --version
scoop uninstall pyguard
```

**Snap:**
```bash
sudo snap install pyguard_0.6.0_amd64.snap --dangerous
pyguard --version
sudo snap remove pyguard
```

## Package Statistics

Track package installation metrics:

- **Chocolatey:** https://community.chocolatey.org/packages/pyguard
- **Scoop:** Via bucket analytics
- **Snap:** https://snapcraft.io/pyguard

## Support

For package-specific issues:
- File an issue: https://github.com/cboyd0319/PyGuard/issues
- Label with: `distribution`, `packaging`
- Include: OS, package manager, version

## Contributing

Contributions welcome! Areas for improvement:
- Additional package managers (apt, yum, pacman, etc.)
- Package automation in CI/CD
- Cross-platform testing
- Package documentation

## License

Package definitions are licensed under the MIT License, same as PyGuard.
