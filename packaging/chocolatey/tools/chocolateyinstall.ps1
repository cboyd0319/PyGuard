$ErrorActionPreference = 'Stop'

$packageName = 'pyguard'
$toolsDir = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"

# Check if Python is installed and meets minimum version
$pythonCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonCmd) {
    throw "Python is not installed. Please install Python 3.11+ first."
}

$pythonVersion = & python --version 2>&1
if ($pythonVersion -match "Python (\d+)\.(\d+)") {
    $majorVersion = [int]$matches[1]
    $minorVersion = [int]$matches[2]
    
    if (($majorVersion -lt 3) -or (($majorVersion -eq 3) -and ($minorVersion -lt 11))) {
        throw "Python 3.11 or higher is required. Found: $pythonVersion"
    }
}

Write-Host "Installing PyGuard via pip..." -ForegroundColor Cyan

# Install PyGuard using pip
$pipArgs = @(
    'install',
    'pyguard',
    '--upgrade'
)

& python -m pip @pipArgs

if ($LASTEXITCODE -ne 0) {
    throw "Failed to install PyGuard via pip"
}

Write-Host "PyGuard installed successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "Quick Start:" -ForegroundColor Yellow
Write-Host "  pyguard .                                # Scan current directory"
Write-Host "  pyguard --fix .                          # Scan with auto-fix"
Write-Host "  pyguard --compliance-html report.html .  # Generate compliance report"
Write-Host ""
Write-Host "Documentation: https://github.com/cboyd0319/PyGuard" -ForegroundColor Cyan
