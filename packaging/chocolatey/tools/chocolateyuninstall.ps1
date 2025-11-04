$ErrorActionPreference = 'Stop'

Write-Host "Uninstalling PyGuard..." -ForegroundColor Cyan

# Uninstall PyGuard using pip
& python -m pip uninstall pyguard -y

if ($LASTEXITCODE -eq 0) {
    Write-Host "PyGuard uninstalled successfully!" -ForegroundColor Green
} else {
    Write-Warning "Failed to uninstall PyGuard via pip. It may have been already removed."
}
