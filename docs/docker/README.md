# PyGuard Docker Image

[![Docker Pulls](https://img.shields.io/docker/pulls/cboyd0319/pyguard)](https://hub.docker.com/r/cboyd0319/pyguard)

Comprehensive Python security & code quality scanner with 1,230+ security checks and auto-fixes.

## Quick Start

```bash
# Pull the image
docker pull cboyd0319/pyguard:latest

# Scan your code (read-only)
docker run -v $(pwd):/code:ro cboyd0319/pyguard:latest /code

# Auto-fix issues (requires write access)
docker run -v $(pwd):/code cboyd0319/pyguard:latest /code --fix
```

## Features

- **1,230+ Security Checks** - OWASP ASVS, CWE Top 25, PCI-DSS, HIPAA, SOC 2
- **199+ Auto-Fixes** - Automated security and code quality fixes
- **20+ Frameworks** - Django, Flask, FastAPI, TensorFlow, PyTorch
- **Multi-Architecture** - Native support for amd64 and arm64
- **100% Local** - Zero telemetry, runs completely offline

## Documentation

Full documentation: https://github.com/cboyd0319/PyGuard
