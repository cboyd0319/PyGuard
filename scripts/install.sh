#!/usr/bin/env bash
# PyGuard Installation Script
# Similar to BazBOM's install.sh approach
# This is a TEMPLATE for v0.7.0+ releases with signed artifacts

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
REPO="cboyd0319/PyGuard"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.pyguard}"
BIN_DIR="${BIN_DIR:-$HOME/.local/bin}"
PYGUARD_VERSION="${PYGUARD_VERSION:-latest}"

# Functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

detect_platform() {
    local os=$(uname -s | tr '[:upper:]' '[:lower:]')
    local arch=$(uname -m)
    
    case "$os" in
        linux*)
            PLATFORM="linux"
            ;;
        darwin*)
            PLATFORM="macos"
            ;;
        *)
            log_error "Unsupported operating system: $os"
            exit 1
            ;;
    esac
    
    case "$arch" in
        x86_64|amd64)
            ARCH="x86_64"
            ;;
        arm64|aarch64)
            ARCH="arm64"
            ;;
        *)
            log_error "Unsupported architecture: $arch"
            exit 1
            ;;
    esac
    
    log_info "Detected platform: $PLATFORM-$ARCH"
}

check_dependencies() {
    local missing_deps=()
    
    # Check for required commands
    for cmd in python3 pip3 curl; do
        if ! command -v $cmd &> /dev/null; then
            missing_deps+=($cmd)
        fi
    done
    
    if [ ${#missing_deps[@]} -gt 0 ]; then
        log_error "Missing required dependencies: ${missing_deps[*]}"
        log_info "Please install them and try again"
        exit 1
    fi
    
    # Check Python version
    local python_version=$(python3 --version | cut -d' ' -f2)
    local major=$(echo $python_version | cut -d'.' -f1)
    local minor=$(echo $python_version | cut -d'.' -f2)
    
    if [ "$major" -lt 3 ] || ([ "$major" -eq 3 ] && [ "$minor" -lt 11 ]); then
        log_error "Python 3.11+ required, found $python_version"
        exit 1
    fi
    
    log_success "All dependencies satisfied (Python $python_version)"
}

get_latest_version() {
    log_info "Fetching latest version from GitHub..."
    
    # Get latest release version from GitHub API
    local latest=$(curl -s "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    
    if [ -z "$latest" ]; then
        log_warn "Could not fetch latest version, using pip installation"
        INSTALL_METHOD="pip"
        return
    fi
    
    PYGUARD_VERSION="$latest"
    log_info "Latest version: $PYGUARD_VERSION"
}

install_via_pip() {
    log_info "Installing PyGuard via pip..."
    
    # Create virtual environment (recommended)
    if [ ! -d "$INSTALL_DIR/venv" ]; then
        log_info "Creating virtual environment..."
        python3 -m venv "$INSTALL_DIR/venv"
    fi
    
    # Activate and install
    source "$INSTALL_DIR/venv/bin/activate"
    
    if [ "$PYGUARD_VERSION" = "latest" ]; then
        pip3 install --upgrade pyguard
    else
        pip3 install --upgrade pyguard==$PYGUARD_VERSION
    fi
    
    # Create wrapper script
    mkdir -p "$BIN_DIR"
    cat > "$BIN_DIR/pyguard" << 'EOF'
#!/usr/bin/env bash
source "$HOME/.pyguard/venv/bin/activate"
exec python -m pyguard "$@"
EOF
    chmod +x "$BIN_DIR/pyguard"
    
    log_success "PyGuard installed successfully via pip"
}

install_via_release() {
    # This will be implemented in v0.7.0+ with signed release artifacts
    log_info "Installing from GitHub releases..."
    
    local version="${PYGUARD_VERSION#v}"
    local filename="pyguard-${version}-${PLATFORM}-${ARCH}.tar.gz"
    local download_url="https://github.com/$REPO/releases/download/$PYGUARD_VERSION/$filename"
    
    log_info "Downloading $filename..."
    
    # TODO v0.7.0: Implement release artifact download
    # - Download tarball
    # - Verify signature (Sigstore/cosign)
    # - Verify SLSA provenance
    # - Extract to INSTALL_DIR
    # - Link binary to BIN_DIR
    
    log_warn "Release artifact installation not yet available"
    log_info "Falling back to pip installation..."
    install_via_pip
}

verify_installation() {
    log_info "Verifying installation..."
    
    # Check if pyguard command is available
    if ! command -v pyguard &> /dev/null; then
        log_error "PyGuard command not found in PATH"
        log_info "Add $BIN_DIR to your PATH:"
        log_info "  export PATH=\"$BIN_DIR:\$PATH\""
        return 1
    fi
    
    # Test pyguard command
    local version=$(pyguard --version 2>&1 || echo "unknown")
    log_success "PyGuard $version installed and working"
    
    return 0
}

setup_shell_integration() {
    log_info "Setting up shell integration..."
    
    # Detect shell
    local shell_rc=""
    case "$SHELL" in
        */bash)
            shell_rc="$HOME/.bashrc"
            ;;
        */zsh)
            shell_rc="$HOME/.zshrc"
            ;;
        */fish)
            shell_rc="$HOME/.config/fish/config.fish"
            ;;
        *)
            log_warn "Unknown shell: $SHELL"
            return
            ;;
    esac
    
    # Add PATH if not already present
    if [ -f "$shell_rc" ] && ! grep -q "$BIN_DIR" "$shell_rc"; then
        echo "" >> "$shell_rc"
        echo "# PyGuard" >> "$shell_rc"
        echo "export PATH=\"$BIN_DIR:\$PATH\"" >> "$shell_rc"
        log_success "Added $BIN_DIR to PATH in $shell_rc"
        log_info "Run: source $shell_rc"
    fi
}

print_usage() {
    cat << EOF
PyGuard Installation Script

USAGE:
    curl -fsSL https://raw.githubusercontent.com/$REPO/main/scripts/install.sh | bash

ENVIRONMENT VARIABLES:
    INSTALL_DIR       Installation directory (default: $HOME/.pyguard)
    BIN_DIR          Binary directory (default: $HOME/.local/bin)
    PYGUARD_VERSION  Version to install (default: latest)

EXAMPLES:
    # Install latest version
    curl -fsSL https://raw.githubusercontent.com/$REPO/main/scripts/install.sh | bash

    # Install specific version
    curl -fsSL https://raw.githubusercontent.com/$REPO/main/scripts/install.sh | PYGUARD_VERSION=v0.7.0 bash

    # Custom installation directory
    curl -fsSL https://raw.githubusercontent.com/$REPO/main/scripts/install.sh | INSTALL_DIR=/opt/pyguard bash

For more information, visit: https://github.com/$REPO

EOF
}

main() {
    echo ""
    log_info "PyGuard Installation Script"
    log_info "Repository: $REPO"
    echo ""
    
    # Parse arguments
    if [ $# -gt 0 ] && [ "$1" = "--help" ]; then
        print_usage
        exit 0
    fi
    
    # Check system
    detect_platform
    check_dependencies
    
    # Get version to install
    if [ "$PYGUARD_VERSION" = "latest" ]; then
        get_latest_version
    fi
    
    # Install
    log_info "Installing PyGuard $PYGUARD_VERSION..."
    
    # Currently only pip installation is available
    # v0.7.0+ will support release artifacts with signing
    INSTALL_METHOD="pip"
    
    case "$INSTALL_METHOD" in
        pip)
            install_via_pip
            ;;
        release)
            install_via_release
            ;;
        *)
            log_error "Unknown installation method: $INSTALL_METHOD"
            exit 1
            ;;
    esac
    
    # Verify and setup
    if verify_installation; then
        setup_shell_integration
        
        echo ""
        log_success "PyGuard installation complete!"
        echo ""
        log_info "Next steps:"
        log_info "  1. Reload your shell: source ~/.bashrc  (or ~/.zshrc)"
        log_info "  2. Verify: pyguard --version"
        log_info "  3. Scan a project: pyguard /path/to/project"
        log_info "  4. See help: pyguard --help"
        echo ""
        log_info "Documentation: https://github.com/$REPO/tree/main/docs"
        echo ""
    else
        echo ""
        log_error "Installation verification failed"
        log_info "Please check the logs and try again"
        echo ""
        exit 1
    fi
}

# Run main function
main "$@"
