# Homebrew Formula for PyGuard
# This formula will be published to homebrew-pyguard tap for v0.7.0

class Pyguard < Formula
  include Language::Python::Virtualenv

  desc "Comprehensive Python security & code quality scanner with 1,230+ checks and auto-fixes"
  homepage "https://github.com/cboyd0319/PyGuard"
  url "https://files.pythonhosted.org/packages/source/p/pyguard/pyguard-0.6.0.tar.gz"
  sha256 "PLACEHOLDER_SHA256"  # Will be calculated from actual release
  license "MIT"
  head "https://github.com/cboyd0319/PyGuard.git", branch: "main"

  # Python 3.11+ required
  depends_on "python@3.13" => :recommended
  depends_on "python@3.12"
  depends_on "python@3.11"

  def python3
    "python3.13"
  end

  def install
    # Install PyGuard and all dependencies in a virtualenv
    virtualenv_install_with_resources
    
    # Generate shell completions if available
    generate_completions_from_executable(bin/"pyguard", shells: [:bash, :zsh, :fish],
                                         shell_parameter_format: :click)
  end

  test do
    # Test version command
    assert_match version.to_s, shell_output("#{bin}/pyguard --version")
    
    # Test basic security scanning
    (testpath/"test_security.py").write <<~PYTHON
      import pickle
      import subprocess
      
      # This should trigger security warnings
      data = pickle.load(open('file.pkl', 'rb'))
      subprocess.call(['ls', user_input])
    PYTHON
    
    # Run scan - should detect security issues
    output = shell_output("#{bin}/pyguard #{testpath}/test_security.py --scan-only 2>&1")
    assert_match(/pickle|subprocess/i, output)
    
    # Test help command
    assert_match "usage:", shell_output("#{bin}/pyguard --help")
    
    # Test auto-fix dry run
    output = shell_output("#{bin}/pyguard #{testpath}/test_security.py --fix --dry-run 2>&1")
    assert_match "would fix", output.downcase
  end
end
