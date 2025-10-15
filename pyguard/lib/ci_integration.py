"""
CI/CD Integration Module for PyGuard.

Generates configuration files for various CI/CD platforms and pre-commit hooks.
Helps teams integrate PyGuard into their development workflow.
"""

from pathlib import Path
from typing import Dict, List, Optional


class CIIntegrationGenerator:
    """Generate CI/CD integration configurations for PyGuard."""

    def __init__(self):
        """Initialize the CI integration generator."""
        self.templates = self._load_templates()

    def _load_templates(self) -> Dict[str, str]:
        """Load CI/CD configuration templates."""
        return {
            "github_actions": self._github_actions_template(),
            "gitlab_ci": self._gitlab_ci_template(),
            "circleci": self._circleci_template(),
            "pre_commit": self._pre_commit_template(),
            "azure_pipelines": self._azure_pipelines_template(),
        }

    def _github_actions_template(self) -> str:
        """Generate GitHub Actions workflow configuration."""
        return """name: PyGuard Security Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]

permissions:
  contents: read
  security-events: write

jobs:
  pyguard-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.13'

      - name: Install PyGuard
        run: pip install pyguard

      - name: Run PyGuard security scan
        run: pyguard . --scan-only --sarif --no-html

      - name: Upload SARIF results
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: pyguard-report.sarif

      - name: Archive HTML report
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: pyguard-report
          path: pyguard-report.html
"""

    def _gitlab_ci_template(self) -> str:
        """Generate GitLab CI configuration."""
        return """# PyGuard Security Scan
pyguard-scan:
  stage: test
  image: python:3.13-slim
  before_script:
    - pip install pyguard
  script:
    - pyguard . --scan-only --no-html
  artifacts:
    reports:
      sast: pyguard-report.sarif
    paths:
      - pyguard-report.html
    when: always
  allow_failure: false
"""

    def _circleci_template(self) -> str:
        """Generate CircleCI configuration."""
        return """version: 2.1

jobs:
  pyguard-scan:
    docker:
      - image: python:3.13-slim
    steps:
      - checkout
      - run:
          name: Install PyGuard
          command: pip install pyguard
      - run:
          name: Run security scan
          command: pyguard . --scan-only
      - store_artifacts:
          path: pyguard-report.html
      - store_artifacts:
          path: pyguard-report.sarif

workflows:
  version: 2
  scan:
    jobs:
      - pyguard-scan
"""

    def _pre_commit_template(self) -> str:
        """Generate pre-commit hook configuration."""
        return """# PyGuard pre-commit hook
repos:
  - repo: local
    hooks:
      - id: pyguard
        name: PyGuard Security & Quality Scan
        entry: pyguard
        language: system
        types: [python]
        pass_filenames: true
        args: ['--scan-only', '--security-only']
"""

    def _azure_pipelines_template(self) -> str:
        """Generate Azure Pipelines configuration."""
        return """# PyGuard Security Scan
trigger:
  - main
  - develop

pool:
  vmImage: 'ubuntu-latest'

steps:
- task: UsePythonVersion@0
  inputs:
    versionSpec: '3.13'
    addToPath: true

- script: |
    pip install pyguard
  displayName: 'Install PyGuard'

- script: |
    pyguard . --scan-only --sarif
  displayName: 'Run PyGuard scan'

- task: PublishBuildArtifacts@1
  inputs:
    pathToPublish: 'pyguard-report.html'
    artifactName: 'pyguard-report'
  condition: always()
"""

    def generate_config(self, ci_platform: str, output_path: Optional[Path] = None) -> str:
        """
        Generate CI/CD configuration for specified platform.

        Args:
            ci_platform: CI/CD platform name (github_actions, gitlab_ci, circleci, etc.)
            output_path: Optional path to write configuration file

        Returns:
            Configuration file content

        Raises:
            ValueError: If platform is not supported
        """
        if ci_platform not in self.templates:
            raise ValueError(
                f"Unsupported CI platform: {ci_platform}. "
                f"Supported: {', '.join(self.templates.keys())}"
            )

        config = self.templates[ci_platform]

        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(config)

        return config

    def generate_all_configs(self, output_dir: Path) -> Dict[str, Path]:
        """
        Generate all CI/CD configurations.

        Args:
            output_dir: Directory to write configuration files

        Returns:
            Dictionary mapping platform names to file paths
        """
        output_dir.mkdir(parents=True, exist_ok=True)
        generated_files = {}

        file_mappings = {
            "github_actions": output_dir / ".github" / "workflows" / "pyguard.yml",
            "gitlab_ci": output_dir / ".gitlab-ci-pyguard.yml",
            "circleci": output_dir / ".circleci" / "config.yml",
            "pre_commit": output_dir / ".pre-commit-config-pyguard.yaml",
            "azure_pipelines": output_dir / "azure-pipelines-pyguard.yml",
        }

        for platform, file_path in file_mappings.items():
            self.generate_config(platform, file_path)
            generated_files[platform] = file_path

        return generated_files

    def list_supported_platforms(self) -> List[str]:
        """
        Get list of supported CI/CD platforms.

        Returns:
            List of platform names
        """
        return list(self.templates.keys())


class PreCommitHookGenerator:
    """Generate pre-commit hooks for PyGuard."""

    def generate_hook_script(self, security_only: bool = True) -> str:
        """
        Generate pre-commit hook script.

        Args:
            security_only: Only run security checks (faster)

        Returns:
            Hook script content
        """
        args = "--scan-only --security-only" if security_only else "--scan-only"

        return f"""#!/usr/bin/env bash
# PyGuard pre-commit hook

# Run PyGuard on staged Python files
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep -E '\\.py$')

if [ -n "$STAGED_FILES" ]; then
    echo "Running PyGuard security scan..."
    pyguard $STAGED_FILES {args}
    
    EXIT_CODE=$?
    
    if [ $EXIT_CODE -ne 0 ]; then
        echo "❌ PyGuard found security issues. Please fix them before committing."
        exit 1
    fi
    
    echo "✅ PyGuard scan passed!"
fi

exit 0
"""

    def install_hook(self, repo_path: Path) -> bool:
        """
        Install pre-commit hook in git repository.

        Args:
            repo_path: Path to git repository

        Returns:
            True if successful, False otherwise
        """
        git_hooks_dir = repo_path / ".git" / "hooks"

        if not git_hooks_dir.exists():
            return False

        hook_path = git_hooks_dir / "pre-commit"
        hook_script = self.generate_hook_script()

        hook_path.write_text(hook_script)
        hook_path.chmod(0o755)  # Make executable

        return True


def generate_ci_config(platform: str, output_path: Optional[str] = None) -> str:
    """
    Convenience function to generate CI/CD configuration.

    Args:
        platform: CI/CD platform name
        output_path: Optional path to write configuration

    Returns:
        Configuration content
    """
    generator = CIIntegrationGenerator()
    output = Path(output_path) if output_path else None
    return generator.generate_config(platform, output)


def install_pre_commit_hook(repo_path: str = ".") -> bool:
    """
    Convenience function to install pre-commit hook.

    Args:
        repo_path: Path to git repository

    Returns:
        True if successful
    """
    generator = PreCommitHookGenerator()
    return generator.install_hook(Path(repo_path))
