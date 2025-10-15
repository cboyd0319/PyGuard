"""Tests for CI/CD integration module."""

import pytest
from pathlib import Path
from pyguard.lib.ci_integration import (
    CIIntegrationGenerator,
    PreCommitHookGenerator,
    generate_ci_config,
    install_pre_commit_hook,
)


class TestCIIntegrationGenerator:
    """Test CI/CD integration generator."""

    def test_initialization(self):
        """Test generator initialization."""
        generator = CIIntegrationGenerator()
        assert generator is not None
        assert len(generator.templates) == 5

    def test_list_supported_platforms(self):
        """Test listing supported platforms."""
        generator = CIIntegrationGenerator()
        platforms = generator.list_supported_platforms()

        assert "github_actions" in platforms
        assert "gitlab_ci" in platforms
        assert "circleci" in platforms
        assert "pre_commit" in platforms
        assert "azure_pipelines" in platforms

    def test_generate_github_actions_config(self):
        """Test GitHub Actions configuration generation."""
        generator = CIIntegrationGenerator()
        config = generator.generate_config("github_actions")

        assert "name: PyGuard Security Scan" in config
        assert "uses: actions/checkout@v4" in config
        assert "pyguard" in config
        assert "sarif" in config

    def test_generate_gitlab_ci_config(self):
        """Test GitLab CI configuration generation."""
        generator = CIIntegrationGenerator()
        config = generator.generate_config("gitlab_ci")

        assert "pyguard-scan:" in config
        assert "pip install pyguard" in config
        assert "sast:" in config

    def test_generate_circleci_config(self):
        """Test CircleCI configuration generation."""
        generator = CIIntegrationGenerator()
        config = generator.generate_config("circleci")

        assert "version: 2.1" in config
        assert "pyguard-scan:" in config
        assert "store_artifacts:" in config

    def test_generate_pre_commit_config(self):
        """Test pre-commit configuration generation."""
        generator = CIIntegrationGenerator()
        config = generator.generate_config("pre_commit")

        assert "repos:" in config
        assert "pyguard" in config
        assert "types: [python]" in config

    def test_generate_azure_pipelines_config(self):
        """Test Azure Pipelines configuration generation."""
        generator = CIIntegrationGenerator()
        config = generator.generate_config("azure_pipelines")

        assert "trigger:" in config
        assert "pip install pyguard" in config
        assert "PublishBuildArtifacts" in config

    def test_unsupported_platform(self):
        """Test error handling for unsupported platform."""
        generator = CIIntegrationGenerator()

        with pytest.raises(ValueError, match="Unsupported CI platform"):
            generator.generate_config("unsupported_platform")

    def test_generate_config_with_output(self, tmp_path):
        """Test generating config with file output."""
        generator = CIIntegrationGenerator()
        output_file = tmp_path / "config.yml"

        config = generator.generate_config("github_actions", output_file)

        assert output_file.exists()
        assert output_file.read_text() == config

    def test_generate_all_configs(self, tmp_path):
        """Test generating all configurations."""
        generator = CIIntegrationGenerator()
        generated = generator.generate_all_configs(tmp_path)

        assert len(generated) == 5
        assert "github_actions" in generated
        assert "gitlab_ci" in generated

        # Check that files were created
        for file_path in generated.values():
            assert file_path.exists()


class TestPreCommitHookGenerator:
    """Test pre-commit hook generator."""

    def test_initialization(self):
        """Test hook generator initialization."""
        generator = PreCommitHookGenerator()
        assert generator is not None

    def test_generate_hook_script_security_only(self):
        """Test generating security-only hook script."""
        generator = PreCommitHookGenerator()
        script = generator.generate_hook_script(security_only=True)

        assert "#!/usr/bin/env bash" in script
        assert "PyGuard pre-commit hook" in script
        assert "--security-only" in script
        assert "git diff --cached" in script

    def test_generate_hook_script_full(self):
        """Test generating full hook script."""
        generator = PreCommitHookGenerator()
        script = generator.generate_hook_script(security_only=False)

        assert "#!/usr/bin/env bash" in script
        assert "--scan-only" in script
        assert "--security-only" not in script

    def test_install_hook_no_git_repo(self, tmp_path):
        """Test hook installation fails without git repo."""
        generator = PreCommitHookGenerator()
        result = generator.install_hook(tmp_path)

        assert result is False

    def test_install_hook_with_git_repo(self, tmp_path):
        """Test hook installation in git repo."""
        # Create mock git hooks directory
        git_hooks_dir = tmp_path / ".git" / "hooks"
        git_hooks_dir.mkdir(parents=True)

        generator = PreCommitHookGenerator()
        result = generator.install_hook(tmp_path)

        assert result is True
        hook_path = git_hooks_dir / "pre-commit"
        assert hook_path.exists()
        assert hook_path.stat().st_mode & 0o111  # Check executable


class TestConvenienceFunctions:
    """Test convenience functions."""

    def test_generate_ci_config_function(self):
        """Test generate_ci_config convenience function."""
        config = generate_ci_config("github_actions")

        assert "PyGuard" in config
        assert len(config) > 0

    def test_generate_ci_config_with_output(self, tmp_path):
        """Test generate_ci_config with output path."""
        output_file = tmp_path / "workflow.yml"
        config = generate_ci_config("github_actions", str(output_file))

        assert output_file.exists()
        assert output_file.read_text() == config

    def test_install_pre_commit_hook_function(self, tmp_path):
        """Test install_pre_commit_hook convenience function."""
        # Create mock git hooks directory
        git_hooks_dir = tmp_path / ".git" / "hooks"
        git_hooks_dir.mkdir(parents=True)

        result = install_pre_commit_hook(str(tmp_path))
        assert result is True
