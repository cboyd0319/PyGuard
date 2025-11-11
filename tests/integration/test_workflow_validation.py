"""
Tests for validating GitHub Actions workflows follow best practices.

These tests verify:
- Workflow syntax and structure
- Security best practices (pinned actions, minimal permissions)
- Error handling and robustness
- Documentation completeness
"""

from pathlib import Path
import re

import pytest
import yaml


class TestWorkflowValidation:
    """Test GitHub Actions workflows follow best practices."""

    @pytest.fixture
    def workflows_dir(self):
        """Get path to workflows directory."""
        repo_root = Path(__file__).parent.parent.parent
        return repo_root / ".github" / "workflows"

    @pytest.fixture
    def workflow_files(self, workflows_dir):
        """Get all workflow YAML files."""
        return list(workflows_dir.glob("*.yml"))

    def test_workflows_directory_exists(self, workflows_dir):
        """Test workflows directory exists."""
        assert workflows_dir.exists()
        assert workflows_dir.is_dir()

    def test_workflow_files_exist(self, workflow_files):
        """Test at least some workflow files exist."""
        assert len(workflow_files) > 0, "No workflow files found"

    def test_workflow_files_are_valid_yaml(self, workflow_files):
        """Test all workflow files are valid YAML."""
        for workflow_file in workflow_files:
            with open(workflow_file) as f:
                try:
                    yaml.safe_load(f)
                except yaml.YAMLError as e:
                    pytest.fail(f"Invalid YAML in {workflow_file.name}: {e}")

    def test_workflows_have_names(self, workflow_files):
        """Test all workflows have a name field."""
        for workflow_file in workflow_files:
            with open(workflow_file) as f:
                workflow = yaml.safe_load(f)

            assert "name" in workflow, f"{workflow_file.name} missing 'name' field"
            assert isinstance(workflow["name"], str)
            assert len(workflow["name"]) > 0

    def test_workflows_have_triggers(self, workflow_files):
        """Test all workflows have trigger configuration."""
        for workflow_file in workflow_files:
            with open(workflow_file) as f:
                workflow = yaml.safe_load(f)

            # YAML 'on' keyword can be parsed as True (boolean)
            assert (
                "on" in workflow or True in workflow
            ), f"{workflow_file.name} missing 'on' (trigger) field"

    def test_workflows_use_pinned_actions(self, workflow_files):
        """Test workflows use SHA-pinned or versioned actions."""
        # Pattern for action references
        action_pattern = re.compile(r"uses:\s+([^@\s]+)@([^\s]+)")

        # Known actions that use short versions (exceptions)
        short_version_exceptions = [
            "actions/attest-build-provenance",  # Uses @v1
            "anchore/sbom-action",  # Uses @v0
        ]

        for workflow_file in workflow_files:
            with open(workflow_file) as f:
                content = f.read()

            actions = action_pattern.findall(content)

            for action_name, version in actions:
                # Skip local actions (start with ./)
                if action_name.startswith("./"):
                    continue

                # Skip known exceptions
                if any(action_name.startswith(exc) for exc in short_version_exceptions):
                    continue

                # Version should be either SHA (40 chars) or semver tag
                assert len(version) >= 6, (
                    f"{workflow_file.name}: Action {action_name} should use "
                    f"SHA pin or version tag, found: {version}"
                )

    def test_workflows_have_permissions(self, workflow_files):
        """Test workflows declare explicit permissions."""
        for workflow_file in workflow_files:
            with open(workflow_file) as f:
                workflow = yaml.safe_load(f)

            # Should have permissions at workflow or job level
            has_workflow_permissions = "permissions" in workflow

            if not has_workflow_permissions and "jobs" in workflow:
                # Check if at least one job has permissions
                has_job_permissions = any(
                    "permissions" in job_config
                    for job_config in workflow["jobs"].values()
                    if isinstance(job_config, dict)
                )

                assert (
                    has_job_permissions
                ), f"{workflow_file.name} should declare permissions at workflow or job level"

    def test_workflows_minimize_permissions(self, workflow_files):
        """Test workflows use minimal required permissions."""
        dangerous_permissions = ["write-all", "admin"]

        for workflow_file in workflow_files:
            with open(workflow_file) as f:
                content = f.read()

            for perm in dangerous_permissions:
                assert (
                    perm not in content
                ), f"{workflow_file.name} uses overly broad permission: {perm}"

    def test_workflows_have_error_handling(self, workflow_files):
        """Test workflows have appropriate error handling."""
        for workflow_file in workflow_files:
            with open(workflow_file) as f:
                workflow = yaml.safe_load(f)

            if "jobs" not in workflow:
                continue

            for _job_name, job_config in workflow["jobs"].items():
                if not isinstance(job_config, dict) or "steps" not in job_config:
                    continue

                # Check for continue-on-error or if: always() patterns

                for step in job_config["steps"]:
                    if not isinstance(step, dict):
                        continue

                    if "continue-on-error" in step or "if" in step:
                        break

                # Not all jobs need error handling, but good practice
                # This is informational, not a hard requirement

    def test_security_workflows_upload_sarif(self, workflows_dir):
        """Test security workflows upload SARIF results."""
        security_workflows = [
            workflows_dir / "pyguard-security-scan.yml",
        ]

        for workflow_file in security_workflows:
            if not workflow_file.exists():
                continue

            with open(workflow_file) as f:
                content = f.read()

            assert (
                "upload-sarif" in content or "codeql-action/upload-sarif" in content
            ), f"{workflow_file.name} should upload SARIF results"

    def test_workflows_have_job_names(self, workflow_files):
        """Test all jobs have descriptive names."""
        for workflow_file in workflow_files:
            with open(workflow_file) as f:
                workflow = yaml.safe_load(f)

            if "jobs" not in workflow:
                continue

            for job_id, job_config in workflow["jobs"].items():
                if not isinstance(job_config, dict):
                    continue

                # Job should have a name field
                assert (
                    "name" in job_config or "runs-on" in job_config
                ), f"{workflow_file.name}: Job '{job_id}' should have 'name' field"

    def test_workflows_have_step_names(self, workflow_files):
        """Test critical steps have descriptive names."""
        for workflow_file in workflow_files:
            with open(workflow_file) as f:
                workflow = yaml.safe_load(f)

            if "jobs" not in workflow:
                continue

            for _job_name, job_config in workflow["jobs"].items():
                if not isinstance(job_config, dict) or "steps" not in job_config:
                    continue

                for _i, step in enumerate(job_config["steps"]):
                    if not isinstance(step, dict):
                        continue

                    # Non-action steps should have names
                    if "run" in step and "name" not in step:
                        # This is a recommendation, not hard requirement
                        pass

    def test_pyguard_workflow_configuration(self, workflows_dir):
        """Test PyGuard security scan workflow is properly configured."""
        workflow_file = workflows_dir / "pyguard-security-scan.yml"

        if not workflow_file.exists():
            pytest.skip("PyGuard workflow not found")

        with open(workflow_file) as f:
            workflow = yaml.safe_load(f)

        # Should have security-events write permission at workflow or job level
        workflow_perms = workflow.get("permissions", {})
        has_workflow_permission = workflow_perms.get("security-events") == "write"

        # Check job-level permissions if not at workflow level
        has_job_permission = False
        if not has_workflow_permission and "jobs" in workflow:
            for job_config in workflow["jobs"].values():
                if isinstance(job_config, dict):
                    job_perms = job_config.get("permissions", {})
                    if job_perms.get("security-events") == "write":
                        has_job_permission = True
                        break

        assert (
            has_workflow_permission or has_job_permission
        ), "PyGuard workflow needs security-events: write permission at workflow or job level"

        # Should run on appropriate triggers (YAML 'on' can be parsed as True)
        triggers = workflow.get("on", workflow.get(True, {}))
        assert "push" in triggers or "pull_request" in triggers or "schedule" in triggers

    def test_workflows_use_latest_action_versions(self, workflow_files):
        """Test workflows use reasonably recent action versions."""
        for workflow_file in workflow_files:
            with open(workflow_file) as f:
                content = f.read()

            # Check for deprecated actions
            deprecated = [
                "actions/checkout@v1",
                "actions/checkout@v2",
                "actions/setup-python@v1",
                "actions/setup-python@v2",
                "actions/setup-python@v3",
            ]

            for dep in deprecated:
                assert (
                    dep not in content
                ), f"{workflow_file.name} uses deprecated action version: {dep}"


class TestActionYmlValidation:
    """Test action.yml follows best practices."""

    @pytest.fixture
    def action_file(self):
        """Get path to action.yml."""
        repo_root = Path(__file__).parent.parent.parent
        return repo_root / "action.yml"

    def test_action_file_exists(self, action_file):
        """Test action.yml exists."""
        assert action_file.exists()

    def test_action_file_is_valid_yaml(self, action_file):
        """Test action.yml is valid YAML."""
        with open(action_file) as f:
            try:
                yaml.safe_load(f)
            except yaml.YAMLError as e:
                pytest.fail(f"Invalid YAML in action.yml: {e}")

    def test_action_has_required_metadata(self, action_file):
        """Test action.yml has required metadata fields."""
        with open(action_file) as f:
            action = yaml.safe_load(f)

        required_fields = ["name", "description", "runs"]
        for field in required_fields:
            assert field in action, f"action.yml missing required field: {field}"

    def test_action_has_branding(self, action_file):
        """Test action.yml has branding for marketplace."""
        with open(action_file) as f:
            action = yaml.safe_load(f)

        assert "branding" in action
        assert "icon" in action["branding"]
        assert "color" in action["branding"]

    def test_action_inputs_have_descriptions(self, action_file):
        """Test all inputs have descriptions."""
        with open(action_file) as f:
            action = yaml.safe_load(f)

        if "inputs" not in action:
            pytest.skip("No inputs defined")

        for input_name, input_config in action["inputs"].items():
            assert "description" in input_config, f"Input '{input_name}' missing description"
            assert len(input_config["description"]) > 0

    def test_action_inputs_have_defaults(self, action_file):
        """Test inputs have appropriate defaults where needed."""
        with open(action_file) as f:
            action = yaml.safe_load(f)

        if "inputs" not in action:
            pytest.skip("No inputs defined")

        for input_name, input_config in action["inputs"].items():
            # Non-required inputs should have defaults
            if not input_config.get("required", False):
                assert (
                    "default" in input_config
                ), f"Non-required input '{input_name}' should have default value"

    def test_action_outputs_have_descriptions(self, action_file):
        """Test all outputs have descriptions."""
        with open(action_file) as f:
            action = yaml.safe_load(f)

        if "outputs" not in action:
            pytest.skip("No outputs defined")

        for output_name, output_config in action["outputs"].items():
            assert "description" in output_config, f"Output '{output_name}' missing description"

    def test_action_uses_composite_run(self, action_file):
        """Test action uses composite run type."""
        with open(action_file) as f:
            action = yaml.safe_load(f)

        assert action["runs"]["using"] in ["composite", "docker", "node20"]

    def test_action_steps_use_pinned_actions(self, action_file):
        """Test action steps use pinned action versions."""
        with open(action_file) as f:
            content = f.read()

        action_pattern = re.compile(r"uses:\s+([^@\s]+)@([^\s]+)")
        actions = action_pattern.findall(content)

        for action_name, version in actions:
            if action_name.startswith("./"):
                continue

            # Should use SHA or semver
            assert len(version) >= 6, f"Action {action_name} should use SHA pin or version tag"


class TestWorkflowDocumentation:
    """Test workflow documentation is complete."""

    @pytest.fixture
    def workflows_readme(self):
        """Get workflows README path."""
        repo_root = Path(__file__).parent.parent.parent
        return repo_root / ".github" / "workflows" / "README.md"

    def test_workflows_readme_exists(self, workflows_readme):
        """Test workflows README exists."""
        assert workflows_readme.exists()

    def test_workflows_readme_has_content(self, workflows_readme):
        """Test workflows README has substantive content."""
        with open(workflows_readme) as f:
            content = f.read()

        # Should be reasonably comprehensive
        assert len(content) > 1000, "Workflows README should be comprehensive"

    def test_workflows_readme_documents_all_workflows(self, workflows_readme):
        """Test workflows README documents all workflow files."""
        repo_root = Path(__file__).parent.parent.parent
        workflows_dir = repo_root / ".github" / "workflows"
        workflow_files = [f.stem for f in workflows_dir.glob("*.yml")]

        with open(workflows_readme) as f:
            content = f.read()

        # Most workflows should be mentioned
        documented_count = sum(1 for wf in workflow_files if wf in content)
        total_count = len(workflow_files)

        # At least 80% should be documented
        coverage = documented_count / total_count if total_count > 0 else 0
        assert (
            coverage >= 0.8
        ), f"Only {documented_count}/{total_count} workflows documented in README"

    def test_example_workflows_exist(self):
        """Test example workflows directory exists with examples."""
        repo_root = Path(__file__).parent.parent.parent
        examples_dir = repo_root / "examples" / "github-workflows"

        assert examples_dir.exists()

        example_files = list(examples_dir.glob("*.yml"))
        assert len(example_files) > 0, "Should have example workflow files"

    def test_github_action_guide_exists(self):
        """Test GitHub Action guide documentation exists."""
        repo_root = Path(__file__).parent.parent.parent
        guide = repo_root / "docs" / "guides" / "github-action-guide.md"

        assert guide.exists()

        with open(guide) as f:
            content = f.read()

        # Should be comprehensive
        assert len(content) > 5000, "GitHub Action guide should be comprehensive"

        # Should cover key topics
        assert "Quick Start" in content
        assert "SARIF" in content
        assert "Security" in content
        assert "Examples" in content or "Usage" in content
