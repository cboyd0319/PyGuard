"""
Tests for Webhook API for CI/CD integration.

Tests webhook endpoints, API key authentication, rate limiting,
scan job management, and CI/CD platform integrations.
"""

import hashlib
import hmac
import time

import pytest

from pyguard.lib.webhook_api import (
    ApiKey,
    GitHubActionsIntegration,
    GitLabCIIntegration,
    JenkinsIntegration,
    PyGuardWebhookAPI,
    RateLimiter,
    ScanJob,
    ScanStatus,
    WebhookConfig,
    WebhookEvent,
)


class TestScanStatus:
    """Test scan status enum."""

    def test_status_values(self):
        """Test all status values."""
        assert ScanStatus.PENDING.value == "pending"
        assert ScanStatus.RUNNING.value == "running"
        assert ScanStatus.COMPLETED.value == "completed"
        assert ScanStatus.FAILED.value == "failed"
        assert ScanStatus.CANCELLED.value == "cancelled"


class TestWebhookEvent:
    """Test webhook event enum."""

    def test_event_values(self):
        """Test all event values."""
        assert WebhookEvent.SCAN_STARTED.value == "scan.started"
        assert WebhookEvent.SCAN_COMPLETED.value == "scan.completed"
        assert WebhookEvent.SCAN_FAILED.value == "scan.failed"
        assert WebhookEvent.ISSUE_FOUND.value == "issue.found"
        assert WebhookEvent.CRITICAL_ISSUE.value == "critical.issue"


class TestScanJob:
    """Test scan job data structure."""

    def test_scan_job_creation(self):
        """Test basic scan job creation."""
        job = ScanJob(job_id="test-123")

        assert job.job_id == "test-123"
        assert job.status == ScanStatus.PENDING
        assert job.issues_found == 0
        assert job.files_scanned == 0

    def test_scan_job_with_details(self):
        """Test scan job with full details."""
        job = ScanJob(
            job_id="test-456",
            status=ScanStatus.COMPLETED,
            target_path="/path/to/code",
            target_repository="https://github.com/test/repo",
            target_branch="main",
            target_commit="abc123",
            issues_found=10,
            critical_issues=2,
            high_issues=3,
            medium_issues=3,
            low_issues=2,
            files_scanned=50,
            lines_scanned=1000,
        )

        assert job.status == ScanStatus.COMPLETED
        assert job.issues_found == 10
        assert job.critical_issues == 2
        assert job.files_scanned == 50


class TestWebhookConfig:
    """Test webhook configuration."""

    def test_webhook_config_creation(self):
        """Test basic webhook config."""
        config = WebhookConfig(
            url="https://example.com/webhook",
            events=[WebhookEvent.SCAN_COMPLETED],
        )

        assert config.url == "https://example.com/webhook"
        assert WebhookEvent.SCAN_COMPLETED in config.events
        assert config.enabled is True
        assert config.retry_count == 3

    def test_webhook_config_with_secret(self):
        """Test webhook with secret."""
        config = WebhookConfig(
            url="https://example.com/webhook",
            events=[WebhookEvent.SCAN_COMPLETED],
            secret="test-secret-123",
        )

        assert config.secret == "test-secret-123"


class TestApiKey:
    """Test API key data structure."""

    def test_api_key_creation(self):
        """Test API key creation."""
        api_key = ApiKey(
            key_id="test-key-123",
            key_secret="secret-abc-xyz",
            description="Test key",
        )

        assert api_key.key_id == "test-key-123"
        assert api_key.key_secret == "secret-abc-xyz"
        assert api_key.enabled is True
        assert "scan:trigger" in api_key.permissions
        assert "scan:read" in api_key.permissions

    def test_api_key_with_custom_permissions(self):
        """Test API key with custom permissions."""
        api_key = ApiKey(
            key_id="test-key-456",
            key_secret="secret-def",
            permissions=["scan:read"],
        )

        assert "scan:read" in api_key.permissions
        assert "scan:trigger" not in api_key.permissions


class TestRateLimiter:
    """Test rate limiting functionality."""

    def test_rate_limiter_allows_initial_requests(self):
        """Test rate limiter allows requests within limit."""
        limiter = RateLimiter()

        # Allow first 5 requests
        for i in range(5):
            assert limiter.is_allowed("key1", limit=5)

    def test_rate_limiter_blocks_excess_requests(self):
        """Test rate limiter blocks requests over limit."""
        limiter = RateLimiter()

        # First 5 requests succeed
        for i in range(5):
            assert limiter.is_allowed("key2", limit=5)

        # 6th request should be blocked
        assert not limiter.is_allowed("key2", limit=5)

    def test_rate_limiter_per_key(self):
        """Test rate limiting is per key."""
        limiter = RateLimiter()

        # Different keys have independent limits
        for i in range(5):
            assert limiter.is_allowed("key_a", limit=5)
            assert limiter.is_allowed("key_b", limit=5)

        # Both keys should be at limit
        assert not limiter.is_allowed("key_a", limit=5)
        assert not limiter.is_allowed("key_b", limit=5)

    def test_rate_limiter_window_reset(self):
        """Test rate limiter window resets."""
        limiter = RateLimiter()

        # Fill the limit
        for i in range(3):
            assert limiter.is_allowed("key3", limit=3, window_seconds=1)

        # At limit
        assert not limiter.is_allowed("key3", limit=3, window_seconds=1)

        # Wait for window to expire
        time.sleep(1.1)

        # Should be allowed again
        assert limiter.is_allowed("key3", limit=3, window_seconds=1)


class TestPyGuardWebhookAPI:
    """Test PyGuard webhook API functionality."""

    @pytest.fixture
    def api(self):
        """Create a test API instance."""
        return PyGuardWebhookAPI(
            host="127.0.0.1",
            port=5008,
            require_https=False,  # For testing
        )

    def test_api_initialization(self, api):
        """Test API initialization."""
        assert api.host == "127.0.0.1"
        assert api.port == 5008
        assert not api.running
        assert len(api.api_keys) == 0
        assert len(api.scan_jobs) == 0

    def test_generate_api_key(self, api):
        """Test API key generation."""
        api_key = api.generate_api_key(description="Test key")

        assert api_key.key_id.startswith("pyguard_")
        assert len(api_key.key_secret) > 20
        assert api_key.description == "Test key"
        assert api_key.enabled is True
        assert api_key.key_id in api.api_keys

    def test_generate_api_key_with_custom_limit(self, api):
        """Test API key generation with custom rate limit."""
        api_key = api.generate_api_key(
            description="Custom limit",
            rate_limit=100,
        )

        assert api_key.rate_limit_per_minute == 100

    def test_validate_api_key_success(self, api):
        """Test successful API key validation."""
        api_key = api.generate_api_key(description="Valid key")

        validated = api.validate_api_key(api_key.key_id, api_key.key_secret)

        assert validated is not None
        assert validated.key_id == api_key.key_id
        assert validated.last_used_at is not None

    def test_validate_api_key_invalid_id(self, api):
        """Test validation with invalid key ID."""
        result = api.validate_api_key("invalid-key-id", "some-secret")

        assert result is None

    def test_validate_api_key_invalid_secret(self, api):
        """Test validation with invalid secret."""
        api_key = api.generate_api_key(description="Test")

        result = api.validate_api_key(api_key.key_id, "wrong-secret")

        assert result is None

    def test_validate_api_key_disabled(self, api):
        """Test validation with disabled key."""
        api_key = api.generate_api_key(description="Disabled")
        api_key.enabled = False

        result = api.validate_api_key(api_key.key_id, api_key.key_secret)

        assert result is None

    def test_check_rate_limit_allowed(self, api):
        """Test rate limit check when allowed."""
        api_key = api.generate_api_key(rate_limit=10)

        assert api.check_rate_limit(api_key)

    def test_check_rate_limit_exceeded(self, api):
        """Test rate limit check when exceeded."""
        api_key = api.generate_api_key(rate_limit=2)

        # Use up the limit
        assert api.check_rate_limit(api_key)
        assert api.check_rate_limit(api_key)

        # Should be rate limited
        assert not api.check_rate_limit(api_key)

    def test_trigger_scan_with_path(self, api):
        """Test triggering a scan with local path."""
        api_key = api.generate_api_key()

        response = api.trigger_scan(
            api_key=api_key,
            target_path="/path/to/code",
        )

        assert response["success"] is True
        assert "job_id" in response
        assert response["status"] == "pending"

        # Verify job was created
        job_id = response["job_id"]
        assert job_id in api.scan_jobs
        assert api.scan_jobs[job_id].target_path == "/path/to/code"

    def test_trigger_scan_with_repository(self, api):
        """Test triggering a scan with repository URL."""
        api_key = api.generate_api_key()

        response = api.trigger_scan(
            api_key=api_key,
            repository="https://github.com/test/repo",
            branch="main",
            commit="abc123",
        )

        assert response["success"] is True
        job_id = response["job_id"]

        scan_job = api.scan_jobs[job_id]
        assert scan_job.target_repository == "https://github.com/test/repo"
        assert scan_job.target_branch == "main"
        assert scan_job.target_commit == "abc123"

    def test_trigger_scan_with_metadata(self, api):
        """Test triggering a scan with metadata."""
        api_key = api.generate_api_key()

        metadata = {
            "ci_platform": "github-actions",
            "build_number": "123",
        }

        response = api.trigger_scan(
            api_key=api_key,
            target_path="/code",
            metadata=metadata,
        )

        assert response["success"] is True
        job_id = response["job_id"]

        assert api.scan_jobs[job_id].metadata == metadata

    def test_trigger_scan_without_target(self, api):
        """Test triggering a scan without target."""
        api_key = api.generate_api_key()

        response = api.trigger_scan(api_key=api_key)

        assert response["success"] is False
        assert response["error_code"] == "INVALID_INPUT"

    def test_trigger_scan_permission_denied(self, api):
        """Test triggering a scan without permission."""
        api_key = api.generate_api_key(permissions=["scan:read"])

        response = api.trigger_scan(
            api_key=api_key,
            target_path="/code",
        )

        assert response["success"] is False
        assert response["error_code"] == "PERMISSION_DENIED"

    def test_get_scan_status_success(self, api):
        """Test getting scan status."""
        api_key = api.generate_api_key()

        # Create a scan job
        trigger_response = api.trigger_scan(
            api_key=api_key,
            target_path="/code",
        )
        job_id = trigger_response["job_id"]

        # Get status
        response = api.get_scan_status(api_key=api_key, job_id=job_id)

        assert response["success"] is True
        assert response["job_id"] == job_id
        assert response["status"] == "pending"

    def test_get_scan_status_not_found(self, api):
        """Test getting status of non-existent job."""
        api_key = api.generate_api_key()

        response = api.get_scan_status(
            api_key=api_key,
            job_id="non-existent-job",
        )

        assert response["success"] is False
        assert response["error_code"] == "JOB_NOT_FOUND"

    def test_get_scan_status_permission_denied(self, api):
        """Test getting status without permission."""
        api_key = api.generate_api_key(permissions=["scan:trigger"])

        response = api.get_scan_status(
            api_key=api_key,
            job_id="some-job",
        )

        assert response["success"] is False
        assert response["error_code"] == "PERMISSION_DENIED"

    def test_get_scan_results_completed(self, api):
        """Test getting results of completed scan."""
        api_key = api.generate_api_key()

        # Create and complete a scan job
        trigger_response = api.trigger_scan(
            api_key=api_key,
            target_path="/code",
        )
        job_id = trigger_response["job_id"]

        # Simulate completion
        scan_job = api.scan_jobs[job_id]
        scan_job.status = ScanStatus.COMPLETED
        scan_job.issues_found = 5
        scan_job.critical_issues = 1

        # Get results
        response = api.get_scan_results(api_key=api_key, job_id=job_id)

        assert response["success"] is True
        assert response["summary"]["issues_found"] == 5
        assert response["summary"]["critical_issues"] == 1

    def test_get_scan_results_incomplete(self, api):
        """Test getting results of incomplete scan."""
        api_key = api.generate_api_key()

        trigger_response = api.trigger_scan(
            api_key=api_key,
            target_path="/code",
        )
        job_id = trigger_response["job_id"]

        response = api.get_scan_results(api_key=api_key, job_id=job_id)

        assert response["success"] is False
        assert response["error_code"] == "SCAN_INCOMPLETE"

    def test_list_scan_jobs_empty(self, api):
        """Test listing jobs when empty."""
        api_key = api.generate_api_key()

        response = api.list_scan_jobs(api_key=api_key)

        assert response["success"] is True
        assert response["count"] == 0
        assert len(response["jobs"]) == 0

    def test_list_scan_jobs_multiple(self, api):
        """Test listing multiple scan jobs."""
        api_key = api.generate_api_key()

        # Create multiple jobs
        for i in range(5):
            api.trigger_scan(
                api_key=api_key,
                target_path=f"/code{i}",
            )

        response = api.list_scan_jobs(api_key=api_key)

        assert response["success"] is True
        assert response["count"] == 5
        assert len(response["jobs"]) == 5

    def test_list_scan_jobs_with_limit(self, api):
        """Test listing jobs with limit."""
        api_key = api.generate_api_key()

        # Create multiple jobs
        for i in range(10):
            api.trigger_scan(api_key=api_key, target_path=f"/code{i}")

        response = api.list_scan_jobs(api_key=api_key, limit=5)

        assert response["count"] == 5
        assert len(response["jobs"]) == 5

    def test_list_scan_jobs_with_filter(self, api):
        """Test listing jobs with status filter."""
        api_key = api.generate_api_key()

        # Create jobs with different statuses
        for i in range(3):
            trigger_response = api.trigger_scan(
                api_key=api_key,
                target_path=f"/code{i}",
            )
            job_id = trigger_response["job_id"]

            # Set some as completed
            if i % 2 == 0:
                api.scan_jobs[job_id].status = ScanStatus.COMPLETED

        response = api.list_scan_jobs(
            api_key=api_key,
            status_filter=ScanStatus.COMPLETED,
        )

        assert response["success"] is True
        # Should have 2 completed (indexes 0 and 2)
        assert response["count"] == 2

    def test_register_webhook_success(self, api):
        """Test registering a webhook."""
        api_key = api.generate_api_key()

        response = api.register_webhook(
            api_key=api_key,
            url="https://example.com/webhook",
            events=[WebhookEvent.SCAN_COMPLETED],
        )

        assert response["success"] is True
        assert response["webhook_url"] == "https://example.com/webhook"
        assert "secret" in response
        assert len(api.webhooks) == 1

    def test_register_webhook_http_blocked(self):
        """Test that HTTP webhooks are blocked when HTTPS required."""
        api = PyGuardWebhookAPI(require_https=True)
        api_key = api.generate_api_key()

        response = api.register_webhook(
            api_key=api_key,
            url="http://example.com/webhook",
            events=[WebhookEvent.SCAN_COMPLETED],
        )

        assert response["success"] is False
        assert response["error_code"] == "INVALID_URL"

    def test_register_webhook_http_allowed_in_dev(self, api):
        """Test that HTTP webhooks are allowed when HTTPS not required."""
        api_key = api.generate_api_key()

        response = api.register_webhook(
            api_key=api_key,
            url="http://localhost:8000/webhook",
            events=[WebhookEvent.SCAN_COMPLETED],
        )

        assert response["success"] is True

    def test_verify_webhook_signature_valid(self, api):
        """Test webhook signature verification with valid signature."""
        payload = '{"event":"scan.completed","job_id":"test-123"}'
        secret = "test-secret"

        signature = hmac.new(
            secret.encode(),
            payload.encode(),
            hashlib.sha256,
        ).hexdigest()

        is_valid = api.verify_webhook_signature(
            payload=payload,
            signature=f"sha256={signature}",
            secret=secret,
        )

        assert is_valid

    def test_verify_webhook_signature_invalid(self, api):
        """Test webhook signature verification with invalid signature."""
        payload = '{"event":"scan.completed"}'
        secret = "test-secret"

        is_valid = api.verify_webhook_signature(
            payload=payload,
            signature="sha256=invalid-signature",
            secret=secret,
        )

        assert not is_valid

    def test_verify_webhook_signature_wrong_format(self, api):
        """Test webhook signature with wrong format."""
        is_valid = api.verify_webhook_signature(
            payload="{}",
            signature="invalid-format",
            secret="secret",
        )

        assert not is_valid

    def test_start_and_stop(self, api):
        """Test starting and stopping the API server."""
        assert not api.running

        api.start()
        assert api.running

        api.stop()
        assert not api.running


class TestCIPlatformIntegrations:
    """Test CI/CD platform integration helpers."""

    def test_github_actions_webhook_parsing(self):
        """Test parsing GitHub Actions webhook payload."""
        payload = {
            "repository": {"full_name": "user/repo"},
            "ref": "refs/heads/main",
            "after": "abc123def456",
            "pusher": {"name": "john_doe"},
            "event": "push",
            "action": "opened",
        }

        parsed = GitHubActionsIntegration.parse_github_webhook(payload)

        assert parsed["repository"] == "user/repo"
        assert parsed["branch"] == "main"
        assert parsed["commit"] == "abc123def456"
        assert parsed["pusher"] == "john_doe"
        assert parsed["metadata"]["event"] == "push"

    def test_gitlab_ci_webhook_parsing(self):
        """Test parsing GitLab CI webhook payload."""
        payload = {
            "project": {"path_with_namespace": "group/project"},
            "ref": "refs/heads/develop",
            "after": "xyz789abc123",
            "user_name": "jane_smith",
            "event_name": "push",
            "pipeline": {"id": 12345},
        }

        parsed = GitLabCIIntegration.parse_gitlab_webhook(payload)

        assert parsed["repository"] == "group/project"
        assert parsed["branch"] == "develop"
        assert parsed["commit"] == "xyz789abc123"
        assert parsed["pusher"] == "jane_smith"
        assert parsed["metadata"]["pipeline_id"] == 12345

    def test_jenkins_webhook_parsing(self):
        """Test parsing Jenkins webhook payload."""
        payload = {
            "name": "MyProject-Build",
            "build": {"number": 42},
            "scm": {
                "url": "https://github.com/org/repo.git",
                "branch": "feature-branch",
                "commit": "def456ghi789",
            },
        }

        parsed = JenkinsIntegration.parse_jenkins_webhook(payload)

        assert parsed["repository"] == "https://github.com/org/repo.git"
        assert parsed["branch"] == "feature-branch"
        assert parsed["commit"] == "def456ghi789"
        assert parsed["metadata"]["build_number"] == 42
        assert parsed["metadata"]["job_name"] == "MyProject-Build"


class TestWebhookAPIIntegration:
    """Integration tests for webhook API workflows."""

    @pytest.fixture
    def api(self):
        """Create a test API instance."""
        return PyGuardWebhookAPI(require_https=False)

    def test_full_scan_workflow(self, api):
        """Test complete scan workflow from trigger to results."""
        # 1. Generate API key
        api_key = api.generate_api_key(description="Integration test")

        # 2. Trigger scan
        trigger_response = api.trigger_scan(
            api_key=api_key,
            target_path="/test/code",
            metadata={"test": "integration"},
        )

        assert trigger_response["success"] is True
        job_id = trigger_response["job_id"]

        # 3. Check status (pending)
        status_response = api.get_scan_status(api_key=api_key, job_id=job_id)
        assert status_response["status"] == "pending"

        # 4. Simulate scan completion
        scan_job = api.scan_jobs[job_id]
        scan_job.status = ScanStatus.COMPLETED
        scan_job.issues_found = 3
        scan_job.critical_issues = 1

        # 5. Get results
        results_response = api.get_scan_results(api_key=api_key, job_id=job_id)

        assert results_response["success"] is True
        assert results_response["summary"]["issues_found"] == 3
        assert results_response["summary"]["critical_issues"] == 1

    def test_multiple_api_keys_workflow(self, api):
        """Test workflow with multiple API keys."""
        # Create two API keys with different permissions
        key1 = api.generate_api_key(
            description="Full access",
            permissions=["scan:trigger", "scan:read"],
        )
        key2 = api.generate_api_key(
            description="Read only",
            permissions=["scan:read"],
        )

        # Key1 can trigger scans
        response1 = api.trigger_scan(api_key=key1, target_path="/code")
        assert response1["success"] is True

        # Key2 cannot trigger scans
        response2 = api.trigger_scan(api_key=key2, target_path="/code")
        assert response2["success"] is False
        assert response2["error_code"] == "PERMISSION_DENIED"

        # But key2 can read status
        job_id = response1["job_id"]
        response3 = api.get_scan_status(api_key=key2, job_id=job_id)
        assert response3["success"] is True

    def test_webhook_registration_and_trigger(self, api):
        """Test webhook registration and triggering."""
        api_key = api.generate_api_key()

        # Register webhook
        webhook_response = api.register_webhook(
            api_key=api_key,
            url="https://example.com/webhook",
            events=[WebhookEvent.SCAN_STARTED, WebhookEvent.SCAN_COMPLETED],
        )

        assert webhook_response["success"] is True

        # Trigger scan (should trigger SCAN_STARTED webhook)
        trigger_response = api.trigger_scan(
            api_key=api_key,
            target_path="/code",
        )

        assert trigger_response["success"] is True
        # Webhook would be triggered asynchronously
        # In production, verify via HTTP call logs
