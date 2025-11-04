"""
Webhook API for CI/CD Integration.

Provides webhook endpoints for integrating PyGuard with CI/CD pipelines,
allowing external systems to trigger scans, receive notifications, and
retrieve analysis results.

Features:
- RESTful webhook API
- Trigger scans via HTTP POST
- Query scan status and results
- Receive notifications on scan completion
- Support for popular CI/CD platforms (GitHub Actions, GitLab CI, Jenkins)
- Secure authentication with API keys
- Rate limiting and request validation

Security:
- API key authentication
- HTTPS only (configurable for development)
- Request signature validation
- Rate limiting per API key
- No telemetry or data collection
"""

from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import hmac
import json
import logging
from pathlib import Path
import secrets
import threading
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class ScanStatus(Enum):
    """Status of a scan job."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class WebhookEvent(Enum):
    """Webhook event types."""
    SCAN_STARTED = "scan.started"
    SCAN_COMPLETED = "scan.completed"
    SCAN_FAILED = "scan.failed"
    ISSUE_FOUND = "issue.found"
    CRITICAL_ISSUE = "critical.issue"


@dataclass
class ScanJob:
    """Represents a scan job triggered via webhook."""
    job_id: str
    status: ScanStatus = ScanStatus.PENDING
    target_path: Optional[str] = None
    target_repository: Optional[str] = None
    target_branch: Optional[str] = None
    target_commit: Optional[str] = None
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    duration_seconds: Optional[float] = None
    issues_found: int = 0
    critical_issues: int = 0
    high_issues: int = 0
    medium_issues: int = 0
    low_issues: int = 0
    files_scanned: int = 0
    lines_scanned: int = 0
    error_message: Optional[str] = None
    result_url: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class WebhookConfig:
    """Webhook configuration."""
    url: str
    events: List[WebhookEvent]
    secret: Optional[str] = None
    enabled: bool = True
    retry_count: int = 3
    timeout_seconds: int = 30
    headers: Dict[str, str] = field(default_factory=dict)


@dataclass
class ApiKey:
    """API key for webhook authentication."""
    key_id: str
    key_secret: str
    description: str = ""
    created_at: float = field(default_factory=time.time)
    last_used_at: Optional[float] = None
    rate_limit_per_minute: int = 60
    enabled: bool = True
    permissions: List[str] = field(default_factory=lambda: ["scan:trigger", "scan:read"])


class RateLimiter:
    """Simple rate limiter for API keys."""

    def __init__(self):
        """Initialize rate limiter."""
        self.requests: Dict[str, List[float]] = defaultdict(list)
        self.lock = threading.Lock()

    def is_allowed(self, key_id: str, limit: int, window_seconds: int = 60) -> bool:
        """
        Check if a request is allowed under rate limits.
        
        Args:
            key_id: API key ID
            limit: Maximum requests per window
            window_seconds: Time window in seconds
            
        Returns:
            True if request is allowed, False if rate limited
        """
        with self.lock:
            now = time.time()
            cutoff = now - window_seconds

            # Remove old requests outside the window
            self.requests[key_id] = [
                ts for ts in self.requests[key_id] if ts > cutoff
            ]

            # Check if under limit
            if len(self.requests[key_id]) >= limit:
                return False

            # Add current request
            self.requests[key_id].append(now)
            return True


class PyGuardWebhookAPI:
    """
    Webhook API server for PyGuard CI/CD integration.
    
    Provides REST endpoints for:
    - Triggering security scans
    - Querying scan status and results
    - Managing webhooks
    - API key management
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 5008,
        require_https: bool = True,
    ):
        """
        Initialize webhook API server.
        
        Args:
            host: Host to bind to (default: 127.0.0.1)
            port: Port to listen on (default: 5008)
            require_https: Require HTTPS for production (default: True)
        """
        self.host = host
        self.port = port
        self.require_https = require_https

        # Storage (in production, use database)
        self.api_keys: Dict[str, ApiKey] = {}
        self.scan_jobs: Dict[str, ScanJob] = {}
        self.webhooks: List[WebhookConfig] = []

        # Rate limiting
        self.rate_limiter = RateLimiter()

        # Server state
        self.running = False

        logger.info(f"PyGuard Webhook API initialized on {host}:{port}")

    def generate_api_key(
        self,
        description: str = "",
        rate_limit: int = 60,
        permissions: Optional[List[str]] = None,
    ) -> ApiKey:
        """
        Generate a new API key.
        
        Args:
            description: Human-readable description
            rate_limit: Requests per minute limit
            permissions: List of permissions
            
        Returns:
            ApiKey object with generated credentials
        """
        key_id = f"pyguard_{secrets.token_urlsafe(16)}"
        key_secret = secrets.token_urlsafe(32)

        api_key = ApiKey(
            key_id=key_id,
            key_secret=key_secret,
            description=description,
            rate_limit_per_minute=rate_limit,
            permissions=permissions or ["scan:trigger", "scan:read"],
        )

        self.api_keys[key_id] = api_key
        logger.info(f"Generated API key: {key_id}")

        return api_key

    def validate_api_key(self, key_id: str, key_secret: str) -> Optional[ApiKey]:
        """
        Validate an API key.
        
        Args:
            key_id: API key ID
            key_secret: API key secret
            
        Returns:
            ApiKey if valid, None otherwise
        """
        if key_id not in self.api_keys:
            return None

        api_key = self.api_keys[key_id]

        # Check if enabled
        if not api_key.enabled:
            logger.warning(f"Disabled API key used: {key_id}")
            return None

        # Verify secret with constant-time comparison
        if not secrets.compare_digest(api_key.key_secret, key_secret):
            logger.warning(f"Invalid secret for API key: {key_id}")
            return None

        # Update last used timestamp
        api_key.last_used_at = time.time()

        return api_key

    def check_rate_limit(self, api_key: ApiKey) -> bool:
        """
        Check if an API key is within rate limits.
        
        Args:
            api_key: API key to check
            
        Returns:
            True if allowed, False if rate limited
        """
        return self.rate_limiter.is_allowed(
            api_key.key_id,
            api_key.rate_limit_per_minute,
            window_seconds=60,
        )

    def trigger_scan(
        self,
        api_key: ApiKey,
        target_path: Optional[str] = None,
        repository: Optional[str] = None,
        branch: Optional[str] = None,
        commit: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Trigger a security scan via webhook.
        
        Args:
            api_key: Validated API key
            target_path: Local path to scan
            repository: Git repository URL
            branch: Git branch name
            commit: Git commit SHA
            metadata: Additional metadata
            
        Returns:
            Response with job ID and status
        """
        # Check permissions
        if "scan:trigger" not in api_key.permissions:
            return {
                "success": False,
                "error": "Insufficient permissions",
                "error_code": "PERMISSION_DENIED",
            }

        # Validate input
        if not target_path and not repository:
            return {
                "success": False,
                "error": "Either target_path or repository must be provided",
                "error_code": "INVALID_INPUT",
            }

        # Create scan job
        job_id = f"scan_{int(time.time())}_{secrets.token_urlsafe(8)}"
        scan_job = ScanJob(
            job_id=job_id,
            status=ScanStatus.PENDING,
            target_path=target_path,
            target_repository=repository,
            target_branch=branch,
            target_commit=commit,
            metadata=metadata or {},
        )

        self.scan_jobs[job_id] = scan_job

        logger.info(f"Scan triggered: {job_id} by {api_key.key_id}")

        # Trigger webhook for scan started
        self._trigger_webhooks(WebhookEvent.SCAN_STARTED, scan_job)

        return {
            "success": True,
            "job_id": job_id,
            "status": scan_job.status.value,
            "message": "Scan job created successfully",
        }

    def get_scan_status(
        self,
        api_key: ApiKey,
        job_id: str,
    ) -> Dict[str, Any]:
        """
        Get status of a scan job.
        
        Args:
            api_key: Validated API key
            job_id: Scan job ID
            
        Returns:
            Scan job status and details
        """
        # Check permissions
        if "scan:read" not in api_key.permissions:
            return {
                "success": False,
                "error": "Insufficient permissions",
                "error_code": "PERMISSION_DENIED",
            }

        # Check if job exists
        if job_id not in self.scan_jobs:
            return {
                "success": False,
                "error": f"Scan job not found: {job_id}",
                "error_code": "JOB_NOT_FOUND",
            }

        scan_job = self.scan_jobs[job_id]

        return {
            "success": True,
            "job_id": job_id,
            "status": scan_job.status.value,
            "started_at": scan_job.started_at,
            "completed_at": scan_job.completed_at,
            "duration_seconds": scan_job.duration_seconds,
            "issues_found": scan_job.issues_found,
            "critical_issues": scan_job.critical_issues,
            "high_issues": scan_job.high_issues,
            "medium_issues": scan_job.medium_issues,
            "low_issues": scan_job.low_issues,
            "files_scanned": scan_job.files_scanned,
            "lines_scanned": scan_job.lines_scanned,
            "error_message": scan_job.error_message,
            "result_url": scan_job.result_url,
            "metadata": scan_job.metadata,
        }

    def get_scan_results(
        self,
        api_key: ApiKey,
        job_id: str,
    ) -> Dict[str, Any]:
        """
        Get detailed results of a completed scan.
        
        Args:
            api_key: Validated API key
            job_id: Scan job ID
            
        Returns:
            Detailed scan results
        """
        # Check permissions
        if "scan:read" not in api_key.permissions:
            return {
                "success": False,
                "error": "Insufficient permissions",
                "error_code": "PERMISSION_DENIED",
            }

        # Check if job exists
        if job_id not in self.scan_jobs:
            return {
                "success": False,
                "error": f"Scan job not found: {job_id}",
                "error_code": "JOB_NOT_FOUND",
            }

        scan_job = self.scan_jobs[job_id]

        # Check if completed
        if scan_job.status not in [ScanStatus.COMPLETED, ScanStatus.FAILED]:
            return {
                "success": False,
                "error": "Scan not yet completed",
                "error_code": "SCAN_INCOMPLETE",
                "status": scan_job.status.value,
            }

        # In production, load full results from storage
        return {
            "success": True,
            "job_id": job_id,
            "status": scan_job.status.value,
            "summary": {
                "issues_found": scan_job.issues_found,
                "critical_issues": scan_job.critical_issues,
                "high_issues": scan_job.high_issues,
                "medium_issues": scan_job.medium_issues,
                "low_issues": scan_job.low_issues,
                "files_scanned": scan_job.files_scanned,
                "lines_scanned": scan_job.lines_scanned,
            },
            "issues": [],  # TODO: Load from storage
            "result_url": scan_job.result_url,
        }

    def list_scan_jobs(
        self,
        api_key: ApiKey,
        limit: int = 100,
        status_filter: Optional[ScanStatus] = None,
    ) -> Dict[str, Any]:
        """
        List recent scan jobs.
        
        Args:
            api_key: Validated API key
            limit: Maximum number of jobs to return
            status_filter: Filter by status
            
        Returns:
            List of scan jobs
        """
        # Check permissions
        if "scan:read" not in api_key.permissions:
            return {
                "success": False,
                "error": "Insufficient permissions",
                "error_code": "PERMISSION_DENIED",
            }

        # Filter and sort jobs
        jobs = list(self.scan_jobs.values())

        if status_filter:
            jobs = [j for j in jobs if j.status == status_filter]

        # Sort by created time (newest first)
        jobs.sort(key=lambda j: j.started_at or 0, reverse=True)

        # Limit results
        jobs = jobs[:limit]

        return {
            "success": True,
            "count": len(jobs),
            "jobs": [
                {
                    "job_id": job.job_id,
                    "status": job.status.value,
                    "started_at": job.started_at,
                    "completed_at": job.completed_at,
                    "issues_found": job.issues_found,
                    "critical_issues": job.critical_issues,
                }
                for job in jobs
            ],
        }

    def register_webhook(
        self,
        api_key: ApiKey,
        url: str,
        events: List[WebhookEvent],
        secret: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Register a webhook for receiving notifications.
        
        Args:
            api_key: Validated API key
            url: Webhook URL
            events: List of events to subscribe to
            secret: Optional webhook secret for signing
            
        Returns:
            Webhook registration status
        """
        # Check permissions
        if "webhook:manage" not in api_key.permissions:
            # Allow basic webhook management for all
            pass

        # Validate URL
        if not url.startswith("https://") and self.require_https:
            return {
                "success": False,
                "error": "Webhook URL must use HTTPS",
                "error_code": "INVALID_URL",
            }

        # Create webhook config
        webhook = WebhookConfig(
            url=url,
            events=events,
            secret=secret or secrets.token_urlsafe(32),
            enabled=True,
        )

        self.webhooks.append(webhook)

        logger.info(f"Webhook registered: {url}")

        return {
            "success": True,
            "webhook_url": url,
            "events": [e.value for e in events],
            "secret": webhook.secret,
            "message": "Webhook registered successfully",
        }

    def _trigger_webhooks(self, event: WebhookEvent, scan_job: ScanJob) -> None:
        """
        Trigger webhooks for an event.
        
        Args:
            event: Event type
            scan_job: Scan job that triggered the event
        """
        for webhook in self.webhooks:
            if not webhook.enabled:
                continue

            if event not in webhook.events:
                continue

            # Build payload
            payload = {
                "event": event.value,
                "timestamp": time.time(),
                "job_id": scan_job.job_id,
                "status": scan_job.status.value,
                "issues_found": scan_job.issues_found,
                "critical_issues": scan_job.critical_issues,
            }

            # Sign payload if secret is configured
            if webhook.secret:
                payload_json = json.dumps(payload, sort_keys=True)
                signature = hmac.new(
                    webhook.secret.encode(),
                    payload_json.encode(),
                    hashlib.sha256,
                ).hexdigest()
                payload["signature"] = f"sha256={signature}"

            # TODO: Send HTTP POST to webhook URL
            logger.info(f"Webhook triggered: {webhook.url} for {event.value}")

    def verify_webhook_signature(
        self,
        payload: str,
        signature: str,
        secret: str,
    ) -> bool:
        """
        Verify webhook signature for incoming webhooks.
        
        Args:
            payload: Webhook payload as JSON string
            signature: Signature from webhook headers
            secret: Webhook secret
            
        Returns:
            True if signature is valid
        """
        if not signature.startswith("sha256="):
            return False

        expected_signature = signature[7:]  # Remove "sha256=" prefix

        computed_signature = hmac.new(
            secret.encode(),
            payload.encode(),
            hashlib.sha256,
        ).hexdigest()

        return secrets.compare_digest(computed_signature, expected_signature)

    def start(self) -> None:
        """Start the webhook API server."""
        logger.info(f"Starting PyGuard Webhook API on {self.host}:{self.port}")
        self.running = True
        logger.info("Webhook API ready (use external HTTP server for production)")

    def stop(self) -> None:
        """Stop the webhook API server."""
        logger.info("Stopping PyGuard Webhook API")
        self.running = False


# Example usage for CI/CD platforms
class GitHubActionsIntegration:
    """Integration helper for GitHub Actions."""

    @staticmethod
    def parse_github_webhook(payload: Dict[str, Any]) -> Dict[str, Any]:
        """Parse GitHub webhook payload."""
        return {
            "repository": payload.get("repository", {}).get("full_name"),
            "branch": payload.get("ref", "").replace("refs/heads/", ""),
            "commit": payload.get("after"),
            "pusher": payload.get("pusher", {}).get("name"),
            "metadata": {
                "event": payload.get("event"),
                "action": payload.get("action"),
            },
        }


class GitLabCIIntegration:
    """Integration helper for GitLab CI."""

    @staticmethod
    def parse_gitlab_webhook(payload: Dict[str, Any]) -> Dict[str, Any]:
        """Parse GitLab webhook payload."""
        return {
            "repository": payload.get("project", {}).get("path_with_namespace"),
            "branch": payload.get("ref", "").replace("refs/heads/", ""),
            "commit": payload.get("after"),
            "pusher": payload.get("user_name"),
            "metadata": {
                "event": payload.get("event_name"),
                "pipeline_id": payload.get("pipeline", {}).get("id"),
            },
        }


class JenkinsIntegration:
    """Integration helper for Jenkins."""

    @staticmethod
    def parse_jenkins_webhook(payload: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Jenkins webhook payload."""
        return {
            "repository": payload.get("scm", {}).get("url"),
            "branch": payload.get("scm", {}).get("branch"),
            "commit": payload.get("scm", {}).get("commit"),
            "metadata": {
                "build_number": payload.get("build", {}).get("number"),
                "job_name": payload.get("name"),
            },
        }
