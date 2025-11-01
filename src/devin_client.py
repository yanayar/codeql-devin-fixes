"""
Devin API client for triggering security fix sessions.

This client handles communication with the Devin API to create sessions,
monitor progress, and retrieve results.
"""
from typing import List, Optional
import requests

from models.alert import CodeQLAlert
from models.session import DevinSession, SessionResult


class DevinClient:
    """
    Client for Devin API operations.

    This client handles:
    - Creating Devin sessions with fix instructions
    - Polling session status
    - Retrieving session results and PR information
    """

    def __init__(self, api_key: str, base_url: str = "https://api.devin.ai/v1"):
        """
        Initialize Devin API client.

        Args:
            api_key: Devin API authentication key
            base_url: Devin API base URL (default: https://api.devin.ai/v1)
        """
        self.api_key = api_key
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json',
        })

    def create_session(
        self,
        repo_url: str,
        alerts: List[CodeQLAlert],
        instructions: Optional[str] = None,
        base_branch: str = "main"
    ) -> DevinSession:
        """
        Create a new Devin session to fix security alerts.

        Args:
            repo_url: URL of the repository to fix
            alerts: List of CodeQL alerts to address
            instructions: Optional custom instructions for Devin
            base_branch: Base branch to work from

        Returns:
            DevinSession object with session_id and initial status

        Raises:
            requests.HTTPError: If API request fails
            ValueError: If alerts list is empty

        Note:
            This will call the Devin API endpoint:
            POST /sessions

            Request body should include:
            - repository_url: URL of the repo
            - task_description: Formatted instructions with alert details
            - alerts: Serialized alert information
            - metadata: Additional context (base_branch, etc.)

            The task_description should be formatted to clearly explain:
            1. The security issues that need fixing
            2. File locations and line numbers
            3. Recommended fixes from CodeQL
            4. Request to create a PR with the fixes
        """
        if not alerts:
            raise ValueError("Cannot create session with empty alerts list")

        raise NotImplementedError("Devin API session creation pending")

    def get_session_status(self, session_id: str) -> DevinSession:
        """
        Get current status of a Devin session.

        Args:
            session_id: The session identifier

        Returns:
            DevinSession with updated status

        Raises:
            requests.HTTPError: If API request fails

        Note:
            This will call the Devin API endpoint:
            GET /sessions/{session_id}

            Response should include:
            - session_id
            - status (pending, in_progress, completed, failed)
            - progress information
            - result (if completed)
        """
        raise NotImplementedError("Devin API status check pending")

    def wait_for_completion(
        self,
        session_id: str,
        timeout: int = 3600,
        poll_interval: int = 30
    ) -> DevinSession:
        """
        Wait for a Devin session to complete.

        Args:
            session_id: The session identifier
            timeout: Maximum time to wait in seconds (default: 1 hour)
            poll_interval: Time between status checks in seconds (default: 30s)

        Returns:
            DevinSession with final status and results

        Raises:
            TimeoutError: If session doesn't complete within timeout
            requests.HTTPError: If API request fails

        Note:
            This method polls the session status at regular intervals until
            the session reaches a terminal state (completed, failed, or timeout).

            Implementation should:
            1. Poll get_session_status() at poll_interval
            2. Check if session is in terminal state
            3. Return when complete or raise TimeoutError
        """
        raise NotImplementedError("Session polling pending")

    def get_session_result(self, session_id: str) -> SessionResult:
        """
        Retrieve the result of a completed session.

        Args:
            session_id: The session identifier

        Returns:
            SessionResult with PR URL, branch name, and fix summary

        Raises:
            requests.HTTPError: If API request fails
            ValueError: If session is not completed

        Note:
            This should extract from the session:
            - PR URL created by Devin
            - Branch name with fixes
            - List of commits made
            - Files that were modified
            - Summary of changes
        """
        raise NotImplementedError("Result retrieval pending")

    def cancel_session(self, session_id: str) -> None:
        """
        Cancel a running Devin session.

        Args:
            session_id: The session identifier

        Raises:
            requests.HTTPError: If API request fails

        Note:
            This will call the Devin API endpoint:
            POST /sessions/{session_id}/cancel
        """
        raise NotImplementedError("Session cancellation pending")

    def _format_task_description(
        self,
        alerts: List[CodeQLAlert],
        base_branch: str
    ) -> str:
        """
        Format a task description for Devin from CodeQL alerts.

        Args:
            alerts: List of alerts to fix
            base_branch: Base branch to work from

        Returns:
            Formatted task description string

        Note:
            The description should be clear and actionable, including:
            - Overview of the security issues
            - Detailed list of each alert with location
            - Recommended fixes
            - Request to create a PR

            Example format:
            '''
            Fix the following CodeQL security issues:

            1. Alert #123: SQL Injection in auth.py:45
               - Issue: User input not sanitized before SQL query
               - Fix: Use parameterized queries

            2. Alert #124: XSS vulnerability in templates/user.html:12
               - Issue: Unescaped user input in template
               - Fix: Use proper HTML escaping

            Please:
            1. Fix all listed security issues
            2. Run tests to ensure fixes don't break functionality
            3. Create a PR with your changes against {base_branch}
            '''
        """
        lines = ["Fix the following CodeQL security issues:\n"]

        for i, alert in enumerate(alerts, 1):
            lines.append(f"{i}. Alert #{alert.alert_id}: {alert.rule_id}")
            lines.append(f"   - Location: {alert.file_path}:{alert.line_number}")
            lines.append(f"   - Severity: {alert.severity}")
            lines.append(f"   - Issue: {alert.message}")
            lines.append(f"   - Recommendation: {alert.recommendation}")
            lines.append("")

        lines.append("Please:")
        lines.append("1. Fix all listed security issues")
        lines.append("2. Run tests to ensure fixes don't break functionality")
        lines.append(f"3. Create a PR with your changes against {base_branch}")

        return "\n".join(lines)
