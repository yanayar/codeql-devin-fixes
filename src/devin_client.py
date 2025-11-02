"""
Devin API client for triggering security fix sessions.

This client handles communication with the Devin API to create sessions,
monitor progress, and retrieve results.
"""
from typing import List, Optional
import requests
import time
import logging
from datetime import datetime

from models.alert import CodeQLAlert
from models.session import DevinSession, SessionResult, SessionStatus

logger = logging.getLogger(__name__)


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

    def _make_request(
        self,
        method: str,
        endpoint: str,
        max_retries: int = 3,
        **kwargs
    ) -> requests.Response:
        """
        Make an API request with retry logic for network errors.

        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint path
            max_retries: Maximum number of retry attempts (default: 3)
            **kwargs: Additional arguments to pass to requests

        Returns:
            Response object

        Raises:
            requests.HTTPError: If request fails after retries
            requests.RequestException: If network error persists after retries
        """
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        last_error = None

        for attempt in range(max_retries):
            try:
                logger.debug(f"Making {method} request to {url} (attempt {attempt + 1}/{max_retries})")
                response = self.session.request(method, url, **kwargs)
                response.raise_for_status()
                return response

            except requests.exceptions.HTTPError as e:
                status_code = e.response.status_code
                logger.warning(f"HTTP error {status_code} on attempt {attempt + 1}/{max_retries}: {e}")

                if status_code >= 500:
                    last_error = e
                    if attempt < max_retries - 1:
                        wait_time = 2 ** attempt
                        logger.info(f"Retrying after {wait_time}s due to server error...")
                        time.sleep(wait_time)
                        continue
                raise

            except requests.exceptions.RequestException as e:
                logger.warning(f"Network error on attempt {attempt + 1}/{max_retries}: {e}")
                last_error = e
                if attempt < max_retries - 1:
                    wait_time = 2 ** attempt
                    logger.info(f"Retrying after {wait_time}s due to network error...")
                    time.sleep(wait_time)
                    continue
                raise

        if last_error:
            raise last_error
        raise requests.RequestException("Request failed after all retries")

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
        """
        if not alerts:
            raise ValueError("Cannot create session with empty alerts list")

        logger.info(f"Creating Devin session for {len(alerts)} alerts in {repo_url}")

        task_description = instructions or self._format_task_description(alerts, base_branch)

        payload = {
            "prompt": task_description,
            "idempotent": False
        }

        try:
            response = self._make_request("POST", "/sessions", json=payload)
            data = response.json()

            session_id = data.get("session_id")
            if not session_id:
                raise ValueError("API response missing session_id")

            logger.info(f"Created Devin session: {session_id}")

            session = DevinSession(
                session_id=session_id,
                status=SessionStatus.PENDING,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
                alerts=alerts,
                repository_url=repo_url,
                instructions=task_description,
                metadata={"base_branch": base_branch}
            )

            return session

        except requests.HTTPError as e:
            error_msg = f"Failed to create Devin session: HTTP {e.response.status_code}"
            try:
                error_detail = e.response.json()
                error_msg += f" - {error_detail}"
            except Exception:
                error_msg += f" - {e.response.text}"
            logger.error(error_msg)
            raise requests.HTTPError(error_msg, response=e.response)

        except Exception as e:
            logger.error(f"Unexpected error creating Devin session: {e}")
            raise

    def get_session_status(self, session_id: str) -> DevinSession:
        """
        Get current status of a Devin session.

        Args:
            session_id: The session identifier

        Returns:
            DevinSession with updated status

        Raises:
            requests.HTTPError: If API request fails
        """
        logger.debug(f"Fetching status for session {session_id}")

        try:
            response = self._make_request("GET", f"/sessions/{session_id}")
            data = response.json()

            status_enum = data.get("status_enum", "working")
            status_map = {
                "working": SessionStatus.IN_PROGRESS,
                "blocked": SessionStatus.IN_PROGRESS,
                "finished": SessionStatus.COMPLETED,
                "expired": SessionStatus.TIMEOUT,
                "suspend_requested": SessionStatus.IN_PROGRESS,
                "suspend_requested_frontend": SessionStatus.IN_PROGRESS,
                "resume_requested": SessionStatus.IN_PROGRESS,
                "resume_requested_frontend": SessionStatus.IN_PROGRESS,
                "resumed": SessionStatus.IN_PROGRESS,
            }
            status = status_map.get(status_enum, SessionStatus.IN_PROGRESS)

            created_at = datetime.fromisoformat(data.get("created_at", datetime.utcnow().isoformat()).replace("+00:00", ""))
            updated_at = datetime.fromisoformat(data.get("updated_at", datetime.utcnow().isoformat()).replace("+00:00", ""))

            result = None
            if status == SessionStatus.COMPLETED:
                pr_data = data.get("pull_request")
                pr_url = pr_data.get("url") if pr_data else None
                result = SessionResult(pr_url=pr_url)

            session = DevinSession(
                session_id=session_id,
                status=status,
                created_at=created_at,
                updated_at=updated_at,
                result=result,
                metadata={"raw_status": status_enum}
            )

            logger.debug(f"Session {session_id} status: {status.value}")
            return session

        except requests.HTTPError as e:
            error_msg = f"Failed to get session status: HTTP {e.response.status_code}"
            try:
                error_detail = e.response.json()
                error_msg += f" - {error_detail}"
            except Exception:
                error_msg += f" - {e.response.text}"
            logger.error(error_msg)
            raise requests.HTTPError(error_msg, response=e.response)

        except Exception as e:
            logger.error(f"Unexpected error getting session status: {e}")
            raise

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
        """
        logger.info(f"Waiting for session {session_id} to complete (timeout: {timeout}s)")
        start_time = time.time()

        while True:
            elapsed = time.time() - start_time
            if elapsed >= timeout:
                error_msg = f"Session {session_id} did not complete within {timeout}s"
                logger.error(error_msg)
                raise TimeoutError(error_msg)

            try:
                session = self.get_session_status(session_id)

                if session.is_terminal():
                    logger.info(f"Session {session_id} reached terminal state: {session.status.value}")
                    return session

                logger.debug(f"Session {session_id} still in progress, waiting {poll_interval}s...")
                time.sleep(poll_interval)

            except requests.HTTPError as e:
                if e.response.status_code == 404:
                    error_msg = f"Session {session_id} not found"
                    logger.error(error_msg)
                    raise ValueError(error_msg)
                raise

            except Exception as e:
                logger.error(f"Error while waiting for session completion: {e}")
                raise

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
        """
        logger.info(f"Retrieving result for session {session_id}")

        try:
            session = self.get_session_status(session_id)

            if not session.is_successful():
                error_msg = f"Session {session_id} is not completed successfully (status: {session.status.value})"
                logger.error(error_msg)
                raise ValueError(error_msg)

            if session.result:
                logger.info(f"Retrieved result for session {session_id}")
                return session.result

            response = self._make_request("GET", f"/sessions/{session_id}")
            data = response.json()

            pr_data = data.get("pull_request")
            pr_url = pr_data.get("url") if pr_data else None

            structured_output = data.get("structured_output", {})

            result = SessionResult(
                pr_url=pr_url,
                branch_name=None,
                commits=[],
                files_modified=[],
                alerts_fixed=0,
                summary=structured_output.get("result") if structured_output else None
            )

            logger.info(f"Retrieved result for session {session_id}: PR={pr_url}")
            return result

        except requests.HTTPError as e:
            error_msg = f"Failed to get session result: HTTP {e.response.status_code}"
            try:
                error_detail = e.response.json()
                error_msg += f" - {error_detail}"
            except Exception:
                error_msg += f" - {e.response.text}"
            logger.error(error_msg)
            raise requests.HTTPError(error_msg, response=e.response)

        except Exception as e:
            logger.error(f"Unexpected error getting session result: {e}")
            raise

    def cancel_session(self, session_id: str) -> None:
        """
        Cancel a running Devin session.

        Args:
            session_id: The session identifier

        Raises:
            requests.HTTPError: If API request fails

        Note:
            The Devin API doesn't have a direct cancel endpoint.
            This method sends a message to the session requesting cancellation.
        """
        logger.info(f"Requesting cancellation for session {session_id}")

        try:
            payload = {
                "message": "Please stop working and cancel this session."
            }
            self._make_request("POST", f"/sessions/{session_id}/messages", json=payload)
            logger.info(f"Cancellation requested for session {session_id}")

        except requests.HTTPError as e:
            error_msg = f"Failed to cancel session: HTTP {e.response.status_code}"
            try:
                error_detail = e.response.json()
                error_msg += f" - {error_detail}"
            except Exception:
                error_msg += f" - {e.response.text}"
            logger.error(error_msg)
            raise requests.HTTPError(error_msg, response=e.response)

        except Exception as e:
            logger.error(f"Unexpected error cancelling session: {e}")
            raise

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
