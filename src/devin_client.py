"""
Devin API client for triggering security fix sessions.

This client handles communication with the Devin API to create sessions,
monitor progress, and retrieve results.
"""
from typing import List, Optional
import requests
import time
import logging
import os
from datetime import datetime
from urllib.parse import urlparse

from models.alert import CodeQLAlert
from models.session import DevinSession, SessionResult, SessionStatus

logger = logging.getLogger(__name__)


class DevinClientError(Exception):
    """Custom exception for Devin client errors with detailed context."""

    def __init__(
        self,
        operation: str,
        message: str,
        status_code: Optional[int] = None,
        endpoint: Optional[str] = None,
        request_id: Optional[str] = None,
        session_id: Optional[str] = None
    ):
        """
        Initialize Devin client error.

        Args:
            operation: Operation that failed (e.g., "create_session")
            message: Error message
            status_code: HTTP status code if applicable
            endpoint: API endpoint that was called
            request_id: Request ID for traceability
            session_id: Session ID if applicable
        """
        self.operation = operation
        self.message = message
        self.status_code = status_code
        self.endpoint = endpoint
        self.request_id = request_id
        self.session_id = session_id

        error_parts = [f"{operation} failed: {message}"]
        if status_code:
            error_parts.append(f"Status: {status_code}")
        if endpoint:
            error_parts.append(f"Endpoint: {endpoint}")
        if request_id:
            error_parts.append(f"Request ID: {request_id}")
        if session_id:
            error_parts.append(f"Session ID: {session_id}")

        super().__init__(" | ".join(error_parts))


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
            DevinClientError: If request fails after retries
        """
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        last_error = None
        
        kwargs.setdefault('timeout', 30)

        for attempt in range(max_retries):
            try:
                logger.debug(f"Making {method} request to {url} (attempt {attempt + 1}/{max_retries})")
                response = self.session.request(method, url, **kwargs)
                
                if 400 <= response.status_code < 500:
                    request_id = response.headers.get('X-Request-ID')
                    error_msg = response.text[:500] if response.text else "No error message"
                    try:
                        error_detail = response.json()
                        if isinstance(error_detail, dict):
                            error_msg = error_detail.get('message', error_msg)
                    except Exception:
                        pass
                    
                    raise DevinClientError(
                        operation="api_request",
                        message=error_msg,
                        status_code=response.status_code,
                        endpoint=url,
                        request_id=request_id
                    )
                
                if response.status_code >= 500:
                    if attempt < max_retries - 1:
                        wait_time = 2 ** attempt
                        logger.warning(
                            f"Server error {response.status_code} "
                            f"(attempt {attempt + 1}/{max_retries}), "
                            f"retrying in {wait_time}s"
                        )
                        time.sleep(wait_time)
                        continue
                    else:
                        request_id = response.headers.get('X-Request-ID')
                        error_msg = response.text[:500] if response.text else "Server error"
                        raise DevinClientError(
                            operation="api_request",
                            message=error_msg,
                            status_code=response.status_code,
                            endpoint=url,
                            request_id=request_id
                        )
                
                response.raise_for_status()
                return response

            except DevinClientError:
                raise

            except requests.exceptions.RequestException as e:
                logger.warning(f"Network error on attempt {attempt + 1}/{max_retries}: {e}")
                last_error = e
                if attempt < max_retries - 1:
                    wait_time = 2 ** attempt
                    logger.info(f"Retrying after {wait_time}s due to network error...")
                    time.sleep(wait_time)
                    continue

        if last_error:
            raise DevinClientError(
                operation="api_request",
                message=f"Request failed after {max_retries} attempts: {last_error}",
                endpoint=url
            )
        raise DevinClientError(
            operation="api_request",
            message="Request failed after all retries",
            endpoint=url
        )

    def create_session(
        self,
        repo_url: str,
        alerts: List[CodeQLAlert],
        instructions: Optional[str] = None,
        base_branch: str = "main",
        branch_name: Optional[str] = None,
        batch_number: Optional[int] = None,
        idempotent: bool = False,
        secret_ids: Optional[List[str]] = None,
        title: Optional[str] = None,
        tags: Optional[List[str]] = None
    ) -> DevinSession:
        """
        Create a new Devin session to fix security alerts.

        Args:
            repo_url: URL of the repository to fix
            alerts: List of CodeQL alerts to address
            instructions: Optional custom instructions for Devin
            base_branch: Base branch to work from
            branch_name: Optional branch name for Devin to commit changes to
            idempotent: Enable idempotent session creation (default: False)
            secret_ids: List of secret IDs to use (None = all secrets, [] = no secrets)
            title: Custom title for the session
            tags: List of tags to add to the session

        Returns:
            DevinSession object with session_id, url, and initial status

        Raises:
            DevinClientError: If API request fails
            ValueError: If alerts list is empty

        Note:
            For private repositories, ensure a GitHub token with repo access
            is configured as a secret in your Devin organization and either
            use all secrets (secret_ids=None) or pass the specific secret ID.
        """
        if not alerts:
            raise ValueError("Cannot create session with empty alerts list")

        logger.info(f"Creating Devin session for {len(alerts)} alerts in {repo_url}")

        task_description = instructions or self._format_task_description(
            repo_url, alerts, base_branch, branch_name, batch_number
        )

        payload = {
            "prompt": task_description,
            "idempotent": idempotent
        }

        if secret_ids is not None:
            payload["secret_ids"] = secret_ids
        
        if title:
            payload["title"] = title
        
        if tags:
            payload["tags"] = tags

        try:
            response = self._make_request("POST", "/sessions", json=payload)
            data = response.json()

            session_id = data.get("session_id")
            session_url = data.get("url")
            
            if not session_id:
                raise DevinClientError(
                    operation="create_session",
                    message="API response missing session_id",
                    endpoint="/sessions"
                )

            logger.info(f"Created Devin session: {session_id}")
            if session_url:
                logger.info(f"Session URL: {session_url}")

            session = DevinSession(
                session_id=session_id,
                status=SessionStatus.PENDING,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
                alerts=alerts,
                repository_url=repo_url,
                instructions=task_description,
                metadata={
                    "base_branch": base_branch,
                    "url": session_url
                }
            )

            return session

        except DevinClientError:
            raise

        except Exception as e:
            logger.error(f"Unexpected error creating Devin session: {e}")
            raise DevinClientError(
                operation="create_session",
                message=f"Unexpected error: {str(e)}",
                endpoint="/sessions"
            )

    def get_session_status(self, session_id: str) -> DevinSession:
        """
        Get current status of a Devin session.

        Args:
            session_id: The session identifier

        Returns:
            DevinSession with updated status

        Raises:
            DevinClientError: If API request fails
        """
        logger.debug(f"Fetching status for session {session_id}")

        try:
            response = self._make_request("GET", f"/sessions/{session_id}")
            data = response.json()

            status_enum = data.get("status_enum") or "working"
            status_map = {
                "working": SessionStatus.IN_PROGRESS,
                "blocked": SessionStatus.IN_PROGRESS,
                "pending": SessionStatus.PENDING,
                "finished": SessionStatus.COMPLETED,
                "expired": SessionStatus.TIMEOUT,
                "timeout": SessionStatus.TIMEOUT,
                "failed": SessionStatus.FAILED,
                "error": SessionStatus.FAILED,
                "cancelled": SessionStatus.FAILED,
                "canceled": SessionStatus.FAILED,
                "suspend_requested": SessionStatus.IN_PROGRESS,
                "suspend_requested_frontend": SessionStatus.IN_PROGRESS,
                "resume_requested": SessionStatus.IN_PROGRESS,
                "resume_requested_frontend": SessionStatus.IN_PROGRESS,
                "resumed": SessionStatus.IN_PROGRESS,
            }
            status = status_map.get(status_enum, SessionStatus.IN_PROGRESS)
            
            if status_enum not in status_map:
                logger.warning(f"Unknown session status_enum '{status_enum}' for session {session_id}, defaulting to IN_PROGRESS")

            created_at = datetime.fromisoformat(data.get("created_at", datetime.utcnow().isoformat()).replace("+00:00", ""))
            updated_at = datetime.fromisoformat(data.get("updated_at", datetime.utcnow().isoformat()).replace("+00:00", ""))

            session_url = data.get("url")
            
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
                metadata={
                    "raw_status": status_enum,
                    "url": session_url
                }
            )

            logger.debug(f"Session {session_id} status: {status.value}")
            return session

        except DevinClientError:
            raise

        except Exception as e:
            logger.error(f"Unexpected error getting session status: {e}")
            raise DevinClientError(
                operation="get_session_status",
                message=f"Unexpected error: {str(e)}",
                session_id=session_id
            )

    def wait_for_completion(
        self,
        session_id: str,
        timeout: int = 3600,
        poll_interval: int = 30,
        initial_delay: int = 30,
        max_polls: int = 500
    ) -> DevinSession:
        """
        Wait for a Devin session to complete.

        Args:
            session_id: The session identifier
            timeout: Maximum time to wait in seconds (default: 1 hour)
            poll_interval: Time between status checks in seconds (default: 30s)
            initial_delay: Seconds to wait before starting polling to allow session initialization (default: 30s)
            max_polls: Maximum number of polls to prevent infinite loops (default: 500)

        Returns:
            DevinSession with final status and results

        Raises:
            TimeoutError: If session doesn't complete within timeout or max_polls
            DevinClientError: If API request fails
        """
        logger.info(f"Waiting for session {session_id} to complete (timeout: {timeout}s, poll_interval: {poll_interval}s, initial_delay: {initial_delay}s, max_polls: {max_polls})")
        
        if initial_delay > 0:
            logger.info(f"Delaying polling start for {initial_delay}s to allow session initialization")
            time.sleep(initial_delay)
            logger.info(f"Starting polling after initial delay of {initial_delay}s")
        
        start_time = time.time()
        poll_count = 0
        blocked_seen = False

        while True:
            elapsed = time.time() - start_time
            if elapsed >= timeout:
                error_msg = f"Session {session_id} did not complete within {timeout}s (after {poll_count} polls)"
                logger.error(error_msg)
                raise TimeoutError(error_msg)
            
            if poll_count >= max_polls:
                error_msg = f"Session {session_id} exceeded maximum polls ({max_polls})"
                logger.error(error_msg)
                raise TimeoutError(error_msg)

            try:
                poll_count += 1
                session = self.get_session_status(session_id)
                
                raw_status = session.metadata.get('raw_status', 'unknown')
                logger.info(
                    f"Poll #{poll_count} for session {session_id}: "
                    f"elapsed={elapsed:.1f}s, "
                    f"status={session.status.value}, "
                    f"raw_status={raw_status}"
                )

                if session.is_terminal():
                    logger.info(f"Session {session_id} reached terminal state: {session.status.value} (after {poll_count} polls)")
                    return session
                
                if raw_status == 'blocked':
                    if blocked_seen:
                        logger.info(f"Session {session_id} is blocked (seen twice); treating as completed for this workflow")
                        session.status = SessionStatus.COMPLETED
                        return session
                    else:
                        logger.info(f"Session {session_id} is blocked (first time); will treat as completed if seen again")
                        blocked_seen = True
                else:
                    blocked_seen = False

                elapsed_after_check = time.time() - start_time
                if elapsed_after_check >= timeout:
                    error_msg = f"Session {session_id} did not complete within {timeout}s (after {poll_count} polls)"
                    logger.error(error_msg)
                    raise TimeoutError(error_msg)
                
                sleep_duration = min(poll_interval, max(0, timeout - elapsed_after_check))
                logger.info(f"Session {session_id} still in progress, sleeping for {sleep_duration:.1f}s...")
                time.sleep(sleep_duration)

            except DevinClientError as e:
                if e.status_code == 404:
                    logger.error(f"Session {session_id} not found (after {poll_count} polls)")
                    raise DevinClientError(
                        operation="wait_for_completion",
                        message=f"Session not found",
                        status_code=404,
                        session_id=session_id
                    )
                raise

            except Exception as e:
                logger.error(f"Error while waiting for session completion (after {poll_count} polls): {e}")
                raise DevinClientError(
                    operation="wait_for_completion",
                    message=f"Unexpected error: {str(e)}",
                    session_id=session_id
                )

    def _parse_devin_output(self, text: str) -> Dict[str, Any]:
        """
        Parse Devin's output text to extract JSON summary and unified diff.
        
        Args:
            text: Raw text output from Devin
            
        Returns:
            Dictionary with parsed 'json_data' and 'diff' keys
            
        Raises:
            ValueError: If parsing fails
        """
        import json
        import re
        
        result = {'json_data': None, 'diff': None}
        
        text_lower = text.lower()
        json_summary_idx = text_lower.find('json summary')
        unified_diff_idx = text_lower.find('unified diff')
        
        if json_summary_idx == -1:
            logger.warning("Could not find 'JSON Summary' header in output")
            return result
        
        json_start = json_summary_idx + len('json summary')
        json_end = unified_diff_idx if unified_diff_idx != -1 else len(text)
        json_section = text[json_start:json_end].strip()
        
        json_section = json_section.strip('`').strip()
        
        brace_start = json_section.find('{')
        brace_end = json_section.rfind('}')
        
        if brace_start != -1 and brace_end != -1:
            json_str = json_section[brace_start:brace_end + 1]
            try:
                result['json_data'] = json.loads(json_str)
                logger.info(f"Successfully parsed JSON summary: {list(result['json_data'].keys())}")
            except json.JSONDecodeError as e:
                logger.warning(f"Failed to parse JSON: {e}")
                logger.debug(f"JSON string attempted: {json_str[:200]}")
        
        if unified_diff_idx != -1:
            diff_start = unified_diff_idx + len('unified diff')
            diff_section = text[diff_start:].strip()
            
            diff_section = diff_section.strip('`').strip()
            
            diff_match = re.search(r'^diff --git', diff_section, re.MULTILINE)
            if diff_match:
                result['diff'] = diff_section[diff_match.start():]
                logger.info(f"Successfully extracted diff: {len(result['diff'])} characters")
            else:
                logger.warning("Could not find 'diff --git' in Unified Diff section")
        
        return result

    def get_session_result(self, session_id: str) -> SessionResult:
        """
        Retrieve the result of a completed session.

        Args:
            session_id: The session identifier

        Returns:
            SessionResult with PR URL, branch name, and fix summary

        Raises:
            DevinClientError: If API request fails or session is not completed
        """
        logger.info(f"Retrieving result for session {session_id}")

        try:
            session = self.get_session_status(session_id)
            raw_status = session.metadata.get('raw_status', 'unknown')

            if not session.is_successful() and raw_status != 'blocked':
                error_msg = f"Session is not completed successfully (status: {session.status.value}, raw_status: {raw_status})"
                logger.error(error_msg)
                raise DevinClientError(
                    operation="get_session_result",
                    message=error_msg,
                    session_id=session_id
                )
            
            if raw_status == 'blocked':
                logger.info(f"Session {session_id} is blocked; treating as completed for automation workflow")

            if session.result:
                logger.info(f"Retrieved result for session {session_id}")
                return session.result

            response = self._make_request("GET", f"/sessions/{session_id}")
            data = response.json()

            pr_data = data.get("pull_request")
            pr_url = pr_data.get("url") if pr_data else None

            structured_output = data.get("structured_output", {})

            branch_name = structured_output.get("branch_name") if structured_output else None
            files_modified = structured_output.get("files_modified", []) if structured_output else []
            diff = structured_output.get("diff") if structured_output else None
            commit_messages = structured_output.get("commit_messages", []) if structured_output else []
            summary = structured_output.get("result") if structured_output else None

            if not diff or not branch_name:
                logger.info(f"structured_output missing diff or branch_name, attempting fallback parsing")
                logger.debug(f"Available response keys: {list(data.keys())}")
                
                raw_text = None
                for key in ['output', 'result', 'text', 'content', 'message', 'transcript']:
                    if key in data and data[key]:
                        raw_text = data[key]
                        logger.info(f"Found raw text in field '{key}'")
                        break
                
                if raw_text:
                    parsed = self._parse_devin_output(raw_text)
                    
                    if parsed['json_data']:
                        branch_name = branch_name or parsed['json_data'].get('branch_name')
                        files_modified = files_modified or parsed['json_data'].get('files_modified', [])
                        commit_messages = commit_messages or parsed['json_data'].get('commit_messages', [])
                        logger.info(f"Extracted from fallback parser: branch={branch_name}, files={len(files_modified)}")
                    
                    if parsed['diff']:
                        diff = diff or parsed['diff']
                        logger.info(f"Extracted diff from fallback parser: {len(diff)} characters")
                else:
                    logger.warning(f"Could not find raw text output in response for fallback parsing")

            result = SessionResult(
                pr_url=pr_url,
                branch_name=branch_name,
                commits=[],
                files_modified=files_modified,
                alerts_fixed=len(files_modified) if files_modified else 0,
                summary=summary,
                diff=diff,
                commit_messages=commit_messages
            )

            if raw_status == 'blocked' and not pr_url and not structured_output and not diff:
                logger.warning(f"Session {session_id} is blocked but has no pull_request, structured_output, or diff data")
                raise DevinClientError(
                    operation="get_session_result",
                    message=f"Session is blocked but no usable result data available (no PR, structured output, or diff)",
                    session_id=session_id
                )

            logger.info(f"Retrieved result for session {session_id}: branch={branch_name}, files={len(files_modified)}, pr_url={pr_url}, diff_len={len(diff) if diff else 0}")
            return result

        except DevinClientError:
            raise

        except Exception as e:
            logger.error(f"Unexpected error getting session result: {e}")
            raise DevinClientError(
                operation="get_session_result",
                message=f"Unexpected error: {str(e)}",
                session_id=session_id
            )

    def request_cancellation(self, session_id: str) -> bool:
        """
        Request cancellation of a running Devin session.

        Args:
            session_id: The session identifier

        Returns:
            True if cancellation request was sent successfully

        Raises:
            DevinClientError: If API request fails

        Note:
            This is a best-effort request. The Devin API doesn't have a direct
            cancel endpoint, so this method sends a message to the session
            requesting cancellation. Devin may not immediately stop work, and
            the session may continue until it reaches a natural stopping point.
        """
        logger.info(f"Requesting cancellation for session {session_id}")

        try:
            payload = {
                "message": "Please stop working and cancel this session."
            }
            self._make_request("POST", f"/sessions/{session_id}/message", json=payload)
            logger.info(f"Cancellation requested for session {session_id}")
            return True

        except DevinClientError as e:
            logger.error(f"Failed to request cancellation for session {session_id}: {e}")
            raise DevinClientError(
                operation="request_cancellation",
                message=e.message,
                status_code=e.status_code,
                endpoint=e.endpoint,
                request_id=e.request_id,
                session_id=session_id
            )

        except Exception as e:
            logger.error(f"Unexpected error requesting cancellation for session {session_id}: {e}")
            raise DevinClientError(
                operation="request_cancellation",
                message=f"Unexpected error: {str(e)}",
                session_id=session_id
            )

    def _format_task_description(
        self,
        repo_url: str,
        alerts: List[CodeQLAlert],
        base_branch: str,
        branch_name: Optional[str] = None,
        batch_number: Optional[int] = None
    ) -> str:
        """
        Format a task description for Devin from CodeQL alerts.

        Args:
            repo_url: URL of the repository to fix
            alerts: List of alerts to fix
            base_branch: Base branch to work from
            branch_name: Optional branch name pattern for Devin to use
            batch_number: Optional batch number for branch naming

        Returns:
            Formatted task description string
        """
        lines = [
            f"Repository: {repo_url}",
            f"Base branch: {base_branch}",
            "",
            "Fix the following CodeQL security issues:",
            ""
        ]

        for i, alert in enumerate(alerts, 1):
            lines.append(f"{i}. Alert #{alert.alert_id}: {alert.rule_id}")
            lines.append(f"   - Location: {alert.file_path}:{alert.line_number}")
            lines.append(f"   - Severity: {alert.severity}")
            lines.append(f"   - Issue: {alert.message}")
            if alert.recommendation:
                lines.append(f"   - Recommendation: {alert.recommendation}")
            lines.append("")

        lines.append("Please:")
        lines.append("1. Clone the repository and checkout the base branch")
        lines.append("2. Fix all listed security issues")
        lines.append("3. Run tests to ensure fixes don't break functionality")
        
        if branch_name:
            lines.append("4. Create a new branch, commit your changes, and push the branch to origin")
            lines.append("")
            lines.append("BRANCH NAMING:")
            if batch_number is not None:
                lines.append(f"- Branch name format: devin-fixes-{{session_id}}-batch-{batch_number}")
                lines.append("- Use THIS session's ID from the session URL (if it starts with 'devin-', drop that prefix)")
                lines.append(f"- Example: if session ID is 'devin-abc123', use branch name 'devin-fixes-abc123-batch-{batch_number}'")
            else:
                lines.append(f"- Use branch name: {branch_name}")
            lines.append("")
            lines.append("IMPORTANT CONSTRAINTS:")
            lines.append("- Do NOT create or open a pull request")
            lines.append("- DO push the branch to origin after committing")
            lines.append("- The GitHub Client will handle PR creation")
            lines.append("")
            lines.append("OUTPUT REQUIREMENTS:")
            lines.append("Output EXACTLY the following two sections in plain text (NO markdown code blocks, NO backticks):")
            lines.append("")
            lines.append("JSON Summary")
            lines.append("{")
            if batch_number is not None:
                lines.append(f'  "branch_name": "devin-fixes-{{session_id}}-batch-{batch_number}",')
            else:
                lines.append(f'  "branch_name": "{branch_name}",')
            lines.append('  "files_modified": ["file1.py", "file2.py"],')
            lines.append('  "commit_messages": ["commit message 1", "commit message 2"]')
            lines.append("}")
            lines.append("")
            lines.append("Unified Diff")
            lines.append("diff --git a/file1.py b/file1.py")
            lines.append("index abc123..def456 100644")
            lines.append("--- a/file1.py")
            lines.append("+++ b/file1.py")
            lines.append("[actual diff content here]")
            lines.append("")
            lines.append("CRITICAL: Do NOT wrap the output in markdown code blocks. Output plain text only.")
            lines.append("STOP after outputting the JSON Summary and Unified Diff sections. Do not perform any other actions.")
        else:
            lines.append(f"4. Create a PR with your changes against {base_branch}")

        return "\n".join(lines)
    
    def _get_app_base_url(self) -> str:
        """
        Derive the Devin app base URL from the API base URL.
        
        Returns:
            Base URL for the Devin web app
            
        Note:
            This method attempts to derive the app URL by:
            1. Using DEVIN_APP_BASE_URL env var if set
            2. Replacing "api." with "app." in the API base URL
            3. Falling back to https://app.devin.ai as default
        """
        env_app_url = os.environ.get('DEVIN_APP_BASE_URL')
        if env_app_url:
            return env_app_url.rstrip('/')
        
        try:
            parsed = urlparse(self.base_url)
            if 'api.' in parsed.netloc:
                app_netloc = parsed.netloc.replace('api.', 'app.')
                return f"{parsed.scheme}://{app_netloc}"
        except Exception as e:
            logger.debug(f"Could not derive app URL from base_url: {e}")
        
        return "https://app.devin.ai"
    
    def get_session_url(self, session_id: str) -> str:
        """
        Get the web URL to view a session in the Devin UI.

        Args:
            session_id: The session identifier

        Returns:
            URL to view the session in the Devin web interface

        Note:
            This method first attempts to retrieve the URL from the session
            metadata (if it was captured during session creation). If not
            available, it constructs the URL from the session_id using the
            pattern: {app_base_url}/sessions/{session_id}
            
            The app base URL is derived from the API base URL by replacing
            "api." with "app.", or can be overridden with the
            DEVIN_APP_BASE_URL environment variable.
            
            The method normalizes URLs by removing the 'devin-' prefix from
            session IDs in the path, as the API sometimes returns session IDs
            with this prefix but the correct URL format doesn't include it.
        """
        try:
            session = self.get_session_status(session_id)
            stored_url = session.metadata.get('url')
            if stored_url:
                normalized_url = stored_url.replace('/sessions/devin-', '/sessions/')
                return normalized_url
        except Exception as e:
            logger.debug(f"Could not retrieve stored URL for session {session_id}: {e}")
        
        normalized_session_id = session_id
        if session_id.startswith('devin-'):
            normalized_session_id = session_id[6:]  # Remove 'devin-' prefix
        
        app_base = self._get_app_base_url()
        constructed_url = f"{app_base}/sessions/{normalized_session_id}"
        logger.debug(f"Constructed session URL: {constructed_url}")
        return constructed_url
