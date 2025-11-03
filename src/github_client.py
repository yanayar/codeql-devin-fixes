"""
GitHub client for fetching CodeQL alerts and creating pull requests.
"""
import logging
import time
from datetime import datetime
from typing import List, Optional, Dict, Any, Callable

import requests
from github import Github, GithubException
from github.PullRequest import PullRequest

from models.alert import CodeQLAlert


logger = logging.getLogger(__name__)


class GitHubClientError(Exception):
    """Custom exception for GitHub client errors with detailed context."""

    def __init__(
        self,
        operation: str,
        message: str,
        status_code: Optional[int] = None,
        endpoint: Optional[str] = None,
        request_id: Optional[str] = None
    ):
        """
        Initialize GitHub client error.

        Args:
            operation: Operation that failed (e.g., "fetch_codeql_alerts")
            message: Error message
            status_code: HTTP status code if applicable
            endpoint: API endpoint that was called
            request_id: GitHub request ID for traceability
        """
        self.operation = operation
        self.message = message
        self.status_code = status_code
        self.endpoint = endpoint
        self.request_id = request_id

        error_parts = [f"{operation} failed: {message}"]
        if status_code:
            error_parts.append(f"Status: {status_code}")
        if endpoint:
            error_parts.append(f"Endpoint: {endpoint}")
        if request_id:
            error_parts.append(f"Request ID: {request_id}")

        super().__init__(" | ".join(error_parts))


class GitHubClient:
    """
    Client for GitHub API operations related to CodeQL alerts and PRs.

    This client handles:
    - Fetching CodeQL security alerts
    - Creating branches for fixes
    - Creating pull requests with fix descriptions
    - Adding comments to PRs
    """

    def __init__(
        self,
        token: str,
        repo_name: str,
        session: Optional[requests.Session] = None,
        logger_instance: Optional[logging.Logger] = None,
        sleep_fn: Callable[[float], None] = time.sleep,
        max_retries: int = 3,
        backoff_base: float = 1.0
    ):
        """
        Initialize GitHub client.

        Args:
            token: GitHub API authentication token
            repo_name: Repository in owner/repo format (e.g., "octocat/hello-world")
            session: Optional requests.Session for testing
            logger_instance: Optional logger for testing
            sleep_fn: Sleep function (for testing without delays)
            max_retries: Maximum number of retries for API calls
            backoff_base: Base delay for exponential backoff (seconds)

        Raises:
            GithubException: If authentication fails or repository not found
        """
        self.token = token
        self.repo_name = repo_name
        self.github = Github(token)
        self.repo = self.github.get_repo(repo_name)
        self.session = session or requests.Session()
        self.logger = logger_instance or logger
        self.sleep_fn = sleep_fn
        self.max_retries = max_retries
        self.backoff_base = backoff_base

        # Parse owner and repo from repo_name
        parts = repo_name.split('/')
        if len(parts) != 2:
            raise ValueError(f"Invalid repo_name format: {repo_name}. Expected 'owner/repo'")
        self.owner, self.repo_short_name = parts

    def _get_headers(self) -> Dict[str, str]:
        """Get headers for GitHub API requests."""
        return {
            'Authorization': f'token {self.token}',
            'Accept': 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28'
        }

    def _code_scanning_base_url(self) -> str:
        """Get base URL for code scanning API."""
        return f"https://api.github.com/repos/{self.owner}/{self.repo_short_name}/code-scanning"

    def _handle_rate_limit(
        self,
        response: requests.Response,
        attempt: int
    ) -> tuple[bool, float]:
        """
        Check if we should retry due to rate limiting.

        Args:
            response: HTTP response
            attempt: Current attempt number

        Returns:
            Tuple of (should_retry, sleep_seconds)
        """
        if response.status_code == 429:
            retry_after = response.headers.get('Retry-After')
            if retry_after:
                sleep_seconds = float(retry_after)
            else:
                sleep_seconds = self.backoff_base * (2 ** attempt)
            return True, sleep_seconds

        if response.status_code == 403:
            remaining = response.headers.get('X-RateLimit-Remaining')
            reset_time = response.headers.get('X-RateLimit-Reset')

            if remaining == '0' or 'rate limit' in response.text.lower():
                if reset_time:
                    sleep_seconds = max(int(reset_time) - time.time(), 0) + 1
                else:
                    sleep_seconds = self.backoff_base * (2 ** attempt)
                return True, sleep_seconds

        return False, 0

    def _request_json(
        self,
        method: str,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None
    ) -> Any:
        """
        Make a JSON API request with retry logic.

        Args:
            method: HTTP method (GET, POST, etc.)
            url: Full URL to request
            params: Query parameters
            json_data: JSON body for POST/PUT requests

        Returns:
            Parsed JSON response

        Raises:
            GitHubClientError: If request fails after retries
        """
        headers = self._get_headers()
        last_exception = None

        for attempt in range(self.max_retries):
            try:
                response = self.session.request(
                    method=method,
                    url=url,
                    headers=headers,
                    params=params,
                    json=json_data,
                    timeout=30
                )

                should_retry, sleep_seconds = self._handle_rate_limit(response, attempt)
                if should_retry:
                    self.logger.warning(
                        f"Rate limited (attempt {attempt + 1}/{self.max_retries}), "
                        f"sleeping {sleep_seconds:.1f}s"
                    )
                    self.sleep_fn(sleep_seconds)
                    continue

                if 400 <= response.status_code < 500:
                    request_id = response.headers.get('X-GitHub-Request-Id')
                    error_msg = response.text[:200] if response.text else "No error message"

                    if response.status_code == 403:
                        error_msg = (
                            "Permission denied. Ensure the token has 'security-events: read' "
                            "permission for code scanning alerts."
                        )

                    raise GitHubClientError(
                        operation="api_request",
                        message=error_msg,
                        status_code=response.status_code,
                        endpoint=url,
                        request_id=request_id
                    )

                if response.status_code >= 500:
                    if attempt < self.max_retries - 1:
                        sleep_seconds = self.backoff_base * (2 ** attempt)
                        self.logger.warning(
                            f"Server error {response.status_code} "
                            f"(attempt {attempt + 1}/{self.max_retries}), "
                            f"retrying in {sleep_seconds:.1f}s"
                        )
                        self.sleep_fn(sleep_seconds)
                        continue
                    else:
                        request_id = response.headers.get('X-GitHub-Request-Id')
                        raise GitHubClientError(
                            operation="api_request",
                            message=f"Server error: {response.text[:200]}",
                            status_code=response.status_code,
                            endpoint=url,
                            request_id=request_id
                        )

                response.raise_for_status()
                return response.json() if response.content else None

            except requests.exceptions.RequestException as e:
                last_exception = e
                if attempt < self.max_retries - 1:
                    sleep_seconds = self.backoff_base * (2 ** attempt)
                    self.logger.warning(
                        f"Network error (attempt {attempt + 1}/{self.max_retries}): {e}, "
                        f"retrying in {sleep_seconds:.1f}s"
                    )
                    self.sleep_fn(sleep_seconds)
                    continue

        raise GitHubClientError(
            operation="api_request",
            message=f"Request failed after {self.max_retries} attempts: {last_exception}",
            endpoint=url
        )

    def _to_alert(self, raw: Dict[str, Any]) -> CodeQLAlert:
        """
        Convert raw GitHub API response to CodeQLAlert.

        Args:
            raw: Raw alert data from GitHub API

        Returns:
            CodeQLAlert object
        """
        severity_mapping = {
            'error': 'medium',
            'warning': 'low',
            'note': 'note'
        }

        severity = (
            raw.get('security_severity_level') or
            raw.get('rule', {}).get('security_severity_level') or
            severity_mapping.get(raw.get('rule', {}).get('severity', '').lower(), 'medium')
        )

        location = raw.get('most_recent_instance', {}).get('location', {})
        file_path = location.get('path', '')
        line_number = location.get('start_line', 0)

        message = (
            raw.get('most_recent_instance', {}).get('message', {}).get('text') or
            raw.get('rule', {}).get('description') or
            ''
        )

        recommendation = raw.get('rule', {}).get('full_description', '')

        created_at_str = raw.get('created_at')
        created_at = None
        if created_at_str:
            try:
                created_at = datetime.fromisoformat(created_at_str.replace('Z', '+00:00'))
            except (ValueError, AttributeError):
                self.logger.warning(f"Could not parse created_at: {created_at_str}")

        return CodeQLAlert(
            alert_id=raw.get('number', 0),
            rule_id=raw.get('rule', {}).get('id') or raw.get('rule', {}).get('rule_id', ''),
            severity=severity.lower() if severity else 'medium',
            file_path=file_path,
            line_number=line_number,
            message=message,
            recommendation=recommendation,
            state=raw.get('state', 'open'),
            created_at=created_at,
            url=raw.get('html_url') or raw.get('url', ''),
            tool=raw.get('tool', {}).get('name', 'CodeQL'),
            raw_data=raw
        )

    def fetch_codeql_alerts(
        self,
        state: str = "open",
        severity: Optional[str] = None
    ) -> List[CodeQLAlert]:
        """
        Fetch CodeQL security alerts from the repository.

        Args:
            state: Alert state to filter by (open, dismissed, fixed)
            severity: Optional severity filter (critical, high, medium, low)

        Returns:
            List of CodeQLAlert objects

        Raises:
            GitHubClientError: If API request fails
        """
        self.logger.info(f"Fetching CodeQL alerts (state={state}, severity={severity})")

        base_url = f"{self._code_scanning_base_url()}/alerts"
        params = {
            'state': state,
            'per_page': 100,
            'page': 1
        }

        if severity:
            params['severity'] = severity

        all_alerts = []

        try:
            while True:
                response_data = self._request_json('GET', base_url, params=params)

                if not response_data:
                    break

                # Convert raw alerts to CodeQLAlert objects
                for raw_alert in response_data:
                    try:
                        alert = self._to_alert(raw_alert)
                        all_alerts.append(alert)
                    except Exception as e:
                        self.logger.warning(
                            f"Failed to parse alert {raw_alert.get('number', 'unknown')}: {e}"
                        )
                        continue

                # Check if there are more pages
                if len(response_data) < 100:
                    break

                params['page'] += 1

            self.logger.info(f"Fetched {len(all_alerts)} alerts")

            severity_counts = {}
            for alert in all_alerts:
                sev = alert.severity
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

            if severity_counts:
                self.logger.info(f"Severity breakdown: {severity_counts}")

            return all_alerts

        except GitHubClientError:
            raise
        except Exception as e:
            raise GitHubClientError(
                operation="fetch_codeql_alerts",
                message=f"Unexpected error: {str(e)}"
            )

    def get_alert_details(self, alert_id: int) -> CodeQLAlert:
        """
        Get detailed information for a specific alert.

        Args:
            alert_id: The alert number/ID

        Returns:
            CodeQLAlert with full details

        Raises:
            GitHubClientError: If alert not found or API request fails
        """
        self.logger.info(f"Fetching details for alert {alert_id}")

        url = f"{self._code_scanning_base_url()}/alerts/{alert_id}"

        try:
            response_data = self._request_json('GET', url)
            alert = self._to_alert(response_data)
            self.logger.info(f"Fetched alert {alert_id}: {alert.rule_id} in {alert.file_path}")
            return alert

        except GitHubClientError:
            raise
        except Exception as e:
            raise GitHubClientError(
                operation="get_alert_details",
                message=f"Unexpected error: {str(e)}"
            )

    def create_branch(
        self,
        branch_name: str,
        base_branch: str = "main"
    ) -> str:
        """
        Create a new branch for fixes.

        Args:
            branch_name: Name for the new branch
            base_branch: Branch to create from (default: main)

        Returns:
            SHA of the branch head

        Raises:
            GitHubClientError: If branch creation fails
        """
        self.logger.info(f"Creating branch '{branch_name}' from '{base_branch}'")

        try:
            base_ref = self.repo.get_git_ref(f"heads/{base_branch}")
            sha = base_ref.object.sha

            # Create the new branch
            self.repo.create_git_ref(ref=f"refs/heads/{branch_name}", sha=sha)

            self.logger.info(f"Created branch '{branch_name}' at {sha[:8]}")
            return sha

        except GithubException as e:
            if e.status == 422:
                raise GitHubClientError(
                    operation="create_branch",
                    message=f"Branch '{branch_name}' already exists or validation failed",
                    status_code=e.status
                )
            raise GitHubClientError(
                operation="create_branch",
                message=f"GitHub API error: {e.data.get('message', str(e))}",
                status_code=e.status
            )
        except Exception as e:
            raise GitHubClientError(
                operation="create_branch",
                message=f"Unexpected error: {str(e)}"
            )

    def create_pull_request(
        self,
        branch: str,
        title: str,
        body: str,
        base_branch: str = "main"
    ) -> PullRequest:
        """
        Create a pull request with security fixes.

        Args:
            branch: Branch containing the fixes
            title: PR title
            body: PR description (should include alert details and fix summary)
            base_branch: Target branch for the PR (default: main)

        Returns:
            PullRequest object

        Raises:
            GitHubClientError: If PR creation fails
        """
        self.logger.info(f"Creating PR from '{branch}' to '{base_branch}': {title}")

        try:
            pr = self.repo.create_pull(
                title=title,
                body=body,
                head=branch,
                base=base_branch
            )

            self.logger.info(f"Created PR #{pr.number}: {pr.html_url}")
            return pr

        except GithubException as e:
            if e.status == 422:
                error_msg = e.data.get('message', str(e))
                if 'pull request already exists' in error_msg.lower():
                    raise GitHubClientError(
                        operation="create_pull_request",
                        message=f"PR already exists for branch '{branch}'",
                        status_code=e.status
                    )
                raise GitHubClientError(
                    operation="create_pull_request",
                    message=f"Validation failed: {error_msg}",
                    status_code=e.status
                )
            raise GitHubClientError(
                operation="create_pull_request",
                message=f"GitHub API error: {e.data.get('message', str(e))}",
                status_code=e.status
            )
        except Exception as e:
            raise GitHubClientError(
                operation="create_pull_request",
                message=f"Unexpected error: {str(e)}"
            )

    def add_pr_comment(self, pr_number: int, comment: str) -> None:
        """
        Add a comment to a pull request.

        Args:
            pr_number: PR number
            comment: Comment text (supports Markdown)

        Raises:
            GitHubClientError: If comment creation fails
        """
        self.logger.info(f"Adding comment to PR #{pr_number}")

        try:
            pr = self.repo.get_pull(pr_number)
            pr.create_issue_comment(comment)
            self.logger.info(f"Added comment to PR #{pr_number}")

        except GithubException as e:
            raise GitHubClientError(
                operation="add_pr_comment",
                message=f"GitHub API error: {e.data.get('message', str(e))}",
                status_code=e.status
            )
        except Exception as e:
            raise GitHubClientError(
                operation="add_pr_comment",
                message=f"Unexpected error: {str(e)}"
            )

    def get_repository_info(self) -> Dict[str, Any]:
        """
        Get repository information.

        Returns:
            Dictionary with repository metadata (name, url, default_branch, etc.)
        """
        return {
            'name': self.repo.name,
            'full_name': self.repo.full_name,
            'url': self.repo.html_url,
            'default_branch': self.repo.default_branch,
            'clone_url': self.repo.clone_url,
        }

    def check_permissions(self) -> Dict[str, bool]:
        """
        Check if the token has required permissions.

        Returns:
            Dictionary with permission flags:
            - can_read_alerts: Can read code scanning alerts
            - can_create_branches: Can create branches
            - can_create_prs: Can create pull requests
        """
        self.logger.info("Checking repository permissions")

        permissions = {
            'can_read_alerts': False,
            'can_create_branches': False,
            'can_create_prs': False
        }

        try:
            if hasattr(self.repo, 'permissions') and self.repo.permissions:
                has_push = self.repo.permissions.push
                permissions['can_create_branches'] = has_push
                permissions['can_create_prs'] = has_push
            else:
                self.logger.warning("Could not determine push permissions")
        except Exception as e:
            self.logger.warning(f"Error checking push permissions: {e}")

        try:
            url = f"{self._code_scanning_base_url()}/alerts"
            params = {'per_page': 1, 'page': 1}
            self._request_json('GET', url, params=params)
            permissions['can_read_alerts'] = True
        except GitHubClientError as e:
            if e.status_code in (403, 404):
                self.logger.warning(
                    f"Cannot read code scanning alerts (status {e.status_code}). "
                    "Ensure token has 'security-events: read' permission."
                )
                permissions['can_read_alerts'] = False
            else:
                self.logger.warning(f"Error checking alert permissions: {e}")
        except Exception as e:
            self.logger.warning(f"Unexpected error checking alert permissions: {e}")

        self.logger.info(f"Permissions: {permissions}")
        return permissions

    def update_file(
        self,
        file_path: str,
        content: str,
        branch: str,
        commit_message: str
    ) -> str:
        """
        Update or create a file in the repository.

        Args:
            file_path: Path to the file in the repository
            content: New content for the file
            branch: Branch to update
            commit_message: Commit message

        Returns:
            SHA of the commit

        Raises:
            GitHubClientError: If file update fails
        """
        self.logger.info(f"Updating file '{file_path}' on branch '{branch}'")

        try:
            try:
                file_obj = self.repo.get_contents(file_path, ref=branch)
                sha = file_obj.sha
            except GithubException as e:
                if e.status == 404:
                    sha = None
                else:
                    raise

            if sha:
                result = self.repo.update_file(
                    path=file_path,
                    message=commit_message,
                    content=content,
                    sha=sha,
                    branch=branch
                )
            else:
                result = self.repo.create_file(
                    path=file_path,
                    message=commit_message,
                    content=content,
                    branch=branch
                )

            commit_sha = result['commit'].sha
            self.logger.info(f"Updated file '{file_path}' with commit {commit_sha[:8]}")
            return commit_sha

        except GithubException as e:
            raise GitHubClientError(
                operation="update_file",
                message=f"GitHub API error: {e.data.get('message', str(e))}",
                status_code=e.status
            )
        except Exception as e:
            raise GitHubClientError(
                operation="update_file",
                message=f"Unexpected error: {str(e)}"
            )

    def apply_diff(
        self,
        diff: str,
        branch: str,
        commit_message: str = "Apply security fixes"
    ) -> List[str]:
        """
        Apply a unified diff to the repository.

        Args:
            diff: Unified diff string
            branch: Branch to apply changes to
            commit_message: Commit message for the changes

        Returns:
            List of commit SHAs created

        Raises:
            GitHubClientError: If applying diff fails

        Note:
            This method parses the unified diff and updates each file individually.
            For complex diffs with multiple files, this may create multiple commits.
        """
        self.logger.info(f"Applying diff to branch '{branch}'")

        try:
            import re
            
            file_diffs = re.split(r'\ndiff --git ', diff)
            if file_diffs[0].startswith('diff --git '):
                file_diffs[0] = file_diffs[0][11:]
            else:
                file_diffs = file_diffs[1:]

            commits = []
            
            for file_diff in file_diffs:
                if not file_diff.strip():
                    continue

                lines = file_diff.split('\n')
                file_path_match = re.match(r'a/(.*?) b/', lines[0])
                if not file_path_match:
                    self.logger.warning(f"Could not parse file path from diff: {lines[0]}")
                    continue

                file_path = file_path_match.group(1)

                try:
                    file_obj = self.repo.get_contents(file_path, ref=branch)
                    current_content = file_obj.decoded_content.decode('utf-8')
                except GithubException as e:
                    if e.status == 404:
                        self.logger.warning(f"File '{file_path}' not found, skipping")
                        continue
                    raise

                new_content = self._apply_patch_to_content(current_content, file_diff)
                
                commit_sha = self.update_file(
                    file_path=file_path,
                    content=new_content,
                    branch=branch,
                    commit_message=f"{commit_message}: {file_path}"
                )
                commits.append(commit_sha)

            self.logger.info(f"Applied diff with {len(commits)} commits")
            return commits

        except GitHubClientError:
            raise
        except Exception as e:
            raise GitHubClientError(
                operation="apply_diff",
                message=f"Unexpected error: {str(e)}"
            )

    def _apply_patch_to_content(self, content: str, patch: str) -> str:
        """
        Apply a patch to file content.

        Args:
            content: Original file content
            patch: Unified diff patch for this file

        Returns:
            Modified content

        Note:
            This is a simplified patch application that handles basic unified diffs.
            For complex patches, consider using a proper patch library.
        """
        import re
        
        lines = content.split('\n')
        patch_lines = patch.split('\n')
        
        result_lines = []
        content_idx = 0
        i = 0
        
        while i < len(patch_lines):
            line = patch_lines[i]
            
            if line.startswith('@@'):
                hunk_match = re.match(r'@@ -(\d+),?(\d*) \+(\d+),?(\d*) @@', line)
                if hunk_match:
                    old_start = int(hunk_match.group(1)) - 1
                    new_start = int(hunk_match.group(3)) - 1
                    
                    while content_idx < old_start and content_idx < len(lines):
                        result_lines.append(lines[content_idx])
                        content_idx += 1
                    
                    i += 1
                    while i < len(patch_lines) and not patch_lines[i].startswith('@@'):
                        pline = patch_lines[i]
                        if pline.startswith('-'):
                            content_idx += 1
                        elif pline.startswith('+'):
                            result_lines.append(pline[1:])
                        elif pline.startswith(' '):
                            result_lines.append(pline[1:])
                            content_idx += 1
                        i += 1
                    continue
            i += 1
        
        while content_idx < len(lines):
            result_lines.append(lines[content_idx])
            content_idx += 1
        
        return '\n'.join(result_lines)
