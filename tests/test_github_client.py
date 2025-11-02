"""
Comprehensive test suite for GitHubClient.

Tests cover:
- Request retry logic and rate limiting
- Alert fetching and parsing
- Permission checking
- Repository operations (branches, PRs, comments)
- Error handling and edge cases
"""
import sys
import os
from datetime import datetime
from unittest.mock import Mock, MagicMock

import pytest
import requests

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

import github_client
from github_client import GitHubClient, GitHubClientError
from models.alert import CodeQLAlert



class FakeResponse:
    """Fake requests.Response for testing."""
    
    def __init__(self, status_code, json_data=None, text="", headers=None, content=None):
        self.status_code = status_code
        self._json_data = json_data
        self.text = text
        self.headers = headers or {}
        self.content = content if content is not None else text.encode('utf-8')
    
    def json(self):
        if self._json_data is None:
            raise ValueError("No JSON data")
        return self._json_data
    
    def raise_for_status(self):
        if 400 <= self.status_code < 600:
            raise requests.HTTPError(f"HTTP {self.status_code}")


class FakeSession:
    """Fake requests.Session for testing."""
    
    def __init__(self, responses=None):
        self.responses = responses or []
        self.call_count = 0
        self.requests = []
    
    def request(self, method, url, headers=None, params=None, json=None, timeout=None):
        self.requests.append({
            'method': method,
            'url': url,
            'headers': headers,
            'params': params,
            'json': json,
            'timeout': timeout
        })
        
        if self.call_count < len(self.responses):
            response = self.responses[self.call_count]
            self.call_count += 1
            return response
        
        return FakeResponse(200, json_data={})


class FakeGithubException(Exception):
    """Fake GithubException for testing."""
    
    def __init__(self, status, data=None):
        self.status = status
        self.data = data or {}
        super().__init__(f"GitHub API error: {status}")


class FakeObj:
    """Fake git object with SHA."""
    
    def __init__(self, sha):
        self.sha = sha


class FakeRef:
    """Fake git reference."""
    
    def __init__(self, sha="abc123def456"):
        self.object = FakeObj(sha)


class FakePerms:
    """Fake repository permissions."""
    
    def __init__(self, push=True):
        self.push = push


class FakePR:
    """Fake pull request."""
    
    def __init__(self, number=1, html_url="https://github.com/owner/repo/pull/1"):
        self.number = number
        self.html_url = html_url


class FakePull:
    """Fake pull request for comments."""
    
    def __init__(self):
        self.comments = []
    
    def create_issue_comment(self, comment):
        self.comments.append(comment)


class FakeRepo:
    """Fake GitHub repository."""
    
    def __init__(self, name="repo", full_name="owner/repo", 
                 default_branch="main", has_permissions=True, push_permission=True):
        self.name = name
        self.full_name = full_name
        self.html_url = f"https://github.com/{full_name}"
        self.default_branch = default_branch
        self.clone_url = f"https://github.com/{full_name}.git"
        self.permissions = FakePerms(push=push_permission) if has_permissions else None
        self._refs = {}
        self._prs = {}
        self._pulls = {}
    
    def get_git_ref(self, ref):
        if ref in self._refs:
            return self._refs[ref]
        return FakeRef()
    
    def create_git_ref(self, ref, sha):
        self._refs[ref] = FakeRef(sha)
    
    def create_pull(self, title, body, head, base):
        pr = FakePR()
        self._prs[head] = pr
        return pr
    
    def get_pull(self, pr_number):
        if pr_number in self._pulls:
            return self._pulls[pr_number]
        pull = FakePull()
        self._pulls[pr_number] = pull
        return pull


class FakeGithub:
    """Fake PyGithub Github client."""
    
    def __init__(self, token):
        self.token = token
        self._repos = {}
    
    def get_repo(self, repo_name):
        if repo_name in self._repos:
            return self._repos[repo_name]
        return FakeRepo(full_name=repo_name)



@pytest.fixture
def monkeypatch_github(monkeypatch):
    """Monkeypatch PyGithub classes in the github_client module."""
    monkeypatch.setattr(github_client, "Github", FakeGithub)
    monkeypatch.setattr(github_client, "GithubException", FakeGithubException)


@pytest.fixture
def fake_session():
    """Create a fake session for testing."""
    return FakeSession()


@pytest.fixture
def sleep_tracker():
    """Track sleep calls for backoff testing."""
    sleeps = []
    return sleeps, lambda seconds: sleeps.append(seconds)



class TestRequestJsonAndRateLimit:
    """Tests for _request_json and _handle_rate_limit methods."""
    
    def test_handle_rate_limit_429_uses_retry_after(self, monkeypatch_github, sleep_tracker):
        """
        Validates: 429 status code returns should_retry=True and uses sleep 
        duration from Retry-After header.
        """
        sleeps, sleep_fn = sleep_tracker
        session = FakeSession()
        client = GitHubClient("token", "owner/repo", session=session, sleep_fn=sleep_fn)
        
        response = FakeResponse(429, headers={'Retry-After': '60'})
        should_retry, sleep_seconds = client._handle_rate_limit(response, attempt=0)
        
        assert should_retry is True
        assert sleep_seconds == 60.0
    
    def test_handle_rate_limit_403_with_remaining_zero_and_reset_time(
        self, monkeypatch_github, sleep_tracker
    ):
        """
        Validates: 403 with X-RateLimit-Remaining="0" returns should_retry=True 
        and calculates sleep from X-RateLimit-Reset timestamp.
        """
        import time
        sleeps, sleep_fn = sleep_tracker
        session = FakeSession()
        client = GitHubClient("token", "owner/repo", session=session, sleep_fn=sleep_fn)
        
        reset_time = int(time.time()) + 120
        response = FakeResponse(
            403, 
            headers={
                'X-RateLimit-Remaining': '0',
                'X-RateLimit-Reset': str(reset_time)
            }
        )
        should_retry, sleep_seconds = client._handle_rate_limit(response, attempt=0)
        
        assert should_retry is True
        assert sleep_seconds >= 120  # At least 120 seconds
    
    def test_handle_rate_limit_403_with_rate_limit_text_no_reset(
        self, monkeypatch_github, sleep_tracker
    ):
        """
        Validates: 403 with "rate limit" in response body but no reset header 
        falls back to exponential backoff.
        """
        sleeps, sleep_fn = sleep_tracker
        session = FakeSession()
        client = GitHubClient("token", "owner/repo", session=session, sleep_fn=sleep_fn)
        
        response = FakeResponse(403, text="API rate limit exceeded")
        should_retry, sleep_seconds = client._handle_rate_limit(response, attempt=1)
        
        assert should_retry is True
        assert sleep_seconds == 2.0  # backoff_base * (2 ** attempt) = 1.0 * 2^1
    
    def test_request_json_retries_on_5xx_then_raises(
        self, monkeypatch_github, sleep_tracker
    ):
        """
        Validates: Server errors (5xx) trigger retry logic with exponential backoff,
        and GitHubClientError is raised after max_retries attempts.
        """
        sleeps, sleep_fn = sleep_tracker
        
        responses = [
            FakeResponse(500, text="Internal Server Error"),
            FakeResponse(500, text="Internal Server Error"),
            FakeResponse(500, text="Internal Server Error"),
        ]
        session = FakeSession(responses=responses)
        
        client = GitHubClient(
            "token", "owner/repo", 
            session=session, 
            sleep_fn=sleep_fn,
            max_retries=3
        )
        
        with pytest.raises(GitHubClientError) as exc_info:
            client._request_json('GET', 'https://api.github.com/test')
        
        assert "Server error" in str(exc_info.value)
        assert len(sleeps) == 2  # Sleeps before retry 2 and 3
        assert sleeps == [1.0, 2.0]  # Exponential backoff
    
    def test_request_json_retries_on_network_errors_then_raises(
        self, monkeypatch_github, sleep_tracker
    ):
        """
        Validates: RequestException triggers retry logic and raises 
        GitHubClientError after max_retries attempts.
        """
        sleeps, sleep_fn = sleep_tracker
        session = Mock()
        
        session.request.side_effect = requests.exceptions.ConnectionError("Network error")
        
        client = GitHubClient(
            "token", "owner/repo", 
            session=session, 
            sleep_fn=sleep_fn,
            max_retries=3
        )
        
        with pytest.raises(GitHubClientError) as exc_info:
            client._request_json('GET', 'https://api.github.com/test')
        
        assert "failed after 3 attempts" in str(exc_info.value)
        assert len(sleeps) == 2  # Sleeps before retry 2 and 3
    
    def test_request_json_4xx_maps_to_client_error_and_does_not_retry(
        self, monkeypatch_github, sleep_tracker
    ):
        """
        Validates: 4xx errors immediately raise GitHubClientError without retry.
        403 errors include specific permission message.
        """
        sleeps, sleep_fn = sleep_tracker
        
        responses = [FakeResponse(403, text="Forbidden")]
        session = FakeSession(responses=responses)
        
        client = GitHubClient(
            "token", "owner/repo", 
            session=session, 
            sleep_fn=sleep_fn
        )
        
        with pytest.raises(GitHubClientError) as exc_info:
            client._request_json('GET', 'https://api.github.com/test')
        
        assert "Permission denied" in str(exc_info.value)
        assert "security-events: read" in str(exc_info.value)
        assert len(sleeps) == 0  # No retries for 4xx



class TestAlertFetchingAndParsing:
    """Tests for alert fetching and parsing methods."""
    
    def test_fetch_codeql_alerts_paginates_and_parses(
        self, monkeypatch_github, sleep_tracker
    ):
        """
        Validates: fetch_codeql_alerts accumulates alerts across multiple pages,
        stops when response has <100 items, and converts to CodeQLAlert objects.
        """
        sleeps, sleep_fn = sleep_tracker
        
        page1_alerts = [
            {
                'number': i,
                'rule': {'id': f'rule-{i}', 'severity': 'error'},
                'state': 'open',
                'most_recent_instance': {
                    'location': {'path': f'file{i}.py', 'start_line': i},
                    'message': {'text': f'Alert {i}'}
                }
            }
            for i in range(100)
        ]
        
        page2_alerts = [
            {
                'number': i,
                'rule': {'id': f'rule-{i}', 'severity': 'warning'},
                'state': 'open',
                'most_recent_instance': {
                    'location': {'path': f'file{i}.py', 'start_line': i},
                    'message': {'text': f'Alert {i}'}
                }
            }
            for i in range(100, 150)
        ]
        
        responses = [
            FakeResponse(200, json_data=page1_alerts, content=b'[...]'),
            FakeResponse(200, json_data=page2_alerts, content=b'[...]'),
        ]
        session = FakeSession(responses=responses)
        
        client = GitHubClient(
            "token", "owner/repo", 
            session=session, 
            sleep_fn=sleep_fn
        )
        
        alerts = client.fetch_codeql_alerts(state="open")
        
        assert len(alerts) == 150
        assert all(isinstance(alert, CodeQLAlert) for alert in alerts)
        assert session.call_count == 2
    
    def test_fetch_codeql_alerts_applies_severity_filter(
        self, monkeypatch_github, sleep_tracker
    ):
        """
        Validates: severity parameter is passed to the API request.
        """
        sleeps, sleep_fn = sleep_tracker
        
        responses = [FakeResponse(200, json_data=[])]
        session = FakeSession(responses=responses)
        
        client = GitHubClient(
            "token", "owner/repo", 
            session=session, 
            sleep_fn=sleep_fn
        )
        
        client.fetch_codeql_alerts(state="open", severity="high")
        
        assert session.requests[0]['params']['severity'] == 'high'
    
    def test_fetch_codeql_alerts_handles_bad_alert_item_gracefully(
        self, monkeypatch_github, sleep_tracker
    ):
        """
        Validates: Malformed alert items are parsed with default values;
        processing continues without crashing even with missing fields.
        """
        sleeps, sleep_fn = sleep_tracker
        
        alerts_data = [
            {
                'number': 1,
                'rule': {'id': 'rule-1', 'severity': 'error'},
                'state': 'open',
                'most_recent_instance': {
                    'location': {'path': 'file1.py', 'start_line': 10},
                    'message': {'text': 'Alert 1'}
                }
            },
            {'number': 2},  # Minimal alert with missing fields
            {
                'number': 3,
                'rule': {'id': 'rule-3', 'severity': 'warning'},
                'state': 'open',
                'most_recent_instance': {
                    'location': {'path': 'file3.py', 'start_line': 30},
                    'message': {'text': 'Alert 3'}
                }
            },
        ]
        
        responses = [FakeResponse(200, json_data=alerts_data, content=b'[...]')]
        session = FakeSession(responses=responses)
        
        client = GitHubClient(
            "token", "owner/repo", 
            session=session, 
            sleep_fn=sleep_fn
        )
        
        alerts = client.fetch_codeql_alerts(state="open")
        
        assert len(alerts) == 3
        assert alerts[0].alert_id == 1
        assert alerts[1].alert_id == 2  # Malformed alert still parsed
        assert alerts[1].file_path == ''  # Has default/empty values
        assert alerts[2].alert_id == 3
    
    def test_get_alert_details_success(self, monkeypatch_github, sleep_tracker):
        """
        Validates: get_alert_details retrieves a single alert and converts 
        it via _to_alert.
        """
        sleeps, sleep_fn = sleep_tracker
        
        alert_data = {
            'number': 42,
            'rule': {'id': 'cpp/tainted-format-string', 'severity': 'error'},
            'state': 'open',
            'most_recent_instance': {
                'location': {'path': 'src/main.cpp', 'start_line': 100},
                'message': {'text': 'Tainted format string'}
            }
        }
        
        responses = [FakeResponse(200, json_data=alert_data, content=b'{}')]
        session = FakeSession(responses=responses)
        
        client = GitHubClient(
            "token", "owner/repo", 
            session=session, 
            sleep_fn=sleep_fn
        )
        
        alert = client.get_alert_details(42)
        
        assert isinstance(alert, CodeQLAlert)
        assert alert.alert_id == 42
        assert alert.rule_id == 'cpp/tainted-format-string'
        assert alert.file_path == 'src/main.cpp'
    
    def test_to_alert_severity_and_dates_mapped(self, monkeypatch_github):
        """
        Validates: _to_alert correctly normalizes severity from various fields
        and parses created_at dates (or returns None on parse failure).
        """
        session = FakeSession()
        client = GitHubClient("token", "owner/repo", session=session)
        
        raw_alert = {
            'number': 1,
            'rule': {'id': 'test-rule', 'severity': 'error'},
            'state': 'open',
            'most_recent_instance': {
                'location': {'path': 'test.py', 'start_line': 1},
                'message': {'text': 'Test'}
            },
            'created_at': '2024-01-15T10:30:00Z'
        }
        
        alert = client._to_alert(raw_alert)
        
        assert alert.severity == 'medium'  # 'error' maps to 'medium'
        assert alert.created_at is not None
        assert isinstance(alert.created_at, datetime)
        
        raw_alert['created_at'] = 'invalid-date'
        alert = client._to_alert(raw_alert)
        assert alert.created_at is None



class TestPermissions:
    """Tests for permission checking."""
    
    def test_check_permissions_push_permissions_true(self, monkeypatch):
        """
        Validates: can_create_branches and can_create_prs are True when 
        repo.permissions.push is True.
        """
        monkeypatch.setattr(github_client, "Github", FakeGithub)
        monkeypatch.setattr(github_client, "GithubException", FakeGithubException)
        
        session = FakeSession(responses=[
            FakeResponse(200, json_data=[], content=b'[]')  # For alerts check
        ])
        
        fake_github = FakeGithub("token")
        fake_repo = FakeRepo(push_permission=True)
        fake_github._repos["owner/repo"] = fake_repo
        
        monkeypatch.setattr(github_client, "Github", lambda token: fake_github)
        
        client = GitHubClient("token", "owner/repo", session=session)
        permissions = client.check_permissions()
        
        assert permissions['can_create_branches'] is True
        assert permissions['can_create_prs'] is True
        assert permissions['can_read_alerts'] is True
    
    def test_check_permissions_cannot_read_alerts_on_403(self, monkeypatch_github):
        """
        Validates: can_read_alerts is False when GET alerts returns 403,
        and a warning is logged.
        """
        session = FakeSession(responses=[
            FakeResponse(403, text="Forbidden")  # For alerts check
        ])
        
        client = GitHubClient("token", "owner/repo", session=session)
        permissions = client.check_permissions()
        
        assert permissions['can_read_alerts'] is False
    
    def test_check_permissions_missing_permissions_attribute(self, monkeypatch):
        """
        Validates: When repo.permissions is None/missing, push permission flags 
        remain False and a warning is logged.
        """
        monkeypatch.setattr(github_client, "Github", FakeGithub)
        monkeypatch.setattr(github_client, "GithubException", FakeGithubException)
        
        session = FakeSession(responses=[
            FakeResponse(200, json_data=[], content=b'[]')
        ])
        
        fake_github = FakeGithub("token")
        fake_repo = FakeRepo(has_permissions=False)
        fake_github._repos["owner/repo"] = fake_repo
        
        monkeypatch.setattr(github_client, "Github", lambda token: fake_github)
        
        client = GitHubClient("token", "owner/repo", session=session)
        permissions = client.check_permissions()
        
        assert permissions['can_create_branches'] is False
        assert permissions['can_create_prs'] is False



class TestRepoOperations:
    """Tests for repository operations (branches, PRs, comments)."""
    
    def test_create_branch_success(self, monkeypatch):
        """
        Validates: create_branch uses base ref SHA, creates git ref, 
        and returns the SHA.
        """
        monkeypatch.setattr(github_client, "Github", FakeGithub)
        monkeypatch.setattr(github_client, "GithubException", FakeGithubException)
        
        session = FakeSession()
        
        fake_github = FakeGithub("token")
        fake_repo = FakeRepo()
        fake_repo._refs["heads/main"] = FakeRef(sha="base-sha-123")
        fake_github._repos["owner/repo"] = fake_repo
        
        monkeypatch.setattr(github_client, "Github", lambda token: fake_github)
        
        client = GitHubClient("token", "owner/repo", session=session)
        sha = client.create_branch("feature-branch", base_branch="main")
        
        assert sha == "base-sha-123"
        assert "refs/heads/feature-branch" in fake_repo._refs
    
    def test_create_branch_already_exists_maps_422(self, monkeypatch):
        """
        Validates: GithubException with status 422 is mapped to GitHubClientError 
        with "branch exists" message.
        """
        monkeypatch.setattr(github_client, "Github", FakeGithub)
        monkeypatch.setattr(github_client, "GithubException", FakeGithubException)
        
        session = FakeSession()
        
        fake_github = FakeGithub("token")
        fake_repo = FakeRepo()
        
        def raise_422(*args, **kwargs):
            raise FakeGithubException(422, {"message": "Reference already exists"})
        
        fake_repo.create_git_ref = raise_422
        fake_github._repos["owner/repo"] = fake_repo
        
        monkeypatch.setattr(github_client, "Github", lambda token: fake_github)
        
        client = GitHubClient("token", "owner/repo", session=session)
        
        with pytest.raises(GitHubClientError) as exc_info:
            client.create_branch("existing-branch")
        
        assert "already exists" in str(exc_info.value)
    
    def test_create_pull_request_success(self, monkeypatch):
        """
        Validates: create_pull_request creates a PR and returns the PR object.
        """
        monkeypatch.setattr(github_client, "Github", FakeGithub)
        monkeypatch.setattr(github_client, "GithubException", FakeGithubException)
        
        session = FakeSession()
        
        fake_github = FakeGithub("token")
        fake_repo = FakeRepo()
        fake_github._repos["owner/repo"] = fake_repo
        
        monkeypatch.setattr(github_client, "Github", lambda token: fake_github)
        
        client = GitHubClient("token", "owner/repo", session=session)
        pr = client.create_pull_request(
            branch="feature-branch",
            title="Fix security issues",
            body="This PR fixes security issues",
            base_branch="main"
        )
        
        assert pr.number == 1
        assert "github.com" in pr.html_url
    
    def test_create_pull_request_existing_pr_422(self, monkeypatch):
        """
        Validates: GithubException with status 422 and "pull request already exists" 
        message is mapped to appropriate GitHubClientError.
        """
        monkeypatch.setattr(github_client, "Github", FakeGithub)
        monkeypatch.setattr(github_client, "GithubException", FakeGithubException)
        
        session = FakeSession()
        
        fake_github = FakeGithub("token")
        fake_repo = FakeRepo()
        
        def raise_422(*args, **kwargs):
            raise FakeGithubException(
                422, 
                {"message": "A pull request already exists for owner:feature-branch"}
            )
        
        fake_repo.create_pull = raise_422
        fake_github._repos["owner/repo"] = fake_repo
        
        monkeypatch.setattr(github_client, "Github", lambda token: fake_github)
        
        client = GitHubClient("token", "owner/repo", session=session)
        
        with pytest.raises(GitHubClientError) as exc_info:
            client.create_pull_request("feature-branch", "Title", "Body")
        
        assert "already exists" in str(exc_info.value)
    
    def test_add_pr_comment_success(self, monkeypatch):
        """
        Validates: add_pr_comment adds a comment via get_pull().create_issue_comment.
        """
        monkeypatch.setattr(github_client, "Github", FakeGithub)
        monkeypatch.setattr(github_client, "GithubException", FakeGithubException)
        
        session = FakeSession()
        
        fake_github = FakeGithub("token")
        fake_repo = FakeRepo()
        fake_pull = FakePull()
        fake_repo._pulls[1] = fake_pull
        fake_github._repos["owner/repo"] = fake_repo
        
        monkeypatch.setattr(github_client, "Github", lambda token: fake_github)
        
        client = GitHubClient("token", "owner/repo", session=session)
        client.add_pr_comment(1, "Great work!")
        
        assert len(fake_pull.comments) == 1
        assert fake_pull.comments[0] == "Great work!"
    
    def test_get_repository_info_returns_expected_fields(self, monkeypatch_github):
        """
        Validates: get_repository_info returns dictionary with expected fields
        (name, full_name, url, default_branch, clone_url).
        """
        session = FakeSession()
        client = GitHubClient("token", "owner/repo", session=session)
        
        info = client.get_repository_info()
        
        assert info['name'] == 'repo'
        assert info['full_name'] == 'owner/repo'
        assert 'github.com' in info['url']
        assert info['default_branch'] == 'main'
        assert info['clone_url'].endswith('.git')



class TestInit:
    """Tests for GitHubClient initialization."""
    
    def test_init_invalid_repo_name_format_raises(self, monkeypatch_github):
        """
        Validates: Invalid repo_name format (missing '/') raises ValueError.
        """
        session = FakeSession()
        
        with pytest.raises(ValueError) as exc_info:
            GitHubClient("token", "invalid-repo-name", session=session)
        
        assert "Invalid repo_name format" in str(exc_info.value)
        assert "Expected 'owner/repo'" in str(exc_info.value)
