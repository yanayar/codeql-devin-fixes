"""
Comprehensive test suite for DevinClient.

This test suite validates the behavior of the DevinClient class including:
- Initialization and configuration
- Session creation with various inputs
- Session status checking
- Session completion waiting with timeout handling
- Result retrieval
- Session cancellation
- Task description formatting
- Error handling for various failure scenarios
- Retry logic for network errors

All tests use pytest mocks to avoid making real API calls.
"""
import pytest
from unittest.mock import Mock, MagicMock, patch, call
from datetime import datetime
import requests
import time
import json

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from devin_client import DevinClient, DevinClientError
from models.alert import CodeQLAlert
from models.session import DevinSession, SessionResult, SessionStatus



@pytest.fixture
def mock_session():
    """
    Fixture that provides a mocked requests.Session object.
    This prevents any real HTTP requests from being made during tests.
    """
    with patch('devin_client.requests.Session') as mock:
        session_instance = MagicMock()
        mock.return_value = session_instance
        yield session_instance


@pytest.fixture
def devin_client(mock_session):
    """
    Fixture that provides a DevinClient instance with mocked session.
    The client is initialized with test credentials.
    """
    client = DevinClient(api_key="test_api_key", base_url="https://api.test.com")
    return client


@pytest.fixture
def sample_alerts():
    """
    Fixture that provides sample CodeQL alerts for testing.
    Returns a list of 3 alerts with different severities and locations.
    """
    return [
        CodeQLAlert(
            alert_id=1,
            rule_id="py/sql-injection",
            severity="high",
            file_path="src/auth.py",
            line_number=45,
            message="SQL injection vulnerability",
            recommendation="Use parameterized queries",
            state="open"
        ),
        CodeQLAlert(
            alert_id=2,
            rule_id="py/xss",
            severity="medium",
            file_path="src/views.py",
            line_number=120,
            message="Cross-site scripting vulnerability",
            recommendation="Escape user input",
            state="open"
        ),
        CodeQLAlert(
            alert_id=3,
            rule_id="py/path-injection",
            severity="critical",
            file_path="src/files.py",
            line_number=78,
            message="Path injection vulnerability",
            recommendation="Validate file paths",
            state="open"
        )
    ]


def test_client_initialization_default_url():
    """
    Validates that DevinClient initializes correctly with default base URL.
    Checks that the API key is stored and default URL is used.
    """
    with patch('devin_client.requests.Session'):
        client = DevinClient(api_key="test_key")
        assert client.api_key == "test_key"
        assert client.base_url == "https://api.devin.ai/v1"


def test_client_initialization_custom_url():
    """
    Validates that DevinClient initializes correctly with a custom base URL.
    Ensures trailing slashes are stripped from the URL.
    """
    with patch('devin_client.requests.Session'):
        client = DevinClient(api_key="test_key", base_url="https://custom.api.com/")
        assert client.api_key == "test_key"
        assert client.base_url == "https://custom.api.com"


def test_client_sets_correct_headers(mock_session):
    """
    Validates that the client sets the correct Authorization and Content-Type headers.
    This ensures API requests will be properly authenticated.
    """
    client = DevinClient(api_key="test_api_key", base_url="https://api.test.com")
    
    mock_session.headers.update.assert_called_once()
    headers = mock_session.headers.update.call_args[0][0]
    assert headers['Authorization'] == 'Bearer test_api_key'
    assert headers['Content-Type'] == 'application/json'


def test_create_session_empty_alerts_raises_error(devin_client):
    """
    Validates that create_session raises ValueError when given an empty alerts list.
    This prevents creating sessions without any work to do.
    """
    with pytest.raises(ValueError, match="Cannot create session with empty alerts list"):
        devin_client.create_session(
            repo_url="https://github.com/test/repo",
            alerts=[],
            base_branch="main"
        )


def test_create_session_success(devin_client, sample_alerts, mock_session):
    """
    Validates that create_session successfully creates a session with valid inputs.
    Checks that the API is called correctly and returns a DevinSession object.
    """
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "session_id": "test_session_123",
        "url": "https://app.devin.ai/sessions/test_session_123"
    }
    mock_session.request.return_value = mock_response
    
    session = devin_client.create_session(
        repo_url="https://github.com/test/repo",
        alerts=sample_alerts,
        base_branch="main"
    )
    
    assert session.session_id == "test_session_123"
    assert session.status == SessionStatus.PENDING
    assert session.repository_url == "https://github.com/test/repo"
    assert len(session.alerts) == 3
    assert session.metadata["base_branch"] == "main"
    assert session.metadata["url"] == "https://app.devin.ai/sessions/test_session_123"
    
    mock_session.request.assert_called_once()
    call_args = mock_session.request.call_args
    assert call_args[0][0] == "POST"
    assert "/sessions" in call_args[0][1]


def test_create_session_with_custom_parameters(devin_client, sample_alerts, mock_session):
    """
    Validates that create_session correctly handles custom parameters like
    idempotent, secret_ids, title, and tags.
    """
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "session_id": "test_session_456",
        "url": "https://app.devin.ai/sessions/test_session_456"
    }
    mock_session.request.return_value = mock_response
    
    session = devin_client.create_session(
        repo_url="https://github.com/test/repo",
        alerts=sample_alerts,
        base_branch="develop",
        idempotent=True,
        secret_ids=["secret_1", "secret_2"],
        title="Fix security issues",
        tags=["security", "codeql"]
    )
    
    assert session.session_id == "test_session_456"
    
    call_args = mock_session.request.call_args
    payload = call_args[1]["json"]
    assert payload["idempotent"] is True
    assert payload["secret_ids"] == ["secret_1", "secret_2"]
    assert payload["title"] == "Fix security issues"
    assert payload["tags"] == ["security", "codeql"]


def test_create_session_missing_session_id(devin_client, sample_alerts, mock_session):
    """
    Validates that create_session raises DevinClientError when the API response
    is missing the required session_id field.
    """
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"url": "https://app.devin.ai/sessions/test"}
    mock_session.request.return_value = mock_response
    
    with pytest.raises(DevinClientError, match="API response missing session_id"):
        devin_client.create_session(
            repo_url="https://github.com/test/repo",
            alerts=sample_alerts,
            base_branch="main"
        )


def test_get_session_status_success(devin_client, mock_session):
    """
    Validates that get_session_status correctly retrieves and maps session status.
    Tests the status mapping from Devin API status_enum to SessionStatus.
    """
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "session_id": "test_session_123",
        "status_enum": "working",
        "created_at": "2024-01-01T00:00:00",
        "updated_at": "2024-01-01T01:00:00",
        "url": "https://app.devin.ai/sessions/test_session_123"
    }
    mock_session.request.return_value = mock_response
    
    session = devin_client.get_session_status("test_session_123")
    
    assert session.session_id == "test_session_123"
    assert session.status == SessionStatus.IN_PROGRESS
    assert isinstance(session.created_at, datetime)
    assert isinstance(session.updated_at, datetime)


def test_get_session_status_completed(devin_client, mock_session):
    """
    Validates that get_session_status correctly handles completed sessions
    and extracts PR URL from the response.
    """
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "session_id": "test_session_123",
        "status_enum": "finished",
        "created_at": "2024-01-01T00:00:00",
        "updated_at": "2024-01-01T02:00:00",
        "url": "https://app.devin.ai/sessions/test_session_123",
        "pull_request": {
            "url": "https://github.com/test/repo/pull/1"
        }
    }
    mock_session.request.return_value = mock_response
    
    session = devin_client.get_session_status("test_session_123")
    
    assert session.status == SessionStatus.COMPLETED
    assert session.result is not None
    assert session.result.pr_url == "https://github.com/test/repo/pull/1"


@patch('devin_client.time.sleep')
def test_wait_for_completion_success(mock_sleep, devin_client, mock_session):
    """
    Validates that wait_for_completion polls the API until the session
    reaches a terminal state. Mocks time.sleep to avoid actual delays.
    """
    responses = [
        {"session_id": "test_123", "status_enum": "working", "created_at": "2024-01-01T00:00:00", "updated_at": "2024-01-01T00:00:00"},
        {"session_id": "test_123", "status_enum": "working", "created_at": "2024-01-01T00:00:00", "updated_at": "2024-01-01T00:30:00"},
        {"session_id": "test_123", "status_enum": "finished", "created_at": "2024-01-01T00:00:00", "updated_at": "2024-01-01T01:00:00", "pull_request": {"url": "https://github.com/test/repo/pull/1"}}
    ]
    
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.side_effect = responses
    mock_session.request.return_value = mock_response
    
    session = devin_client.wait_for_completion("test_123", timeout=3600, poll_interval=30)
    
    assert session.status == SessionStatus.COMPLETED
    assert mock_session.request.call_count == 3
    assert mock_sleep.call_count == 2


@patch('devin_client.time.time')
@patch('devin_client.time.sleep')
def test_wait_for_completion_timeout(mock_sleep, mock_time, devin_client, mock_session):
    """
    Validates that wait_for_completion raises TimeoutError when the session
    doesn't complete within the specified timeout period.
    """
    mock_time.side_effect = [0, 30, 60, 90, 120, 150, 180, 200]
    
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "session_id": "test_123",
        "status_enum": "working",
        "created_at": "2024-01-01T00:00:00",
        "updated_at": "2024-01-01T00:00:00"
    }
    mock_session.request.return_value = mock_response
    
    with pytest.raises(TimeoutError, match="did not complete within 100s"):
        devin_client.wait_for_completion("test_123", timeout=100, poll_interval=30)


def test_get_session_result_success(devin_client, mock_session):
    """
    Validates that get_session_result successfully retrieves the result
    of a completed session. Since get_session_status already returns a result
    with PR URL for completed sessions, this test validates that behavior.
    """
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "session_id": "test_123",
        "status_enum": "finished",
        "created_at": "2024-01-01T00:00:00",
        "updated_at": "2024-01-01T01:00:00",
        "pull_request": {
            "url": "https://github.com/test/repo/pull/1"
        }
    }
    mock_session.request.return_value = mock_response
    
    result = devin_client.get_session_result("test_123")
    
    assert isinstance(result, SessionResult)
    assert result.pr_url == "https://github.com/test/repo/pull/1"


def test_get_session_result_not_completed(devin_client, mock_session):
    """
    Validates that get_session_result raises DevinClientError when called
    on a session that hasn't completed successfully.
    """
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "session_id": "test_123",
        "status_enum": "working",
        "created_at": "2024-01-01T00:00:00",
        "updated_at": "2024-01-01T00:30:00"
    }
    mock_session.request.return_value = mock_response
    
    with pytest.raises(DevinClientError, match="Session is not completed successfully"):
        devin_client.get_session_result("test_123")


def test_request_cancellation_success(devin_client, mock_session):
    """
    Validates that request_cancellation successfully sends a cancellation
    message to the session and returns True.
    """
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"status": "message_sent"}
    mock_session.request.return_value = mock_response
    
    result = devin_client.request_cancellation("test_123")
    
    assert result is True
    mock_session.request.assert_called_once()
    call_args = mock_session.request.call_args
    assert call_args[0][0] == "POST"
    assert "/sessions/test_123/message" in call_args[0][1]
    assert "Please stop working" in call_args[1]["json"]["message"]


def test_make_request_4xx_error(devin_client, mock_session):
    """
    Validates that _make_request raises DevinClientError for 4xx responses
    and extracts error message from JSON response when available.
    """
    mock_response = Mock()
    mock_response.status_code = 400
    mock_response.text = "Bad request"
    mock_response.json.return_value = {"message": "Invalid session ID"}
    mock_response.headers.get.return_value = "req_123"
    mock_session.request.return_value = mock_response
    
    with pytest.raises(DevinClientError) as exc_info:
        devin_client._make_request("GET", "/sessions/invalid")
    
    error = exc_info.value
    assert error.status_code == 400
    assert "Invalid session ID" in error.message
    assert error.request_id == "req_123"


@patch('devin_client.time.sleep')
def test_make_request_5xx_retry(mock_sleep, devin_client, mock_session):
    """
    Validates that _make_request retries on 5xx server errors with
    exponential backoff before eventually raising DevinClientError.
    """
    mock_response = Mock()
    mock_response.status_code = 503
    mock_response.text = "Service unavailable"
    mock_response.headers.get.return_value = None
    mock_session.request.return_value = mock_response
    
    with pytest.raises(DevinClientError) as exc_info:
        devin_client._make_request("GET", "/sessions/test", max_retries=3)
    
    error = exc_info.value
    assert error.status_code == 503
    assert mock_session.request.call_count == 3
    assert mock_sleep.call_count == 2


@patch('devin_client.time.sleep')
def test_make_request_network_error_retry(mock_sleep, devin_client, mock_session):
    """
    Validates that _make_request retries on network errors (RequestException)
    with exponential backoff before raising DevinClientError.
    """
    mock_session.request.side_effect = requests.exceptions.ConnectionError("Network error")
    
    with pytest.raises(DevinClientError) as exc_info:
        devin_client._make_request("GET", "/sessions/test", max_retries=3)
    
    error = exc_info.value
    assert "Request failed after 3 attempts" in error.message
    assert mock_session.request.call_count == 3
    assert mock_sleep.call_count == 2


def test_format_task_description_single_alert(devin_client):
    """
    Validates that _format_task_description correctly formats a single alert
    with all required fields including repo URL and base branch.
    """
    alerts = [
        CodeQLAlert(
            alert_id=1,
            rule_id="py/sql-injection",
            severity="high",
            file_path="src/auth.py",
            line_number=45,
            message="SQL injection vulnerability",
            recommendation="Use parameterized queries",
            state="open"
        )
    ]
    
    description = devin_client._format_task_description(
        "https://github.com/test/repo",
        alerts,
        "main"
    )
    
    assert "Repository: https://github.com/test/repo" in description
    assert "Base branch: main" in description
    
    assert "Fix the following CodeQL security issues" in description
    assert "Alert #1: py/sql-injection" in description
    assert "Location: src/auth.py:45" in description
    assert "Severity: high" in description
    assert "Issue: SQL injection vulnerability" in description
    assert "Recommendation: Use parameterized queries" in description
    
    assert "1. Clone the repository and checkout the base branch" in description
    assert "4. Create a PR with your changes against main" in description


def test_format_task_description_multiple_alerts(devin_client, sample_alerts):
    """
    Validates that _format_task_description correctly formats multiple alerts
    and preserves their order.
    """
    description = devin_client._format_task_description(
        "https://github.com/test/repo",
        sample_alerts,
        "develop"
    )
    
    assert "1. Alert #1: py/sql-injection" in description
    assert "2. Alert #2: py/xss" in description
    assert "3. Alert #3: py/path-injection" in description
    
    assert "src/auth.py:45" in description
    assert "src/views.py:120" in description
    assert "src/files.py:78" in description
    
    assert "Base branch: develop" in description
    assert "Create a PR with your changes against develop" in description


def test_format_task_description_empty_recommendation(devin_client):
    """
    Validates that _format_task_description handles alerts with empty
    recommendations by omitting the Recommendation line.
    """
    alerts = [
        CodeQLAlert(
            alert_id=1,
            rule_id="py/unknown-vulnerability",
            severity="low",
            file_path="src/test.py",
            line_number=5,
            message="Potential security issue",
            recommendation="",
            state="open"
        )
    ]
    
    description = devin_client._format_task_description(
        "https://github.com/test/repo",
        alerts,
        "main"
    )
    
    assert "Alert #1: py/unknown-vulnerability" in description
    assert "Issue: Potential security issue" in description
    lines = description.split('\n')
    recommendation_lines = [line for line in lines if line.strip().startswith("- Recommendation:")]
    assert len(recommendation_lines) == 0


def test_client_strips_trailing_slashes(mock_session):
    """
    Validates that DevinClient strips multiple trailing slashes from base URL
    to prevent malformed API endpoint URLs.
    """
    client = DevinClient(api_key="test_key", base_url="https://api.test.com///")
    assert client.base_url == "https://api.test.com"


def test_get_session_url_success(devin_client, mock_session):
    """
    Validates that get_session_url retrieves the session URL from metadata.
    """
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "session_id": "test_123",
        "status_enum": "working",
        "created_at": "2024-01-01T00:00:00",
        "updated_at": "2024-01-01T00:00:00",
        "url": "https://app.devin.ai/sessions/test_123"
    }
    mock_session.request.return_value = mock_response
    
    url = devin_client.get_session_url("test_123")
    
    assert url == "https://app.devin.ai/sessions/test_123"


def test_get_session_url_fallback(devin_client, mock_session):
    """
    Validates that get_session_url constructs a URL from session_id
    when the stored URL is not available in metadata. The URL is derived
    from the client's base_url by replacing 'api.' with 'app.'.
    """
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "session_id": "test_123",
        "status_enum": "working",
        "created_at": "2024-01-01T00:00:00",
        "updated_at": "2024-01-01T00:00:00"
    }
    mock_session.request.return_value = mock_response
    
    url = devin_client.get_session_url("test_123")
    
    assert url == "https://app.test.com/sessions/test_123"


def test_get_session_url_error_fallback(devin_client, mock_session):
    """
    Validates that get_session_url constructs a URL even when
    get_session_status fails, providing a fallback URL derived from
    the client's base_url.
    """
    mock_session.request.side_effect = Exception("Network error")
    
    url = devin_client.get_session_url("test_123")
    
    assert url == "https://app.test.com/sessions/test_123"
