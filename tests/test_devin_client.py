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

All tests use pytest mocks to avoid making real API calls.
"""
import pytest
from unittest.mock import Mock, MagicMock, patch
from datetime import datetime
import requests
import time

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from devin_client import DevinClient
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


def test_create_session_not_implemented(devin_client, sample_alerts):
    """
    Validates that create_session raises NotImplementedError as it's not yet implemented.
    This test will need to be updated once the method is implemented.
    """
    with pytest.raises(NotImplementedError, match="Devin API session creation pending"):
        devin_client.create_session(
            repo_url="https://github.com/test/repo",
            alerts=sample_alerts,
            base_branch="main"
        )


def test_get_session_status_not_implemented(devin_client):
    """
    Validates that get_session_status raises NotImplementedError as it's not yet implemented.
    This test will need to be updated once the method is implemented.
    """
    with pytest.raises(NotImplementedError, match="Devin API status check pending"):
        devin_client.get_session_status(session_id="test_session_123")


def test_wait_for_completion_not_implemented(devin_client):
    """
    Validates that wait_for_completion raises NotImplementedError as it's not yet implemented.
    This test will need to be updated once the method is implemented.
    """
    with pytest.raises(NotImplementedError, match="Session polling pending"):
        devin_client.wait_for_completion(
            session_id="test_session_123",
            timeout=60,
            poll_interval=10
        )


def test_get_session_result_not_implemented(devin_client):
    """
    Validates that get_session_result raises NotImplementedError as it's not yet implemented.
    This test will need to be updated once the method is implemented.
    """
    with pytest.raises(NotImplementedError, match="Result retrieval pending"):
        devin_client.get_session_result(session_id="test_session_123")


def test_cancel_session_not_implemented(devin_client):
    """
    Validates that cancel_session raises NotImplementedError as it's not yet implemented.
    This test will need to be updated once the method is implemented.
    """
    with pytest.raises(NotImplementedError, match="Session cancellation pending"):
        devin_client.cancel_session(session_id="test_session_123")


def test_format_task_description_single_alert(devin_client):
    """
    Validates that _format_task_description correctly formats a single alert.
    Checks that all alert details are included in the formatted description.
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
    
    description = devin_client._format_task_description(alerts, "main")
    
    assert "Fix the following CodeQL security issues" in description
    assert "Alert #1: py/sql-injection" in description
    assert "Location: src/auth.py:45" in description
    assert "Severity: high" in description
    assert "Issue: SQL injection vulnerability" in description
    assert "Recommendation: Use parameterized queries" in description
    assert "Create a PR with your changes against main" in description


def test_format_task_description_multiple_alerts(devin_client, sample_alerts):
    """
    Validates that _format_task_description correctly formats multiple alerts.
    Ensures all alerts are numbered and included in the description.
    """
    description = devin_client._format_task_description(sample_alerts, "develop")
    
    assert "1. Alert #1: py/sql-injection" in description
    assert "2. Alert #2: py/xss" in description
    assert "3. Alert #3: py/path-injection" in description
    
    assert "src/auth.py:45" in description
    assert "src/views.py:120" in description
    assert "src/files.py:78" in description
    
    assert "Create a PR with your changes against develop" in description


def test_format_task_description_has_required_sections(devin_client, sample_alerts):
    """
    Validates that _format_task_description includes all required sections:
    - Header
    - Alert details
    - Instructions for fixing, testing, and creating PR
    """
    description = devin_client._format_task_description(sample_alerts, "main")
    
    assert "Fix the following CodeQL security issues" in description
    assert "Please:" in description
    assert "1. Fix all listed security issues" in description
    assert "2. Run tests to ensure fixes don't break functionality" in description
    assert "3. Create a PR with your changes against main" in description


def test_format_task_description_different_base_branches(devin_client, sample_alerts):
    """
    Validates that _format_task_description correctly uses different base branch names.
    This ensures the PR instruction references the correct target branch.
    """
    for branch in ["main", "develop", "feature/security-fixes", "release/v1.0"]:
        description = devin_client._format_task_description(sample_alerts, branch)
        assert f"Create a PR with your changes against {branch}" in description


def test_format_task_description_includes_severity(devin_client, sample_alerts):
    """
    Validates that _format_task_description includes severity information for each alert.
    This helps prioritize fixes based on criticality.
    """
    description = devin_client._format_task_description(sample_alerts, "main")
    
    assert "Severity: high" in description
    assert "Severity: medium" in description
    assert "Severity: critical" in description


def test_format_task_description_special_characters(devin_client):
    """
    Validates that _format_task_description handles alerts with special characters.
    Ensures the formatter doesn't break with quotes, newlines, or other special chars.
    """
    alerts = [
        CodeQLAlert(
            alert_id=1,
            rule_id="py/code-injection",
            severity="critical",
            file_path="src/eval_handler.py",
            line_number=10,
            message="Code injection via eval() with user input \"data\"",
            recommendation="Never use eval() with untrusted input; use ast.literal_eval()",
            state="open"
        )
    ]
    
    description = devin_client._format_task_description(alerts, "main")
    
    assert 'eval() with user input "data"' in description
    assert "ast.literal_eval()" in description


def test_format_task_description_empty_recommendation(devin_client):
    """
    Validates that _format_task_description handles alerts with empty recommendations.
    This tests edge case where CodeQL might not provide specific fix guidance.
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
    
    description = devin_client._format_task_description(alerts, "main")
    
    assert "Alert #1: py/unknown-vulnerability" in description
    assert "Recommendation:" in description


def test_format_task_description_preserves_order(devin_client):
    """
    Validates that _format_task_description preserves the order of alerts.
    This is important when alerts are pre-sorted by priority or location.
    """
    alerts = [
        CodeQLAlert(
            alert_id=5, rule_id="rule5", severity="low",
            file_path="file5.py", line_number=1,
            message="msg5", recommendation="rec5"
        ),
        CodeQLAlert(
            alert_id=2, rule_id="rule2", severity="high",
            file_path="file2.py", line_number=1,
            message="msg2", recommendation="rec2"
        ),
        CodeQLAlert(
            alert_id=8, rule_id="rule8", severity="medium",
            file_path="file8.py", line_number=1,
            message="msg8", recommendation="rec8"
        ),
    ]
    
    description = devin_client._format_task_description(alerts, "main")
    
    lines = description.split('\n')
    alert_lines = [line for line in lines if line.startswith(('1.', '2.', '3.'))]
    
    assert "Alert #5: rule5" in alert_lines[0]
    assert "Alert #2: rule2" in alert_lines[1]
    assert "Alert #8: rule8" in alert_lines[2]


def test_client_strips_trailing_slashes(mock_session):
    """
    Validates that DevinClient strips multiple trailing slashes from base URL.
    This prevents malformed API endpoint URLs.
    """
    client = DevinClient(api_key="test_key", base_url="https://api.test.com///")
    assert client.base_url == "https://api.test.com"


def test_format_task_description_long_messages(devin_client):
    """
    Validates that _format_task_description handles alerts with very long messages.
    This ensures the formatter doesn't truncate or break with lengthy descriptions.
    """
    long_message = "This is a very long security vulnerability description " * 20
    long_recommendation = "This is a very detailed recommendation " * 15
    
    alerts = [
        CodeQLAlert(
            alert_id=1,
            rule_id="py/complex-vulnerability",
            severity="high",
            file_path="src/complex.py",
            line_number=100,
            message=long_message,
            recommendation=long_recommendation,
            state="open"
        )
    ]
    
    description = devin_client._format_task_description(alerts, "main")
    
    assert long_message in description
    assert long_recommendation in description
    assert "Alert #1: py/complex-vulnerability" in description


def test_format_task_description_multiple_files(devin_client):
    """
    Validates that _format_task_description correctly handles alerts from different files.
    This tests the common scenario where security issues span multiple source files.
    """
    alerts = [
        CodeQLAlert(
            alert_id=1, rule_id="rule1", severity="high",
            file_path="src/auth/login.py", line_number=10,
            message="Auth issue", recommendation="Fix auth"
        ),
        CodeQLAlert(
            alert_id=2, rule_id="rule2", severity="medium",
            file_path="src/api/endpoints.py", line_number=50,
            message="API issue", recommendation="Fix API"
        ),
        CodeQLAlert(
            alert_id=3, rule_id="rule3", severity="low",
            file_path="tests/test_security.py", line_number=5,
            message="Test issue", recommendation="Fix test"
        ),
    ]
    
    description = devin_client._format_task_description(alerts, "main")
    
    assert "src/auth/login.py:10" in description
    assert "src/api/endpoints.py:50" in description
    assert "tests/test_security.py:5" in description
