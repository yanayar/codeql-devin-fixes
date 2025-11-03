"""
Data model for Devin AI fix sessions.
"""
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


class SessionStatus(Enum):
    """Status of a Devin session."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"


@dataclass
class SessionResult:
    """
    Result of a completed Devin session.

    Attributes:
        pr_url: URL of the pull request created by Devin
        branch_name: Name of the branch with fixes
        commits: List of commit SHAs created
        files_modified: List of files that were modified
        alerts_fixed: Number of alerts addressed
        summary: Human-readable summary of changes
        diff: Unified diff of all changes
        commit_messages: List of commit messages
    """
    pr_url: Optional[str] = None
    branch_name: Optional[str] = None
    commits: List[str] = field(default_factory=list)
    files_modified: List[str] = field(default_factory=list)
    alerts_fixed: int = 0
    summary: Optional[str] = None
    diff: Optional[str] = None
    commit_messages: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary format."""
        return {
            'pr_url': self.pr_url,
            'branch_name': self.branch_name,
            'commits': self.commits,
            'files_modified': self.files_modified,
            'alerts_fixed': self.alerts_fixed,
            'summary': self.summary,
            'diff': self.diff,
            'commit_messages': self.commit_messages,
        }


@dataclass
class DevinSession:
    """
    Represents a Devin AI session for fixing security issues.

    Attributes:
        session_id: Unique identifier for the Devin session
        status: Current status of the session
        created_at: Timestamp when session was created
        updated_at: Timestamp of last status update
        alerts: List of CodeQL alerts being addressed in this session
        result: Session result (populated when completed)
        error_message: Error details if session failed
        repository_url: URL of the repository being fixed
        instructions: Custom instructions provided to Devin
        metadata: Additional session metadata
    """

    session_id: str
    status: SessionStatus
    created_at: datetime
    updated_at: datetime
    alerts: List[Any] = field(default_factory=list)  # List[CodeQLAlert]
    result: Optional[SessionResult] = None
    error_message: Optional[str] = None
    repository_url: Optional[str] = None
    instructions: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        """Return a human-readable string representation of the session."""
        alert_count = len(self.alerts)
        return (
            f"Session {self.session_id}: {self.status.value} "
            f"({alert_count} alerts)"
        )

    def is_terminal(self) -> bool:
        """
        Check if session is in a terminal state (completed, failed, or timeout).

        Returns:
            True if session is finished, False if still in progress
        """
        return self.status in [
            SessionStatus.COMPLETED,
            SessionStatus.FAILED,
            SessionStatus.TIMEOUT
        ]

    def is_successful(self) -> bool:
        """
        Check if session completed successfully.

        Returns:
            True if session completed successfully, False otherwise
        """
        return self.status == SessionStatus.COMPLETED

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert session to dictionary format for serialization.

        Returns:
            Dictionary representation of the session
        """
        return {
            'session_id': self.session_id,
            'status': self.status.value,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'alert_count': len(self.alerts),
            'result': self.result.to_dict() if self.result else None,
            'error_message': self.error_message,
            'repository_url': self.repository_url,
            'metadata': self.metadata,
        }

    @classmethod
    def from_api_response(cls, response: Dict[str, Any]) -> 'DevinSession':
        """
        Create a DevinSession from Devin API response data.

        Args:
            response: Raw session data from Devin API

        Returns:
            DevinSession instance

        Note:
            This method will be implemented to parse the Devin API response
            structure and extract relevant fields.
        """
        raise NotImplementedError("Devin API integration pending")
