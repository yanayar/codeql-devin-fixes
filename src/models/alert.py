"""
Data model for CodeQL security alerts.
"""
from dataclasses import dataclass
from typing import Optional, Dict, Any
from datetime import datetime


@dataclass
class CodeQLAlert:
    """
    Represents a CodeQL security alert from GitHub.

    Attributes:
        alert_id: Unique identifier for the alert (GitHub alert number)
        rule_id: CodeQL rule identifier that triggered this alert
        severity: Severity level (critical, high, medium, low, warning, note)
        file_path: Path to the file containing the security issue
        line_number: Line number where the issue occurs
        message: Human-readable description of the security issue
        recommendation: Suggested fix or remediation guidance
        state: Current state of the alert (open, dismissed, fixed)
        created_at: Timestamp when alert was created
        url: URL to view the alert on GitHub
        tool: Tool that generated the alert (e.g., "CodeQL")
        raw_data: Original alert data from GitHub API for reference
    """

    alert_id: int
    rule_id: str
    severity: str
    file_path: str
    line_number: int
    message: str
    recommendation: str
    state: str = "open"
    created_at: Optional[datetime] = None
    url: Optional[str] = None
    tool: str = "CodeQL"
    raw_data: Optional[Dict[str, Any]] = None

    def __str__(self) -> str:
        """Return a human-readable string representation of the alert."""
        return (
            f"Alert #{self.alert_id}: {self.rule_id} "
            f"({self.severity}) in {self.file_path}:{self.line_number}"
        )

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert alert to dictionary format for serialization.

        Returns:
            Dictionary representation of the alert
        """
        return {
            'alert_id': self.alert_id,
            'rule_id': self.rule_id,
            'severity': self.severity,
            'file_path': self.file_path,
            'line_number': self.line_number,
            'message': self.message,
            'recommendation': self.recommendation,
            'state': self.state,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'url': self.url,
            'tool': self.tool,
        }

    @classmethod
    def from_github_alert(cls, github_alert: Dict[str, Any]) -> 'CodeQLAlert':
        """
        Create a CodeQLAlert from GitHub API response data.

        Args:
            github_alert: Raw alert data from GitHub API

        Returns:
            CodeQLAlert instance

        Note:
            This method will be implemented to parse the GitHub API response
            structure and extract relevant fields.
        """
        raise NotImplementedError("GitHub API integration pending")

    def get_context_lines(self, before: int = 5, after: int = 5) -> str:
        """
        Get surrounding code context for the alert location.

        Args:
            before: Number of lines to include before the alert line
            after: Number of lines to include after the alert line

        Returns:
            String containing the code context

        Note:
            This will require file system access to read the source file.
        """
        raise NotImplementedError("File context extraction pending")
