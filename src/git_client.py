"""
GitHub client for creating PRs with security fixes.
"""
from github import Github


class GitHubClient:
    """Client for GitHub API operations."""

    def __init__(self, token: str, repo_name: str):
        """
        Initialize GitHub client.

        """
        self.github = Github(token)
        self.repo = self.github.get_repo(repo_name)
        self.repo_name = repo_name
