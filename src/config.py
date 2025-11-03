"""
Configuration management for CodeQL-Devin fixes.

Loads and validates configuration from environment variables.
"""
import os
from dataclasses import dataclass


@dataclass
class Config:
    """
    Application configuration loaded from environment variables.

    Attributes:
        github_token: GitHub API authentication token
        github_repository: Target repository in owner/repo format
        devin_api_key: Devin API authentication key
        devin_api_url: Devin API base URL
        batch_size: Maximum number of alerts per batch
        batch_strategy: Strategy for batching alerts (file or severity)
        base_branch: Branch to create PRs against
        push_mode: If True, Devin pushes branches (secret_ids=None); if False, use diff-only workflow (secret_ids=[])
    """

    github_token: str
    github_repository: str
    devin_api_key: str
    devin_api_url: str = "https://api.devin.ai/v1"
    batch_size: int = 5
    batch_strategy: str = "file"
    base_branch: str = "main"
    push_mode: bool = False

    @classmethod
    def load_from_env(cls) -> 'Config':
        """
        Load configuration from environment variables.

        Returns:
            Config instance with values from environment

        Raises:
            ValueError: If required environment variables are missing

        Environment Variables:
            Required:
                - GITHUB_TOKEN: GitHub API token
                - GITHUB_REPOSITORY: Repository in owner/repo format
                - DEVIN_API_KEY: Devin API key

            Optional:
                - DEVIN_API_URL: Devin API base URL (default: https://api.devin.ai/v1)
                - BATCH_SIZE: Max alerts per batch (default: 5)
                - BATCH_STRATEGY: Batching strategy (default: file)
                - BASE_BRANCH: Base branch for PRs (default: main)
                - PUSH_MODE: If true, Devin pushes branches; if false, use diff-only workflow (default: false)
        """
        github_token = os.getenv('GITHUB_TOKEN')
        github_repository = os.getenv('GITHUB_REPOSITORY')
        devin_api_key = os.getenv('DEVIN_API_KEY')

        if not github_token:
            raise ValueError("GITHUB_TOKEN environment variable is required")
        if not github_repository:
            raise ValueError("GITHUB_REPOSITORY environment variable is required")
        if not devin_api_key:
            raise ValueError("DEVIN_API_KEY environment variable is required")

        devin_api_url = os.getenv('DEVIN_API_URL', 'https://api.devin.ai/v1')
        batch_size = int(os.getenv('BATCH_SIZE', '5'))
        batch_strategy = os.getenv('BATCH_STRATEGY', 'file')
        base_branch = os.getenv('BASE_BRANCH', 'main')
        push_mode = os.getenv('PUSH_MODE', 'false').lower() == 'true'

        return cls(
            github_token=github_token,
            github_repository=github_repository,
            devin_api_key=devin_api_key,
            devin_api_url=devin_api_url,
            batch_size=batch_size,
            batch_strategy=batch_strategy,
            base_branch=base_branch,
            push_mode=push_mode,
        )

    def validate(self) -> None:
        """
        Validate configuration values.

        Raises:
            ValueError: If configuration values are invalid
        """
        if self.batch_size < 1:
            raise ValueError("batch_size must be at least 1")

        valid_strategies = ['file', 'severity']
        if self.batch_strategy not in valid_strategies:
            raise ValueError(
                f"batch_strategy must be one of {valid_strategies}, "
                f"got '{self.batch_strategy}'"
            )

        if '/' not in self.github_repository:
            raise ValueError(
                "github_repository must be in owner/repo format, "
                f"got '{self.github_repository}'"
            )

    def __str__(self) -> str:
        """Return a string representation with sensitive data masked."""
        return (
            f"Config(repository={self.github_repository}, "
            f"batch_size={self.batch_size}, "
            f"batch_strategy={self.batch_strategy}, "
            f"base_branch={self.base_branch}, "
            f"push_mode={self.push_mode})"
        )
