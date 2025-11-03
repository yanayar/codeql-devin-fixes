# CodeQL-Devin Fixes Architecture

## Overview

This GitHub Action automatically identifies and fixes CodeQL security issues using Devin AI. The system fetches open CodeQL alerts from a repository, batches them strategically, and uses Devin to generate fixes for each batch, creating pull requests with the proposed changes.

## High-Level Workflow

1. **Trigger**: GitHub Action runs on schedule or manual trigger
2. **Fetch Alerts**: Retrieve open CodeQL alerts via GitHub API
3. **Batch Alerts**: Group alerts by file or severity strategy
4. **Process Batches**: For each batch:
   - Create a Devin session with alert details and repository URL
   - Wait for Devin to fix code and push branch (or generate diff)
   - Poll session status; treat "blocked" as terminal state after seen twice
   - If branch was pushed, verify it exists; otherwise apply diff to new branch
   - Create pull request automatically with alert details and session link
5. **Report**: Generate summary.json with results and PR links

## Data Flow

```
GitHub Repository (CodeQL Alerts)
    ↓
GitHub API Client (fetch alerts)
    ↓
Batch Strategy (group alerts)
    ↓
Devin Client (create fix session)
    ↓
Devin API (generate fixes)
    ↓
GitHub API Client (create branch & PR)
    ↓
Pull Requests (with fixes)
```

## Module Architecture

### 1. Main Orchestrator (`src/main.py`)

**Status**: IMPLEMENTED

**Responsibility**: Entry point that coordinates the entire workflow

**Key Functions**:
- `main()`: Main entry point that orchestrates the workflow
- `load_config()`: Load and validate configuration from environment variables
- `initialize_github_client()`: Create GitHub API client with token
- `initialize_devin_client()`: Create Devin API client
- `fetch_alerts()`: Retrieve open CodeQL alerts from GitHub
- `batch_alerts()`: Group alerts using configured strategy
- `process_batches()`: Process each batch with Devin
- `process_single_batch()`: Handle single batch (session creation, waiting, PR creation)
- `generate_summary()`: Create summary.json with workflow results

**Data Flow**:
- Reads: Environment variables via Config
- Writes: Logs, summary.json
- Calls: GitHubClient, create_batches, DevinClient

### 2. GitHub Client (`src/github_client.py`)

**Status**: IMPLEMENTED

**Responsibility**: Interface with GitHub API for alerts and PR management

**Key Methods**:
- `fetch_codeql_alerts()`: Retrieve all open CodeQL alerts with pagination
- `get_alert_details(alert_id)`: Get detailed information for a specific alert
- `create_branch(branch_name, base_branch)`: Create a new branch from base
- `apply_diff(diff, branch, commit_message)`: Apply unified diff to branch
- `create_pull_request(branch, title, body)`: Create a PR with fixes
- `add_pr_comment(pr_number, comment)`: Add comments to PRs
- `check_permissions()`: Verify token has required permissions

**Data Flow**:
- Reads: GitHub API (alerts, repository info, file contents)
- Writes: GitHub API (branches, file updates, PRs, comments)
- Returns: CodeQLAlert objects, PullRequest objects, commit SHAs

### 3. CodeQL Alert Model (`src/models/alert.py`)

**Status**: IMPLEMENTED

**Responsibility**: Data model for CodeQL alerts

**Key Attributes**:
- `alert_id`: Unique identifier (GitHub alert number)
- `rule_id`: CodeQL rule that triggered
- `severity`: Critical, high, medium, low, warning, note
- `file_path`: File containing the issue
- `line_number`: Line where issue occurs
- `message`: Description of the issue
- `recommendation`: Suggested fix
- `state`: Alert state (open, dismissed, fixed)
- `created_at`: Timestamp when alert was created
- `url`: URL to view alert on GitHub
- `raw_data`: Original alert data from GitHub API

### 4. Batch Strategy (`src/batch_strategy.py`)

**Status**: IMPLEMENTED

**Responsibility**: Group alerts into logical batches for processing

**Key Functions**:
- `batch_by_file(alerts, max_per_batch)`: Group alerts by file path, reducing context switching
- `batch_by_severity(alerts, max_per_batch)`: Group by severity level, prioritizing critical issues
- `create_batches(alerts, strategy, max_per_batch)`: Main entry point that dispatches to the appropriate strategy

**Batching Strategies**:

1. **File-Based (`file`)**: Groups alerts by file to minimize context switching for Devin. When fixing multiple issues in the same file, Devin loads the file context once, understands the code structure better, and makes related fixes together. This reduces merge conflicts but may delay high-severity issues in files with many low-severity alerts.

2. **Severity-Based (`severity`)**: Prioritizes critical security issues first by sorting alerts from critical to low severity. This ensures the most important vulnerabilities are addressed immediately, improving security posture incrementally. However, it may cause more context switching between files and potential merge conflicts.

**Data Flow**:
- Reads: List of CodeQLAlert objects, strategy name, max batch size
- Returns: List of batches (each batch is a list of CodeQLAlert objects)

### 5. Devin Client (`src/devin_client.py`)

**Status**: IMPLEMENTED

**Responsibility**: Interface with Devin API to create fix sessions

**Key Methods**:
- `create_session(repo_url, alerts, instructions, base_branch, branch_name, secret_ids, push_mode)`: Start a Devin session with formatted task description
- `get_session_status(session_id)`: Check session progress and map status to SessionStatus enum
- `wait_for_completion(session_id, timeout, poll_interval)`: Poll until session completes; treats "blocked" as terminal after seen twice
- `get_session_result(session_id)`: Retrieve fixes from structured_output.json_summary with fallback parsing
- `_parse_devin_output(text)`: Extract JSON summary and unified diff from raw text output
- `_format_task_description()`: Generate detailed instructions for Devin with alert details and output requirements

**Data Flow**:
- Reads: CodeQLAlert objects, repository information, configuration
- Writes: Devin API (session creation with formatted instructions)
- Returns: DevinSession objects, SessionResult with branch_name/files_modified/diff/commit_messages

### 6. Session Model (`src/models/session.py`)

**Status**: IMPLEMENTED

**Responsibility**: Data model for Devin sessions

**Key Classes**:
- `SessionStatus`: Enum with PENDING, IN_PROGRESS, COMPLETED, FAILED, TIMEOUT
- `SessionResult`: Contains pr_url, branch_name, commits, files_modified, alerts_fixed, summary, diff, commit_messages
- `DevinSession`: Main session model with session_id, status, created_at, updated_at, alerts, result, error_message, repository_url, instructions, metadata

**Key Methods**:
- `is_terminal()`: Check if session is in terminal state (completed, failed, or timeout)
- `is_successful()`: Check if session completed successfully

### 7. Configuration (`src/config.py`)

**Status**: IMPLEMENTED

**Responsibility**: Centralized configuration management

**Key Methods**:
- `load_from_env()`: Load configuration from environment variables
- `validate()`: Ensure all required config is present and valid

**Configuration Items**:
- `GITHUB_TOKEN`: GitHub API authentication (required)
- `GITHUB_REPOSITORY`: Target repository in owner/repo format (required)
- `DEVIN_API_KEY`: Devin API authentication (required)
- `DEVIN_API_URL`: Devin API endpoint (default: https://api.devin.ai/v1)
- `BATCH_SIZE`: Maximum alerts per batch (default: 5)
- `BATCH_STRATEGY`: Strategy to use - "file" or "severity" (default: file)
- `BASE_BRANCH`: Branch to create PRs against (default: main)
- `PUSH_MODE`: If true, Devin pushes branches; if false, use diff-only workflow (default: false)

## Implementation Details

### Blocked Status Handling

The `wait_for_completion()` method in DevinClient treats "blocked" as a terminal state. When a session status is "blocked", the polling loop tracks this state. If "blocked" is observed twice consecutively, the session status is set to COMPLETED and result retrieval proceeds normally. This allows the workflow to continue even when Devin is waiting for user input.

### Structured Output Parsing

Session results are extracted from `structured_output.json_summary` returned by the Devin API:
- `branch_name`: Name of the branch created by Devin
- `files_modified`: List of files that were changed
- `commit_messages`: List of commit messages from Devin's work
- `unified_diff`: Complete diff of all changes

If `structured_output` is missing or incomplete, a fallback parser (`_parse_devin_output()`) extracts "JSON Summary" and "Unified Diff" sections from raw text output.

### PR Creation Workflow

The system supports two execution paths based on `push_mode` configuration:

1. **Push Mode (push_mode=True)**: Devin pushes branches directly to the repository
   - System verifies the pushed branch exists on GitHub
   - If branch exists, uses it directly for PR creation
   - If branch doesn't exist, falls back to diff-only workflow

2. **Diff-Only Mode (push_mode=False, default)**: System handles branch creation
   - Devin generates unified diff without pushing
   - GitHubClient creates branch from base
   - GitHubClient applies diff using `apply_diff()` method
   - System creates PR from the newly created branch

Both paths result in automatic PR creation with alert details and session links.

## GitHub Action Integration

The system runs as a GitHub Action with the following configuration:

**Triggers**: Scheduled (e.g., weekly) or manual workflow_dispatch

**Required Permissions**:
- `contents: write` - Create branches and commits
- `pull-requests: write` - Create PRs
- `security-events: read` - Read CodeQL alerts

**Execution**: Runs `python src/main.py` with environment variables configured

## Environment Variables

Required:
- `GITHUB_TOKEN`: GitHub API token with repo and security-events permissions
- `GITHUB_REPOSITORY`: Repository in owner/repo format
- `DEVIN_API_KEY`: Devin API authentication key

Optional:
- `DEVIN_API_URL`: Devin API base URL (default: https://api.devin.ai/v1)
- `BATCH_SIZE`: Maximum alerts per batch (default: 5)
- `BATCH_STRATEGY`: Batching strategy (default: file)
- `BASE_BRANCH`: Base branch for PRs (default: main)
- `PUSH_MODE`: If true, Devin pushes branches; if false, use diff-only workflow (default: false)

## Error Handling

The system implements comprehensive error handling:

1. **GitHub API Errors**: Custom `GitHubClientError` exception with retry logic, exponential backoff, and rate limit handling
2. **Devin API Errors**: Custom `DevinClientError` exception with retry for transient errors (500s), immediate failure for client errors (400s)
3. **Session Timeouts**: Configurable timeout (default: 3600s) with poll interval (default: 30s) and max polls limit
4. **Partial Failures**: Workflow continues processing remaining batches if one fails; all results are collected in summary.json

## Testing

The system includes comprehensive test coverage:

1. **Unit Tests**: Each module has independent tests with mocks (test_github_client.py, test_devin_client.py, test_batch_strategy.py)
2. **Integration Tests**: Tests for GitHub and Devin API interactions with real API responses
3. **Simple Integration Test**: Basic workflow validation (simple_integration_test.py)
