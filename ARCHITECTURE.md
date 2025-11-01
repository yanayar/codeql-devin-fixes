# CodeQL-Devin Fixes Architecture

## Overview

This GitHub Action automatically identifies and fixes CodeQL security issues using Devin AI. The system fetches open CodeQL alerts from a repository, batches them strategically, and uses Devin to generate fixes for each batch, creating pull requests with the proposed changes.

## High-Level Workflow

1. **Trigger**: GitHub Action runs on schedule or manual trigger
2. **Fetch Alerts**: Retrieve open CodeQL alerts via GitHub API
3. **Batch Alerts**: Group alerts by file, issue type, or count limit
4. **Process Batches**: For each batch:
   - Create a Devin session with alert details
   - Wait for Devin to generate fixes
   - Create a new branch and pull request with fixes
5. **Report**: Summarize results and link to created PRs

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

**Responsibility**: Entry point that coordinates the entire workflow

**Key Methods**:
- `main()`: Main entry point that orchestrates the workflow
- `parse_arguments()`: Parse command-line arguments
- `load_config()`: Load configuration from environment variables
- `run_workflow()`: Execute the complete workflow

**Data Flow**:
- Reads: Environment variables, command-line arguments
- Writes: Logs, summary reports
- Calls: GitHubClient, BatchStrategy, DevinClient

### 2. GitHub Client (`src/github_client.py`)

**Responsibility**: Interface with GitHub API for alerts and PR management

**Key Methods**:
- `fetch_codeql_alerts()`: Retrieve all open CodeQL alerts
- `get_alert_details(alert_id)`: Get detailed information for a specific alert
- `create_branch(branch_name, base_branch)`: Create a new branch
- `create_pull_request(branch, title, body)`: Create a PR with fixes
- `add_pr_comment(pr_number, comment)`: Add comments to PRs

**Data Flow**:
- Reads: GitHub API (alerts, repository info)
- Writes: GitHub API (branches, PRs, comments)
- Returns: Alert objects, PR objects

### 3. CodeQL Alert Model (`src/models/alert.py`)

**Responsibility**: Data model for CodeQL alerts

**Key Attributes**:
- `alert_id`: Unique identifier
- `rule_id`: CodeQL rule that triggered
- `severity`: Critical, high, medium, low
- `file_path`: File containing the issue
- `line_number`: Line where issue occurs
- `message`: Description of the issue
- `recommendation`: Suggested fix

### 4. Batch Strategy (`src/batch_strategy.py`)

**Responsibility**: Group alerts into logical batches for processing

**Key Functions**:
- `batch_by_file(alerts, max_per_batch)`: Group alerts by file path, reducing context switching
- `batch_by_severity(alerts, max_per_batch)`: Group by severity level, prioritizing critical issues
- `create_batches(alerts, strategy, max_per_batch)`: Main entry point that dispatches to the appropriate strategy

**Batching Strategies**:

1. **File-Based (`file`)**: Groups alerts by file to minimize context switching for Devin. When fixing multiple issues in the same file, Devin can load the file context once, understand the code structure better, and make related fixes together. This reduces merge conflicts but may delay high-severity issues in files with many low-severity alerts.

2. **Severity-Based (`severity`)**: Prioritizes critical security issues first by sorting alerts from critical to low severity. This ensures the most important vulnerabilities are addressed immediately, improving security posture incrementally. However, it may cause more context switching between files and potential merge conflicts.

**Data Flow**:
- Reads: List of Alert objects, strategy name, max batch size
- Returns: List of batches (each batch is a list of alerts)

### 5. Devin Client (`src/devin_client.py`)

**Responsibility**: Interface with Devin API to create fix sessions

**Key Methods**:
- `create_session(repo_url, alerts, instructions)`: Start a Devin session
- `get_session_status(session_id)`: Check session progress
- `wait_for_completion(session_id, timeout)`: Poll until session completes
- `get_session_result(session_id)`: Retrieve fixes and PR info

**Data Flow**:
- Reads: Alert details, repository information
- Writes: Devin API (session creation, instructions)
- Returns: Session objects, fix results

### 6. Session Model (`src/models/session.py`)

**Responsibility**: Data model for Devin sessions

**Key Attributes**:
- `session_id`: Unique session identifier
- `status`: pending, in_progress, completed, failed
- `created_at`: Timestamp
- `alerts`: List of alerts being fixed
- `result`: Session outcome (PR URL, branch name, etc.)

### 7. Configuration (`src/config.py`)

**Responsibility**: Centralized configuration management

**Key Methods**:
- `load_from_env()`: Load configuration from environment variables
- `validate()`: Ensure all required config is present

**Configuration Items**:
- `GITHUB_TOKEN`: GitHub API authentication
- `GITHUB_REPOSITORY`: Target repository (owner/repo)
- `DEVIN_API_KEY`: Devin API authentication
- `DEVIN_API_URL`: Devin API endpoint
- `BATCH_SIZE`: Maximum alerts per batch
- `BATCH_STRATEGY`: Strategy to use (file or severity)
- `BASE_BRANCH`: Branch to create PRs against (default: main)

## GitHub Action YAML Structure

The action should be defined in `.github/workflows/codeql-fixes.yml`:

```yaml
name: CodeQL Fixes with Devin

on:
  schedule:
    - cron: '0 0 * * 1'  # Weekly on Monday
  workflow_dispatch:      # Manual trigger

permissions:
  contents: write
  pull-requests: write
  security-events: read

jobs:
  fix-codeql-issues:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install dependencies
        run: |
          pip install -r requirements.txt
      
      - name: Run CodeQL fixes
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          GITHUB_REPOSITORY: ${{ github.repository }}
          DEVIN_API_KEY: ${{ secrets.DEVIN_API_KEY }}
          DEVIN_API_URL: https://api.devin.ai/v1
          BATCH_SIZE: 5
          BATCH_STRATEGY: file
          BASE_BRANCH: main
        run: |
          python src/main.py
```

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
- `DRY_RUN`: If true, don't create PRs (default: false)

## Error Handling

Each module should implement proper error handling:

1. **GitHub API Errors**: Retry with exponential backoff, log failures
2. **Devin API Errors**: Retry transient errors, fail fast on auth errors
3. **Session Timeouts**: Configurable timeout with graceful degradation
4. **Partial Failures**: Continue processing remaining batches if one fails

## Testing Strategy

1. **Unit Tests**: Test each module independently with mocks
2. **Integration Tests**: Test GitHub and Devin API interactions
3. **End-to-End Tests**: Full workflow test with test repository

## Future Enhancements

1. Support for custom batching strategies
2. Parallel processing of batches
3. Incremental fixes (only new alerts since last run)
4. Custom Devin instructions per rule type
5. Metrics and reporting dashboard
