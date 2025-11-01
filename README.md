# CodeQL-Devin Fixes

Automatically identify and fix CodeQL security issues using Devin AI.

## Overview

This GitHub Action fetches open CodeQL alerts from your repository, batches them strategically, and uses Devin to generate fixes for each batch. The action creates pull requests with the proposed security fixes, making it easy to review and merge improvements.

## Features

- **Automated Security Fixes**: Automatically fix CodeQL security issues using Devin AI
- **Intelligent Batching**: Group alerts by file, severity, rule type, or count
- **Pull Request Creation**: Automatically create PRs with fixes for easy review
- **Configurable**: Customize batch size, strategy, and other settings
- **Dry Run Mode**: Test the workflow without creating actual PRs

## Architecture

For detailed architecture documentation, see [ARCHITECTURE.md](ARCHITECTURE.md).

### High-Level Workflow

1. GitHub Action triggers (scheduled or manual)
2. Fetch open CodeQL alerts via GitHub API
3. Batch alerts using configured strategy
4. For each batch:
   - Create a Devin session with alert details
   - Wait for Devin to generate fixes
   - Create a pull request with the fixes
5. Generate summary report

### Module Structure

```
src/
├── main.py              # Main orchestrator
├── config.py            # Configuration management
├── github_client.py     # GitHub API client
├── devin_client.py      # Devin API client
├── batch_strategy.py    # Alert batching strategies
└── models/
    ├── alert.py         # CodeQL alert data model
    └── session.py       # Devin session data model
```

## Setup

### Prerequisites

- Python 3.11+
- GitHub repository with CodeQL configured
- Devin API access

### Installation

1. Clone this repository or add it to your project
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Configuration

#### Required Secrets

Add these secrets to your GitHub repository:

- `DEVIN_API_KEY`: Your Devin API authentication key

#### Required Permissions

The GitHub Action needs these permissions:
- `contents: write` - Create branches
- `pull-requests: write` - Create PRs
- `security-events: read` - Read CodeQL alerts

### GitHub Action Setup

1. Copy `.github/workflows/codeql-fixes.yml` to your repository
2. Configure the workflow schedule or trigger manually
3. Set required secrets in repository settings

The action will run automatically based on the schedule or can be triggered manually from the Actions tab.

## Usage

### Running Locally

```bash
export GITHUB_TOKEN="your-github-token"
export GITHUB_REPOSITORY="owner/repo"
export DEVIN_API_KEY="your-devin-api-key"
export BATCH_SIZE=5
export BATCH_STRATEGY="file"

python src/main.py
```

### Running as GitHub Action

The action runs automatically based on the configured schedule. You can also trigger it manually:

1. Go to the Actions tab in your repository
2. Select "CodeQL Fixes with Devin"
3. Click "Run workflow"
4. Configure options (optional):
   - Batch size
   - Batch strategy
   - Dry run mode

## Configuration Options

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `GITHUB_TOKEN` | Yes | - | GitHub API token |
| `GITHUB_REPOSITORY` | Yes | - | Repository in owner/repo format |
| `DEVIN_API_KEY` | Yes | - | Devin API key |
| `DEVIN_API_URL` | No | `https://api.devin.ai/v1` | Devin API base URL |
| `BATCH_SIZE` | No | `5` | Maximum alerts per batch |
| `BATCH_STRATEGY` | No | `file` | Batching strategy |
| `BASE_BRANCH` | No | `main` | Base branch for PRs |
| `DRY_RUN` | No | `false` | Dry run mode (no PRs) |

### Batch Strategies

The system supports two batching strategies, each optimized for different scenarios:

#### File-Based Strategy (`file`)

Groups alerts that affect the same file together, reducing context switching for Devin.

**How it works:**
- Groups all alerts by file path
- Sorts alerts within each file by line number
- Splits files with >max_per_batch alerts into multiple batches
- Processes files in alphabetical order

**Benefits:**
- **Reduced Context Switching**: Devin loads each file's context once and fixes multiple issues together
- **Better Code Understanding**: Working on one file at a time allows deeper comprehension of the code structure
- **Related Fixes**: Issues in the same file are often related and can be fixed together more efficiently
- **Fewer Merge Conflicts**: Changes are localized to specific files, reducing the risk of conflicts

**Tradeoffs:**
- May delay high-severity issues if they're in files with many low-severity alerts
- Less optimal if critical vulnerabilities are spread across many files

**Best for:**
- Repositories with concentrated issues in specific files
- When code context and understanding are priorities
- Teams that prefer localized, focused changes

#### Severity-Based Strategy (`severity`)

Prioritizes fixing the most critical security issues first, regardless of file location.

**How it works:**
- Sorts all alerts by severity: critical → high → medium → low → warning → note
- Breaks ties by file path and line number for deterministic ordering
- Splits into batches of max_per_batch size
- Processes highest severity alerts first

**Benefits:**
- **Risk Prioritization**: Critical vulnerabilities are addressed immediately
- **Clear Impact**: Security posture improves incrementally with each batch
- **Compliance**: Helps meet security requirements by fixing high-severity issues first
- **Measurable Progress**: Easy to track risk reduction over time

**Tradeoffs:**
- More context switching between files as Devin jumps between different locations
- Potential for more merge conflicts if multiple batches touch the same files
- May be less efficient if many critical issues are in the same file

**Best for:**
- Security-critical applications where risk reduction is paramount
- Compliance-driven workflows that require addressing high-severity issues first
- Repositories with well-distributed issues across many files

#### Choosing a Strategy

**Use `file` strategy when:**
- You have many alerts concentrated in specific files
- Code context and understanding are important
- You want to minimize merge conflicts
- Development efficiency is a priority

**Use `severity` strategy when:**
- Security risk reduction is the top priority
- You need to demonstrate compliance with security standards
- Critical issues are spread across many files
- You want clear, measurable security improvements

## Development

### Project Structure

```
.
├── .github/
│   └── workflows/
│       └── codeql-fixes.yml    # GitHub Action workflow
├── src/
│   ├── main.py                 # Main orchestrator
│   ├── config.py               # Configuration management
│   ├── github_client.py        # GitHub API client
│   ├── devin_client.py         # Devin API client
│   ├── batch_strategy.py       # Batching strategies
│   └── models/
│       ├── __init__.py
│       ├── alert.py            # Alert data model
│       └── session.py          # Session data model
├── requirements.txt            # Python dependencies
├── ARCHITECTURE.md             # Detailed architecture docs
└── README.md                   # This file
```

### Implementation Status

This project currently contains stub implementations with comprehensive docstrings. The following components need to be implemented:

#### GitHub Client (`src/github_client.py`)
- [ ] `fetch_codeql_alerts()` - Fetch alerts from GitHub Code Scanning API
- [ ] `get_alert_details()` - Get detailed alert information
- [ ] `create_branch()` - Create branch for fixes
- [ ] `create_pull_request()` - Create PR with fixes
- [ ] `add_pr_comment()` - Add comments to PRs
- [ ] `check_permissions()` - Verify token permissions

#### Devin Client (`src/devin_client.py`)
- [ ] `create_session()` - Create Devin session via API
- [ ] `get_session_status()` - Check session status
- [ ] `wait_for_completion()` - Poll until session completes
- [ ] `get_session_result()` - Retrieve session results
- [ ] `cancel_session()` - Cancel running session

#### Batch Strategy (`src/batch_strategy.py`)
- [x] `batch_by_file()` - Group by file (implemented)
- [x] `batch_by_severity()` - Group by severity (implemented)
- [x] `create_batches()` - Main batching function (implemented)

#### Main Orchestrator (`src/main.py`)
- [ ] `load_config()` - Load and validate configuration
- [ ] `initialize_github_client()` - Initialize GitHub client
- [ ] `initialize_devin_client()` - Initialize Devin client
- [ ] `fetch_alerts()` - Fetch alerts from GitHub
- [ ] `batch_alerts()` - Batch alerts using strategy
- [ ] `process_batches()` - Process all batches
- [ ] `process_single_batch()` - Process one batch
- [ ] `generate_summary()` - Generate summary report

#### Data Models (`src/models/`)
- [ ] `CodeQLAlert.from_github_alert()` - Parse GitHub API response
- [ ] `CodeQLAlert.get_context_lines()` - Extract code context
- [ ] `DevinSession.from_api_response()` - Parse Devin API response

### Running Tests

```bash
pytest
```

### Code Style

This project follows Python best practices:
- Type hints for all function parameters and returns
- Comprehensive docstrings for all classes and methods
- No hardcoded credentials (use environment variables)
- Modular design for testability

## API Integration Notes

### GitHub Code Scanning API

The GitHub client will use the Code Scanning API to fetch alerts:

```
GET /repos/{owner}/{repo}/code-scanning/alerts
```

Documentation: https://docs.github.com/en/rest/code-scanning

### Devin API

The Devin client will integrate with the Devin API to create sessions and retrieve results. API documentation should be consulted for:
- Session creation endpoint
- Status polling endpoint
- Result retrieval format

## Troubleshooting

### No alerts found

- Ensure CodeQL is configured and has run on your repository
- Check that alerts are in "open" state
- Verify the GitHub token has `security-events: read` permission

### Authentication errors

- Verify `GITHUB_TOKEN` has required permissions
- Ensure `DEVIN_API_KEY` is valid and not expired
- Check that the repository name is in correct `owner/repo` format

### Session timeouts

- Increase timeout in `wait_for_completion()` call
- Check Devin API status for service issues
- Reduce batch size to process fewer alerts per session

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Implement your changes with tests
4. Submit a pull request

## License

MIT License - see LICENSE file for details

## Support

For issues or questions:
- Open an issue in this repository
- Consult [ARCHITECTURE.md](ARCHITECTURE.md) for detailed design
- Check Devin API documentation for API-specific questions
