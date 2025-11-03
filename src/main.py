"""
Main orchestrator for CodeQL-Devin fixes workflow.

This module coordinates the entire workflow:
1. Load configuration from environment
2. Fetch CodeQL alerts from GitHub
3. Batch alerts using configured strategy
4. Create Devin sessions for each batch
5. Wait for fixes and create PRs
6. Report results
"""
from dotenv import load_dotenv
load_dotenv()

import sys
import logging
from typing import List, Dict, Any

from config import Config
from github_client import GitHubClient
from devin_client import DevinClient
from batch_strategy import create_batches
from models.alert import CodeQLAlert


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def main():
    """
    Main entry point for the CodeQL-Devin fixes workflow.

    This function orchestrates the complete workflow:
    1. Load and validate configuration
    2. Initialize GitHub and Devin clients
    3. Fetch open CodeQL alerts
    4. Batch alerts using configured strategy
    5. Process each batch with Devin
    6. Generate summary report

    Returns:
        Exit code (0 for success, 1 for failure)
    """
    try:
        logger.info("Starting CodeQL-Devin fixes workflow")

        config = load_config()
        logger.info(f"Configuration loaded: {config}")

        github_client = initialize_github_client(config)
        devin_client = initialize_devin_client(config)

        alerts = fetch_alerts(github_client)
        if not alerts:
            logger.info("No open CodeQL alerts found. Nothing to fix.")
            return 0

        logger.info(f"Found {len(alerts)} open CodeQL alerts")

        batches = batch_alerts(alerts, config)
        logger.info(f"Created {len(batches)} batches using {config.batch_strategy} strategy")

        results = process_batches(batches, github_client, devin_client, config)

        generate_summary(results, config)

        logger.info("Workflow completed successfully")
        return 0

    except Exception as e:
        logger.error(f"Workflow failed: {e}", exc_info=True)
        return 1


def load_config() -> Config:
    """
    Load and validate configuration from environment variables.

    Returns:
        Config object with validated settings

    Raises:
        ValueError: If required configuration is missing or invalid

    Note:
        This will call Config.load_from_env() and Config.validate()
    """
    config = Config.load_from_env()
    config.validate()
    return config


def initialize_github_client(config: Config) -> GitHubClient:
    """
    Initialize GitHub API client.

    Args:
        config: Application configuration

    Returns:
        GitHubClient instance

    Raises:
        Exception: If GitHub authentication fails

    Note:
        This should:
        1. Create GitHubClient with token and repo name
        2. Verify permissions (check_permissions())
        3. Log repository information
    """
    logger.info(f"Initializing GitHub client for {config.github_repository}")
    
    client = GitHubClient(
        token=config.github_token,
        repo_name=config.github_repository
    )
    
    repo_info = client.get_repository_info()
    logger.info(f"Connected to repository: {repo_info['full_name']}")
    logger.info(f"Default branch: {repo_info['default_branch']}")
    
    permissions = client.check_permissions()
    if not permissions['can_read_alerts']:
        logger.warning("Token may not have permission to read code scanning alerts")
    if not permissions['can_create_branches'] or not permissions['can_create_prs']:
        logger.warning("Token may not have permission to create branches or PRs")
    
    return client


def initialize_devin_client(config: Config) -> DevinClient:
    """
    Initialize Devin API client.

    Args:
        config: Application configuration

    Returns:
        DevinClient instance

    Note:
        This should create DevinClient with API key and base URL
    """
    logger.info("Initializing Devin API client")
    
    client = DevinClient(
        api_key=config.devin_api_key,
        base_url=config.devin_api_url
    )
    
    return client


def fetch_alerts(github_client: GitHubClient) -> List[CodeQLAlert]:
    """
    Fetch open CodeQL alerts from GitHub.

    Args:
        github_client: GitHub API client

    Returns:
        List of open CodeQL alerts

    Raises:
        Exception: If fetching alerts fails

    Note:
        This should:
        1. Call github_client.fetch_codeql_alerts(state="open")
        2. Filter out any alerts that should be skipped
        3. Log alert summary (count by severity, etc.)
    """
    logger.info("Fetching open CodeQL alerts")
    
    alerts = github_client.fetch_codeql_alerts(state="open")
    
    if alerts:
        severity_counts = {}
        for alert in alerts:
            sev = alert.severity.lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        logger.info(f"Found {len(alerts)} open alerts: {severity_counts}")
    
    return alerts


def batch_alerts(alerts: List[CodeQLAlert], config: Config) -> List[List[CodeQLAlert]]:
    """
    Group alerts into batches using configured strategy.

    Args:
        alerts: List of all alerts
        config: Application configuration

    Returns:
        List of batches (each batch is a list of alerts)

    Note:
        This calls create_batches() with the configured strategy and logs
        batch information for traceability.
    """
    batches = create_batches(
        alerts,
        strategy=config.batch_strategy,
        max_per_batch=config.batch_size
    )

    for i, batch in enumerate(batches, 1):
        logger.info(f"Batch {i}: {len(batch)} alerts")
        if batch:
            severities = {}
            for alert in batch:
                sev = alert.severity.lower()
                severities[sev] = severities.get(sev, 0) + 1
            logger.info(f"  Severity breakdown: {severities}")

    return batches


def process_batches(
    batches: List[List[CodeQLAlert]],
    github_client: GitHubClient,
    devin_client: DevinClient,
    config: Config
) -> List[Dict[str, Any]]:
    """
    Process each batch of alerts with Devin.

    Args:
        batches: List of alert batches
        github_client: GitHub API client
        devin_client: Devin API client
        config: Application configuration

    Returns:
        List of results for each batch

    Note:
        For each batch, this should:
        1. Create a Devin session with the alerts
        2. Wait for session to complete
        3. Check if session was successful
        4. If dry_run is False, verify PR was created
        5. Collect results for summary

        If a batch fails, log the error and continue with remaining batches.
    """
    results = []
    
    for i, batch in enumerate(batches, 1):
        logger.info(f"Processing batch {i}/{len(batches)} with {len(batch)} alerts")
        
        try:
            result = process_single_batch(
                batch_num=i,
                alerts=batch,
                github_client=github_client,
                devin_client=devin_client,
                config=config
            )
            results.append(result)
            
            if result.get('status') == 'success':
                logger.info(f"Batch {i} completed successfully")
                if result.get('pr_url'):
                    logger.info(f"PR created: {result['pr_url']}")
            else:
                logger.error(f"Batch {i} failed: {result.get('error', 'Unknown error')}")
                
        except Exception as e:
            logger.error(f"Batch {i} failed with exception: {e}", exc_info=True)
            results.append({
                'batch_num': i,
                'alert_count': len(batch),
                'status': 'failed',
                'error': str(e)
            })
    
    return results


def process_single_batch(
    batch_num: int,
    alerts: List[CodeQLAlert],
    github_client: GitHubClient,
    devin_client: DevinClient,
    config: Config
) -> Dict[str, Any]:
    """
    Process a single batch of alerts.

    Args:
        batch_num: Batch number (for logging)
        alerts: Alerts in this batch
        github_client: GitHub API client
        devin_client: Devin API client
        config: Application configuration

    Returns:
        Dictionary with batch results:
        - batch_num: Batch number
        - alert_count: Number of alerts
        - session_id: Devin session ID
        - status: Success/failure status
        - pr_url: PR URL if created
        - error: Error message if failed

    Note:
        This should:
        1. Get repository info from github_client
        2. Create Devin session with alerts
        3. Wait for completion (with timeout)
        4. Get session result
        5. Return structured result
    """
    try:
        repo_info = github_client.get_repository_info()
        repo_url = repo_info['clone_url']
        
        branch_name = f"codeql-fix/batch-{batch_num}"
        
        logger.info(f"Creating Devin session for batch {batch_num}")
        
        secret_ids = None if config.push_mode else []
        
        session = devin_client.create_session(
            repo_url=repo_url,
            alerts=alerts,
            base_branch=config.base_branch,
            branch_name=branch_name,
            batch_number=batch_num,
            secret_ids=secret_ids,
            push_mode=config.push_mode,
            title=f"Fix CodeQL alerts (batch {batch_num})"
        )
        
        branch_name = f"codeql-fix/batch-{batch_num}-{session.session_id}"
        
        logger.info(f"Waiting for Devin session {session.session_id} to complete")
        completed_session = devin_client.wait_for_completion(
            session_id=session.session_id,
            timeout=3600,
            poll_interval=30
        )
        
        if not completed_session.is_successful():
            return {
                'batch_num': batch_num,
                'alert_count': len(alerts),
                'session_id': session.session_id,
                'status': 'failed',
                'error': f"Session failed with status: {completed_session.status.value}"
            }
        
        result = devin_client.get_session_result(session.session_id)
        
        if config.dry_run:
            logger.info(f"Dry run mode: skipping PR creation for batch {batch_num}")
            return {
                'batch_num': batch_num,
                'alert_count': len(alerts),
                'session_id': session.session_id,
                'status': 'success',
                'dry_run': True,
                'branch_name': result.branch_name or branch_name,
                'files_modified': result.files_modified
            }
        
        if not config.push_mode:
            if not result.diff:
                logger.error(f"No diff found in session result for batch {batch_num}")
                return {
                    'batch_num': batch_num,
                    'alert_count': len(alerts),
                    'session_id': session.session_id,
                    'status': 'failed',
                    'error': 'No diff found in session result'
                }
            
            logger.info(f"Diff-only mode: creating branch '{branch_name}' and applying diff")
            github_client.create_branch(
                branch_name=branch_name,
                base_branch=config.base_branch
            )
            
            commits = github_client.apply_diff(
                diff=result.diff,
                branch=branch_name,
                commit_message="Fix CodeQL security issues"
            )
        elif result.branch_name:
            logger.info(f"Devin pushed branch '{result.branch_name}', checking if it exists on GitHub")
            try:
                repo_info = github_client.get_repository_info()
                repo = github_client.repo
                try:
                    repo.get_git_ref(f'heads/{result.branch_name}')
                    logger.info(f"Branch '{result.branch_name}' exists on GitHub, skipping create_branch and apply_diff")
                    branch_name = result.branch_name
                    commits = result.commit_messages or []
                except Exception as e:
                    logger.warning(f"Branch '{result.branch_name}' not found on GitHub: {e}")
                    logger.info(f"Falling back to apply_diff workflow")
                    if not result.diff:
                        logger.error(f"No diff found and branch not pushed for batch {batch_num}")
                        return {
                            'batch_num': batch_num,
                            'alert_count': len(alerts),
                            'session_id': session.session_id,
                            'status': 'failed',
                            'error': 'No diff found and branch not pushed'
                        }
                    
                    logger.info(f"Creating branch '{branch_name}' for batch {batch_num}")
                    github_client.create_branch(
                        branch_name=branch_name,
                        base_branch=config.base_branch
                    )
                    
                    logger.info(f"Applying diff to branch '{branch_name}'")
                    commits = github_client.apply_diff(
                        diff=result.diff,
                        branch=branch_name,
                        commit_message="Fix CodeQL security issues"
                    )
            except Exception as e:
                logger.error(f"Error checking if branch exists: {e}")
                if not result.diff:
                    logger.error(f"No diff found and cannot verify branch for batch {batch_num}")
                    return {
                        'batch_num': batch_num,
                        'alert_count': len(alerts),
                        'session_id': session.session_id,
                        'status': 'failed',
                        'error': f'No diff found and cannot verify branch: {str(e)}'
                    }
                
                logger.info(f"Creating branch '{branch_name}' for batch {batch_num}")
                github_client.create_branch(
                    branch_name=branch_name,
                    base_branch=config.base_branch
                )
                
                logger.info(f"Applying diff to branch '{branch_name}'")
                commits = github_client.apply_diff(
                    diff=result.diff,
                    branch=branch_name,
                    commit_message="Fix CodeQL security issues"
                )
        else:
            if not result.diff:
                logger.warning(f"No diff found in session result for batch {batch_num}")
                return {
                    'batch_num': batch_num,
                    'alert_count': len(alerts),
                    'session_id': session.session_id,
                    'status': 'failed',
                    'error': 'No diff found in session result'
                }
            
            logger.info(f"Creating branch '{branch_name}' for batch {batch_num}")
            github_client.create_branch(
                branch_name=branch_name,
                base_branch=config.base_branch
            )
            
            logger.info(f"Applying diff to branch '{branch_name}'")
            commits = github_client.apply_diff(
                diff=result.diff,
                branch=branch_name,
                commit_message="Fix CodeQL security issues"
            )
        
        pr_title = f"Fix CodeQL security alerts (batch {batch_num})"
        pr_body = f"""## CodeQL Security Fixes

This PR addresses {len(alerts)} CodeQL security alert(s) identified in the repository.

"""
        for i, alert in enumerate(alerts, 1):
            pr_body += f"\n{i}. **{alert.rule_id}** ({alert.severity})"
            pr_body += f"\n   - File: `{alert.file_path}:{alert.line_number}`"
            pr_body += f"\n   - Issue: {alert.message}"
        
        pr_body += f"\n\n### Changes\n"
        pr_body += f"- Files modified: {len(result.files_modified)}\n"
        pr_body += f"- Commits: {len(commits)}\n"
        
        if result.summary:
            pr_body += f"\n### Summary\n{result.summary}\n"
        
        pr_body += f"\n---\n"
        pr_body += f"Generated by automated CodeQL fixes workflow\n"
        pr_body += f"Devin session: {devin_client.get_session_url(session.session_id)}\n"
        
        logger.info(f"Creating PR for batch {batch_num}")
        pr = github_client.create_pull_request(
            branch=branch_name,
            title=pr_title,
            body=pr_body,
            base_branch=config.base_branch
        )
        
        return {
            'batch_num': batch_num,
            'alert_count': len(alerts),
            'session_id': session.session_id,
            'status': 'success',
            'pr_url': pr.html_url,
            'pr_number': pr.number,
            'branch_name': branch_name,
            'commits': commits,
            'files_modified': result.files_modified
        }
        
    except Exception as e:
        logger.error(f"Error processing batch {batch_num}: {e}", exc_info=True)
        return {
            'batch_num': batch_num,
            'alert_count': len(alerts),
            'status': 'failed',
            'error': str(e)
        }


def generate_summary(results: List[Dict[str, Any]], config: Config) -> None:
    """
    Generate and save workflow summary.

    Args:
        results: List of batch processing results
        config: Application configuration

    Note:
        This should:
        1. Calculate statistics (total alerts, successful batches, etc.)
        2. Create summary dictionary
        3. Save to summary.json file
        4. Log summary to console

        Summary should include:
        - Total alerts processed
        - Number of batches
        - Successful/failed batches
        - List of created PRs
        - Execution time
    """
    import json
    from datetime import datetime
    
    total_alerts = sum(r.get('alert_count', 0) for r in results)
    successful_batches = sum(1 for r in results if r.get('status') == 'success')
    failed_batches = sum(1 for r in results if r.get('status') == 'failed')
    
    prs_created = [
        {
            'batch_num': r['batch_num'],
            'pr_url': r['pr_url'],
            'pr_number': r.get('pr_number'),
            'alerts_fixed': r.get('alert_count')
        }
        for r in results if r.get('pr_url')
    ]
    
    summary = {
        'timestamp': datetime.utcnow().isoformat(),
        'repository': config.github_repository,
        'batch_strategy': config.batch_strategy,
        'batch_size': config.batch_size,
        'dry_run': config.dry_run,
        'statistics': {
            'total_batches': len(results),
            'successful_batches': successful_batches,
            'failed_batches': failed_batches,
            'total_alerts_processed': total_alerts,
            'prs_created': len(prs_created)
        },
        'pull_requests': prs_created,
        'results': results
    }
    
    with open('summary.json', 'w') as f:
        json.dump(summary, f, indent=2)
    
    logger.info("=" * 60)
    logger.info("WORKFLOW SUMMARY")
    logger.info("=" * 60)
    logger.info(f"Repository: {config.github_repository}")
    logger.info(f"Total batches: {len(results)}")
    logger.info(f"Successful: {successful_batches}")
    logger.info(f"Failed: {failed_batches}")
    logger.info(f"Total alerts processed: {total_alerts}")
    logger.info(f"PRs created: {len(prs_created)}")
    
    if prs_created:
        logger.info("\nPull Requests:")
        for pr in prs_created:
            logger.info(f"  - Batch {pr['batch_num']}: {pr['pr_url']}")
    
    if failed_batches > 0:
        logger.info("\nFailed batches:")
        for r in results:
            if r.get('status') == 'failed':
                logger.info(f"  - Batch {r['batch_num']}: {r.get('error', 'Unknown error')}")
    
    logger.info("=" * 60)
    logger.info(f"Summary saved to summary.json")


if __name__ == "__main__":
    sys.exit(main())
