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
    github_client = GitHubClient(
        token=config.github_token,
        repo_name=config.github_repository
    )
    
    repo_info = github_client.get_repository_info()
    logger.info(f"Connected to repository: {repo_info['full_name']}")
    logger.info(f"Default branch: {repo_info['default_branch']}")
    
    permissions = github_client.check_permissions()
    logger.info(f"Permissions: {permissions}")
    
    return github_client


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
    logger.info("Initializing Devin client")
    devin_client = DevinClient(
        api_key=config.devin_api_key,
        base_url=config.devin_api_url
    )
    return devin_client


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
        logger.info(f"Alert severity breakdown: {severity_counts}")
    
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
                'status': 'error',
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
        
        logger.info(f"Creating Devin session for batch {batch_num}")
        session = devin_client.create_session(
            repo_url=repo_url,
            alerts=alerts,
            base_branch=config.base_branch
        )
        
        logger.info(f"Session created: {session.session_id}")
        session_url = devin_client.get_session_url(session.session_id)
        logger.info(f"Session URL: {session_url}")
        
        if config.dry_run:
            logger.info("Dry run mode: skipping wait for completion")
            return {
                'batch_num': batch_num,
                'alert_count': len(alerts),
                'session_id': session.session_id,
                'session_url': session_url,
                'status': 'dry_run',
                'pr_url': None
            }
        
        logger.info(f"Waiting for session {session.session_id} to complete")
        completed_session = devin_client.wait_for_completion(session.session_id)
        
        if completed_session.is_successful():
            result = devin_client.get_session_result(session.session_id)
            return {
                'batch_num': batch_num,
                'alert_count': len(alerts),
                'session_id': session.session_id,
                'session_url': session_url,
                'status': 'success',
                'pr_url': result.pr_url,
                'summary': result.summary
            }
        else:
            error_msg = completed_session.error_message or f"Session ended with status: {completed_session.status.value}"
            return {
                'batch_num': batch_num,
                'alert_count': len(alerts),
                'session_id': session.session_id,
                'session_url': session_url,
                'status': 'failed',
                'error': error_msg
            }
    
    except TimeoutError as e:
        logger.error(f"Batch {batch_num} timed out: {e}")
        return {
            'batch_num': batch_num,
            'alert_count': len(alerts),
            'session_id': session.session_id if 'session' in locals() else None,
            'session_url': session_url if 'session_url' in locals() else None,
            'status': 'timeout',
            'error': f"Session timed out: {str(e)}"
        }
            
    except Exception as e:
        logger.error(f"Error processing batch {batch_num}: {e}", exc_info=True)
        return {
            'batch_num': batch_num,
            'alert_count': len(alerts),
            'status': 'error',
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
    total_batches = len(results)
    successful_batches = sum(1 for r in results if r.get('status') == 'success')
    failed_batches = sum(1 for r in results if r.get('status') in ['failed', 'error'])
    timeout_batches = sum(1 for r in results if r.get('status') == 'timeout')
    dry_run_batches = sum(1 for r in results if r.get('status') == 'dry_run')
    
    pr_urls = [r.get('pr_url') for r in results if r.get('pr_url')]
    session_urls = [r.get('session_url') for r in results if r.get('session_url')]
    
    summary = {
        'timestamp': datetime.utcnow().isoformat(),
        'repository': config.github_repository,
        'batch_strategy': config.batch_strategy,
        'batch_size': config.batch_size,
        'dry_run': config.dry_run,
        'statistics': {
            'total_alerts': total_alerts,
            'total_batches': total_batches,
            'successful_batches': successful_batches,
            'failed_batches': failed_batches,
            'timeout_batches': timeout_batches,
            'dry_run_batches': dry_run_batches
        },
        'pr_urls': pr_urls,
        'session_urls': session_urls,
        'results': results
    }
    
    with open('summary.json', 'w') as f:
        json.dump(summary, f, indent=2)
    
    logger.info("=" * 60)
    logger.info("WORKFLOW SUMMARY")
    logger.info("=" * 60)
    logger.info(f"Repository: {config.github_repository}")
    logger.info(f"Total alerts processed: {total_alerts}")
    logger.info(f"Total batches: {total_batches}")
    logger.info(f"Successful batches: {successful_batches}")
    logger.info(f"Failed batches: {failed_batches}")
    if timeout_batches > 0:
        logger.info(f"Timeout batches: {timeout_batches}")
    if dry_run_batches > 0:
        logger.info(f"Dry run batches: {dry_run_batches}")
    
    if pr_urls:
        logger.info(f"PRs created: {len(pr_urls)}")
        for pr_url in pr_urls:
            logger.info(f"  - {pr_url}")
    
    if session_urls:
        logger.info(f"Devin sessions: {len(session_urls)}")
        for session_url in session_urls:
            logger.info(f"  - {session_url}")
    
    logger.info("=" * 60)
    logger.info(f"Summary saved to summary.json")


if __name__ == "__main__":
    sys.exit(main())
