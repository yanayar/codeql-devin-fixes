"""
Batching strategies for grouping CodeQL alerts.

This module provides two strategies for grouping alerts into batches
for processing by Devin:
- File-based: Groups alerts by file to reduce context switching
- Severity-based: Prioritizes critical issues first
"""
from typing import List
from collections import defaultdict

from models.alert import CodeQLAlert


SEVERITY_ORDER = ["critical", "high", "medium", "low", "warning", "note"]


def batch_by_file(
    alerts: List[CodeQLAlert],
    max_per_batch: int = 5
) -> List[List[CodeQLAlert]]:
    """
    Batch alerts by file path.

    This strategy groups alerts that affect the same file together, which
    reduces context switching for Devin. When fixing multiple issues in the
    same file, Devin can:
    - Load the file context once
    - Understand the code structure better
    - Make related fixes together
    - Reduce the risk of merge conflicts

    Tradeoffs:
    - Pros: Efficient context usage, related fixes together, fewer file loads
    - Cons: May delay high-severity issues in files with many low-severity ones

    Args:
        alerts: List of CodeQL alerts to batch
        max_per_batch: Maximum number of alerts per batch

    Returns:
        List of batches, where each batch contains alerts from the same file,
        sorted by line number. Files with >max_per_batch alerts are split
        into multiple batches.

    Example:
        If file.py has 12 alerts and max_per_batch=5:
        - Batch 1: file.py alerts 1-5 (lines 10-50)
        - Batch 2: file.py alerts 6-10 (lines 55-95)
        - Batch 3: file.py alerts 11-12 (lines 100-110)
    """
    if not alerts:
        return []

    file_groups = defaultdict(list)
    for alert in alerts:
        file_groups[alert.file_path].append(alert)

    batches = []
    for file_path in sorted(file_groups.keys()):
        file_alerts = sorted(file_groups[file_path], key=lambda a: a.line_number)

        for i in range(0, len(file_alerts), max_per_batch):
            batch = file_alerts[i:i + max_per_batch]
            batches.append(batch)

    return batches


def batch_by_severity(
    alerts: List[CodeQLAlert],
    max_per_batch: int = 5
) -> List[List[CodeQLAlert]]:
    """
    Batch alerts by severity level.

    This strategy prioritizes fixing the most critical security issues first.
    Alerts are sorted by severity (critical → high → medium → low → warning → note),
    then split into batches. This ensures that:
    - Critical vulnerabilities are addressed immediately
    - High-impact issues get fixed before low-impact ones
    - Security posture improves incrementally

    Tradeoffs:
    - Pros: Prioritizes impact, fixes critical issues first, clear risk reduction
    - Cons: May cause more context switching between files, potential merge conflicts

    Args:
        alerts: List of CodeQL alerts to batch
        max_per_batch: Maximum number of alerts per batch

    Returns:
        List of batches, sorted by severity priority. Within each batch,
        alerts are sorted by file path (for stability). Ties broken by
        file path name.

    Example:
        With 3 critical, 5 high, and 2 medium alerts (max_per_batch=5):
        - Batch 1: 3 critical + 2 high (sorted by file path)
        - Batch 2: 3 high (sorted by file path)
        - Batch 3: 2 medium (sorted by file path)
    """
    if not alerts:
        return []

    def severity_key(alert: CodeQLAlert) -> tuple:
        severity_lower = alert.severity.lower()
        try:
            severity_index = SEVERITY_ORDER.index(severity_lower)
        except ValueError:
            severity_index = len(SEVERITY_ORDER)

        return (severity_index, alert.file_path, alert.line_number)

    sorted_alerts = sorted(alerts, key=severity_key)

    batches = []
    for i in range(0, len(sorted_alerts), max_per_batch):
        batch = sorted_alerts[i:i + max_per_batch]
        batches.append(batch)

    return batches


def create_batches(
    alerts: List[CodeQLAlert],
    strategy: str,
    max_per_batch: int = 5
) -> List[List[CodeQLAlert]]:
    """
    Create batches of alerts using the specified strategy.

    Args:
        alerts: List of CodeQL alerts to batch
        strategy: Batching strategy to use ("file" or "severity")
        max_per_batch: Maximum number of alerts per batch

    Returns:
        List of batches (each batch is a list of alerts)

    Raises:
        ValueError: If strategy is not "file" or "severity"

    Example:
        >>> batches = create_batches(alerts, strategy="file", max_per_batch=5)
        >>> for i, batch in enumerate(batches):
        ...     print(f"Batch {i+1}: {len(batch)} alerts")
    """
    strategies = {
        'file': batch_by_file,
        'severity': batch_by_severity,
    }

    if strategy not in strategies:
        raise ValueError(
            f"Unknown batch strategy: {strategy}. "
            f"Valid options: {', '.join(strategies.keys())}"
        )

    return strategies[strategy](alerts, max_per_batch)
