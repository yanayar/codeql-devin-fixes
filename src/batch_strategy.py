"""
Batching strategies for grouping CodeQL alerts.

This module provides different strategies for grouping alerts into batches
for processing by Devin.
"""
from typing import List

from models.alert import CodeQLAlert


class BatchStrategy:
    """
    Base class for alert batching strategies.

    Subclasses should implement the batch() method to define
    how alerts are grouped into batches.
    """

    def __init__(self, max_per_batch: int = 5):
        """
        Initialize batch strategy.

        Args:
            max_per_batch: Maximum number of alerts per batch
        """
        self.max_per_batch = max_per_batch

    def batch(self, alerts: List[CodeQLAlert]) -> List[List[CodeQLAlert]]:
        """
        Group alerts into batches.

        Args:
            alerts: List of CodeQL alerts to batch

        Returns:
            List of batches, where each batch is a list of alerts

        Raises:
            NotImplementedError: Must be implemented by subclass
        """
        raise NotImplementedError("Subclass must implement batch()")


class FileBasedBatchStrategy(BatchStrategy):
    """
    Batch alerts by file path.

    Groups alerts that affect the same file together, up to max_per_batch.
    This is useful because fixes in the same file can often be done together
    and may have related context.
    """

    def batch(self, alerts: List[CodeQLAlert]) -> List[List[CodeQLAlert]]:
        """
        Group alerts by file path.

        Args:
            alerts: List of CodeQL alerts to batch

        Returns:
            List of batches grouped by file

        Note:
            Implementation should:
            1. Group alerts by file_path
            2. For each file, create batches of up to max_per_batch alerts
            3. Sort alerts within each file by line_number for logical ordering
        """
        raise NotImplementedError("File-based batching pending")


class SeverityBasedBatchStrategy(BatchStrategy):
    """
    Batch alerts by severity level.

    Groups alerts of the same severity together, prioritizing critical/high
    severity issues. This allows fixing the most important issues first.
    """

    def batch(self, alerts: List[CodeQLAlert]) -> List[List[CodeQLAlert]]:
        """
        Group alerts by severity level.

        Args:
            alerts: List of CodeQL alerts to batch

        Returns:
            List of batches grouped by severity (critical first, then high, etc.)

        Note:
            Implementation should:
            1. Group alerts by severity
            2. Order severity groups: critical, high, medium, low, warning, note
            3. Within each severity, create batches of up to max_per_batch
            4. Return batches in priority order
        """
        raise NotImplementedError("Severity-based batching pending")


class RuleBasedBatchStrategy(BatchStrategy):
    """
    Batch alerts by CodeQL rule type.

    Groups alerts triggered by the same rule together. This is useful because
    the same type of vulnerability often has similar fixes across the codebase.
    """

    def batch(self, alerts: List[CodeQLAlert]) -> List[List[CodeQLAlert]]:
        """
        Group alerts by rule ID.

        Args:
            alerts: List of CodeQL alerts to batch

        Returns:
            List of batches grouped by rule type

        Note:
            Implementation should:
            1. Group alerts by rule_id
            2. For each rule, create batches of up to max_per_batch alerts
            3. Sort by severity within each rule group
        """
        raise NotImplementedError("Rule-based batching pending")


class CountBasedBatchStrategy(BatchStrategy):
    """
    Simple count-based batching.

    Groups alerts into batches of max_per_batch size without any
    special grouping logic. This is the simplest strategy.
    """

    def batch(self, alerts: List[CodeQLAlert]) -> List[List[CodeQLAlert]]:
        """
        Group alerts into fixed-size batches.

        Args:
            alerts: List of CodeQL alerts to batch

        Returns:
            List of batches with up to max_per_batch alerts each

        Note:
            Implementation should:
            1. Sort alerts by severity (critical first)
            2. Split into chunks of max_per_batch size
            3. Return list of batches
        """
        raise NotImplementedError("Count-based batching pending")


def get_batch_strategy(strategy_name: str, max_per_batch: int = 5) -> BatchStrategy:
    """
    Factory function to get a batch strategy by name.

    Args:
        strategy_name: Name of the strategy (file, severity, rule, count)
        max_per_batch: Maximum alerts per batch

    Returns:
        BatchStrategy instance

    Raises:
        ValueError: If strategy_name is not recognized

    Example:
        >>> strategy = get_batch_strategy('file', max_per_batch=10)
        >>> batches = strategy.batch(alerts)
    """
    strategies = {
        'file': FileBasedBatchStrategy,
        'severity': SeverityBasedBatchStrategy,
        'rule': RuleBasedBatchStrategy,
        'count': CountBasedBatchStrategy,
    }

    if strategy_name not in strategies:
        raise ValueError(
            f"Unknown batch strategy: {strategy_name}. "
            f"Valid options: {', '.join(strategies.keys())}"
        )

    return strategies[strategy_name](max_per_batch=max_per_batch)
