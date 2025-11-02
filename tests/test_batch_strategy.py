"""
Comprehensive test suite for batch_strategy module.

This test suite validates the behavior of batching strategies including:
- batch_by_file(): Groups alerts by file path with line number sorting
- batch_by_severity(): Groups alerts by severity priority
- create_batches(): Dispatcher function for strategy selection

Tests cover edge cases including:
- Empty alert lists
- Single alert
- Multiple files with varying alert counts
- Mixed severities
- Large batches that need splitting
- Unknown severity levels
- Invalid strategy names
"""
import pytest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from batch_strategy import batch_by_file, batch_by_severity, create_batches, SEVERITY_ORDER
from models.alert import CodeQLAlert


@pytest.fixture
def sample_alerts_single_file():
    """
    Fixture providing alerts from a single file.
    Returns 3 alerts from the same file at different line numbers.
    """
    return [
        CodeQLAlert(
            alert_id=1,
            rule_id="py/sql-injection",
            severity="high",
            file_path="src/auth.py",
            line_number=45,
            message="SQL injection vulnerability",
            recommendation="Use parameterized queries",
            state="open"
        ),
        CodeQLAlert(
            alert_id=2,
            rule_id="py/command-injection",
            severity="critical",
            file_path="src/auth.py",
            line_number=20,
            message="Command injection vulnerability",
            recommendation="Validate user input",
            state="open"
        ),
        CodeQLAlert(
            alert_id=3,
            rule_id="py/weak-crypto",
            severity="medium",
            file_path="src/auth.py",
            line_number=100,
            message="Weak cryptographic algorithm",
            recommendation="Use stronger encryption",
            state="open"
        )
    ]


@pytest.fixture
def sample_alerts_multiple_files():
    """
    Fixture providing alerts from multiple files.
    Returns 6 alerts across 3 different files.
    """
    return [
        CodeQLAlert(
            alert_id=1,
            rule_id="py/sql-injection",
            severity="high",
            file_path="src/auth.py",
            line_number=45,
            message="SQL injection vulnerability",
            recommendation="Use parameterized queries",
            state="open"
        ),
        CodeQLAlert(
            alert_id=2,
            rule_id="py/xss",
            severity="medium",
            file_path="src/views.py",
            line_number=120,
            message="Cross-site scripting vulnerability",
            recommendation="Escape user input",
            state="open"
        ),
        CodeQLAlert(
            alert_id=3,
            rule_id="py/path-injection",
            severity="critical",
            file_path="src/files.py",
            line_number=78,
            message="Path injection vulnerability",
            recommendation="Validate file paths",
            state="open"
        ),
        CodeQLAlert(
            alert_id=4,
            rule_id="py/weak-crypto",
            severity="low",
            file_path="src/auth.py",
            line_number=100,
            message="Weak cryptographic algorithm",
            recommendation="Use stronger encryption",
            state="open"
        ),
        CodeQLAlert(
            alert_id=5,
            rule_id="py/hardcoded-credentials",
            severity="critical",
            file_path="src/config.py",
            line_number=15,
            message="Hardcoded credentials",
            recommendation="Use environment variables",
            state="open"
        ),
        CodeQLAlert(
            alert_id=6,
            rule_id="py/insecure-deserialization",
            severity="high",
            file_path="src/views.py",
            line_number=50,
            message="Insecure deserialization",
            recommendation="Validate serialized data",
            state="open"
        )
    ]


@pytest.fixture
def sample_alerts_mixed_severities():
    """
    Fixture providing alerts with all severity levels.
    Returns alerts covering the full severity spectrum.
    """
    return [
        CodeQLAlert(
            alert_id=1,
            rule_id="rule1",
            severity="critical",
            file_path="src/a.py",
            line_number=10,
            message="Critical issue",
            recommendation="Fix immediately",
            state="open"
        ),
        CodeQLAlert(
            alert_id=2,
            rule_id="rule2",
            severity="high",
            file_path="src/b.py",
            line_number=20,
            message="High severity issue",
            recommendation="Fix soon",
            state="open"
        ),
        CodeQLAlert(
            alert_id=3,
            rule_id="rule3",
            severity="medium",
            file_path="src/c.py",
            line_number=30,
            message="Medium severity issue",
            recommendation="Fix when possible",
            state="open"
        ),
        CodeQLAlert(
            alert_id=4,
            rule_id="rule4",
            severity="low",
            file_path="src/d.py",
            line_number=40,
            message="Low severity issue",
            recommendation="Consider fixing",
            state="open"
        ),
        CodeQLAlert(
            alert_id=5,
            rule_id="rule5",
            severity="warning",
            file_path="src/e.py",
            line_number=50,
            message="Warning",
            recommendation="Review code",
            state="open"
        ),
        CodeQLAlert(
            alert_id=6,
            rule_id="rule6",
            severity="note",
            file_path="src/f.py",
            line_number=60,
            message="Informational note",
            recommendation="For your information",
            state="open"
        )
    ]


class TestBatchByFile:
    """Test suite for batch_by_file() function."""

    def test_empty_alerts_list(self):
        """
        Validates that batch_by_file returns an empty list when given no alerts.
        This is an important edge case to handle gracefully.
        """
        batches = batch_by_file([], max_per_batch=5)
        assert batches == []

    def test_single_alert(self):
        """
        Validates that batch_by_file correctly handles a single alert.
        Should return one batch containing the single alert.
        """
        alerts = [
            CodeQLAlert(
                alert_id=1,
                rule_id="py/test",
                severity="high",
                file_path="src/test.py",
                line_number=10,
                message="Test issue",
                recommendation="Fix it",
                state="open"
            )
        ]
        batches = batch_by_file(alerts, max_per_batch=5)
        
        assert len(batches) == 1
        assert len(batches[0]) == 1
        assert batches[0][0].alert_id == 1

    def test_single_file_sorted_by_line_number(self, sample_alerts_single_file):
        """
        Validates that alerts from the same file are sorted by line number.
        Input has alerts at lines 45, 20, 100 - should be sorted to 20, 45, 100.
        """
        batches = batch_by_file(sample_alerts_single_file, max_per_batch=5)
        
        assert len(batches) == 1
        assert len(batches[0]) == 3
        assert batches[0][0].line_number == 20
        assert batches[0][1].line_number == 45
        assert batches[0][2].line_number == 100

    def test_multiple_files_separate_batches(self, sample_alerts_multiple_files):
        """
        Validates that alerts from different files are grouped into separate batches.
        With 6 alerts across 4 files (auth.py has 2), should create 4 batches.
        """
        batches = batch_by_file(sample_alerts_multiple_files, max_per_batch=5)
        
        assert len(batches) == 4
        
        file_paths = [batch[0].file_path for batch in batches]
        assert "src/auth.py" in file_paths
        assert "src/config.py" in file_paths
        assert "src/files.py" in file_paths
        assert "src/views.py" in file_paths

    def test_files_sorted_alphabetically(self, sample_alerts_multiple_files):
        """
        Validates that batches are ordered by file path alphabetically.
        Files should appear in order: auth.py, config.py, files.py, views.py.
        """
        batches = batch_by_file(sample_alerts_multiple_files, max_per_batch=5)
        
        file_paths = [batch[0].file_path for batch in batches]
        assert file_paths == sorted(file_paths)

    def test_single_file_exceeds_max_per_batch(self):
        """
        Validates that a file with more alerts than max_per_batch is split
        into multiple batches. With 12 alerts and max_per_batch=5, should
        create 3 batches: [5, 5, 2].
        """
        alerts = [
            CodeQLAlert(
                alert_id=i,
                rule_id=f"rule{i}",
                severity="high",
                file_path="src/large.py",
                line_number=i * 10,
                message=f"Issue {i}",
                recommendation="Fix it",
                state="open"
            )
            for i in range(1, 13)
        ]
        
        batches = batch_by_file(alerts, max_per_batch=5)
        
        assert len(batches) == 3
        assert len(batches[0]) == 5
        assert len(batches[1]) == 5
        assert len(batches[2]) == 2
        
        assert batches[0][0].line_number == 10
        assert batches[0][4].line_number == 50
        assert batches[1][0].line_number == 60
        assert batches[1][4].line_number == 100
        assert batches[2][0].line_number == 110
        assert batches[2][1].line_number == 120

    def test_multiple_files_some_exceed_max(self):
        """
        Validates correct batching when some files exceed max_per_batch.
        File A has 7 alerts (split into 2 batches), File B has 3 alerts (1 batch).
        """
        alerts = []
        
        for i in range(1, 8):
            alerts.append(
                CodeQLAlert(
                    alert_id=i,
                    rule_id=f"rule{i}",
                    severity="high",
                    file_path="src/file_a.py",
                    line_number=i * 10,
                    message=f"Issue {i}",
                    recommendation="Fix it",
                    state="open"
                )
            )
        
        for i in range(8, 11):
            alerts.append(
                CodeQLAlert(
                    alert_id=i,
                    rule_id=f"rule{i}",
                    severity="medium",
                    file_path="src/file_b.py",
                    line_number=i * 10,
                    message=f"Issue {i}",
                    recommendation="Fix it",
                    state="open"
                )
            )
        
        batches = batch_by_file(alerts, max_per_batch=5)
        
        assert len(batches) == 3
        
        assert batches[0][0].file_path == "src/file_a.py"
        assert len(batches[0]) == 5
        
        assert batches[1][0].file_path == "src/file_a.py"
        assert len(batches[1]) == 2
        
        assert batches[2][0].file_path == "src/file_b.py"
        assert len(batches[2]) == 3

    def test_max_per_batch_one(self):
        """
        Validates that max_per_batch=1 creates one batch per alert.
        With 3 alerts, should create 3 batches.
        """
        alerts = [
            CodeQLAlert(
                alert_id=i,
                rule_id=f"rule{i}",
                severity="high",
                file_path="src/test.py",
                line_number=i * 10,
                message=f"Issue {i}",
                recommendation="Fix it",
                state="open"
            )
            for i in range(1, 4)
        ]
        
        batches = batch_by_file(alerts, max_per_batch=1)
        
        assert len(batches) == 3
        for batch in batches:
            assert len(batch) == 1

    def test_alerts_within_same_file_maintain_line_order(self):
        """
        Validates that when a file is split into multiple batches,
        line number ordering is maintained across batches.
        """
        alerts = [
            CodeQLAlert(
                alert_id=i,
                rule_id=f"rule{i}",
                severity="high",
                file_path="src/test.py",
                line_number=i * 5,
                message=f"Issue {i}",
                recommendation="Fix it",
                state="open"
            )
            for i in [3, 1, 5, 2, 4, 6]
        ]
        
        batches = batch_by_file(alerts, max_per_batch=3)
        
        assert len(batches) == 2
        
        assert batches[0][0].line_number == 5
        assert batches[0][1].line_number == 10
        assert batches[0][2].line_number == 15
        
        assert batches[1][0].line_number == 20
        assert batches[1][1].line_number == 25
        assert batches[1][2].line_number == 30


class TestBatchBySeverity:
    """Test suite for batch_by_severity() function."""

    def test_empty_alerts_list(self):
        """
        Validates that batch_by_severity returns an empty list when given no alerts.
        This is an important edge case to handle gracefully.
        """
        batches = batch_by_severity([], max_per_batch=5)
        assert batches == []

    def test_single_alert(self):
        """
        Validates that batch_by_severity correctly handles a single alert.
        Should return one batch containing the single alert.
        """
        alerts = [
            CodeQLAlert(
                alert_id=1,
                rule_id="py/test",
                severity="high",
                file_path="src/test.py",
                line_number=10,
                message="Test issue",
                recommendation="Fix it",
                state="open"
            )
        ]
        batches = batch_by_severity(alerts, max_per_batch=5)
        
        assert len(batches) == 1
        assert len(batches[0]) == 1
        assert batches[0][0].alert_id == 1

    def test_severity_order_respected(self, sample_alerts_mixed_severities):
        """
        Validates that alerts are sorted by severity priority.
        Order should be: critical, high, medium, low, warning, note.
        """
        batches = batch_by_severity(sample_alerts_mixed_severities, max_per_batch=10)
        
        assert len(batches) == 1
        batch = batches[0]
        
        assert batch[0].severity == "critical"
        assert batch[1].severity == "high"
        assert batch[2].severity == "medium"
        assert batch[3].severity == "low"
        assert batch[4].severity == "warning"
        assert batch[5].severity == "note"

    def test_same_severity_sorted_by_file_path(self):
        """
        Validates that alerts with the same severity are sorted by file path.
        This provides stable, predictable ordering.
        """
        alerts = [
            CodeQLAlert(
                alert_id=1,
                rule_id="rule1",
                severity="high",
                file_path="src/z.py",
                line_number=10,
                message="Issue 1",
                recommendation="Fix it",
                state="open"
            ),
            CodeQLAlert(
                alert_id=2,
                rule_id="rule2",
                severity="high",
                file_path="src/a.py",
                line_number=20,
                message="Issue 2",
                recommendation="Fix it",
                state="open"
            ),
            CodeQLAlert(
                alert_id=3,
                rule_id="rule3",
                severity="high",
                file_path="src/m.py",
                line_number=30,
                message="Issue 3",
                recommendation="Fix it",
                state="open"
            )
        ]
        
        batches = batch_by_severity(alerts, max_per_batch=5)
        
        assert len(batches) == 1
        assert batches[0][0].file_path == "src/a.py"
        assert batches[0][1].file_path == "src/m.py"
        assert batches[0][2].file_path == "src/z.py"

    def test_same_severity_and_file_sorted_by_line_number(self):
        """
        Validates that alerts with the same severity and file path
        are sorted by line number as a final tie-breaker.
        """
        alerts = [
            CodeQLAlert(
                alert_id=1,
                rule_id="rule1",
                severity="high",
                file_path="src/test.py",
                line_number=100,
                message="Issue 1",
                recommendation="Fix it",
                state="open"
            ),
            CodeQLAlert(
                alert_id=2,
                rule_id="rule2",
                severity="high",
                file_path="src/test.py",
                line_number=20,
                message="Issue 2",
                recommendation="Fix it",
                state="open"
            ),
            CodeQLAlert(
                alert_id=3,
                rule_id="rule3",
                severity="high",
                file_path="src/test.py",
                line_number=50,
                message="Issue 3",
                recommendation="Fix it",
                state="open"
            )
        ]
        
        batches = batch_by_severity(alerts, max_per_batch=5)
        
        assert len(batches) == 1
        assert batches[0][0].line_number == 20
        assert batches[0][1].line_number == 50
        assert batches[0][2].line_number == 100

    def test_mixed_severities_split_into_batches(self):
        """
        Validates that alerts are split into batches when exceeding max_per_batch,
        while maintaining severity priority. With 3 critical, 5 high, 2 medium
        and max_per_batch=5, should create 3 batches.
        """
        alerts = []
        
        for i in range(1, 4):
            alerts.append(
                CodeQLAlert(
                    alert_id=i,
                    rule_id=f"critical{i}",
                    severity="critical",
                    file_path=f"src/file{i}.py",
                    line_number=10,
                    message=f"Critical issue {i}",
                    recommendation="Fix immediately",
                    state="open"
                )
            )
        
        for i in range(4, 9):
            alerts.append(
                CodeQLAlert(
                    alert_id=i,
                    rule_id=f"high{i}",
                    severity="high",
                    file_path=f"src/file{i}.py",
                    line_number=20,
                    message=f"High issue {i}",
                    recommendation="Fix soon",
                    state="open"
                )
            )
        
        for i in range(9, 11):
            alerts.append(
                CodeQLAlert(
                    alert_id=i,
                    rule_id=f"medium{i}",
                    severity="medium",
                    file_path=f"src/file{i}.py",
                    line_number=30,
                    message=f"Medium issue {i}",
                    recommendation="Fix when possible",
                    state="open"
                )
            )
        
        batches = batch_by_severity(alerts, max_per_batch=5)
        
        assert len(batches) == 2
        
        assert all(alert.severity == "critical" for alert in batches[0][:3])
        assert all(alert.severity == "high" for alert in batches[0][3:5])
        
        assert all(alert.severity == "high" for alert in batches[1][:3])
        assert all(alert.severity == "medium" for alert in batches[1][3:5])

    def test_unknown_severity_sorted_last(self):
        """
        Validates that alerts with unknown severity levels are sorted
        after all known severities. This handles edge cases gracefully.
        """
        alerts = [
            CodeQLAlert(
                alert_id=1,
                rule_id="rule1",
                severity="unknown",
                file_path="src/a.py",
                line_number=10,
                message="Unknown severity",
                recommendation="Fix it",
                state="open"
            ),
            CodeQLAlert(
                alert_id=2,
                rule_id="rule2",
                severity="critical",
                file_path="src/b.py",
                line_number=20,
                message="Critical issue",
                recommendation="Fix immediately",
                state="open"
            ),
            CodeQLAlert(
                alert_id=3,
                rule_id="rule3",
                severity="note",
                file_path="src/c.py",
                line_number=30,
                message="Note",
                recommendation="For info",
                state="open"
            ),
            CodeQLAlert(
                alert_id=4,
                rule_id="rule4",
                severity="weird",
                file_path="src/d.py",
                line_number=40,
                message="Weird severity",
                recommendation="Fix it",
                state="open"
            )
        ]
        
        batches = batch_by_severity(alerts, max_per_batch=10)
        
        assert len(batches) == 1
        assert batches[0][0].severity == "critical"
        assert batches[0][1].severity == "note"
        assert batches[0][2].severity in ["unknown", "weird"]
        assert batches[0][3].severity in ["unknown", "weird"]

    def test_case_insensitive_severity(self):
        """
        Validates that severity comparison is case-insensitive.
        "HIGH", "High", and "high" should all be treated the same.
        """
        alerts = [
            CodeQLAlert(
                alert_id=1,
                rule_id="rule1",
                severity="HIGH",
                file_path="src/a.py",
                line_number=10,
                message="Issue 1",
                recommendation="Fix it",
                state="open"
            ),
            CodeQLAlert(
                alert_id=2,
                rule_id="rule2",
                severity="Critical",
                file_path="src/b.py",
                line_number=20,
                message="Issue 2",
                recommendation="Fix it",
                state="open"
            ),
            CodeQLAlert(
                alert_id=3,
                rule_id="rule3",
                severity="medium",
                file_path="src/c.py",
                line_number=30,
                message="Issue 3",
                recommendation="Fix it",
                state="open"
            )
        ]
        
        batches = batch_by_severity(alerts, max_per_batch=10)
        
        assert len(batches) == 1
        assert batches[0][0].alert_id == 2
        assert batches[0][1].alert_id == 1
        assert batches[0][2].alert_id == 3

    def test_max_per_batch_one(self):
        """
        Validates that max_per_batch=1 creates one batch per alert,
        maintaining severity order.
        """
        alerts = [
            CodeQLAlert(
                alert_id=1,
                rule_id="rule1",
                severity="low",
                file_path="src/a.py",
                line_number=10,
                message="Low issue",
                recommendation="Fix it",
                state="open"
            ),
            CodeQLAlert(
                alert_id=2,
                rule_id="rule2",
                severity="critical",
                file_path="src/b.py",
                line_number=20,
                message="Critical issue",
                recommendation="Fix it",
                state="open"
            ),
            CodeQLAlert(
                alert_id=3,
                rule_id="rule3",
                severity="high",
                file_path="src/c.py",
                line_number=30,
                message="High issue",
                recommendation="Fix it",
                state="open"
            )
        ]
        
        batches = batch_by_severity(alerts, max_per_batch=1)
        
        assert len(batches) == 3
        assert batches[0][0].severity == "critical"
        assert batches[1][0].severity == "high"
        assert batches[2][0].severity == "low"


class TestCreateBatches:
    """Test suite for create_batches() dispatcher function."""

    def test_file_strategy(self, sample_alerts_multiple_files):
        """
        Validates that create_batches correctly dispatches to batch_by_file
        when strategy="file".
        """
        batches = create_batches(sample_alerts_multiple_files, strategy="file", max_per_batch=5)
        
        assert len(batches) > 0
        
        file_batches = batch_by_file(sample_alerts_multiple_files, max_per_batch=5)
        assert len(batches) == len(file_batches)

    def test_severity_strategy(self, sample_alerts_mixed_severities):
        """
        Validates that create_batches correctly dispatches to batch_by_severity
        when strategy="severity".
        """
        batches = create_batches(sample_alerts_mixed_severities, strategy="severity", max_per_batch=5)
        
        assert len(batches) > 0
        
        severity_batches = batch_by_severity(sample_alerts_mixed_severities, max_per_batch=5)
        assert len(batches) == len(severity_batches)

    def test_invalid_strategy_raises_error(self, sample_alerts_multiple_files):
        """
        Validates that create_batches raises ValueError for unknown strategies.
        This ensures clear error messages for configuration mistakes.
        """
        with pytest.raises(ValueError, match="Unknown batch strategy: invalid"):
            create_batches(sample_alerts_multiple_files, strategy="invalid", max_per_batch=5)

    def test_error_message_lists_valid_strategies(self, sample_alerts_multiple_files):
        """
        Validates that the error message includes the list of valid strategies
        to help users correct their configuration.
        """
        with pytest.raises(ValueError, match="Valid options: file, severity"):
            create_batches(sample_alerts_multiple_files, strategy="unknown", max_per_batch=5)

    def test_empty_alerts_with_file_strategy(self):
        """
        Validates that create_batches handles empty alerts list with file strategy.
        """
        batches = create_batches([], strategy="file", max_per_batch=5)
        assert batches == []

    def test_empty_alerts_with_severity_strategy(self):
        """
        Validates that create_batches handles empty alerts list with severity strategy.
        """
        batches = create_batches([], strategy="severity", max_per_batch=5)
        assert batches == []

    def test_default_max_per_batch(self, sample_alerts_multiple_files):
        """
        Validates that create_batches uses default max_per_batch=5 when not specified.
        """
        batches_default = create_batches(sample_alerts_multiple_files, strategy="file")
        batches_explicit = create_batches(sample_alerts_multiple_files, strategy="file", max_per_batch=5)
        
        assert len(batches_default) == len(batches_explicit)


class TestSeverityOrderConstant:
    """Test suite for SEVERITY_ORDER constant."""

    def test_severity_order_defined(self):
        """
        Validates that SEVERITY_ORDER constant is properly defined.
        """
        assert SEVERITY_ORDER is not None
        assert isinstance(SEVERITY_ORDER, list)

    def test_severity_order_contains_expected_values(self):
        """
        Validates that SEVERITY_ORDER contains all expected severity levels
        in the correct priority order.
        """
        expected = ["critical", "high", "medium", "low", "warning", "note"]
        assert SEVERITY_ORDER == expected

    def test_severity_order_no_duplicates(self):
        """
        Validates that SEVERITY_ORDER contains no duplicate values.
        """
        assert len(SEVERITY_ORDER) == len(set(SEVERITY_ORDER))
