# Create quick_test.py
from dotenv import load_dotenv
import os
from src.devin_client import DevinClient
from src.github_client import GitHubClient
from src.models.alert import CodeQLAlert

load_dotenv()

# Fetch real alerts
github_client = GitHubClient(
    token=os.getenv("GITHUB_TOKEN"),
    repo_name=os.getenv("GITHUB_REPOSITORY")
)
alerts = github_client.fetch_codeql_alerts()

if not alerts:
    print("⚠️  No alerts found. Add mock alert for testing:")
    alerts = [
        CodeQLAlert(
            alert_id=999,
            rule_id="test/manual-test",
            severity="low",
            file_path="README.md",
            line_number=1,
            message="Test alert for Devin integration",
            recommendation="This is a test",
            state="open",
            url="https://github.com/test"
        )
    ]

# Test Devin API
print(f"Testing with {len(alerts)} alert(s)...")
devin_client = DevinClient(api_key=os.getenv("DEVIN_API_KEY"))

# Create session with just 1 alert
session = devin_client.create_session(
    repo_url=f"https://github.com/{os.getenv('GITHUB_REPOSITORY')}",
    alerts=alerts[:1],  # Just one alert
    base_branch="main"
)

print(f"✅ Session created: {session.session_id}")
print(f"🔗 View at: {devin_client.get_session_url(session.session_id)}")

# Check status
status = devin_client.get_session_status(session.session_id)
print(f"📊 Status: {status.status.value}")
print(f"✅ Real API test passed!")