import os
import requests

SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")


def send_slack_alert(message: str) -> bool:
    """Sends a message to the configured Slack Incoming Webhook.
    Returns False (and never raises) if no webhook is configured or the
    request fails — alerting must never crash the backend."""
    if not SLACK_WEBHOOK_URL:
        print(f"[slack_alert] SLACK_WEBHOOK_URL not set — would have sent: {message}")
        return False
    try:
        resp = requests.post(SLACK_WEBHOOK_URL, json={"text": message}, timeout=5)
        return resp.status_code == 200
    except requests.RequestException as exc:
        print(f"[slack_alert] failed to send Slack alert: {exc}")
        return False
