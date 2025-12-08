#!/usr/bin/env python3
"""
Test script to verify Discord and Slack webhook notifications
Usage: python test_notifications.py <webhook_url>
"""

import sys
import requests
from datetime import datetime


def test_discord_webhook(webhook_url):
    """Test Discord webhook with a sample message"""
    print("Testing Discord webhook...")
    
    payload = {
        "embeds": [{
            "title": "🧪 Test Notification",
            "description": (
                "This is a test notification from Akvorado DDoS Detector.\n\n"
                "**Target IP:** 192.168.1.1\n"
                "**Packets/sec:** 150,000\n"
                "**Bytes/sec:** 1,500,000,000 (1.50 Gbps)\n"
                "**Flows/sec:** 15,000\n"
                "**Unique Sources:** 2,000\n"
                f"**Time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            ),
            "color": 0xFFCC00,  # Yellow
            "timestamp": datetime.now().isoformat(),
            "footer": {
                "text": "Akvorado DDoS Detector - Test Message"
            }
        }]
    }
    
    try:
        response = requests.post(webhook_url, json=payload, timeout=10)
        response.raise_for_status()
        print("✓ Discord notification sent successfully!")
        return True
    except Exception as e:
        print(f"✗ Failed to send Discord notification: {e}")
        return False


def test_slack_webhook(webhook_url):
    """Test Slack webhook with a sample message"""
    print("Testing Slack webhook...")
    
    payload = {
        "attachments": [{
            "color": "#FFCC00",  # Yellow
            "title": "🧪 Test Notification",
            "text": (
                "This is a test notification from Akvorado DDoS Detector.\n\n"
                "*Target IP:* 192.168.1.1\n"
                "*Packets/sec:* 150,000\n"
                "*Bytes/sec:* 1,500,000,000 (1.50 Gbps)\n"
                "*Flows/sec:* 15,000\n"
                "*Unique Sources:* 2,000\n"
                f"*Time:* {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            ),
            "footer": "Akvorado DDoS Detector - Test Message",
            "ts": int(datetime.now().timestamp())
        }]
    }
    
    try:
        response = requests.post(webhook_url, json=payload, timeout=10)
        response.raise_for_status()
        print("✓ Slack notification sent successfully!")
        return True
    except Exception as e:
        print(f"✗ Failed to send Slack notification: {e}")
        return False


def main():
    """Main entry point"""
    if len(sys.argv) < 2:
        print("Usage: python test_notifications.py <webhook_url>")
        print("")
        print("Examples:")
        print("  python test_notifications.py https://discord.com/api/webhooks/...")
        print("  python test_notifications.py https://hooks.slack.com/services/...")
        sys.exit(1)
    
    webhook_url = sys.argv[1]
    
    print("=" * 50)
    print("Webhook Notification Test")
    print("=" * 50)
    print(f"Webhook URL: {webhook_url[:50]}...")
    print("")
    
    # Determine webhook type
    if "discord.com" in webhook_url:
        success = test_discord_webhook(webhook_url)
    elif "slack.com" in webhook_url:
        success = test_slack_webhook(webhook_url)
    else:
        print("Unknown webhook type. Supported: Discord, Slack")
        sys.exit(1)
    
    print("")
    if success:
        print("✓ Test completed successfully!")
        print("Check your Discord/Slack channel for the test message.")
    else:
        print("✗ Test failed. Please check the webhook URL and try again.")
        sys.exit(1)


if __name__ == "__main__":
    main()
