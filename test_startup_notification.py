#!/usr/bin/env python3
"""
Test script for startup notification
"""

import os
import sys
from unittest.mock import Mock, patch
from datetime import datetime

# Import the detector module
import ddos_detector


def test_startup_notification():
    """Test the startup notification feature"""
    print("\n" + "="*60)
    print("🧪 Testing Startup Notification")
    print("="*60)
    
    # Create a temporary config
    config = ddos_detector.Config.__new__(ddos_detector.Config)
    config.config = {
        'clickhouse': {'host': 'localhost', 'port': 9000, 'database': 'flows', 'user': 'default', 'password': ''},
        'detection': {
            'check_interval': 60,
            'time_window': 300,
            'thresholds': {
                'total_external_bps_threshold': 1000000000,
                'dst_bps_threshold': 1000000000,
                'entropy_threshold': 0.8
            }
        },
        'notifications': {
            'discord_webhook': 'https://discord.com/api/webhooks/test',
            'slack_webhook': '',
            'cooldown': 300
        },
        'abuseipdb': {
            'enabled': True,
            'api_key': 'test_key',
            'max_age_days': 90
        },
        'logging': {'level': 'INFO', 'file': 'test.log'}
    }
    
    # Create notification manager
    notifier = ddos_detector.NotificationManager(config)
    
    # Test data
    stats_summary = {
        'total_bps': 2500000000,  # 2.5 Gbps
        'top_destinations_count': 5,
        'attacks_detected': 1,
        'top_destination': {
            'dst_ip': '203.0.113.10',
            'bps': 1800000000,  # 1.8 Gbps
            'unique_sources': 3500
        }
    }
    
    abuse_check = {
        'ip_address': '198.51.100.42',
        'total_reports': 127,
        'abuse_confidence_score': 85,
        'country_code': 'US',
        'isp': 'Example ISP Inc.'
    }
    
    # Format and display the startup message
    print("\n📋 Startup Message:")
    print("-" * 60)
    message = notifier._format_startup_message(stats_summary, abuse_check)
    print(message)
    print("-" * 60)
    
    # Test with no attacks
    stats_summary_clean = {
        'total_bps': 500000000,  # 0.5 Gbps
        'top_destinations_count': 3,
        'attacks_detected': 0,
        'top_destination': {
            'dst_ip': '203.0.113.20',
            'bps': 300000000,  # 0.3 Gbps
            'unique_sources': 150
        }
    }
    
    print("\n📋 Startup Message (No Attacks):")
    print("-" * 60)
    message_clean = notifier._format_startup_message(stats_summary_clean, None)
    print(message_clean)
    print("-" * 60)
    
    # Mock Discord request
    with patch('requests.post') as mock_post:
        mock_post.return_value.status_code = 200
        
        print("\n🔔 Testing Discord notification...")
        notifier._send_discord_startup('https://discord.com/test', message, stats_summary)
        
        if mock_post.called:
            print("✓ Discord startup notification would be sent")
            payload = mock_post.call_args[1]['json']
            print(f"  - Title: {payload['embeds'][0]['title']}")
            print(f"  - Color: {hex(payload['embeds'][0]['color'])}")
        else:
            print("✗ Discord notification was not called")
    
    # Mock Slack request
    with patch('requests.post') as mock_post:
        mock_post.return_value.status_code = 200
        
        print("\n🔔 Testing Slack notification...")
        notifier._send_slack_startup('https://slack.com/test', message, stats_summary)
        
        if mock_post.called:
            print("✓ Slack startup notification would be sent")
            payload = mock_post.call_args[1]['json']
            print(f"  - Title: {payload['attachments'][0]['title']}")
            print(f"  - Color: {payload['attachments'][0]['color']}")
        else:
            print("✗ Slack notification was not called")
    
    print("\n" + "="*60)
    print("✅ Startup Notification Test Complete")
    print("="*60)


if __name__ == '__main__':
    test_startup_notification()
