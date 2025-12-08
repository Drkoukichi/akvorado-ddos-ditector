#!/usr/bin/env python3
"""
Simple tests for DDoS Detector functionality
"""

import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch, Mock
from datetime import datetime

# Import the detector module
import ddos_detector


class TestConfig(unittest.TestCase):
    """Test configuration loading"""
    
    def test_config_with_defaults(self):
        """Test config loads with default values"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("clickhouse:\n  host: testhost\n")
            config_path = f.name
        
        try:
            config = ddos_detector.Config(config_path)
            self.assertEqual(config.get('clickhouse', 'host'), 'testhost')
            self.assertIsNotNone(config.get('detection', 'check_interval'))
        finally:
            os.unlink(config_path)
    
    def test_config_environment_override(self):
        """Test environment variables override config file"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("clickhouse:\n  host: filehost\n")
            config_path = f.name
        
        try:
            os.environ['CLICKHOUSE_HOST'] = 'envhost'
            config = ddos_detector.Config(config_path)
            self.assertEqual(config.get('clickhouse', 'host'), 'envhost')
        finally:
            os.unlink(config_path)
            if 'CLICKHOUSE_HOST' in os.environ:
                del os.environ['CLICKHOUSE_HOST']


class TestNotificationManager(unittest.TestCase):
    """Test notification functionality"""
    
    def setUp(self):
        """Set up test fixtures"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("""
notifications:
  discord_webhook: "https://discord.com/test"
  slack_webhook: "https://slack.com/test"
  cooldown: 60
            """)
            self.config_path = f.name
        self.config = ddos_detector.Config(self.config_path)
        self.notifier = ddos_detector.NotificationManager(self.config)
    
    def tearDown(self):
        """Clean up"""
        os.unlink(self.config_path)
    
    def test_should_notify_first_time(self):
        """Test notification allowed on first occurrence"""
        self.assertTrue(self.notifier._should_notify("192.168.1.1"))
    
    def test_should_notify_cooldown(self):
        """Test cooldown period prevents duplicate notifications"""
        target = "192.168.1.1"
        self.notifier.last_notifications[target] = datetime.now()
        self.assertFalse(self.notifier._should_notify(target))
    
    def test_format_message(self):
        """Test message formatting"""
        attack_info = {
            'dst_ip': '192.168.1.1',
            'bps': 1500000000,
            'entropy': 0.85,
            'unique_sources': 2000,
            'attack_type': 'DDoS'
        }
        message = self.notifier._format_message(attack_info)
        self.assertIn('192.168.1.1', message)
        self.assertIn('DDoS', message)
        self.assertIn('0.8500', message)
    
    @patch('requests.post')
    def test_send_discord(self, mock_post):
        """Test Discord notification sending"""
        mock_post.return_value.status_code = 200
        attack_info = {
            'dst_ip': '192.168.1.1',
            'bps': 1500000000,
            'entropy': 0.85,
            'unique_sources': 2000,
            'attack_type': 'DDoS'
        }
        message = "Test message"
        self.notifier._send_discord("https://discord.com/test", message, attack_info)
        mock_post.assert_called_once()
    
    @patch('requests.post')
    def test_send_slack(self, mock_post):
        """Test Slack notification sending"""
        mock_post.return_value.status_code = 200
        attack_info = {
            'dst_ip': '192.168.1.1',
            'bps': 1500000000,
            'entropy': 0.85,
            'unique_sources': 2000,
            'attack_type': 'DDoS'
        }
        message = "Test message"
        self.notifier._send_slack("https://slack.com/test", message, attack_info)
        mock_post.assert_called_once()


class TestDDoSDetector(unittest.TestCase):
    """Test DDoS detection logic"""
    
    def setUp(self):
        """Set up test fixtures"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("""
clickhouse:
  host: localhost
  port: 9000
  database: flows
detection:
  thresholds:
    total_external_bps_threshold: 1000000000
    dst_bps_threshold: 1000000000
    entropy_threshold: 0.8
            """)
            self.config_path = f.name
        self.config = ddos_detector.Config(self.config_path)
    
    def tearDown(self):
        """Clean up"""
        os.unlink(self.config_path)
    
    def test_entropy_calculation(self):
        """Test normalized entropy calculation"""
        # Create a minimal detector instance just for entropy calculation
        detector = ddos_detector.DDoSDetector.__new__(ddos_detector.DDoSDetector)
        
        # Test case 1: Evenly distributed sources (high entropy)
        src_ips = ['10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4']
        src_bytes = [250, 250, 250, 250]
        entropy = detector.calculate_normalized_entropy(src_ips, src_bytes)
        self.assertGreater(entropy, 0.95)  # Should be close to 1.0
        
        # Test case 2: Single dominant source (low entropy)
        src_ips = ['10.0.0.1', '10.0.0.2']
        src_bytes = [950, 50]
        entropy = detector.calculate_normalized_entropy(src_ips, src_bytes)
        self.assertLess(entropy, 0.5)  # Should be low
        
        # Test case 3: Empty list
        entropy = detector.calculate_normalized_entropy([], [])
        self.assertEqual(entropy, 0.0)
    
    @patch('ddos_detector.ClickHouseClient')
    @patch('ddos_detector.NotificationManager')
    def test_detect_ddos_attack(self, mock_notifier, mock_db):
        """Test detection of DDoS attack (high entropy)"""
        # Mock database client
        mock_db_instance = Mock()
        mock_db_instance.get_total_external_traffic.return_value = 2000000000  # 2 Gbps
        mock_db_instance.get_dst_traffic_stats.return_value = [
            {
                'dst_ip': '192.168.1.1',
                'bps': 1500000000,  # 1.5 Gbps
                'src_ips': ['10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4'],
                'src_bytes': [375000000, 375000000, 375000000, 375000000]  # Evenly distributed
            }
        ]
        mock_db.return_value = mock_db_instance
        
        # Mock notifier
        mock_notifier_instance = Mock()
        mock_notifier.return_value = mock_notifier_instance
        
        # Create detector
        detector = ddos_detector.DDoSDetector(self.config)
        
        # Detect attacks
        attacks = detector.detect_attacks()
        
        # Verify DDoS attack detected (entropy should be high)
        self.assertEqual(len(attacks), 1)
        self.assertEqual(attacks[0]['dst_ip'], '192.168.1.1')
        self.assertEqual(attacks[0]['attack_type'], 'DDoS')
    
    @patch('ddos_detector.ClickHouseClient')
    @patch('ddos_detector.NotificationManager')
    def test_detect_dos_attack(self, mock_notifier, mock_db):
        """Test detection of DoS attack (low entropy)"""
        # Mock database client
        mock_db_instance = Mock()
        mock_db_instance.get_total_external_traffic.return_value = 2000000000  # 2 Gbps
        mock_db_instance.get_dst_traffic_stats.return_value = [
            {
                'dst_ip': '192.168.1.1',
                'bps': 1500000000,  # 1.5 Gbps
                'src_ips': ['10.0.0.1', '10.0.0.2'],
                'src_bytes': [1400000000, 100000000]  # Heavily skewed to one source
            }
        ]
        mock_db.return_value = mock_db_instance
        
        # Mock notifier
        mock_notifier_instance = Mock()
        mock_notifier.return_value = mock_notifier_instance
        
        # Create detector
        detector = ddos_detector.DDoSDetector(self.config)
        
        # Detect attacks
        attacks = detector.detect_attacks()
        
        # Verify DoS attack detected (entropy should be low)
        self.assertEqual(len(attacks), 1)
        self.assertEqual(attacks[0]['dst_ip'], '192.168.1.1')
        self.assertEqual(attacks[0]['attack_type'], 'DoS')
    
    @patch('ddos_detector.ClickHouseClient')
    @patch('ddos_detector.NotificationManager')
    def test_no_detection_below_threshold(self, mock_notifier, mock_db):
        """Test no detection when below threshold"""
        # Mock database client
        mock_db_instance = Mock()
        mock_db_instance.get_total_external_traffic.return_value = 500000000  # 0.5 Gbps - below threshold
        mock_db_instance.get_dst_traffic_stats.return_value = []
        mock_db.return_value = mock_db_instance
        
        # Mock notifier
        mock_notifier_instance = Mock()
        mock_notifier.return_value = mock_notifier_instance
        
        # Create detector
        detector = ddos_detector.DDoSDetector(self.config)
        
        # Detect attacks
        attacks = detector.detect_attacks()
        
        # Verify no attacks detected
        self.assertEqual(len(attacks), 0)


if __name__ == '__main__':
    # Run tests
    unittest.main()
