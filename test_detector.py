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
import requests

# Import the detector module
import ddos_detector


class TestConfig(unittest.TestCase):
    """Test configuration loading"""
    
    def test_config_with_defaults(self):
        """Test config loads with default values"""
        print("\n  [Config] Testing default configuration loading...")
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
        print("  [Config] Testing environment variable override...")
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
        print("  [Notification] Testing first-time notification allowance...")
        self.assertTrue(self.notifier._should_notify("192.168.1.1"))
    
    def test_should_notify_cooldown(self):
        """Test cooldown period prevents duplicate notifications"""
        print("  [Notification] Testing cooldown period blocking...")
        target = "192.168.1.1"
        self.notifier.last_notifications[target] = datetime.now()
        self.assertFalse(self.notifier._should_notify(target))
    
    def test_format_message(self):
        """Test message formatting"""
        print("  [Notification] Testing message formatting...")
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
        print("  [Notification] Testing Discord webhook sending...")
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
        print("  [Notification] Testing Slack webhook sending...")
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
        print("  [Detection] Testing entropy calculation...")
        # Test case 1: Evenly distributed sources (high entropy)
        print("    - Case 1: Evenly distributed sources (high entropy)")
        src_ips = ['10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4']
        src_bytes = [250, 250, 250, 250]
        entropy = ddos_detector.DDoSDetector.calculate_normalized_entropy(src_ips, src_bytes)
        print(f"      Entropy: {entropy:.4f} (expected > 0.95)")
        self.assertGreater(entropy, 0.95)  # Should be close to 1.0
        
        # Test case 2: Single dominant source (low entropy)
        print("    - Case 2: Single dominant source (low entropy)")
        src_ips = ['10.0.0.1', '10.0.0.2']
        src_bytes = [950, 50]
        entropy = ddos_detector.DDoSDetector.calculate_normalized_entropy(src_ips, src_bytes)
        print(f"      Entropy: {entropy:.4f} (expected < 0.5)")
        self.assertLess(entropy, 0.5)  # Should be low
        
        # Test case 3: Empty list
        print("    - Case 3: Empty list")
        entropy = ddos_detector.DDoSDetector.calculate_normalized_entropy([], [])
        print(f"      Entropy: {entropy:.4f} (expected = 0.0)")
        self.assertEqual(entropy, 0.0)
    
    @patch('ddos_detector.ClickHouseClient')
    @patch('ddos_detector.NotificationManager')
    def test_detect_ddos_attack(self, mock_notifier, mock_db):
        """Test detection of DDoS attack (high entropy)"""
        print("  [Detection] Testing DDoS attack detection (high entropy)...")
        # Mock database client
        mock_db_instance = Mock()
        mock_db_instance.get_total_external_traffic.return_value = 2000000000  # 2 Gbps
        mock_db_instance.get_dst_traffic_stats.return_value = [
            {
                'dst_ip': '192.168.1.1',
                'bps': 1500000000,  # 1.5 Gbps
                'src_ips': ['10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4'],
                'src_bytes': [375000000, 375000000, 375000000, 375000000],  # Evenly distributed
                'unique_sources': 4
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
        print(f"    ✓ Detected {attacks[0]['attack_type']} attack on {attacks[0]['dst_ip']} (entropy: {attacks[0].get('entropy', 0):.4f})")
    
    @patch('ddos_detector.AbuseIPDBClient')
    @patch('ddos_detector.ClickHouseClient')
    @patch('ddos_detector.NotificationManager')
    def test_detect_dos_attack(self, mock_notifier, mock_db, mock_abuseipdb):
        """Test detection of DoS attack (low entropy) - Note: Without AbuseIPDB reported IP, low entropy alone won't trigger alert"""
        print("  [Detection] Testing DoS classification (low entropy, no alert without reported IP)...")
        # Mock database client
        mock_db_instance = Mock()
        mock_db_instance.get_total_external_traffic.return_value = 2000000000  # 2 Gbps
        mock_db_instance.get_dst_traffic_stats.return_value = [
            {
                'dst_ip': '192.168.1.1',
                'bps': 1500000000,  # 1.5 Gbps
                'src_ips': ['10.0.0.1', '10.0.0.2'],
                'src_bytes': [1400000000, 100000000],  # Heavily skewed to one source
                'unique_sources': 2
            }
        ]
        mock_db.return_value = mock_db_instance
        
        # Mock AbuseIPDB client - no reported IPs
        mock_abuseipdb_instance = Mock()
        mock_abuseipdb_instance.enabled = False  # Disabled to test entropy-only logic
        mock_abuseipdb.return_value = mock_abuseipdb_instance
        
        # Mock notifier
        mock_notifier_instance = Mock()
        mock_notifier.return_value = mock_notifier_instance
        
        # Create detector
        detector = ddos_detector.DDoSDetector(self.config)
        
        # Detect attacks
        attacks = detector.detect_attacks()
        
        # Verify NO attack detected (low entropy + no reported IP = no alert)
        # The attack would be classified as DoS if triggered, but it's not triggered
        self.assertEqual(len(attacks), 0)
        print(f"    ✓ No attack detected with low entropy and no reported IP (expected behavior)")
    
    @patch('ddos_detector.ClickHouseClient')
    @patch('ddos_detector.NotificationManager')
    def test_no_detection_below_threshold(self, mock_notifier, mock_db):
        """Test no detection when below threshold"""
        print("  [Detection] Testing no detection when below threshold...")
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
        print("    ✓ No attacks detected (traffic below threshold)")


class TestAbuseIPDBClient(unittest.TestCase):
    """Test AbuseIPDB API client functionality"""
    
    def setUp(self):
        """Set up test fixtures"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("""
abuseipdb:
  api_key: "test_api_key_12345"
  max_age_days: 90
            """)
            self.config_path = f.name
        self.config = ddos_detector.Config(self.config_path)
        self.client = ddos_detector.AbuseIPDBClient(self.config)
    
    def tearDown(self):
        """Clean up"""
        os.unlink(self.config_path)
    
    def test_client_enabled_with_api_key(self):
        """Test client is enabled when API key is provided"""
        print("  [AbuseIPDB] Testing client enabled with API key...")
        self.assertTrue(self.client.enabled)
        self.assertEqual(self.client.api_key, "test_api_key_12345")
    
    def test_client_disabled_without_api_key(self):
        """Test client is disabled when API key is not provided"""
        print("  [AbuseIPDB] Testing client disabled without API key...")
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("abuseipdb:\n  api_key: ''\n")
            config_path = f.name
        
        try:
            config = ddos_detector.Config(config_path)
            client = ddos_detector.AbuseIPDBClient(config)
            self.assertFalse(client.enabled)
        finally:
            os.unlink(config_path)
    
    @patch('requests.get')
    def test_check_ip_reported(self, mock_get):
        """Test checking an IP that has been reported"""
        print("  [AbuseIPDB] Testing reported IP check...")
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'data': {
                'ipAddress': '1.2.3.4',
                'abuseConfidenceScore': 100,
                'totalReports': 50,
                'countryCode': 'CN',
                'usageType': 'Data Center',
                'isp': 'Example ISP'
            }
        }
        mock_get.return_value = mock_response
        
        result = self.client.check_ip('1.2.3.4')
        
        self.assertIsNotNone(result)
        self.assertEqual(result['ip_address'], '1.2.3.4')
        self.assertEqual(result['total_reports'], 50)
        self.assertEqual(result['abuse_confidence_score'], 100)
        self.assertTrue(result['is_reported'])
        print(f"    ✓ IP 1.2.3.4 marked as reported (reports: {result['total_reports']}, score: {result['abuse_confidence_score']})")
    
    @patch('requests.get')
    def test_check_ip_not_reported(self, mock_get):
        """Test checking an IP that has not been reported"""
        print("  [AbuseIPDB] Testing clean IP check...")
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'data': {
                'ipAddress': '8.8.8.8',
                'abuseConfidenceScore': 0,
                'totalReports': 0,
                'countryCode': 'US',
                'usageType': 'Content Delivery Network',
                'isp': 'Google'
            }
        }
        mock_get.return_value = mock_response
        
        result = self.client.check_ip('8.8.8.8')
        
        self.assertIsNotNone(result)
        self.assertEqual(result['total_reports'], 0)
        self.assertFalse(result['is_reported'])
        print(f"    ✓ IP 8.8.8.8 marked as clean (reports: {result['total_reports']})")
    
    @patch('requests.get')
    def test_check_ip_api_error(self, mock_get):
        """Test handling of API errors"""
        print("  [AbuseIPDB] Testing API error handling...")
        mock_get.side_effect = requests.exceptions.RequestException("API Error")
        
        result = self.client.check_ip('1.2.3.4')
        
        self.assertIsNone(result)
        print("    ✓ API error handled gracefully")
    
    def test_check_ip_when_disabled(self):
        """Test that check returns None when client is disabled"""
        print("  [AbuseIPDB] Testing disabled client behavior...")
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("abuseipdb:\n  api_key: ''\n")
            config_path = f.name
        
        try:
            config = ddos_detector.Config(config_path)
            client = ddos_detector.AbuseIPDBClient(config)
            result = client.check_ip('1.2.3.4')
            self.assertIsNone(result)
            print("    ✓ Disabled client returns None")
        finally:
            os.unlink(config_path)


class TestDDoSDetectorWithAbuseIPDB(unittest.TestCase):
    """Test DDoS detection logic with AbuseIPDB integration"""
    
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
abuseipdb:
  api_key: "test_api_key_12345"
  max_age_days: 90
            """)
            self.config_path = f.name
        self.config = ddos_detector.Config(self.config_path)
    
    def tearDown(self):
        """Clean up"""
        os.unlink(self.config_path)
    
    @patch('ddos_detector.AbuseIPDBClient')
    @patch('ddos_detector.ClickHouseClient')
    @patch('ddos_detector.NotificationManager')
    def test_detect_with_reported_ip(self, mock_notifier, mock_db, mock_abuseipdb):
        """Test detection with reported IP from AbuseIPDB"""
        print("  [Detection+AbuseIPDB] Testing detection with reported IP...")
        
        # Mock database client
        mock_db_instance = Mock()
        mock_db_instance.get_total_external_traffic.return_value = 2000000000  # 2 Gbps
        mock_db_instance.get_dst_traffic_stats.return_value = [
            {
                'dst_ip': '192.168.1.1',
                'bps': 1500000000,  # 1.5 Gbps
                'src_ips': ['10.0.0.1', '10.0.0.2'],
                'src_bytes': [1400000000, 100000000],  # Low entropy
                'unique_sources': 2
            }
        ]
        mock_db.return_value = mock_db_instance
        
        # Mock AbuseIPDB client
        mock_abuseipdb_instance = Mock()
        mock_abuseipdb_instance.enabled = True
        # First IP check returns reported IP
        mock_abuseipdb_instance.check_ip.return_value = {
            'ip_address': '10.0.0.1',
            'abuse_confidence_score': 100,
            'total_reports': 50,
            'is_reported': True,
            'country_code': 'CN',
            'usage_type': 'Data Center',
            'isp': 'Malicious ISP'
        }
        mock_abuseipdb.return_value = mock_abuseipdb_instance
        
        # Mock notifier
        mock_notifier_instance = Mock()
        mock_notifier.return_value = mock_notifier_instance
        
        # Create detector
        detector = ddos_detector.DDoSDetector(self.config)
        
        # Detect attacks
        attacks = detector.detect_attacks()
        
        # Verify attack detected due to reported IP (even with low entropy)
        self.assertEqual(len(attacks), 1)
        self.assertEqual(attacks[0]['dst_ip'], '192.168.1.1')
        self.assertIsNotNone(attacks[0]['abuse_info'])
        self.assertEqual(attacks[0]['abuse_info']['total_reports'], 50)
        print(f"    ✓ Attack detected due to reported IP (reports: {attacks[0]['abuse_info']['total_reports']})")
    
    @patch('ddos_detector.AbuseIPDBClient')
    @patch('ddos_detector.ClickHouseClient')
    @patch('ddos_detector.NotificationManager')
    def test_detect_with_high_entropy_no_reported_ip(self, mock_notifier, mock_db, mock_abuseipdb):
        """Test detection with high entropy but no reported IPs"""
        print("  [Detection+AbuseIPDB] Testing detection with high entropy, no reported IP...")
        
        # Mock database client
        mock_db_instance = Mock()
        mock_db_instance.get_total_external_traffic.return_value = 2000000000
        mock_db_instance.get_dst_traffic_stats.return_value = [
            {
                'dst_ip': '192.168.1.1',
                'bps': 1500000000,
                'src_ips': ['10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4'],
                'src_bytes': [375000000, 375000000, 375000000, 375000000],  # High entropy
                'unique_sources': 4
            }
        ]
        mock_db.return_value = mock_db_instance
        
        # Mock AbuseIPDB client - all IPs return not reported
        mock_abuseipdb_instance = Mock()
        mock_abuseipdb_instance.enabled = True
        mock_abuseipdb_instance.check_ip.return_value = {
            'ip_address': '10.0.0.1',
            'abuse_confidence_score': 0,
            'total_reports': 0,
            'is_reported': False,
            'country_code': 'US',
            'usage_type': 'ISP',
            'isp': 'Clean ISP'
        }
        mock_abuseipdb.return_value = mock_abuseipdb_instance
        
        # Mock notifier
        mock_notifier_instance = Mock()
        mock_notifier.return_value = mock_notifier_instance
        
        # Create detector
        detector = ddos_detector.DDoSDetector(self.config)
        
        # Detect attacks
        attacks = detector.detect_attacks()
        
        # Verify attack detected due to high entropy
        self.assertEqual(len(attacks), 1)
        self.assertTrue(attacks[0]['entropy_triggered'])
        self.assertIsNone(attacks[0]['abuse_info'])
        print(f"    ✓ Attack detected due to high entropy (entropy: {attacks[0]['entropy']:.4f})")
    
    @patch('ddos_detector.AbuseIPDBClient')
    @patch('ddos_detector.ClickHouseClient')
    @patch('ddos_detector.NotificationManager')
    def test_no_detection_low_entropy_no_reported_ip(self, mock_notifier, mock_db, mock_abuseipdb):
        """Test no detection when low entropy and no reported IPs"""
        print("  [Detection+AbuseIPDB] Testing no detection with low entropy and clean IPs...")
        
        # Mock database client
        mock_db_instance = Mock()
        mock_db_instance.get_total_external_traffic.return_value = 2000000000
        mock_db_instance.get_dst_traffic_stats.return_value = [
            {
                'dst_ip': '192.168.1.1',
                'bps': 1500000000,
                'src_ips': ['10.0.0.1', '10.0.0.2'],
                'src_bytes': [1400000000, 100000000],  # Low entropy
                'unique_sources': 2
            }
        ]
        mock_db.return_value = mock_db_instance
        
        # Mock AbuseIPDB client - all IPs clean
        mock_abuseipdb_instance = Mock()
        mock_abuseipdb_instance.enabled = True
        mock_abuseipdb_instance.check_ip.return_value = {
            'ip_address': '10.0.0.1',
            'abuse_confidence_score': 0,
            'total_reports': 0,
            'is_reported': False,
            'country_code': 'US',
            'usage_type': 'ISP',
            'isp': 'Clean ISP'
        }
        mock_abuseipdb.return_value = mock_abuseipdb_instance
        
        # Mock notifier
        mock_notifier_instance = Mock()
        mock_notifier.return_value = mock_notifier_instance
        
        # Create detector
        detector = ddos_detector.DDoSDetector(self.config)
        
        # Detect attacks
        attacks = detector.detect_attacks()
        
        # Verify no attacks detected
        self.assertEqual(len(attacks), 0)
        print("    ✓ No attack detected (low entropy + clean IPs)")
    
    @patch('ddos_detector.AbuseIPDBClient')
    @patch('ddos_detector.ClickHouseClient')
    @patch('ddos_detector.NotificationManager')
    def test_api_quota_saving(self, mock_notifier, mock_db, mock_abuseipdb):
        """Test API calls stop after first reported IP is found"""
        print("  [Detection+AbuseIPDB] Testing API quota saving (stops after first reported IP)...")
        
        # Mock database client with two destinations
        mock_db_instance = Mock()
        mock_db_instance.get_total_external_traffic.return_value = 3000000000
        mock_db_instance.get_dst_traffic_stats.return_value = [
            {
                'dst_ip': '192.168.1.1',
                'bps': 1500000000,
                'src_ips': ['10.0.0.1', '10.0.0.2'],
                'src_bytes': [750000000, 750000000],
                'unique_sources': 2
            },
            {
                'dst_ip': '192.168.1.2',
                'bps': 1200000000,
                'src_ips': ['10.0.0.3', '10.0.0.4'],
                'src_bytes': [600000000, 600000000],
                'unique_sources': 2
            }
        ]
        mock_db.return_value = mock_db_instance
        
        # Mock AbuseIPDB client
        mock_abuseipdb_instance = Mock()
        mock_abuseipdb_instance.enabled = True
        # First call returns reported IP
        mock_abuseipdb_instance.check_ip.return_value = {
            'ip_address': '10.0.0.1',
            'abuse_confidence_score': 100,
            'total_reports': 50,
            'is_reported': True,
            'country_code': 'CN',
            'usage_type': 'Data Center',
            'isp': 'Malicious ISP'
        }
        mock_abuseipdb.return_value = mock_abuseipdb_instance
        
        # Mock notifier
        mock_notifier_instance = Mock()
        mock_notifier.return_value = mock_notifier_instance
        
        # Create detector
        detector = ddos_detector.DDoSDetector(self.config)
        
        # Detect attacks
        attacks = detector.detect_attacks()
        
        # Verify both attacks detected:
        # - First one with reported IP (triggers API and alert)
        # - Second one with high entropy (no API call, but high entropy triggers alert)
        self.assertEqual(len(attacks), 2)
        self.assertEqual(attacks[0]['dst_ip'], '192.168.1.1')
        self.assertIsNotNone(attacks[0]['abuse_info'])  # Has AbuseIPDB info
        self.assertEqual(attacks[1]['dst_ip'], '192.168.1.2')
        self.assertIsNone(attacks[1]['abuse_info'])  # No AbuseIPDB info (quota reached)
        self.assertTrue(attacks[1]['entropy_triggered'])  # Triggered by entropy
        
        # Check that API was called only once (for first destination, stopped after first reported IP)
        self.assertEqual(mock_abuseipdb_instance.check_ip.call_count, 1)
        print(f"    ✓ API quota saved: only {mock_abuseipdb_instance.check_ip.call_count} API call(s) made")
        print(f"    ✓ Second destination detected via entropy (no API call needed)")


if __name__ == '__main__':
    # Run tests
    print("\n" + "="*60)
    print("🧪 Akvorado DDoS Detector - Test Suite")
    print("="*60)
    unittest.main(verbosity=2)
