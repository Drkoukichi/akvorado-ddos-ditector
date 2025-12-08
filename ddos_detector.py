#!/usr/bin/env python3
"""
DDoS Detection System for Akvorado
Monitors network flow data from ClickHouse and sends alerts to Discord/Slack
"""

import os
import sys
import time
import logging
import math
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import yaml
import clickhouse_connect
import requests
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


class Config:
    """Configuration manager"""
    
    def __init__(self, config_path: str = "config.yaml"):
        self.config_path = config_path
        self.config = self._load_config()
    
    def _load_config(self) -> dict:
        """Load configuration from YAML file or environment variables"""
        config = {}
        
        # Try to load from YAML file
        if os.path.exists(self.config_path):
            with open(self.config_path, 'r') as f:
                config = yaml.safe_load(f) or {}
        
        # Override with environment variables if present
        config.setdefault('clickhouse', {})
        config['clickhouse']['host'] = os.getenv('CLICKHOUSE_HOST', config.get('clickhouse', {}).get('host', 'localhost'))
        config['clickhouse']['port'] = int(os.getenv('CLICKHOUSE_PORT', config.get('clickhouse', {}).get('port', 9000)))
        config['clickhouse']['database'] = os.getenv('CLICKHOUSE_DATABASE', config.get('clickhouse', {}).get('database', 'flows'))
        config['clickhouse']['user'] = os.getenv('CLICKHOUSE_USER', config.get('clickhouse', {}).get('user', 'default'))
        config['clickhouse']['password'] = os.getenv('CLICKHOUSE_PASSWORD', config.get('clickhouse', {}).get('password', ''))
        
        config.setdefault('detection', {})
        config['detection']['check_interval'] = int(os.getenv('CHECK_INTERVAL', config.get('detection', {}).get('check_interval', 60)))
        config['detection']['time_window'] = int(os.getenv('TIME_WINDOW', config.get('detection', {}).get('time_window', 300)))
        
        config['detection'].setdefault('thresholds', {})
        config['detection']['thresholds']['total_external_bps_threshold'] = int(os.getenv('TOTAL_EXTERNAL_BPS_THRESHOLD', config.get('detection', {}).get('thresholds', {}).get('total_external_bps_threshold', 1000000000)))
        config['detection']['thresholds']['dst_bps_threshold'] = int(os.getenv('DST_BPS_THRESHOLD', config.get('detection', {}).get('thresholds', {}).get('dst_bps_threshold', 1000000000)))
        config['detection']['thresholds']['entropy_threshold'] = float(os.getenv('ENTROPY_THRESHOLD', config.get('detection', {}).get('thresholds', {}).get('entropy_threshold', 0.8)))
        
        config.setdefault('notifications', {})
        config['notifications']['discord_webhook'] = os.getenv('DISCORD_WEBHOOK', config.get('notifications', {}).get('discord_webhook', ''))
        config['notifications']['slack_webhook'] = os.getenv('SLACK_WEBHOOK', config.get('notifications', {}).get('slack_webhook', ''))
        config['notifications']['cooldown'] = int(os.getenv('NOTIFICATION_COOLDOWN', config.get('notifications', {}).get('cooldown', 300)))
        
        config.setdefault('logging', {})
        config['logging']['level'] = os.getenv('LOG_LEVEL', config.get('logging', {}).get('level', 'INFO'))
        config['logging']['file'] = os.getenv('LOG_FILE', config.get('logging', {}).get('file', 'ddos_detector.log'))
        
        config.setdefault('abuseipdb', {})
        config['abuseipdb']['api_key'] = os.getenv('ABUSEIPDB_API_KEY', config.get('abuseipdb', {}).get('api_key', ''))
        config['abuseipdb']['enabled'] = bool(config['abuseipdb']['api_key'])
        config['abuseipdb']['max_age_days'] = int(os.getenv('ABUSEIPDB_MAX_AGE_DAYS', config.get('abuseipdb', {}).get('max_age_days', 90)))
        
        return config
    
    def get(self, *keys, default=None):
        """Get nested configuration value"""
        value = self.config
        for key in keys:
            if isinstance(value, dict):
                value = value.get(key)
            else:
                return default
            if value is None:
                return default
        return value


class ClickHouseClient:
    """ClickHouse database client for Akvorado"""
    
    def __init__(self, config: Config):
        self.config = config
        self.client = None
        self._connect()
    
    def _connect(self):
        """Connect to ClickHouse database"""
        try:
            self.client = clickhouse_connect.get_client(
                host=self.config.get('clickhouse', 'host'),
                port=self.config.get('clickhouse', 'port'),
                database=self.config.get('clickhouse', 'database'),
                username=self.config.get('clickhouse', 'user'),
                password=self.config.get('clickhouse', 'password')
            )
            logging.info(f"Connected to ClickHouse at {self.config.get('clickhouse', 'host')}")
        except Exception as e:
            logging.error(f"Failed to connect to ClickHouse: {e}")
            raise
    
    def get_total_external_traffic(self, time_window: int) -> float:
        """
        Get total traffic with InIfBoundary = external
        
        Args:
            time_window: Time window in seconds
            
        Returns:
            Total bytes per second for external traffic
        """
        try:
            end_time = datetime.now()
            start_time = end_time - timedelta(seconds=time_window)
            
            query = f"""
            SELECT
                sum(Bytes) / {time_window} as bps
            FROM flows
            WHERE TimeReceived >= toDateTime('{start_time.strftime('%Y-%m-%d %H:%M:%S')}')
              AND TimeReceived <= toDateTime('{end_time.strftime('%Y-%m-%d %H:%M:%S')}')
              AND InIfBoundary = 'external'
            """
            
            result = self.client.query(query)
            
            if result.result_rows and len(result.result_rows) > 0:
                return float(result.result_rows[0][0] or 0)
            return 0.0
            
        except Exception as e:
            logging.error(f"Failed to query total external traffic: {e}")
            return 0.0
    
    def get_dst_traffic_stats(self, time_window: int) -> List[Dict]:
        """
        Get aggregated traffic statistics per destination IP for external traffic
        
        Args:
            time_window: Time window in seconds
            
        Returns:
            List of dictionaries with traffic statistics per destination
        """
        try:
            end_time = datetime.now()
            start_time = end_time - timedelta(seconds=time_window)
            
            query = f"""
            SELECT
                DstAddr as dst_ip,
                sum(Bytes) / {time_window} as bps,
                groupArray(SrcAddr) as src_ips,
                groupArray(Bytes) as src_bytes,
                uniq(SrcAddr) as unique_sources
            FROM flows
            WHERE TimeReceived >= toDateTime('{start_time.strftime('%Y-%m-%d %H:%M:%S')}')
              AND TimeReceived <= toDateTime('{end_time.strftime('%Y-%m-%d %H:%M:%S')}')
              AND InIfBoundary = 'external'
            GROUP BY DstAddr
            HAVING bps > 1000000
            ORDER BY bps DESC
            LIMIT 100
            """
            
            result = self.client.query(query)
            
            stats = []
            for row in result.result_rows:
                stats.append({
                    'dst_ip': row[0],
                    'bps': float(row[1]),
                    'src_ips': row[2],
                    'src_bytes': row[3],
                    'unique_sources': int(row[4])
                })
            
            return stats
            
        except Exception as e:
            logging.error(f"Failed to query destination traffic stats: {e}")
            return []


class AbuseIPDBClient:
    """Client for AbuseIPDB API"""
    
    def __init__(self, config: Config):
        self.config = config
        self.api_key = config.get('abuseipdb', 'api_key')
        self.enabled = config.get('abuseipdb', 'enabled', default=False)
        self.max_age_days = config.get('abuseipdb', 'max_age_days', default=90)
        self.base_url = 'https://api.abuseipdb.com/api/v2'
    
    def check_ip(self, ip_address: str) -> Optional[Dict]:
        """Check if an IP address has been reported to AbuseIPDB
        
        Args:
            ip_address: IP address to check
            
        Returns:
            Dictionary with abuse information or None if not available
        """
        if not self.enabled:
            logging.debug("AbuseIPDB API is disabled")
            return None
        
        try:
            headers = {
                'Key': self.api_key,
                'Accept': 'application/json'
            }
            
            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': self.max_age_days,
                'verbose': ''
            }
            
            response = requests.get(
                f'{self.base_url}/check',
                headers=headers,
                params=params,
                timeout=10
            )
            
            response.raise_for_status()
            data = response.json()
            
            if 'data' in data:
                ip_data = data['data']
                result = {
                    'ip_address': ip_data.get('ipAddress'),
                    'abuse_confidence_score': ip_data.get('abuseConfidenceScore', 0),
                    'total_reports': ip_data.get('totalReports', 0),
                    'is_reported': ip_data.get('totalReports', 0) > 0,
                    'country_code': ip_data.get('countryCode', 'Unknown'),
                    'usage_type': ip_data.get('usageType', 'Unknown'),
                    'isp': ip_data.get('isp', 'Unknown')
                }
                
                logging.info(
                    f"AbuseIPDB check for {ip_address}: "
                    f"reports={result['total_reports']}, "
                    f"score={result['abuse_confidence_score']}"
                )
                
                return result
            
            return None
            
        except requests.exceptions.RequestException as e:
            logging.error(f"Failed to check IP {ip_address} with AbuseIPDB: {e}")
            return None
        except Exception as e:
            logging.error(f"Unexpected error checking IP {ip_address}: {e}")
            return None


class NotificationManager:
    """Manage notifications to Discord and Slack"""
    
    def __init__(self, config: Config):
        self.config = config
        self.last_notifications: Dict[str, datetime] = {}
    
    def _should_notify(self, target: str) -> bool:
        """Check if enough time has passed since last notification for this target"""
        cooldown = self.config.get('notifications', 'cooldown')
        last_time = self.last_notifications.get(target)
        
        if last_time is None:
            return True
        
        return (datetime.now() - last_time).total_seconds() >= cooldown
    
    def send_alert(self, attack_info: Dict):
        """Send DDoS alert to configured notification channels"""
        target = attack_info['dst_ip']
        
        if not self._should_notify(target):
            logging.debug(f"Skipping notification for {target} due to cooldown")
            return
        
        # Prepare message
        message = self._format_message(attack_info)
        
        # Send to Discord
        discord_webhook = self.config.get('notifications', 'discord_webhook')
        if discord_webhook:
            self._send_discord(discord_webhook, message, attack_info)
        
        # Send to Slack
        slack_webhook = self.config.get('notifications', 'slack_webhook')
        if slack_webhook:
            self._send_slack(slack_webhook, message, attack_info)
        
        # Update last notification time
        self.last_notifications[target] = datetime.now()
    
    def _format_message(self, attack_info: Dict) -> str:
        """Format alert message"""
        attack_type = attack_info.get('attack_type', 'DDoS')
        emoji = "🚨" if attack_type == "DDoS" else "⚠️"
        
        message = (
            f"{emoji} **{attack_type} Attack Detected!** {emoji}\n\n"
            f"**Target IP:** {attack_info['dst_ip']}\n"
            f"**Bytes/sec:** {attack_info['bps']:,.0f} ({attack_info['bps']/1000000000:.2f} Gbps)\n"
            f"**Entropy:** {attack_info.get('entropy', 0):.4f}\n"
            f"**Unique Sources:** {attack_info.get('unique_sources', 0):,}\n"
            f"**Time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        )
        
        # Add AbuseIPDB information if available
        abuse_info = attack_info.get('abuse_info')
        if abuse_info:
            message += (
                f"\n**🔍 AbuseIPDB Check:**\n"
                f"**Reported IP Found:** {abuse_info.get('ip_address')}\n"
                f"**Total Reports:** {abuse_info.get('total_reports', 0)}\n"
                f"**Abuse Score:** {abuse_info.get('abuse_confidence_score', 0)}%\n"
                f"**Country:** {abuse_info.get('country_code', 'Unknown')}\n"
                f"**ISP:** {abuse_info.get('isp', 'Unknown')}\n"
            )
        elif attack_info.get('entropy_triggered'):
            message += f"\n**⚠️ Alert Reason:** High source IP entropy detected\n"
        
        return message
    
    def _send_discord(self, webhook_url: str, message: str, attack_info: Dict):
        """Send notification to Discord"""
        try:
            attack_type = attack_info.get('attack_type', 'DDoS')
            
            # Determine color based on attack type and severity
            if attack_type == "DDoS":
                color = 0xFF0000  # Red - DDoS
            else:
                color = 0xFF6600  # Orange - DoS
            
            emoji = "🚨" if attack_type == "DDoS" else "⚠️"
            
            payload = {
                "embeds": [{
                    "title": f"{emoji} {attack_type} Attack Detected",
                    "description": message,
                    "color": color,
                    "timestamp": datetime.now().isoformat(),
                    "footer": {
                        "text": "Akvorado DDoS Detector"
                    }
                }]
            }
            
            response = requests.post(webhook_url, json=payload, timeout=10)
            response.raise_for_status()
            logging.info(f"Discord notification sent for {attack_info['dst_ip']} ({attack_type})")
            
        except Exception as e:
            logging.error(f"Failed to send Discord notification: {e}")
    
    def _send_slack(self, webhook_url: str, message: str, attack_info: Dict):
        """Send notification to Slack"""
        try:
            attack_type = attack_info.get('attack_type', 'DDoS')
            
            # Determine color based on attack type
            if attack_type == "DDoS":
                color = "danger"  # Red
            else:
                color = "warning"  # Orange
            
            emoji = "🚨" if attack_type == "DDoS" else "⚠️"
            
            payload = {
                "attachments": [{
                    "color": color,
                    "title": f"{emoji} {attack_type} Attack Detected",
                    "text": message,
                    "footer": "Akvorado DDoS Detector",
                    "ts": int(datetime.now().timestamp())
                }]
            }
            
            response = requests.post(webhook_url, json=payload, timeout=10)
            response.raise_for_status()
            logging.info(f"Slack notification sent for {attack_info['dst_ip']} ({attack_type})")
            
        except Exception as e:
            logging.error(f"Failed to send Slack notification: {e}")


class DDoSDetector:
    """Main DDoS detection engine"""
    
    def __init__(self, config: Config):
        self.config = config
        self.db_client = ClickHouseClient(config)
        self.notifier = NotificationManager(config)
        self.abuseipdb_client = AbuseIPDBClient(config)
    
    @staticmethod
    def calculate_normalized_entropy(src_ips: List, src_bytes: List) -> float:
        """
        Calculate normalized entropy of source IPs based on their traffic distribution
        
        Args:
            src_ips: List of source IP addresses
            src_bytes: List of bytes for each source IP
            
        Returns:
            Normalized entropy value between 0 and 1
        """
        if not src_ips or not src_bytes:
            return 0.0
        
        # Calculate total bytes
        total_bytes = sum(src_bytes)
        if total_bytes == 0:
            return 0.0
        
        # Calculate entropy
        entropy = 0.0
        for bytes_val in src_bytes:
            if bytes_val > 0:
                p = bytes_val / total_bytes
                entropy -= p * math.log2(p)
        
        # Normalize entropy (max entropy is log2(n) where n is number of sources)
        n = len(src_ips)
        if n <= 1:
            return 0.0
        
        max_entropy = math.log2(n)
        normalized_entropy = entropy / max_entropy if max_entropy > 0 else 0.0
        
        return normalized_entropy
    
    def detect_attacks(self) -> List[Dict]:
        """
        Detect potential DoS/DDoS attacks using the new logic:
        1. Check if total external traffic exceeds 1 Gbps
        2. If yes, check each destination IP for traffic > 1 Gbps
        3. For each destination > 1 Gbps, check source IPs with AbuseIPDB
        4. Alert if: IP is reported in AbuseIPDB OR entropy is high
        5. Stop API calls after first reported IP is found (to save API quota)
        """
        time_window = self.config.get('detection', 'time_window')
        thresholds = self.config.get('detection', 'thresholds')
        
        # Step 1: Check total external traffic
        total_external_bps = self.db_client.get_total_external_traffic(time_window)
        total_threshold = thresholds.get('total_external_bps_threshold', 1000000000)
        
        logging.debug(f"Total external traffic: {total_external_bps/1000000000:.2f} Gbps (threshold: {total_threshold/1000000000:.2f} Gbps)")
        
        if total_external_bps <= total_threshold:
            logging.debug("Total external traffic below threshold, no further checks needed")
            return []
        
        logging.info(f"Total external traffic exceeds threshold: {total_external_bps/1000000000:.2f} Gbps")
        
        # Step 2: Check per-destination traffic
        dst_stats = self.db_client.get_dst_traffic_stats(time_window)
        dst_threshold = thresholds.get('dst_bps_threshold', 1000000000)
        entropy_threshold = thresholds.get('entropy_threshold', 0.8)
        
        attacks = []
        api_quota_reached = False  # Flag to stop API calls after first reported IP
        
        for stat in dst_stats:
            if stat['bps'] > dst_threshold:
                # Step 3: Calculate entropy
                entropy = self.calculate_normalized_entropy(stat['src_ips'], stat['src_bytes'])
                
                # Determine attack type based on entropy
                if entropy > entropy_threshold:
                    attack_type = "DDoS"
                else:
                    attack_type = "DoS"
                
                # Step 4: Check source IPs with AbuseIPDB (if not already found a reported IP)
                should_alert = False
                abuse_info = None
                entropy_triggered = False
                
                if not api_quota_reached and self.abuseipdb_client.enabled:
                    # Check source IPs against AbuseIPDB
                    for src_ip in stat['src_ips']:
                        abuse_result = self.abuseipdb_client.check_ip(src_ip)
                        
                        if abuse_result and abuse_result.get('is_reported'):
                            # Found a reported IP - trigger alert and stop API calls
                            should_alert = True
                            abuse_info = abuse_result
                            api_quota_reached = True
                            logging.warning(
                                f"Reported IP found: {src_ip} "
                                f"(reports: {abuse_result.get('total_reports')}, "
                                f"score: {abuse_result.get('abuse_confidence_score')}%)"
                            )
                            break
                    
                    # If no reported IP found but entropy is high, still alert
                    if not should_alert and entropy > entropy_threshold:
                        should_alert = True
                        entropy_triggered = True
                        logging.warning(
                            f"High entropy detected for {stat['dst_ip']}: {entropy:.4f}"
                        )
                else:
                    # AbuseIPDB disabled or quota reached - check entropy only
                    if entropy > entropy_threshold:
                        should_alert = True
                        entropy_triggered = True
                
                # Step 5: Add to attacks list if alert criteria met
                if should_alert:
                    attack_info = {
                        'dst_ip': stat['dst_ip'],
                        'bps': stat['bps'],
                        'entropy': entropy,
                        'unique_sources': stat['unique_sources'],
                        'attack_type': attack_type,
                        'abuse_info': abuse_info,
                        'entropy_triggered': entropy_triggered
                    }
                    
                    attacks.append(attack_info)
                    logging.warning(
                        f"{attack_type} attack detected: {stat['dst_ip']} - "
                        f"{stat['bps']/1000000000:.2f} Gbps, "
                        f"entropy: {entropy:.4f}, "
                        f"sources: {stat['unique_sources']}, "
                        f"abuse_reported: {abuse_info is not None}"
                    )
        
        return attacks
    
    def run(self):
        """Main detection loop"""
        check_interval = self.config.get('detection', 'check_interval')
        
        logging.info("DDoS Detector started")
        logging.info(f"Check interval: {check_interval}s, Time window: {self.config.get('detection', 'time_window')}s")
        
        while True:
            try:
                attacks = self.detect_attacks()
                
                for attack in attacks:
                    self.notifier.send_alert(attack)
                
                if attacks:
                    logging.info(f"Detected {len(attacks)} attack(s)")
                else:
                    logging.debug("No attacks detected")
                
                time.sleep(check_interval)
                
            except KeyboardInterrupt:
                logging.info("DDoS Detector stopped by user")
                break
            except Exception as e:
                logging.error(f"Error in detection loop: {e}", exc_info=True)
                time.sleep(check_interval)


def setup_logging(config: Config):
    """Configure logging"""
    log_level = getattr(logging, config.get('logging', 'level', default='INFO').upper())
    log_file = config.get('logging', 'file')
    
    # Configure logging to both file and console
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
    )


def main():
    """Main entry point"""
    print("Akvorado DDoS Detector")
    print("=" * 50)
    
    try:
        # Load configuration
        config = Config()
        
        # Setup logging
        setup_logging(config)
        
        # Create and run detector
        detector = DDoSDetector(config)
        detector.run()
        
    except Exception as e:
        logging.critical(f"Failed to start DDoS Detector: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
