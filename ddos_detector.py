#!/usr/bin/env python3
"""
DDoS Detection System for Akvorado
Monitors network flow data from ClickHouse and sends alerts to Discord/Slack
"""

import os
import sys
import time
import logging
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
        config['detection']['thresholds']['pps_threshold'] = int(os.getenv('PPS_THRESHOLD', config.get('detection', {}).get('thresholds', {}).get('pps_threshold', 100000)))
        config['detection']['thresholds']['bps_threshold'] = int(os.getenv('BPS_THRESHOLD', config.get('detection', {}).get('thresholds', {}).get('bps_threshold', 1000000000)))
        config['detection']['thresholds']['unique_sources_threshold'] = int(os.getenv('UNIQUE_SOURCES_THRESHOLD', config.get('detection', {}).get('thresholds', {}).get('unique_sources_threshold', 1000)))
        config['detection']['thresholds']['fps_threshold'] = int(os.getenv('FPS_THRESHOLD', config.get('detection', {}).get('thresholds', {}).get('fps_threshold', 10000)))
        
        config.setdefault('notifications', {})
        config['notifications']['discord_webhook'] = os.getenv('DISCORD_WEBHOOK', config.get('notifications', {}).get('discord_webhook', ''))
        config['notifications']['slack_webhook'] = os.getenv('SLACK_WEBHOOK', config.get('notifications', {}).get('slack_webhook', ''))
        config['notifications']['cooldown'] = int(os.getenv('NOTIFICATION_COOLDOWN', config.get('notifications', {}).get('cooldown', 300)))
        
        config.setdefault('logging', {})
        config['logging']['level'] = os.getenv('LOG_LEVEL', config.get('logging', {}).get('level', 'INFO'))
        config['logging']['file'] = os.getenv('LOG_FILE', config.get('logging', {}).get('file', 'ddos_detector.log'))
        
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
    
    def get_traffic_stats(self, time_window: int) -> List[Dict]:
        """
        Get aggregated traffic statistics for the specified time window
        
        Args:
            time_window: Time window in seconds
            
        Returns:
            List of dictionaries with traffic statistics per destination
        """
        try:
            # Calculate time range
            end_time = datetime.now()
            start_time = end_time - timedelta(seconds=time_window)
            
            # Query to get aggregated traffic stats
            # This query assumes Akvorado's standard schema
            # Adjust column names based on your actual schema
            query = f"""
            SELECT
                DstAddr as dst_ip,
                count() as flows,
                sum(Packets) as packets,
                sum(Bytes) as bytes,
                uniq(SrcAddr) as unique_sources,
                sum(Packets) / {time_window} as pps,
                sum(Bytes) / {time_window} as bps,
                count() / {time_window} as fps
            FROM flows
            WHERE TimeReceived >= toDateTime('{start_time.strftime('%Y-%m-%d %H:%M:%S')}')
              AND TimeReceived <= toDateTime('{end_time.strftime('%Y-%m-%d %H:%M:%S')}')
            GROUP BY DstAddr
            HAVING pps > 1000 OR unique_sources > 100
            ORDER BY pps DESC
            LIMIT 100
            """
            
            result = self.client.query(query)
            
            # Convert result to list of dictionaries
            columns = ['dst_ip', 'flows', 'packets', 'bytes', 'unique_sources', 'pps', 'bps', 'fps']
            stats = []
            for row in result.result_rows:
                stats.append(dict(zip(columns, row)))
            
            return stats
            
        except Exception as e:
            logging.error(f"Failed to query traffic stats: {e}")
            return []


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
        return (
            f"🚨 **DDoS Attack Detected!** 🚨\n\n"
            f"**Target IP:** {attack_info['dst_ip']}\n"
            f"**Packets/sec:** {attack_info['pps']:,.0f}\n"
            f"**Bytes/sec:** {attack_info['bps']:,.0f} ({attack_info['bps']/1000000000:.2f} Gbps)\n"
            f"**Flows/sec:** {attack_info['fps']:,.0f}\n"
            f"**Unique Sources:** {attack_info['unique_sources']:,}\n"
            f"**Total Packets:** {attack_info['packets']:,}\n"
            f"**Total Bytes:** {attack_info['bytes']:,}\n"
            f"**Time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        )
    
    def _send_discord(self, webhook_url: str, message: str, attack_info: Dict):
        """Send notification to Discord"""
        try:
            # Determine color based on severity
            if attack_info['pps'] > 500000 or attack_info['bps'] > 5000000000:
                color = 0xFF0000  # Red - Critical
            elif attack_info['pps'] > 200000 or attack_info['bps'] > 2000000000:
                color = 0xFF6600  # Orange - High
            else:
                color = 0xFFCC00  # Yellow - Medium
            
            payload = {
                "embeds": [{
                    "title": "🚨 DDoS Attack Detected",
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
            logging.info(f"Discord notification sent for {attack_info['dst_ip']}")
            
        except Exception as e:
            logging.error(f"Failed to send Discord notification: {e}")
    
    def _send_slack(self, webhook_url: str, message: str, attack_info: Dict):
        """Send notification to Slack"""
        try:
            # Determine color based on severity
            if attack_info['pps'] > 500000 or attack_info['bps'] > 5000000000:
                color = "danger"  # Red
            elif attack_info['pps'] > 200000 or attack_info['bps'] > 2000000000:
                color = "warning"  # Orange
            else:
                color = "#FFCC00"  # Yellow
            
            payload = {
                "attachments": [{
                    "color": color,
                    "title": "🚨 DDoS Attack Detected",
                    "text": message,
                    "footer": "Akvorado DDoS Detector",
                    "ts": int(datetime.now().timestamp())
                }]
            }
            
            response = requests.post(webhook_url, json=payload, timeout=10)
            response.raise_for_status()
            logging.info(f"Slack notification sent for {attack_info['dst_ip']}")
            
        except Exception as e:
            logging.error(f"Failed to send Slack notification: {e}")


class DDoSDetector:
    """Main DDoS detection engine"""
    
    def __init__(self, config: Config):
        self.config = config
        self.db_client = ClickHouseClient(config)
        self.notifier = NotificationManager(config)
    
    def detect_attacks(self) -> List[Dict]:
        """Detect potential DDoS attacks"""
        time_window = self.config.get('detection', 'time_window')
        stats = self.db_client.get_traffic_stats(time_window)
        
        attacks = []
        thresholds = self.config.get('detection', 'thresholds')
        
        for stat in stats:
            # Check if any threshold is exceeded
            if (stat['pps'] > thresholds.get('pps_threshold', float('inf')) or
                stat['bps'] > thresholds.get('bps_threshold', float('inf')) or
                stat['unique_sources'] > thresholds.get('unique_sources_threshold', float('inf')) or
                stat['fps'] > thresholds.get('fps_threshold', float('inf'))):
                
                attacks.append(stat)
                logging.warning(f"DDoS attack detected: {stat['dst_ip']} - {stat['pps']:.0f} pps, {stat['bps']/1000000000:.2f} Gbps")
        
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
