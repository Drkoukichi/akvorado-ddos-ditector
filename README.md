# Akvorado DDoS Detector

A Python-based DDoS detection system that monitors network flow data from Akvorado's ClickHouse database and sends real-time alerts to Discord or Slack.

## Features

- 🔍 **Real-time DDoS Detection** - Monitors network flows for suspicious patterns
- 📊 **Multiple Detection Metrics** - Analyzes traffic volume, entropy, and source distribution
- 🚫 **AbuseIPDB Integration** - Validates source IPs against known malicious IP database
- 🔔 **Multi-channel Notifications** - Supports Discord and Slack webhooks
- 🚀 **Startup Notifications** - Sends traffic summary with AbuseIPDB check on startup
- 🐳 **Docker Support** - Easy deployment with Docker and Docker Compose
- ⚙️ **Flexible Configuration** - Configure via YAML file or environment variables
- 📝 **Detailed Logging** - Comprehensive logging for monitoring and debugging
- 💰 **API Quota Management** - Intelligent API usage to minimize external service calls

## How It Works

The detector uses a three-step approach to identify DoS and DDoS attacks:

### Detection Logic

1. **Total External Traffic Check**
   - Monitors total traffic where `InIfBoundary = external`
   - Only proceeds if total traffic exceeds 1 Gbps (configurable)

2. **Per-Destination Analysis**
   - Identifies destination IPs with traffic exceeding 1 Gbps (configurable)
   - Collects source IP distribution data

3. **AbuseIPDB Verification** (Optional)
   - Checks source IPs against AbuseIPDB for known malicious activity
   - Stops API calls after first reported IP found (quota saving)
   - Provides abuse confidence score and report count

4. **Alert Triggers**
   - **Trigger 1**: Source IP found in AbuseIPDB with reports
   - **Trigger 2**: High entropy (> 0.8) indicating distributed attack
   - Attack is flagged if **either** condition is met

5. **Attack Classification**
   - Calculates **Normalized Entropy** of source IP distribution
   - **High Entropy (> 0.8)**: Traffic distributed across many sources → **DDoS Attack**
   - **Low Entropy (≤ 0.8)**: Traffic concentrated in few sources → **DoS Attack**

### Entropy-Based Classification

Normalized entropy measures how evenly distributed the attack traffic is across source IPs:
- **DDoS**: Many attackers, high entropy (distributed attack)
- **DoS**: Single or few attackers, low entropy (concentrated attack)

### AbuseIPDB Integration

The detector can optionally validate source IPs against [AbuseIPDB](https://www.abuseipdb.com/), a database of reported malicious IPs:
- **Smart Detection**: Alerts even with low entropy if source IP is known to be malicious
- **API Quota Saving**: Stops checking after first reported IP is found
- **Rich Context**: Provides abuse score, report count, ISP, and country information
- **Optional**: Works without API key using entropy-only detection

When attacks are detected, alerts are sent to configured notification channels (Discord/Slack) with attack type, traffic volume, entropy value, source count, and AbuseIPDB information (if available).

## Prerequisites

- Python 3.11+ (if running without Docker)
- Access to Akvorado's ClickHouse database
- Discord and/or Slack webhook URLs for notifications

## Quick Start

### Using Docker Compose (Recommended)

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Drkoukichi/akvorado-ddos-ditector.git
   cd akvorado-ddos-ditector
   ```

2. **Create configuration file:**
   ```bash
   cp config.yaml.example config.yaml
   ```

3. **Edit `config.yaml` or create `.env` file:**
   ```bash
   cp .env.example .env
   # Edit .env with your settings
   ```

4. **Configure your webhooks and ClickHouse connection:**
   - Set `DISCORD_WEBHOOK` and/or `SLACK_WEBHOOK` in `.env`
   - Configure ClickHouse connection details
   - Adjust detection thresholds as needed

5. **Test your webhooks (optional):**
   ```bash
   python examples/test_notifications.py <your_webhook_url>
   ```

6. **Start the detector:**
   ```bash
   docker-compose up -d
   ```
   
   Or use the quick start script:
   ```bash
   bash examples/quick_start.sh
   ```

7. **View logs:**
   ```bash
   docker-compose logs -f ddos-detector
   ```

### Using Python Directly

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Create configuration:**
   ```bash
   cp config.yaml.example config.yaml
   # Edit config.yaml with your settings
   ```

3. **Run the detector:**
   ```bash
   python ddos_detector.py
   ```

## Configuration

### Configuration File (config.yaml)

See `config.yaml.example` for a complete configuration template. Key settings:

```yaml
clickhouse:
  host: "localhost"
  port: 9000
  database: "flows"
  user: "default"
  password: ""

detection:
  check_interval: 60        # Check every 60 seconds
  time_window: 300          # Analyze last 5 minutes
  thresholds:
    # Step 1: Total external traffic threshold
    total_external_bps_threshold: 1000000000  # 1 Gbps
    
    # Step 2: Per-destination threshold
    dst_bps_threshold: 1000000000  # 1 Gbps
    
    # Step 3: Entropy threshold for DoS vs DDoS classification
    entropy_threshold: 0.8  # > 0.8 = DDoS, ≤ 0.8 = DoS

abuseipdb:
  api_key: ""              # Your AbuseIPDB API key (leave empty to disable)
  max_age_days: 90         # Consider reports from last 90 days

notifications:
  discord_webhook: "https://discord.com/api/webhooks/..."
  slack_webhook: "https://hooks.slack.com/services/..."
  cooldown: 300  # Wait 5 minutes between alerts for same target
```

### Environment Variables

All configuration options can be set via environment variables:

- `CLICKHOUSE_HOST`, `CLICKHOUSE_PORT`, `CLICKHOUSE_DATABASE`, `CLICKHOUSE_USER`, `CLICKHOUSE_PASSWORD`
- `CHECK_INTERVAL`, `TIME_WINDOW`
- `TOTAL_EXTERNAL_BPS_THRESHOLD`, `DST_BPS_THRESHOLD`, `ENTROPY_THRESHOLD`
- `ABUSEIPDB_API_KEY`, `ABUSEIPDB_MAX_AGE_DAYS`
- `DISCORD_WEBHOOK`, `SLACK_WEBHOOK`, `NOTIFICATION_COOLDOWN`
- `LOG_LEVEL`, `LOG_FILE`

## Setting Up AbuseIPDB (Optional)

AbuseIPDB integration enhances detection by validating source IPs against a database of reported malicious activity.

### Getting an API Key

1. Go to [AbuseIPDB](https://www.abuseipdb.com/)
2. Create a free account
3. Navigate to your [API settings](https://www.abuseipdb.com/account/api)
4. Copy your API key
5. Add it to your configuration:
   ```yaml
   abuseipdb:
     api_key: "your_api_key_here"
     max_age_days: 90
   ```
   Or as environment variable:
   ```bash
   ABUSEIPDB_API_KEY=your_api_key_here
   ```

### API Usage and Limits

- **Free Tier**: 1,000 requests per day
- **Smart Quota Management**: The detector stops API calls after finding the first reported IP
- **Optional Feature**: The detector works without AbuseIPDB, using entropy-only detection
- **Recommended**: Enable for production environments to reduce false positives

### Benefits

- **Fewer False Positives**: Known malicious IPs trigger alerts even with low entropy
- **Rich Context**: Get ISP, country, and abuse history information
- **Early Detection**: Identify attacks from known bad actors quickly

## Setting Up Webhooks

### Discord Webhook

1. Go to your Discord server settings
2. Navigate to **Integrations** → **Webhooks**
3. Click **New Webhook**
4. Copy the webhook URL
5. Add it to your configuration as `DISCORD_WEBHOOK`

### Slack Webhook

1. Go to [Slack API Apps](https://api.slack.com/apps)
2. Create a new app or select existing one
3. Enable **Incoming Webhooks**
4. Add a new webhook to your workspace
5. Copy the webhook URL
6. Add it to your configuration as `SLACK_WEBHOOK`

## Integration with Akvorado

This detector is designed to work with Akvorado's ClickHouse database. Make sure:

1. Akvorado is deployed and collecting flow data
2. ClickHouse is accessible from the detector
3. The database name and table schema match your Akvorado setup
4. The detector has read access to the flows table

If you're using a custom Akvorado setup, you may need to adjust the SQL query in `ddos_detector.py` to match your schema.

## Docker Deployment

### With Existing Akvorado Deployment

If you already have Akvorado running, update `docker-compose.yml`:

1. Comment out or remove the `clickhouse` service
2. Set `CLICKHOUSE_HOST` to your Akvorado ClickHouse host
3. Adjust the network configuration to match your setup

### Standalone Deployment

The included `docker-compose.yml` includes a ClickHouse service for testing. For production use with Akvorado:

```bash
docker-compose up -d ddos-detector
```

## Examples

The `examples/` directory contains helpful scripts:

### Test Notifications

Test your Discord or Slack webhook before deploying:

```bash
python examples/test_notifications.py https://discord.com/api/webhooks/...
python examples/test_notifications.py https://hooks.slack.com/services/...
```

### Quick Start Script

Automated setup and deployment:

```bash
bash examples/quick_start.sh
```

This script will:
- Check for Docker installation
- Create configuration files from templates
- Build the Docker image
- Start the detector

## Monitoring and Maintenance

### Viewing Logs

```bash
# Docker
docker-compose logs -f ddos-detector

# Local logs
tail -f logs/ddos_detector.log
```

### Adjusting Thresholds

Monitor the logs to understand normal traffic patterns and adjust thresholds accordingly:

**Traffic Thresholds:**
- `total_external_bps_threshold`: Set based on your expected total external traffic
- `dst_bps_threshold`: Set based on typical per-destination traffic volumes
- Start with 1 Gbps (default) and adjust based on your network capacity

**Entropy Threshold (0.0 - 1.0):**
- **Higher values (e.g., 0.9)**: Only highly distributed attacks classified as DDoS (stricter)
- **Lower values (e.g., 0.6)**: More attacks classified as DDoS (looser)
- **Default 0.8**: Balanced classification
- Monitor logs to see entropy values for actual attacks and tune accordingly

### Notification Cooldown

The cooldown period prevents alert spam for ongoing attacks. Adjust based on your needs:

- Shorter cooldown (60-300s) for quick updates
- Longer cooldown (600-1800s) to reduce noise

## Troubleshooting

### Connection Issues

If you can't connect to ClickHouse:
- Check host and port settings
- Verify network connectivity
- Check ClickHouse authentication
- Review Docker network configuration

### No Detections

If attacks aren't being detected:
- Check if flow data is available in ClickHouse
- Verify thresholds aren't too high
- Review SQL query compatibility with your schema
- Check logs for errors

### Notification Issues

If alerts aren't being sent:
- Verify webhook URLs are correct
- Check network connectivity to Discord/Slack
- Review logs for error messages
- Test webhooks manually with curl

## Security Considerations

- Store sensitive credentials in `.env` file (not in version control)
- Use read-only database credentials
- Restrict network access to ClickHouse
- Keep webhook URLs secret
- Regularly update dependencies

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## License

This project is open source. See LICENSE file for details.

## Support

For issues, questions, or contributions, please open an issue on GitHub.