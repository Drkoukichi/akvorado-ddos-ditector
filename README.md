# Akvorado DDoS Detector

A Python-based DDoS detection system that monitors network flow data from Akvorado's ClickHouse database and sends real-time alerts to Discord or Slack.

## Features

- 🔍 **Real-time DDoS Detection** - Monitors network flows for suspicious patterns
- 📊 **Multiple Detection Metrics** - Analyzes packets per second, bytes per second, unique sources, and flows per second
- 🔔 **Multi-channel Notifications** - Supports Discord and Slack webhooks
- 🐳 **Docker Support** - Easy deployment with Docker and Docker Compose
- ⚙️ **Flexible Configuration** - Configure via YAML file or environment variables
- 📝 **Detailed Logging** - Comprehensive logging for monitoring and debugging

## How It Works

The detector queries Akvorado's ClickHouse database at regular intervals to analyze network flow data. It aggregates traffic statistics per destination IP and checks against configurable thresholds:

- **Packets Per Second (PPS)** - Detects high packet rate attacks
- **Bytes Per Second (BPS)** - Detects volumetric attacks
- **Unique Source IPs** - Detects distributed attacks
- **Flows Per Second (FPS)** - Detects connection flood attacks

When thresholds are exceeded, alerts are sent to configured notification channels with detailed attack information.

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

5. **Start the detector:**
   ```bash
   docker-compose up -d
   ```

6. **View logs:**
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
    pps_threshold: 100000   # 100k packets/sec
    bps_threshold: 1000000000  # 1 Gbps
    unique_sources_threshold: 1000
    fps_threshold: 10000

notifications:
  discord_webhook: "https://discord.com/api/webhooks/..."
  slack_webhook: "https://hooks.slack.com/services/..."
  cooldown: 300  # Wait 5 minutes between alerts for same target
```

### Environment Variables

All configuration options can be set via environment variables:

- `CLICKHOUSE_HOST`, `CLICKHOUSE_PORT`, `CLICKHOUSE_DATABASE`, `CLICKHOUSE_USER`, `CLICKHOUSE_PASSWORD`
- `CHECK_INTERVAL`, `TIME_WINDOW`
- `PPS_THRESHOLD`, `BPS_THRESHOLD`, `UNIQUE_SOURCES_THRESHOLD`, `FPS_THRESHOLD`
- `DISCORD_WEBHOOK`, `SLACK_WEBHOOK`, `NOTIFICATION_COOLDOWN`
- `LOG_LEVEL`, `LOG_FILE`

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

- Start with high thresholds to avoid false positives
- Gradually lower thresholds based on your network baseline
- Different networks require different thresholds

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