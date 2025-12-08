# Architecture and Design

## Overview

The Akvorado DDoS Detector is a Python-based monitoring system that analyzes network flow data from Akvorado's ClickHouse database to detect Distributed Denial of Service (DDoS) attacks in real-time.

## System Architecture

```
┌─────────────────────────────────────────────────────┐
│                  Akvorado System                     │
│  ┌──────────────┐         ┌──────────────────┐     │
│  │ Flow Collector│ ───────>│ ClickHouse DB    │     │
│  └──────────────┘         └──────────────────┘     │
└──────────────────────────────┬──────────────────────┘
                               │ Query flow data
                               │
┌──────────────────────────────▼──────────────────────┐
│              DDoS Detector Container                 │
│  ┌──────────────────────────────────────────────┐  │
│  │  ddos_detector.py                            │  │
│  │  ┌────────────────────────────────────────┐ │  │
│  │  │ Config Manager                         │ │  │
│  │  │ - Load YAML config                     │ │  │
│  │  │ - Load environment variables           │ │  │
│  │  └────────────────────────────────────────┘ │  │
│  │  ┌────────────────────────────────────────┐ │  │
│  │  │ ClickHouse Client                      │ │  │
│  │  │ - Connect to database                  │ │  │
│  │  │ - Query aggregated traffic stats       │ │  │
│  │  └────────────────────────────────────────┘ │  │
│  │  ┌────────────────────────────────────────┐ │  │
│  │  │ DDoS Detector                          │ │  │
│  │  │ - Analyze traffic patterns             │ │  │
│  │  │ - Apply detection thresholds           │ │  │
│  │  │ - Identify attacks                     │ │  │
│  │  └────────────────────────────────────────┘ │  │
│  │  ┌────────────────────────────────────────┐ │  │
│  │  │ Notification Manager                   │ │  │
│  │  │ - Format alert messages                │ │  │
│  │  │ - Send to Discord/Slack                │ │  │
│  │  │ - Manage cooldown periods              │ │  │
│  │  └────────────────────────────────────────┘ │  │
│  └──────────────────────────────────────────────┘  │
└─────────────────────┬───────┬─────────────────────┘
                      │       │
         ┌────────────┘       └────────────┐
         │                                  │
         ▼                                  ▼
┌──────────────────┐            ┌──────────────────┐
│  Discord Server  │            │  Slack Workspace │
│  (Webhooks)      │            │  (Webhooks)      │
└──────────────────┘            └──────────────────┘
```

## Component Design

### 1. Configuration Manager (`Config`)

**Responsibility:** Load and manage system configuration

**Features:**
- Loads configuration from YAML files
- Overrides with environment variables
- Provides nested value access
- Supports default values

**Configuration Sources (Priority Order):**
1. Environment variables (highest)
2. YAML configuration file
3. Built-in defaults (lowest)

### 2. ClickHouse Client (`ClickHouseClient`)

**Responsibility:** Interface with Akvorado's ClickHouse database

**Key Methods:**
- `_connect()`: Establishes database connection
- `get_traffic_stats(time_window)`: Queries aggregated flow data

**Query Design:**
- Aggregates traffic by destination IP
- Calculates rates (PPS, BPS, FPS)
- Counts unique source IPs
- Filters for significant traffic
- Time-windowed analysis

### 3. DDoS Detector (`DDoSDetector`)

**Responsibility:** Analyze traffic and detect attacks

**Detection Metrics:**
- **PPS (Packets Per Second):** High packet rate attacks
- **BPS (Bytes Per Second):** Volumetric attacks
- **FPS (Flows Per Second):** Connection flood attacks
- **Unique Sources:** Distributed attacks

**Algorithm:**
1. Query traffic statistics from database
2. For each destination IP:
   - Compare metrics against thresholds
   - If any threshold exceeded → Flag as attack
3. Return list of detected attacks

**Threshold Logic:**
Attack detected if ANY of these conditions are met:
```python
pps > pps_threshold OR
bps > bps_threshold OR
unique_sources > unique_sources_threshold OR
fps > fps_threshold
```

### 4. Notification Manager (`NotificationManager`)

**Responsibility:** Send alerts to notification channels

**Features:**
- Multi-channel support (Discord, Slack)
- Cooldown management (prevent spam)
- Severity-based color coding
- Rich message formatting

**Message Structure:**
- Target IP address
- Traffic metrics
- Timestamp
- Visual severity indicator (colors)

**Cooldown Mechanism:**
- Tracks last notification time per target
- Prevents duplicate alerts within cooldown period
- Independent cooldown per destination IP

## Data Flow

1. **Initialization:**
   - Load configuration
   - Connect to ClickHouse
   - Initialize notification manager

2. **Detection Loop (every `check_interval` seconds):**
   ```
   Query DB → Analyze Traffic → Detect Attacks → Send Alerts → Wait → Repeat
   ```

3. **Attack Detection:**
   ```python
   for each destination_ip in traffic_stats:
       if exceeds_any_threshold(destination_ip):
           classify_as_attack()
           notify_channels()
   ```

4. **Notification Flow:**
   ```
   Format Message → Check Cooldown → Send Discord → Send Slack → Update Cooldown
   ```

## Design Decisions

### 1. Why Time Windows?

Analyzing traffic over a time window (default: 5 minutes) provides:
- Smooths out temporary spikes
- Captures sustained attack patterns
- Reduces false positives
- Provides context for analysis

### 2. Why Multiple Metrics?

Different DDoS attack types have different signatures:
- **Volumetric Attacks:** High BPS, moderate PPS
- **Protocol Attacks:** High PPS, moderate BPS
- **Application Layer:** High FPS, many unique sources
- **Distributed Attacks:** Many unique sources

Using multiple metrics ensures broad attack detection.

### 3. Why Cooldown Periods?

Without cooldown:
- Alert spam during ongoing attacks
- Notification fatigue
- Resource waste

With cooldown:
- One alert per attack per cooldown period
- Follow-up alerts if attack continues
- Balanced between awareness and noise

### 4. Why Environment Variables + Config Files?

**Config Files:**
- Good for static settings
- Easy to version control
- Human-readable

**Environment Variables:**
- Good for secrets (webhooks, passwords)
- Container-friendly
- Easy to override

Using both provides flexibility for different deployment scenarios.

### 5. Why Docker?

**Benefits:**
- Consistent deployment environment
- Easy integration with Akvorado
- Isolated dependencies
- Simple scaling and management
- Works with orchestration platforms

## Security Considerations

### 1. Database Access
- Use read-only credentials
- Limit to specific database/tables
- Network isolation when possible

### 2. Credentials Management
- Never commit secrets to git
- Use environment variables or secrets management
- Rotate credentials periodically

### 3. Webhook Security
- Keep webhook URLs private
- Regenerate if exposed
- Use HTTPS only

### 4. Network Isolation
- Run in isolated Docker network
- Restrict outbound connections
- Use firewall rules

## Performance Considerations

### 1. Query Optimization
- Pre-aggregation in database (GROUP BY)
- Limited result set (LIMIT, HAVING)
- Indexed columns for time-based queries
- Efficient time window selection

### 2. Memory Usage
- Stateless design (minimal memory footprint)
- No large data caching
- Connection pooling in ClickHouse client

### 3. CPU Usage
- Simple threshold comparisons
- No complex calculations
- Efficient Python data structures

### 4. Network Usage
- Batch notifications where possible
- Configurable check intervals
- Cooldown reduces duplicate traffic

## Scalability

### Horizontal Scaling
- Multiple detector instances possible
- Each can monitor different targets
- Shared ClickHouse backend
- Independent notification channels

### Vertical Scaling
- Increase check frequency
- Larger time windows
- More metrics per query
- Additional notification channels

## Testing Strategy

### Unit Tests
- Configuration loading
- Threshold detection logic
- Notification formatting
- Cooldown mechanism

### Integration Tests
- Database connectivity
- Webhook delivery
- End-to-end detection flow

### Manual Testing
- Notification appearance
- Alert timing
- Configuration validation

## Future Enhancements

Potential improvements:
1. **Machine Learning:** Anomaly detection for dynamic thresholds
2. **Historical Analysis:** Trend analysis and reporting
3. **Multiple Databases:** Support for other data sources
4. **Advanced Filtering:** Whitelist/blacklist IP ranges
5. **Dashboard:** Web UI for monitoring and configuration
6. **Metrics Export:** Prometheus/Grafana integration
7. **Alert Aggregation:** Combine related attacks
8. **Automatic Response:** Integration with mitigation systems

## Deployment Patterns

### Pattern 1: Standalone
```
DDoS Detector → Existing Akvorado → Notifications
```
Best for: Simple deployments, testing

### Pattern 2: Integrated
```
Akvorado Stack (with embedded detector) → Notifications
```
Best for: Production environments, single management plane

### Pattern 3: Distributed
```
Multiple Detectors → Shared Akvorado → Centralized Notifications
```
Best for: Large networks, geographic distribution

## Maintenance

### Regular Tasks
- Review and adjust thresholds
- Monitor false positive rate
- Check webhook validity
- Update dependencies
- Review logs for anomalies

### Troubleshooting
1. Check configuration
2. Verify database connectivity
3. Test webhook URLs
4. Review logs
5. Validate permissions

## Conclusion

This architecture provides a robust, flexible, and maintainable solution for DDoS detection using Akvorado's network flow data. The modular design allows for easy customization and extension while maintaining simplicity and reliability.
