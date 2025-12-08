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
│  │  │ AbuseIPDB Client                       │ │  │
│  │  │ - Check IPs against malicious DB       │ │  │
│  │  │ - Get abuse reports and scores         │ │  │
│  │  │ - Manage API quota                     │ │  │
│  │  └────────────────────────────────────────┘ │  │
│  │  ┌────────────────────────────────────────┐ │  │
│  │  │ DDoS Detector                          │ │  │
│  │  │ - Analyze traffic patterns             │ │  │
│  │  │ - Calculate entropy                    │ │  │
│  │  │ - Validate with AbuseIPDB              │ │  │
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

**Key Configuration Sections:**
- ClickHouse connection settings
- Detection thresholds and time windows
- AbuseIPDB API credentials
- Notification channels and cooldowns
- Logging configuration

### 2. ClickHouse Client (`ClickHouseClient`)

**Responsibility:** Interface with Akvorado's ClickHouse database

**Key Methods:**
- `_connect()`: Establishes database connection
- `get_total_external_traffic(time_window)`: Queries total external traffic
- `get_dst_traffic_stats(time_window)`: Queries per-destination traffic with source IP distribution

**Query Design:**
- Filters for external boundary traffic (`InIfBoundary = 'external'`)
- Aggregates traffic by destination IP
- Calculates bytes per second (BPS)
- Collects source IP lists and their traffic distribution
- Counts unique source IPs
- Filters for significant traffic (> 1 Mbps)
- Time-windowed analysis

### 3. AbuseIPDB Client (`AbuseIPDBClient`)

**Responsibility:** Validate source IPs against AbuseIPDB malicious IP database

**Key Methods:**
- `check_ip(ip_address)`: Check if an IP has been reported for malicious activity

**Features:**
- Optional integration (enabled only with API key)
- Returns abuse confidence score (0-100%)
- Provides report count and ISP information
- Smart quota management (stops after first reported IP)
- Error handling for API failures

**Response Data:**
- IP address
- Abuse confidence score
- Total number of reports
- Country code
- ISP name
- Usage type (Data Center, ISP, etc.)

### 4. DDoS Detector (`DDoSDetector`)

**Responsibility:** Analyze traffic and detect attacks

**Detection Metrics:**
- **BPS (Bytes Per Second):** Volumetric attacks (primary metric)
- **Normalized Entropy:** Distribution of traffic across source IPs
- **Unique Sources:** Number of distinct attacking sources
- **AbuseIPDB Reports:** Known malicious IP validation

**Algorithm:**
1. Check total external traffic threshold (1 Gbps default)
   - If below threshold, skip detailed analysis (no attack)
2. Query per-destination traffic statistics from database
3. For each destination IP exceeding threshold (1 Gbps default):
   a. Calculate normalized entropy of source IP distribution
   b. Classify attack type:
      - High entropy (> 0.8) → DDoS (distributed)
      - Low entropy (≤ 0.8) → DoS (concentrated)
   c. If AbuseIPDB enabled, check source IPs:
      - Query API for each source IP
      - Stop after first reported IP found (quota saving)
   d. Trigger alert if:
      - Source IP found in AbuseIPDB with reports, OR
      - Entropy exceeds threshold (0.8)
4. Return list of detected attacks with metadata

**Entropy Calculation:**
```python
entropy = -Σ(p_i * log2(p_i))  # Shannon entropy
normalized_entropy = entropy / log2(n)  # Normalize to [0, 1]
```
Where:
- p_i = proportion of traffic from source i
- n = number of unique sources

**API Quota Management:**
- Single flag tracks if reported IP found
- Once set, no more API calls made
- Saves API quota for future detections
- Allows multiple destinations to be checked efficiently
   - Compare metrics against thresholds
   - If any threshold exceeded → Flag as attack
3. Return list of detected attacks

**Threshold Logic:**
Two-stage detection process:

**Stage 1: Traffic Volume Check**
```python
total_external_bps > total_threshold (1 Gbps) AND
destination_bps > dst_threshold (1 Gbps)
```

**Stage 2: Alert Trigger (if Stage 1 passes)**
```python
(source_ip in AbuseIPDB with reports) OR
(normalized_entropy > entropy_threshold)
```

This approach:
- Reduces false positives from legitimate high traffic
- Combines reputation-based and behavior-based detection
- Saves API quota by using entropy as alternative signal

### 5. Notification Manager (`NotificationManager`)

**Responsibility:** Send alerts to notification channels

**Features:**
- Multi-channel support (Discord, Slack)
- Cooldown management (prevent spam)
- Severity-based color coding
- Rich message formatting

**Message Structure:**
- Target IP address
- Traffic metrics (BPS, Gbps)
- Normalized entropy value
- Unique source count
- Attack type (DoS/DDoS)
- AbuseIPDB information (if available):
  - Reported IP address
  - Total reports
  - Abuse confidence score
  - Country and ISP
- Alert reason (AbuseIPDB or entropy)
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
   total_traffic = get_total_external_traffic()
   if total_traffic <= threshold:
       return []  # No attack
   
   api_quota_reached = False
   for each destination_ip in traffic_stats:
       if destination_bps > threshold:
           entropy = calculate_entropy(src_ips, src_bytes)
           attack_type = 'DDoS' if entropy > 0.8 else 'DoS'
           
           should_alert = False
           abuse_info = None
           
           # Check AbuseIPDB if enabled and quota not reached
           if abuseipdb_enabled and not api_quota_reached:
               for src_ip in source_ips:
                   abuse_info = check_abuseipdb(src_ip)
                   if abuse_info and abuse_info.is_reported:
                       should_alert = True
                       api_quota_reached = True  # Stop further API calls
                       break
           
           # Check entropy if no reported IP found
           if not should_alert and entropy > entropy_threshold:
               should_alert = True
           
           if should_alert:
               notify_channels(attack_info)
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

### 2. Why Entropy-Based Detection?

Traditional threshold-based detection can miss attacks or generate false positives. Entropy-based detection provides:

**Benefits:**
- **Attack Classification:** Distinguish DoS (single source) from DDoS (distributed)
- **Adaptive Detection:** Works across different attack scales
- **Behavior Analysis:** Focuses on traffic distribution, not just volume
- **Reduced False Positives:** High legitimate traffic won't trigger alerts alone

**Attack Signatures:**
- **DDoS (High Entropy):** Traffic evenly distributed across many sources
- **DoS (Low Entropy):** Traffic concentrated from few sources
- **Normal Traffic:** Usually has moderate entropy with organic patterns

Combining entropy with AbuseIPDB provides both behavior-based and reputation-based detection.

### 3. Why AbuseIPDB Integration?

**Advantages:**
- **Reduced False Positives:** Known bad IPs trigger alerts even with low entropy
- **Early Detection:** Identify attacks from known malicious actors quickly
- **Rich Context:** ISP, country, and history information for investigations
- **API Efficiency:** Smart quota management stops after first reported IP

**Trade-offs:**
- Optional dependency (works without API key)
- API rate limits (1,000/day free tier)
- External service dependency
- Privacy considerations (IP sharing)

**When to Use:**
- Production environments with known attack patterns
- Networks with external-facing services
- Organizations with security requirements
- Environments needing audit trails

### 4. Why Cooldown Periods?

Without cooldown:
- Alert spam during ongoing attacks
- Notification fatigue
- Resource waste

With cooldown:
- One alert per attack per cooldown period
- Follow-up alerts if attack continues
- Balanced between awareness and noise

### 5. Why Environment Variables + Config Files?

**Config Files:**
- Good for static settings
- Easy to version control
- Human-readable

**Environment Variables:**
- Good for secrets (webhooks, passwords)
- Container-friendly
- Easy to override

Using both provides flexibility for different deployment scenarios.

### 6. Why Docker?

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
- No large data caching (except cooldown tracking)
- Connection pooling in ClickHouse client
- Limited source IP list size from queries

### 3. CPU Usage
- Simple threshold comparisons
- Lightweight entropy calculations (logarithmic operations)
- Efficient Python data structures
- Minimal AbuseIPDB API overhead

### 4. Network Usage
- Batch notifications where possible
- Configurable check intervals
- Cooldown reduces duplicate traffic
- AbuseIPDB API quota management:
  - Stops after first reported IP
  - Typically 1-10 API calls per detection cycle
  - Respects rate limits (1,000/day free tier)

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
9. **Enhanced AbuseIPDB:**
   - Cache results to reduce API calls
   - Configurable abuse score thresholds
   - Report attacks back to AbuseIPDB
10. **Advanced Entropy Analysis:**
   - Time-series entropy tracking
   - Baseline learning for normal entropy patterns
   - Multi-dimensional entropy (IP, port, protocol)

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
