# Pi-hole LLM Analytics

A comprehensive Python application that analyzes Pi-hole DNS logs using Large Language Models (LLMs) to provide intelligent insights, threat detection, and automated anomaly analysis.

## Features

### **Intelligent DNS Analysis**
- AI-powered categorization of DNS queries and domains
- Automated anomaly detection using machine learning patterns
- Natural language search over DNS logs
- Comprehensive reporting with actionable insights

### **Advanced Security Monitoring**
- Real-time threat detection and alerting
- Domain reputation analysis with threat intelligence
- DNS tunneling and beaconing detection
- Suspicious client activity monitoring
- Pattern-based attack recognition

### **Analytics & Reporting**
- Daily, weekly, and security-focused reports
- Client-specific activity analysis
- Domain categorization and trend analysis
- Customizable alert thresholds and notifications
- Export capabilities (JSON, text, structured reports)

### **Modular Architecture**
- Clean separation of concerns with dedicated modules
- Type-safe data models with comprehensive validation
- Configurable components for different environments
- Extensive logging and error handling
- RESTful API design patterns

## Quick Start

### Prerequisites

- **Python 3.11+** (required for modern type hints and performance)
- **Pi-hole v6+** with API access enabled
- **Ollama** with gpt-oss:latest model installed
- Network access between the analytics server and Pi-hole

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/pihole-llm-analytics.git
   cd pihole-llm-analytics
   ```

2. **Set up Python virtual environment:**
   ```bash
   python -m venv venv
   
   # On Windows:
   venv\Scripts\activate
   
   # On macOS/Linux:
   source venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment variables:**
   ```bash
   # Copy the example configuration
   cp .env.example .env
   
   # Edit .env with your settings
   nano .env
   ```

### Configuration

Create a `.env` file in the project root with your settings:

```bash
# Pi-hole Configuration
PIHOLE_HOST=192.168.7.99        # Pi-hole server IP/hostname
PIHOLE_PORT=8080                # Pi-hole admin interface port (default: 80)
PIHOLE_PASSWORD=your_admin_password  # Pi-hole admin password (NOT API token)

# LLM Configuration  
LLM_URL=http://localhost:11434
LLM_MODEL=gpt-oss:latest
LLM_TIMEOUT=30

# Analytics Configuration
ANALYTICS_LOG_COUNT=1000
ANALYTICS_ENABLE_CACHING=true
ANALYTICS_ANOMALY_THRESHOLD=0.1

# Security Configuration
SECURITY_ENABLE_THREAT_DETECTION=true
SECURITY_ALERT_THRESHOLD=medium
SECURITY_ENABLE_REPUTATION_CHECK=true

# Application Configuration
APP_LOG_LEVEL=INFO
APP_LOG_FORMAT=json
```

**Important Notes**:
- Use `PIHOLE_PASSWORD` for your Pi-hole admin password, not the API token
- Include `PIHOLE_HOST` and `PIHOLE_PORT` separately for better control
- The diagnostic tool (`diagnose.py`) can help verify your configuration

## Usage

### Command Line Interface

The application provides a comprehensive CLI for all operations:

```bash
# Run comprehensive DNS analysis
python -m pihole_analytics analyze --count 1000

# Generate security report for the last 7 days
python -m pihole_analytics report --type security --days 7

# Search DNS logs with natural language
python -m pihole_analytics search "suspicious DNS queries from last hour"

# Check system status and component health
python -m pihole_analytics status

# Analyze specific client activity
python -m pihole_analytics client-analysis 192.168.1.100 --hours 24

# Check domain reputation
python -m pihole_analytics reputation suspicious-domain.com

# Categorize domains using AI
python -m pihole_analytics categorize google.com facebook.com doubleclick.net
```

### Python API

Use the modular API for integration into other applications:

```python
from pihole_analytics.main import PiholeAnalytics

# Initialize with default configuration
analytics = PiholeAnalytics()

# Run comprehensive analysis
results = analytics.run_analysis(count=1000)

# Generate security report
security_report = analytics.generate_report("security", days=7)

# Search logs with natural language
search_results = analytics.search_logs("blocked advertising domains")

# Analyze specific client
client_analysis = analytics.get_client_analysis("192.168.1.100", hours=24)

# Check system health
status = analytics.get_system_status()
```

## Architecture

### Project Structure

```
pihole-llm-analytics/
├── pihole_analytics/           # Main package
│   ├── core/                   # Core functionality
│   │   ├── pihole_client.py   # Pi-hole API client
│   │   └── llm_client.py      # LLM integration
│   ├── analytics/              # Analytics engine
│   │   └── analyzer.py        # DNS analysis and reporting
│   ├── security/               # Security monitoring
│   │   └── threat_detector.py # Threat detection and alerting
│   ├── utils/                  # Shared utilities
│   │   ├── models.py          # Data models and types
│   │   ├── config.py          # Configuration management
│   │   └── logging.py         # Logging utilities
│   ├── main.py                # Main application interface
│   ├── cli.py                 # Command-line interface
│   └── __main__.py            # Module entry point
├── example_usage.py           # Comprehensive examples
├── app.py                     # Legacy standalone script
├── requirements.txt           # Python dependencies
└── README.md                 # This file
```

### Key Components

#### **Core Clients**
- **PiholeClient**: Robust Pi-hole API integration with authentication, retry logic, and error handling
- **LLMClient**: Ollama integration for AI-powered analysis with multiple prompt types and response parsing

#### **Analytics Engine**
- **DNSAnalyzer**: Comprehensive DNS log analysis with anomaly detection, categorization, and reporting
- **ThreatDetector**: Advanced security monitoring with pattern recognition and threat intelligence

#### **Data Models**
- Type-safe dataclasses for all data structures
- Comprehensive enums for status codes and categories
- Validation and serialization support

#### **Configuration System**
- Environment variable-based configuration
- Dataclass-based config objects with validation
- Support for multiple configuration sources

### Security Features

#### **Threat Detection**
- **Domain Reputation Analysis**: Real-time checking against threat intelligence feeds
- **Pattern Recognition**: Detection of DNS tunneling, beaconing, and other suspicious patterns
- **Anomaly Detection**: Statistical analysis to identify unusual query patterns
- **Alert Generation**: Configurable alerts with severity levels and automated notifications

#### **Monitoring Capabilities**
- **Client Behavior Analysis**: Track individual client query patterns and anomalies
- **Temporal Analysis**: Identify time-based attack patterns and suspicious activity windows
- **Domain Classification**: AI-powered categorization of domains and threat assessment
- **Trend Analysis**: Long-term pattern recognition for emerging threats

## Configuration Options

### Pi-hole Settings
- `PIHOLE_HOST`: Pi-hole server IP address or hostname
- `PIHOLE_PORT`: Pi-hole admin interface port (default: 80)
- `PIHOLE_PASSWORD`: Pi-hole admin password (required for query logs access)
- `PIHOLE_TIMEOUT`: Request timeout in seconds (default: 30)

### LLM Settings
- `LLM_URL`: Ollama server URL (default: http://localhost:11434)
- `LLM_MODEL`: Model name (gpt-oss:latest recommended)
- `LLM_TIMEOUT`: Request timeout in seconds (default: 30)

### Analytics Settings
- `ANALYTICS_LOG_COUNT`: Number of recent queries to analyze (default: 1000)
- `ANALYTICS_ENABLE_CACHING`: Enable response caching (default: true)
- `ANALYTICS_ANOMALY_THRESHOLD`: Anomaly detection sensitivity (default: 0.1)

### Security Settings
- `SECURITY_ENABLE_THREAT_DETECTION`: Enable threat detection (default: true)
- `SECURITY_ALERT_THRESHOLD`: Minimum alert severity (low/medium/high/critical)
- `SECURITY_ENABLE_REPUTATION_CHECK`: Enable domain reputation checking (default: true)

## Examples

### Basic Analysis
```python
from pihole_analytics.main import PiholeAnalytics

analytics = PiholeAnalytics()
results = analytics.run_analysis(count=500)

print(f"Analyzed {results['summary']['total_queries']} queries")
print(f"Block rate: {results['summary']['block_rate']*100:.1f}%")
print(f"Anomalies detected: {results['summary']['anomalies_detected']}")
```

### Security Monitoring
```python
# Generate security report
security_report = analytics.generate_report("security", days=7)

# Check for active threats
if security_report.get("threat_analysis"):
    threats = security_report["threat_analysis"]["threats_detected"]
    print(f"Active threats: {threats}")

# Review security alerts
for alert in security_report.get("active_alerts", []):
    print(f"Alert: {alert['title']} - {alert['severity']}")
```

### Client Analysis
```python
# Analyze specific client activity
client_ip = "192.168.1.100"
analysis = analytics.get_client_analysis(client_ip, hours=24)

print(f"Client {client_ip} analysis:")
print(f"  Total queries: {analysis['summary']['total_queries']}")
print(f"  Unique domains: {analysis['summary']['unique_domains']}")
print(f"  Block rate: {analysis['summary']['block_rate']*100:.1f}%")
```

## Troubleshooting

### Common Issues

#### **Pi-hole Authentication Errors (401 Unauthorized)**

**Problem**: Application authenticates successfully but fails when fetching queries with 401 Unauthorized error.

**Symptoms**:
```
2025-08-27 13:19:39,471 - pihole_analytics.piholeclient - INFO - Successfully authenticated to Pi-hole
2025-08-27 13:19:39,532 - pihole_analytics.piholeclient - ERROR - Error occurred: 401 Client Error: Unauthorized for url: http://192.168.7.99:8080/api/queries?sid=...
```

**Fixed in v1.1**: The application now automatically tries multiple authentication methods for Pi-hole v6.0+ compatibility.

**How it works**:
1. **Session-based authentication** (Pi-hole v5.x, backward compatibility)
2. **Password-based per-request authentication** (Pi-hole v6.0+)
3. **Legacy API token method** (older custom installations)

**Quick Test**:
```bash
# Set your environment variables
export PIHOLE_HOST=192.168.7.99
export PIHOLE_PORT=8080
export PIHOLE_PASSWORD=your_admin_password

# Test the fix
python -m pihole_analytics analyze --type security --days 1
```

**If still having issues**:

1. **Run diagnostics**:
   ```bash
   python diagnose.py
   # This will test all authentication methods and show which one works
   ```

2. **Verify Pi-hole admin password**:
   ```bash
   # Test login via Pi-hole web interface first
   # Use the exact same password in PIHOLE_PASSWORD
   ```

3. **Check Pi-hole API settings**:
   - Navigate to Pi-hole Settings → API
   - Ensure API access is enabled
   - Check Query log display permissions

4. **Manual authentication test**:
   ```python
   from pihole_analytics.utils.config import PiholeConfig
   from pihole_analytics.core.pihole_client import PiholeClient
   
   config = PiholeConfig(host="your_ip", port=8080, password="your_password")
   with PiholeClient(config) as client:
       queries = client.fetch_queries(5)  # Now uses multiple auth methods
       print(f"Success! Got {len(queries)} queries")
   ```

**Pi-hole Version Notes**:
- **v5.x and earlier**: Uses session-based authentication
- **v6.0+**: Requires password-based auth for queries endpoint  
- **Custom installations**: May require legacy API token format

The application automatically detects your Pi-hole version and uses the appropriate authentication method.

#### **Pi-hole Connection Errors**
- Verify Pi-hole URL and API key in `.env`
- Ensure Pi-hole API is enabled in admin settings
- Check network connectivity and firewall rules

#### **LLM Service Errors**
- Verify Ollama is running: `ollama list`
- Ensure gpt-oss:latest model is installed: `ollama pull gpt-oss:latest`
- Check LLM service URL and timeout settings

#### **Analysis Errors**
- Start with smaller query counts for testing
- Check Pi-hole logs for any query retrieval issues
- Verify sufficient system memory for large datasets

### Debugging

Enable verbose logging for detailed diagnostic information:

```bash
# Set environment variable
export APP_LOG_LEVEL=DEBUG

# Or use CLI flag
python -m pihole_analytics --verbose analyze
```

#### **Using the Diagnostic Tool**

The project includes a `diagnose.py` script for testing Pi-hole API connectivity:

```bash
# Run the diagnostic tool
python diagnose.py

# This will test:
# - Authentication to Pi-hole
# - All available API endpoints
# - Data retrieval and parsing
# - Provide detailed error information
```

**Example diagnostic output**:
```
Getting session ID...
✓ Authentication successful: BOf8VGaTLcX62ezS0Zw64g=

Testing: http://192.168.7.99:8080/api/summary?sid=...
  Keys: ['domains_being_blocked', 'dns_queries_today', 'ads_blocked_today', ...]

Testing: http://192.168.7.99:8080/api/queries?sid=...
  ✗ Failed: 401 Client Error: Unauthorized for url: ...
```

This helps identify exactly which endpoints are working and which are failing.

### Performance Optimization

- **Query Count**: Start with 500-1000 queries for initial testing
- **Caching**: Enable analytics caching for repeated analyses
- **LLM Timeout**: Adjust timeout based on model size and hardware
- **Memory Usage**: Monitor system memory with large query datasets

## Development

### Setting up Development Environment

1. **Install development dependencies:**
   ```bash
   pip install pytest pylint black mypy
   ```

2. **Run code quality checks:**
   ```bash
   # Linting
   pylint pihole_analytics/
   
   # Type checking
   mypy pihole_analytics/
   
   # Code formatting
   black pihole_analytics/
   ```

3. **Run tests:**
   ```bash
   pytest tests/
   ```

### Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make your changes with proper testing
4. Ensure code quality: `pylint`, `mypy`, `black`
5. Submit a pull request with detailed description

### API Design

The application follows clean architecture principles:

- **Separation of Concerns**: Each module has a single responsibility
- **Dependency Injection**: Configuration and clients are injected
- **Type Safety**: Comprehensive type hints and validation
- **Error Handling**: Structured error handling with proper logging
- **Extensibility**: Easy to add new analyzers and detectors

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- **Pi-hole Project**: For providing excellent DNS filtering capabilities
- **Ollama**: For local LLM hosting and management
- **Python Community**: For robust libraries and development tools

## Support

For questions, issues, or contributions:

1. **Issues**: Use GitHub Issues for bug reports and feature requests
2. **Documentation**: Check the comprehensive examples and code comments
3. **Community**: Join discussions in the repository discussions section

---

**Note**: This application is designed for network analysis and security monitoring. Ensure compliance with your organization's security policies and data handling requirements when deploying in production environments.
